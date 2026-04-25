//! Identity chains — stable identity references via evolving policy event chains.
//!
//! An identity chain is a SAD Event Log where:
//! - Topic: `kels/sad/v1/identity/chain`
//! - Content: `None` at every version (policy is carried in `write_policy`)
//! - Chain prefix: the stable identity reference
//! - `write_policy`: the current policy's SAID (self-governing)

use kels_core::{SadEvent, SelVerification, compute_sad_event_prefix};
use verifiable_storage::SelfAddressed;

use crate::{Policy, error::PolicyError};

/// Well-known topic for identity chains.
pub const IDENTITY_CHAIN_TOPIC: &str = "kels/sad/v1/identity/chain";

/// Create a v0 inception event for an identity chain.
///
/// The returned event's `prefix` is the stable identity reference.
/// `write_policy` is set to `initial_policy.said` — the identity is self-governing.
///
/// To enable `advance()` (policy rotation), follow the inception with an `Est`
/// event at v1 declaring `governance_policy`. Without it, `advance()` produces
/// an `Evl` that the verifier rejects at submission (governance_policy must be
/// established on the branch). See `advance()` for the higher-threshold
/// authorization rules that apply to rotation.
pub fn create(initial_policy: &Policy) -> Result<SadEvent, PolicyError> {
    initial_policy
        .verify_said()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Policy SAID verification failed: {e}")))?;

    SadEvent::icp(IDENTITY_CHAIN_TOPIC, initial_policy.said, None)
        .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to create identity event: {e}")))
}

/// Create the next version of an identity chain with an updated policy.
///
/// Takes a `SelVerification` token (chain must be verified before advancing)
/// and a new policy. The new policy must differ from the current write_policy —
/// an identity chain advance with an unchanged policy is meaningless (content is
/// always None, custody is always None, there's nothing else to change).
///
/// The produced event is an `Evl` (was `Upd` before #131). This means the advance
/// is evaluated against `governance_policy` — a higher-threshold authorization bar
/// than `write_policy`. Policy replacement now requires satisfying both the previous
/// write_policy (the soft check on every v1+ event) and the governance_policy (the
/// hard check that gates Evl acceptance).
///
/// Precondition: the chain must have `governance_policy` established (via a prior
/// `Est` at v1 or a v0 declaration on the inception event). If not, the returned
/// event will be rejected by `SelVerifier` at submission — `advance()` itself
/// does not surface this error.
pub fn advance(
    verification: &SelVerification,
    new_policy: &Policy,
) -> Result<SadEvent, PolicyError> {
    if !verification.policy_satisfied() {
        return Err(PolicyError::InvalidPolicy(
            "Cannot advance — chain policy not satisfied".to_string(),
        ));
    }

    new_policy
        .verify_said()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Policy SAID verification failed: {e}")))?;

    if verification.topic() != IDENTITY_CHAIN_TOPIC {
        return Err(PolicyError::InvalidPolicy(format!(
            "Not an identity chain — topic is '{}', expected '{}'",
            verification.topic(),
            IDENTITY_CHAIN_TOPIC
        )));
    }

    if new_policy.said == *verification.write_policy() {
        return Err(PolicyError::InvalidPolicy(
            "Identity chain advance requires a different policy — \
             content and custody are always None, so unchanged write_policy is a no-op"
                .to_string(),
        ));
    }

    // Route through `SadEvent::evl` — the per-kind constructor runs
    // `validate_structure` internally, so any future tightening of Evl's
    // rules surfaces here at construction rather than at server-side
    // verification. Identity chains carry no custody at any version (see
    // `create` above), so the inherited custody is `None` and no explicit
    // reset is needed.
    SadEvent::evl(
        verification.current_event(),
        None,                  // content: identity chains carry none
        Some(new_policy.said), // write_policy: the rotation
        None,                  // governance_policy: not evolved on advance
    )
    .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to create advance event: {e}")))
}

/// Compute the identity chain prefix for a given initial policy.
///
/// Deterministic — anyone can compute this offline from the policy SAID.
pub fn compute_identity_prefix(initial_policy: &Policy) -> Result<cesr::Digest256, PolicyError> {
    initial_policy
        .verify_said()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Policy SAID verification failed: {e}")))?;

    compute_sad_event_prefix(initial_policy.said, IDENTITY_CHAIN_TOPIC)
        .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to compute prefix: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)]
// Happy-path tests stage setup chains via `SadEventBuilder::incept_deterministic`.
// The `add_governance_declaration` helper and the non-identity-chain v0 in the
// wrong-topic test stay hand-built: they produce intermediate partial states or
// cross-topic shapes that the builder refuses by design.
mod tests {
    use std::sync::Arc;

    use kels_core::{KelsError, PolicyChecker, SadEventBuilder, SadEventKind, SelVerifier};
    use verifiable_storage::Chained;

    use super::*;

    struct AlwaysPassChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn satisfies(&self, _: &SadEvent, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Accepts the soft wp check for `Est` (so governance_policy can establish)
    /// but rejects it for every other kind — lets the test build a chain where
    /// `policy_satisfied()` is false while the governance_policy is still
    /// established (required after the R6 Est-arm defense-in-depth gate).
    struct RejectAdvanceChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectAdvanceChecker {
        async fn satisfies(
            &self,
            event: &SadEvent,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(event.kind == SadEventKind::Est)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    fn test_policy(label: &str) -> Policy {
        let prefix = cesr::Digest256::blake3_256(label.as_bytes());
        Policy::build(&format!("endorse({prefix})"), None, false).unwrap()
    }

    #[test]
    fn test_create_identity_chain() {
        let policy = test_policy("test-identity");
        let v0 = create(&policy).unwrap();

        assert_eq!(v0.version, 0);
        assert!(v0.content.is_none());
        assert!(v0.previous.is_none());
        assert_eq!(v0.write_policy, Some(policy.said));
        assert_eq!(v0.topic, IDENTITY_CHAIN_TOPIC);
    }

    #[test]
    fn test_create_deterministic_prefix() {
        let policy = test_policy("test-identity");
        let v0_a = create(&policy).unwrap();
        let v0_b = create(&policy).unwrap();
        assert_eq!(v0_a.prefix, v0_b.prefix);
        assert_eq!(v0_a.said, v0_b.said);
    }

    #[test]
    fn test_create_rejects_invalid_said() {
        let mut policy = test_policy("test-identity");
        policy.expression = "tampered".to_string(); // invalidate SAID
        assert!(create(&policy).is_err());
    }

    /// Declare governance_policy on an event (Est kind).
    fn add_governance_declaration(event: &mut SadEvent) {
        let gp_policy = test_policy("governance");
        event.kind = SadEventKind::Est;
        event.governance_policy = Some(gp_policy.said);
        // Est forbids write_policy
        event.write_policy = None;
    }

    #[tokio::test]
    async fn test_advance_identity_chain() {
        let policy1 = test_policy("policy-1");
        let policy2 = test_policy("policy-2");
        let gp = test_policy("governance");

        // Stage v0 Icp + v1 Est via the builder. Identity chains are
        // prefix-discoverable, so governance lives on v1 (Est), not v0.
        let mut builder = SadEventBuilder::new(None, None, None);
        builder
            .incept_deterministic(IDENTITY_CHAIN_TOPIC, policy1.said, gp.said, None)
            .unwrap();
        let staged = builder.pending_events().to_vec();
        let v0 = staged[0].clone();
        let prefix = v0.prefix;

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&staged).await.unwrap();
        let verification = verifier.finish().await.unwrap();

        let v2 = advance(&verification, &policy2).unwrap();
        assert_eq!(v2.version, 2);
        assert!(v2.content.is_none());
        assert_eq!(v2.kind, SadEventKind::Evl);
        assert_eq!(v2.write_policy, Some(policy2.said));
        assert_eq!(v2.prefix, prefix);

        // Close the loop: feed the full chain [v0, v1, v2] back through a
        // fresh verifier to prove the produced Evl passes verification (a
        // different code path than the Upd it replaced) and that
        // tracked_write_policy advances to policy2.said.
        let mut full_chain = staged.clone();
        full_chain.push(v2);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&full_chain).await.unwrap();
        let reverification = verifier.finish().await.unwrap();
        assert!(reverification.policy_satisfied());
        assert_eq!(reverification.write_policy(), &policy2.said);
    }

    #[test]
    fn test_compute_identity_prefix_matches_create() {
        let policy = test_policy("test-identity");
        let v0 = create(&policy).unwrap();
        let computed = compute_identity_prefix(&policy).unwrap();
        assert_eq!(v0.prefix, computed);
    }

    #[tokio::test]
    async fn test_advance_rejects_wrong_topic() {
        // Create a non-identity chain event with governance_policy and verify it
        let policy = test_policy("test");
        let gp_policy = test_policy("governance");
        let v0 =
            SadEvent::icp("kels/sad/v1/keys/mlkem", policy.said, Some(gp_policy.said)).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();

        let policy2 = test_policy("policy-2");
        let err = advance(&verification, &policy2).unwrap_err();
        assert!(err.to_string().contains("Not an identity chain"));
    }

    #[tokio::test]
    async fn test_advance_rejects_unchanged_policy() {
        let policy = test_policy("test-identity");
        let gp = test_policy("governance");

        let mut builder = SadEventBuilder::new(None, None, None);
        builder
            .incept_deterministic(IDENTITY_CHAIN_TOPIC, policy.said, gp.said, None)
            .unwrap();
        let staged = builder.pending_events().to_vec();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&staged[0].prefix), Arc::clone(&checker));
        verifier.verify_page(&staged).await.unwrap();
        let verification = verifier.finish().await.unwrap();

        // Advance with the same policy — should fail
        let err = advance(&verification, &policy).unwrap_err();
        assert!(err.to_string().contains("unchanged write_policy"));
    }

    #[tokio::test]
    async fn test_advance_rejects_unsatisfied_policy() {
        let policy1 = test_policy("policy-1");
        let policy2 = test_policy("policy-2");
        let v0 = create(&policy1).unwrap();

        // v1: Est establishes governance_policy (RejectAdvanceChecker accepts Est
        // so the R6 Est-arm gate permits the governance_policy advance).
        let mut v1 = v0.clone();
        add_governance_declaration(&mut v1);
        v1.increment().unwrap();

        // v2: Upd that soft-fails the wp check under RejectAdvanceChecker —
        // this is what makes policy_satisfied() false on the final verification.
        let mut v2 = v1.clone();
        v2.content = Some(cesr::Digest256::blake3_256(b"content"));
        v2.kind = SadEventKind::Upd;
        v2.write_policy = None;
        v2.governance_policy = None;
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(RejectAdvanceChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());

        let err = advance(&verification, &policy2).unwrap_err();
        assert!(err.to_string().contains("policy not satisfied"));
    }
}
