//! Identity chains — stable identity references via evolving policy pointer chains.
//!
//! An identity chain is a SAD pointer chain where:
//! - Topic: `kels/identity/v1/chain`
//! - Content: `None` at every version (policy is carried in `write_policy`)
//! - Chain prefix: the stable identity reference
//! - `write_policy`: the current policy's SAID (self-governing)

use kels_core::{SadPointer, SadPointerVerification, compute_sad_pointer_prefix};
use verifiable_storage::{Chained, SelfAddressed};

use crate::{Policy, error::PolicyError};

/// Well-known topic for identity chains.
pub const IDENTITY_CHAIN_TOPIC: &str = "kels/identity/v1/chain";

/// Create a v0 inception pointer for an identity chain.
///
/// The returned pointer's `prefix` is the stable identity reference.
/// `write_policy` is set to `initial_policy.said` — the identity is self-governing.
pub fn create(initial_policy: &Policy) -> Result<SadPointer, PolicyError> {
    initial_policy
        .verify_said()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Policy SAID verification failed: {e}")))?;

    SadPointer::create(
        IDENTITY_CHAIN_TOPIC.to_string(),
        None,
        None,
        initial_policy.said,
        None,
        None,
    )
    .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to create identity pointer: {e}")))
}

/// Create the next version of an identity chain with an updated policy.
///
/// Takes a `SadPointerVerification` token (chain must be verified before advancing)
/// and a new policy. The new policy must differ from the current write_policy —
/// an identity chain advance with an unchanged policy is meaningless (content is
/// always None, custody is always None, there's nothing else to change).
pub fn advance(
    verification: &SadPointerVerification,
    new_policy: &Policy,
) -> Result<SadPointer, PolicyError> {
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

    if new_policy.said == verification.current_record().write_policy {
        return Err(PolicyError::InvalidPolicy(
            "Identity chain advance requires a different policy — \
             content and custody are always None, so unchanged write_policy is a no-op"
                .to_string(),
        ));
    }

    let mut pointer = verification.current_record().clone();
    pointer.content = None;
    pointer.custody = None;
    pointer.write_policy = new_policy.said;
    pointer
        .increment()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to increment pointer: {e}")))?;

    Ok(pointer)
}

/// Compute the identity chain prefix for a given initial policy.
///
/// Deterministic — anyone can compute this offline from the policy SAID.
pub fn compute_identity_prefix(initial_policy: &Policy) -> Result<cesr::Digest256, PolicyError> {
    initial_policy
        .verify_said()
        .map_err(|e| PolicyError::InvalidPolicy(format!("Policy SAID verification failed: {e}")))?;

    compute_sad_pointer_prefix(initial_policy.said, IDENTITY_CHAIN_TOPIC)
        .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to compute prefix: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)]
mod tests {
    use kels_core::{KelsError, PolicyChecker, SadChainVerifier};

    use super::*;

    struct AlwaysPassChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn satisfies(&self, _: &SadPointer, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct RejectAdvanceChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectAdvanceChecker {
        async fn satisfies(&self, _: &SadPointer, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(false)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
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
        assert_eq!(v0.write_policy, policy.said);
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

    /// Add a first checkpoint to a pointer (sets checkpoint_policy + is_checkpoint).
    fn add_first_checkpoint(pointer: &mut SadPointer) {
        let cp_policy = test_policy("checkpoint");
        pointer.checkpoint_policy = Some(cp_policy.said);
        pointer.is_checkpoint = Some(true);
    }

    #[tokio::test]
    async fn test_advance_identity_chain() {
        let policy1 = test_policy("policy-1");
        let policy2 = test_policy("policy-2");
        let v0 = create(&policy1).unwrap();
        let prefix = v0.prefix;

        // Create a v1 with checkpoint so the chain passes verification
        let mut v1_cp = v0.clone();
        add_first_checkpoint(&mut v1_cp);
        v1_cp.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0.clone(), v1_cp]).await.unwrap();
        let verification = verifier.finish().await.unwrap();

        let v2 = advance(&verification, &policy2).unwrap();
        assert_eq!(v2.version, 2);
        assert!(v2.content.is_none());
        assert_eq!(v2.write_policy, policy2.said);
        assert_eq!(v2.prefix, prefix);
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
        // Create a non-identity chain pointer with checkpoint_policy and verify it
        let policy = test_policy("test");
        let cp_policy = test_policy("checkpoint");
        let v0 = SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            policy.said,
            Some(cp_policy.said),
            Some(true),
        )
        .unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();

        let policy2 = test_policy("policy-2");
        let err = advance(&verification, &policy2).unwrap_err();
        assert!(err.to_string().contains("Not an identity chain"));
    }

    #[tokio::test]
    async fn test_advance_rejects_unchanged_policy() {
        let policy = test_policy("test-identity");
        let v0 = create(&policy).unwrap();

        // Add a v1 with checkpoint so verification passes
        let mut v1_cp = v0.clone();
        add_first_checkpoint(&mut v1_cp);
        v1_cp.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1_cp]).await.unwrap();
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

        // Build a v1 with checkpoint so the checker can reject it
        let mut v1 = v0.clone();
        v1.content = Some(cesr::Digest256::blake3_256(b"content"));
        add_first_checkpoint(&mut v1);
        v1.increment().unwrap();

        let checker = RejectAdvanceChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());

        let err = advance(&verification, &policy2).unwrap_err();
        assert!(err.to_string().contains("policy not satisfied"));
    }
}
