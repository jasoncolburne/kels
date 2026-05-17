//! Federation IEL handling and handshake authorization.
//!
//! Replaces the prior registry-fetch + allowlist refresh model (#190). The
//! authority for who is allowed to participate in the gossip mesh is the
//! federation IEL's current `authPolicy` — an `any(iel(X_1), ..., iel(X_n))`
//! expression naming peer-identity IEL prefixes. Handshake authorization is
//! a direct membership lookup against the walked `FederationState`.
//!
//! **Verify on every handshake.** Per the system thesis (every consumer
//! verifies independently; the DB cannot be trusted), the federation IEL
//! chain is re-walked from the local sadstore on every `verify_peer` call —
//! no cross-handshake cache. Between two handshakes the chain could have
//! been `Cnt`'d, `Evl`'d, or otherwise advanced; a stale snapshot would
//! authorize peers the current state no longer admits (or fail to detect
//! that the federation IEL itself has terminated). One startup walk runs as
//! a precondition to fail-fast on a misconfigured federation prefix; that
//! result is not retained.
//!
//! Design:
//! - `docs/design/infrastructure/federation.md` (federation as identity,
//!   policy shape, threshold formula, configuration, recovery)
//! - `docs/design/infrastructure/peer-identity.md` (handshake authorization)
//! - `CLAUDE.md §Verification Invariant` (consuming requires fresh
//!   verification — applies to federation IEL state, not just KEL state)

use std::collections::BTreeSet;
use std::sync::Arc;

use cesr::{Digest256, Matter};
use thiserror::Error;
use tracing::warn;

use kels_core::{
    AnchoredIelResolver, HttpIelSource, HttpKelSource, IelResolver, KelsError, PagedIelSource,
    PagedKelSource, PolicyChecker, SadStoreClient, UnavailableIelResolver, verify_identity_events,
};
use kels_policy::{
    AnchoredPolicyChecker, FederationPolicyShape, FederationPolicyShapeError, Policy,
    PolicyResolver, verify_federation_policy_shape,
};
use verifiable_storage::SelfAddressed;

/// Compile-time default federation IEL prefix baked into the binary at build
/// (via the `FEDERATION_IEL_PREFIX` build-time env var). Runtime override is
/// the same env var; mismatch logs a startup warning per
/// `docs/design/infrastructure/federation.md §Configuration`.
pub const COMPILE_TIME_FEDERATION_IEL_PREFIX: &str = env!("FEDERATION_IEL_PREFIX");

/// Resolve the federation IEL prefix from `FEDERATION_IEL_PREFIX` (runtime
/// env override; falls back to the compile-time default). Mismatch between
/// override and default logs a warning — expected during contested-federation
/// recovery.
pub fn resolve_federation_iel_prefix() -> Result<Digest256, FederationAuthError> {
    let raw = std::env::var("FEDERATION_IEL_PREFIX")
        .unwrap_or_else(|_| COMPILE_TIME_FEDERATION_IEL_PREFIX.to_string());
    if raw != COMPILE_TIME_FEDERATION_IEL_PREFIX {
        warn!(
            runtime = %raw,
            compile_time_default = %COMPILE_TIME_FEDERATION_IEL_PREFIX,
            "FEDERATION_IEL_PREFIX runtime override differs from compile-time default — \
             expected during contested-federation recovery (see federation.md §Recovery); \
             treating the env value as authoritative"
        );
    }
    Digest256::from_qb64(&raw).map_err(|e| {
        FederationAuthError::Config(format!(
            "FEDERATION_IEL_PREFIX is not a valid CESR digest: {e}"
        ))
    })
}

/// Transient snapshot of the federation IEL state, **constructed fresh on
/// every call** to [`walk_federation_iel`] — never held across handshakes.
/// Returned + consumed within a single authorization decision.
///
/// Per `CLAUDE.md §Verification Invariant`, consuming-class state (i.e.,
/// state on which security decisions are made) must come from a fresh
/// verification token. Caching this struct across handshakes would let a
/// `Cnt`'d / `Evl`'d federation IEL admit peers the current chain no longer
/// admits.
#[derive(Debug, Clone)]
pub struct FederationState {
    /// Federation IEL prefix (matches `resolve_federation_iel_prefix()`).
    /// Held so callers can sanity-check which IEL the walk-result describes
    /// — useful when the runtime override differs from the compile-time
    /// default during contested-federation recovery.
    #[allow(dead_code)]
    pub iel_prefix: Digest256,
    /// Tip event's tracked `authPolicy` SAID. Surfaced for callers that
    /// want a stable handle on "which auth-policy version is this view"
    /// — e.g., the announcement-driven federation handler diffing
    /// member sets across event arrivals (Gap 9). The current
    /// `is_peer_authorized` doesn't read it (direct membership lookup).
    #[allow(dead_code)]
    pub current_auth_policy_said: Digest256,
    /// Member IEL prefixes extracted from the conforming auth_policy.
    pub members: BTreeSet<Digest256>,
    /// Governance threshold `M(n)` from the conforming governance_policy.
    pub governance_threshold: u64,
}

#[derive(Error, Debug)]
pub enum FederationAuthError {
    #[error("config error: {0}")]
    Config(String),
    #[error("federation IEL not locally known under prefix {0}")]
    FederationIelNotFound(Digest256),
    #[error("federation IEL verification failed: {0}")]
    IelVerification(String),
    #[error("federation IEL is contested-terminal — recovery requires a fresh prefix")]
    Contested,
    #[error("federation IEL is decommissioned-terminal")]
    Decommissioned,
    #[error("federation IEL is divergent — no canonical authPolicy")]
    Divergent,
    #[error("federation IEL has no tip event locally")]
    NoTipEvent,
    #[error("federation policy-shape verification failed: {0}")]
    PolicyShape(#[from] FederationPolicyShapeError),
    #[error("policy resolver error: {0}")]
    PolicyResolver(String),
    #[error("kels error: {0}")]
    Kels(#[from] KelsError),
}

/// `PolicyResolver` that fetches policies from a SADStore via HTTP, with
/// SAID re-verification on every fetch so a tampered server can't substitute
/// content. Mirrors the CLI's `SadStoreSourcedPolicyResolver`.
struct SadStoreSourcedPolicyResolver {
    client: SadStoreClient,
}

#[async_trait::async_trait]
impl PolicyResolver for SadStoreSourcedPolicyResolver {
    async fn resolve_policy(&self, said: &Digest256) -> Result<Policy, kels_policy::PolicyError> {
        let value = self.client.get_sad_object(said).await.map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!("fetch {}: {}", said, e))
        })?;
        let policy: Policy = serde_json::from_value(value).map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!("parse {}: {}", said, e))
        })?;
        policy.verify_said().map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!(
                "SAID verification failed for {}: {}",
                said, e
            ))
        })?;
        Ok(policy)
    }
}

/// Bundled evaluator context for federation IEL operations. Constructed once
/// at gossip startup against the local sadstore + kels HTTP surfaces, then
/// shared (via `Arc::clone`) by the load/refresh loop and by every
/// `is_peer_authorized` call.
///
/// **Two-checker wiring breaks the AnchoredPolicyChecker ↔ IelResolver
/// construction cycle.** `inner_checker` uses `UnavailableIelResolver`
/// internally; it backs the `iel_resolver`'s peer-IEL chain walks (peer IELs
/// carry `kel()`-only policies per federation convention — no recursion).
/// `iel_aware_checker` is the outer construction the federation IEL chain
/// walker sees, so federation `iel(X)` leaves on Evl `governance_policy`
/// satisfactions resolve correctly.
#[derive(Clone)]
pub struct FederationEvaluator {
    pub policy_resolver: Arc<dyn PolicyResolver + Send + Sync>,
    pub iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    pub iel_aware_checker: Arc<dyn PolicyChecker + Send + Sync>,
    pub iel_source: Arc<dyn PagedIelSource + Send + Sync>,
}

impl FederationEvaluator {
    pub fn new(sadstore_url: &str, kels_url: &str) -> Result<Self, FederationAuthError> {
        let sad_client = SadStoreClient::new(sadstore_url).map_err(|e| {
            FederationAuthError::Config(format!("sadstore client for {sadstore_url}: {e}"))
        })?;
        let policy_resolver: Arc<dyn PolicyResolver + Send + Sync> =
            Arc::new(SadStoreSourcedPolicyResolver { client: sad_client });

        let kel_source: Arc<dyn PagedKelSource + Send + Sync> = Arc::new(
            HttpKelSource::new(kels_url, "/api/v1/kels/kel/fetch").map_err(|e| {
                FederationAuthError::Config(format!("kel source for {kels_url}: {e}"))
            })?,
        );
        let iel_source: Arc<dyn PagedIelSource + Send + Sync> =
            Arc::new(HttpIelSource::new(sadstore_url).map_err(|e| {
                FederationAuthError::Config(format!("iel source for {sadstore_url}: {e}"))
            })?);

        let inner_iel_resolver: Arc<dyn IelResolver + Send + Sync> =
            Arc::new(UnavailableIelResolver);
        let inner_checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
                Arc::clone(&inner_iel_resolver),
            ));
        let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(AnchoredIelResolver::new(
            Arc::clone(&iel_source),
            inner_checker,
            kels_core::page_size(),
            kels_core::max_pages(),
        ));
        let iel_aware_checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
                Arc::clone(&iel_resolver),
            ));

        Ok(Self {
            policy_resolver,
            iel_resolver,
            iel_aware_checker,
            iel_source,
        })
    }
}

/// Walk the federation IEL fresh from the local sadstore and return a
/// transient [`FederationState`] snapshot. Verifies the chain via
/// `verify_identity_events` using the iel-aware policy checker (so Evl
/// `governance_policy` satisfactions with `iel(...)` leaves resolve),
/// reads the tip event's tracked `auth_policy` + `governance_policy`
/// SAIDs, resolves them, and verifies the pair conforms to the federation
/// shape convention.
///
/// **Called fresh on every handshake** — see the module-level note. Result
/// must not be retained across handshakes.
///
/// Terminal / divergent chains return loud errors — gossip refuses to
/// authorize handshakes against a contested or decommissioned federation
/// IEL. Recovery is operator-driven (see `federation.md §Recovery`).
pub async fn walk_federation_iel(
    iel_prefix: &Digest256,
    evaluator: &FederationEvaluator,
) -> Result<FederationState, FederationAuthError> {
    let verification = verify_identity_events(
        iel_prefix,
        evaluator.iel_source.as_ref(),
        Arc::clone(&evaluator.iel_aware_checker),
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .map_err(map_verification_error)?;

    if verification.is_contested() {
        return Err(FederationAuthError::Contested);
    }
    if verification.is_decommissioned() {
        return Err(FederationAuthError::Decommissioned);
    }
    if verification.is_divergent() {
        return Err(FederationAuthError::Divergent);
    }

    let tip = verification
        .current_event()
        .ok_or(FederationAuthError::NoTipEvent)?;
    let auth_policy_said = verification.auth_policy_at(&tip.said).ok_or_else(|| {
        FederationAuthError::IelVerification(format!(
            "auth_policy not recorded at tip {} (chain integrity)",
            tip.said
        ))
    })?;
    let gov_policy_said = verification
        .governance_policy_at(&tip.said)
        .ok_or_else(|| {
            FederationAuthError::IelVerification(format!(
                "governance_policy not recorded at tip {} (chain integrity)",
                tip.said
            ))
        })?;

    let auth_policy = evaluator
        .policy_resolver
        .resolve_policy(&auth_policy_said)
        .await
        .map_err(|e| FederationAuthError::PolicyResolver(e.to_string()))?;
    let gov_policy = evaluator
        .policy_resolver
        .resolve_policy(&gov_policy_said)
        .await
        .map_err(|e| FederationAuthError::PolicyResolver(e.to_string()))?;

    let shape: FederationPolicyShape = verify_federation_policy_shape(&auth_policy, &gov_policy)?;

    Ok(FederationState {
        iel_prefix: *iel_prefix,
        current_auth_policy_said: auth_policy_said,
        members: shape.members,
        governance_threshold: shape.governance_threshold,
    })
}

/// Map a federation-IEL verification error into the typed FederationAuthError
/// surface (preserves terminal / not-found semantics for callers that route
/// on the variant).
fn map_verification_error(err: KelsError) -> FederationAuthError {
    match err {
        KelsError::ContestedIel(_) => FederationAuthError::Contested,
        KelsError::IelDecommissioned(_) => FederationAuthError::Decommissioned,
        KelsError::IelDivergent(_) => FederationAuthError::Divergent,
        KelsError::NotFound(_) => FederationAuthError::FederationIelNotFound(Digest256::default()),
        other => FederationAuthError::IelVerification(other.to_string()),
    }
}

/// Check whether a peer identity (IEL prefix) is in the federation's
/// current `authPolicy` member set.
///
/// Direct membership check against [`FederationState::members`]. Callers
/// pass a peer's identity (IEL prefix) — never a KEL prefix. The KEL is a
/// signing-key custody detail surfaced by signature verification; identity
/// is the IEL.
///
/// `federation` must come from a **fresh** [`walk_federation_iel`] call on
/// the same security decision — see the module-level note on no
/// cross-handshake caching.
pub fn is_peer_authorized(federation: &FederationState, peer_iel_prefix: &Digest256) -> bool {
    federation.members.contains(peer_iel_prefix)
}

/// Resolve a peer's current signing KEL prefix from its IEL prefix.
///
/// Walks the peer's IEL via the evaluator's [`IelResolver`] → reads
/// `resolve_current_auth_policy(iel)` → resolves the policy SAD body →
/// expects a degenerate single-KEL identity convention (`authPolicy =
/// kel(K)`) and extracts `K`.
///
/// Returns `FederationAuthError::PolicyResolver` if the policy expression
/// is not a single `kel(...)` leaf — only degenerate identities are
/// supported as gossip peers (per
/// `docs/design/infrastructure/peer-identity.md §Gossip identity =
/// degenerate IEL over an HSM-backed KEL`).
///
/// Bundled internally by [`KelsPeerVerifier::verify_peer`] so callers
/// never have to resolve IEL → KEL themselves; exposed for other
/// consumers (debug tooling, federation membership audits) that need
/// the current signer for a peer.
pub async fn resolve_peer_signing_kel(
    peer_iel_prefix: &Digest256,
    evaluator: &FederationEvaluator,
) -> Result<Digest256, FederationAuthError> {
    let policy_said = evaluator
        .iel_resolver
        .resolve_current_auth_policy(peer_iel_prefix)
        .await
        .map_err(|e| {
            FederationAuthError::PolicyResolver(format!(
                "resolve current authPolicy for IEL {peer_iel_prefix}: {e}"
            ))
        })?;
    let policy = evaluator
        .policy_resolver
        .resolve_policy(&policy_said)
        .await
        .map_err(|e| FederationAuthError::PolicyResolver(format!("resolve policy SAD: {e}")))?;
    let ast = policy
        .parse()
        .map_err(|e| FederationAuthError::PolicyResolver(format!("parse policy expression: {e}")))?;
    match ast {
        kels_policy::PolicyNode::Kel(kel_prefix) => Ok(kel_prefix),
        other => Err(FederationAuthError::PolicyResolver(format!(
            "IEL {peer_iel_prefix}'s current authPolicy is not a degenerate kel(K) leaf \
             (got: {other:?}); only single-KEL gossip identities are supported"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_time_prefix_is_set() {
        // The buildscript / env! provides a value (real federation prefix
        // or the all-A placeholder during dev). Confirms env! resolved.
        assert!(!COMPILE_TIME_FEDERATION_IEL_PREFIX.is_empty());
    }

    #[test]
    fn test_resolve_uses_compile_time_default_when_runtime_unset() {
        // Safety: this test mutates the process env. Avoid running in
        // parallel with other tests that read FEDERATION_IEL_PREFIX. We
        // intentionally only inspect the no-override path here — the
        // override path mutates state and is exercised by integration
        // tests if/when added.
        // SAFETY: This test does not run in parallel with other tests
        // touching FEDERATION_IEL_PREFIX.
        // SAFETY: remove_var on a single-threaded test is safe.
        // Note: `set_var`/`remove_var` are `unsafe` in Rust 2024.
        unsafe {
            std::env::remove_var("FEDERATION_IEL_PREFIX");
        }
        let resolved = resolve_federation_iel_prefix().expect("default parses");
        assert_eq!(resolved.qb64(), COMPILE_TIME_FEDERATION_IEL_PREFIX);
    }

    // ==================== peer-identity authorization tests ====================

    use async_trait::async_trait;
    use kels_core::{IdentityEvent, IdentityEventKind, IelChainPositionBatch, IelSatisfaction};
    use kels_policy::{InMemoryPolicyResolver, Policy};
    use std::collections::BTreeMap;

    /// In-memory `IelResolver`: maps `iel_prefix → current authPolicy SAID`.
    /// Only `resolve_current_auth_policy` is exercised by the helpers in
    /// this module; the rest return errors so they surface as test
    /// mis-configuration.
    struct InMemoryIelResolver {
        auth_policies: BTreeMap<Digest256, Digest256>,
    }

    #[async_trait]
    impl IelResolver for InMemoryIelResolver {
        async fn fetch_iel_event(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_auth_policy_at(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_governance_policy_at(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn iel_chain_positions(
            &self,
            _: &Digest256,
            _: &[Digest256],
        ) -> Result<IelChainPositionBatch, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn is_satisfied(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<IelSatisfaction, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_identity_for_event(&self, _: &Digest256) -> Result<Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_current_auth_policy(
            &self,
            identity: &Digest256,
        ) -> Result<Digest256, KelsError> {
            self.auth_policies
                .get(identity)
                .copied()
                .ok_or_else(|| KelsError::NotFound(format!("IEL {identity} not in test resolver")))
        }
    }

    /// Dummy `PolicyChecker` — never invoked by `is_peer_authorized` (a
    /// direct membership lookup) nor by `resolve_peer_signing_kel` (only
    /// the policy + iel resolvers).
    struct DummyPolicyChecker;

    #[async_trait]
    impl kels_core::PolicyChecker for DummyPolicyChecker {
        async fn evaluate(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<kels_core::AnchorEvaluation, KelsError> {
            Err(KelsError::NotFound(
                "DummyPolicyChecker invoked unexpectedly".to_string(),
            ))
        }
        async fn is_immune(&self, _: &Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Dummy IEL source — `is_peer_authorized` doesn't walk via the
    /// source, so any access here surfaces a test misconfiguration.
    struct DummyIelSource;

    #[async_trait]
    impl kels_core::PagedIelSource for DummyIelSource {
        async fn fetch_page(
            &self,
            _: &Digest256,
            _: Option<&Digest256>,
            _: usize,
        ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
            Err(KelsError::NotFound(
                "DummyIelSource invoked from is_peer_authorized — should not happen".to_string(),
            ))
        }
    }

    fn d(label: &str) -> Digest256 {
        cesr::Digest256::blake3_256(label.as_bytes())
    }

    /// Construct a federation-shaped test fixture. Returns the
    /// `FederationState`, a `FederationEvaluator` wired to in-memory
    /// resolvers, and the verified-KEL prefixes that satisfy each member
    /// Federation state with the given member IEL labels; auth_policy
    /// SAID is a placeholder digest (the new `is_peer_authorized` is a
    /// direct membership check and doesn't need the policy to resolve).
    fn fed_state_with_members(member_labels: &[&str]) -> FederationState {
        FederationState {
            iel_prefix: d("fed-iel"),
            current_auth_policy_said: d("fed-auth-policy"),
            members: member_labels.iter().map(|l| d(l)).collect(),
            governance_threshold: 3,
        }
    }

    // ==================== is_peer_authorized ====================

    #[test]
    fn is_peer_authorized_admits_member_iel() {
        let state = fed_state_with_members(&["iel-alice", "iel-bob", "iel-charlie"]);
        for label in ["iel-alice", "iel-bob", "iel-charlie"] {
            assert!(
                is_peer_authorized(&state, &d(label)),
                "{label} should be in the federation member set"
            );
        }
    }

    #[test]
    fn is_peer_authorized_rejects_non_member_iel() {
        let state = fed_state_with_members(&["iel-alice", "iel-bob"]);
        assert!(!is_peer_authorized(&state, &d("iel-stranger")));
    }

    #[test]
    fn is_peer_authorized_rejects_everyone_when_membership_empty() {
        let state = fed_state_with_members(&[]);
        assert!(!is_peer_authorized(&state, &d("iel-anybody")));
    }

    // ==================== resolve_peer_signing_kel ====================

    /// Build an evaluator whose IEL resolver knows the given identities'
    /// authPolicies, with each one being a degenerate `kel(K)` leaf.
    /// `members` maps `iel_label → kel_label`.
    fn evaluator_with_degenerate_identities(
        members: &[(&str, &str)],
    ) -> (FederationEvaluator, BTreeMap<Digest256, Digest256>) {
        let mut policies = Vec::new();
        let mut iel_to_policy_said: BTreeMap<Digest256, Digest256> = BTreeMap::new();
        let mut iel_to_kel: BTreeMap<Digest256, Digest256> = BTreeMap::new();
        for (iel_label, kel_label) in members {
            let iel = d(iel_label);
            let kel = d(kel_label);
            let policy =
                Policy::build(&format!("kel({kel})"), None, true).expect("policy builds");
            iel_to_policy_said.insert(iel, policy.said);
            iel_to_kel.insert(iel, kel);
            policies.push(policy);
        }
        let policy_resolver: Arc<dyn PolicyResolver + Send + Sync> =
            Arc::new(InMemoryPolicyResolver::new(policies));
        let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(InMemoryIelResolver {
            auth_policies: iel_to_policy_said,
        });
        let iel_aware_checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> =
            Arc::new(DummyPolicyChecker);
        let iel_source: Arc<dyn kels_core::PagedIelSource + Send + Sync> = Arc::new(DummyIelSource);
        (
            FederationEvaluator {
                policy_resolver,
                iel_resolver,
                iel_aware_checker,
                iel_source,
            },
            iel_to_kel,
        )
    }

    #[tokio::test]
    async fn resolve_peer_signing_kel_returns_current_kel_for_degenerate_identity() {
        let (evaluator, iel_to_kel) =
            evaluator_with_degenerate_identities(&[("iel-alice", "kel-alice")]);
        let alice_iel = d("iel-alice");
        let resolved = resolve_peer_signing_kel(&alice_iel, &evaluator)
            .await
            .expect("resolution succeeds");
        assert_eq!(resolved, *iel_to_kel.get(&alice_iel).unwrap());
    }

    #[tokio::test]
    async fn resolve_peer_signing_kel_errors_on_non_degenerate_identity() {
        // A threshold identity (`threshold(2, [kel(A), kel(B)])`) doesn't
        // collapse to a single kel(K). The helper requires the
        // degenerate single-KEL gossip-peer convention; non-conforming
        // identities surface as a loud error.
        let a = d("kel-a");
        let b = d("kel-b");
        let policy = Policy::build(
            &format!("threshold(2, [kel({a}), kel({b})])"),
            None,
            true,
        )
        .unwrap();
        let identity = d("iel-multi");
        let mut auth_policies = BTreeMap::new();
        auth_policies.insert(identity, policy.said);
        let evaluator = FederationEvaluator {
            policy_resolver: Arc::new(InMemoryPolicyResolver::new(vec![policy])),
            iel_resolver: Arc::new(InMemoryIelResolver { auth_policies }),
            iel_aware_checker: Arc::new(DummyPolicyChecker),
            iel_source: Arc::new(DummyIelSource),
        };
        let err = resolve_peer_signing_kel(&identity, &evaluator)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FederationAuthError::PolicyResolver(_)),
            "expected PolicyResolver, got {err:?}"
        );
    }

    // Suppress dead_code on IdentityEventKind import in tests that don't
    // construct events.
    #[allow(dead_code)]
    fn _silence_event_kind() -> IdentityEventKind {
        IdentityEventKind::Evl
    }
}
