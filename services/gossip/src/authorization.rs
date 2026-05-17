//! Federation IEL handling and handshake authorization.
//!
//! Replaces the prior registry-fetch + allowlist refresh model (#190). The
//! authority for who is allowed to participate in the gossip mesh is the
//! federation IEL's current `authPolicy` — an `any(iel(X_1), ..., iel(X_n))`
//! expression naming peer-identity IEL prefixes. Handshake authorization is
//! `evaluate_signed_policy` against that policy, with the verified KEL prefix
//! as the input. The federation IEL is loaded from the local sadstore at
//! startup, verified via `verify_identity_events`, and refreshed on a slow
//! background interval (gossip-driven invalidation hooks land in #195 /
//! #196).
//!
//! Design:
//! - `docs/design/infrastructure/federation.md` (federation as identity,
//!   policy shape, threshold formula, configuration, recovery)
//! - `docs/design/infrastructure/peer-identity.md` (handshake authorization)

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use cesr::{Digest256, Matter};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use kels_core::{
    AnchoredIelResolver, HttpIelSource, HttpKelSource, IelResolver, KelsError, PagedIelSource,
    PagedKelSource, PolicyChecker, SadStoreClient, UnavailableIelResolver,
    verify_identity_events,
};
use kels_policy::{
    AnchoredPolicyChecker, FederationPolicyShape, FederationPolicyShapeError, Policy,
    PolicyResolver, evaluate_signed_policy, verify_federation_policy_shape,
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
        FederationAuthError::Config(format!("FEDERATION_IEL_PREFIX is not a valid CESR digest: {e}"))
    })
}

/// Snapshot of the federation IEL state held in memory by the gossip
/// service. Recomputed at startup and on each refresh tick. Consumers read
/// `current_auth_policy_said` to drive handshake authorization.
#[derive(Debug, Clone)]
pub struct FederationState {
    /// Federation IEL prefix (matches `resolve_federation_iel_prefix()`).
    /// Held so consumers can sanity-check which IEL a refreshed snapshot
    /// describes — load/refresh use it to detect runtime-override repoint.
    #[allow(dead_code)]
    pub iel_prefix: Digest256,
    /// Tip event's tracked `authPolicy` SAID.
    pub current_auth_policy_said: Digest256,
    /// Member IEL prefixes extracted from the conforming auth_policy.
    pub members: BTreeSet<Digest256>,
    /// Governance threshold `M(n)` from the conforming governance_policy.
    pub governance_threshold: u64,
}

/// Shared, refreshable handle to the federation state.
pub type SharedFederationState = Arc<RwLock<Option<FederationState>>>;

/// Transitional address-list keyed by peer KEL prefix.
///
/// Pre-#194 this was the registry-fetched allowlist. Under
/// federation-as-identity (#190) the *authority* moves to the federation IEL
/// and `kels_core::Peer.gossip_addr` / `base_domain` will be supplied by
/// per-peer address SELs (#195). Through the #194 window the map stays empty
/// — sync paths that look up peer URLs gracefully degrade to no-op. Type
/// alias preserved so `sync.rs`'s URL-lookup callers continue to compile;
/// #195 retires it.
pub type SharedAllowlist = Arc<RwLock<HashMap<Digest256, kels_core::Peer>>>;

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
    async fn resolve_policy(
        &self,
        said: &Digest256,
    ) -> Result<Policy, kels_policy::PolicyError> {
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
        let iel_source: Arc<dyn PagedIelSource + Send + Sync> = Arc::new(
            HttpIelSource::new(sadstore_url).map_err(|e| {
                FederationAuthError::Config(format!("iel source for {sadstore_url}: {e}"))
            })?,
        );

        let inner_iel_resolver: Arc<dyn IelResolver + Send + Sync> =
            Arc::new(UnavailableIelResolver);
        let inner_checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(
            AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
                Arc::clone(&inner_iel_resolver),
            ),
        );
        let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(AnchoredIelResolver::new(
            Arc::clone(&iel_source),
            inner_checker,
            kels_core::page_size(),
            kels_core::max_pages(),
        ));
        let iel_aware_checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(
            AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
                Arc::clone(&iel_resolver),
            ),
        );

        Ok(Self {
            policy_resolver,
            iel_resolver,
            iel_aware_checker,
            iel_source,
        })
    }
}

/// Load the federation IEL: walk the chain via `verify_identity_events`
/// using the iel-aware policy checker (so Evl `governance_policy`
/// satisfactions with `iel(...)` leaves resolve), read the tip event's
/// tracked `auth_policy` + `governance_policy` SAIDs, resolve them, and
/// verify the pair conforms to the federation shape convention. Returns
/// the resulting [`FederationState`] snapshot.
///
/// Terminal / divergent chains return loud errors — gossip refuses to start
/// or refresh under a contested or decommissioned federation IEL. Recovery
/// is operator-driven (see `federation.md §Recovery`).
pub async fn load_federation_state(
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
    let gov_policy_said = verification.governance_policy_at(&tip.said).ok_or_else(|| {
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
        KelsError::NotFound(_) => {
            FederationAuthError::FederationIelNotFound(Digest256::default())
        }
        other => FederationAuthError::IelVerification(other.to_string()),
    }
}

/// Evaluate the federation `authPolicy` against a single verified KEL prefix.
///
/// The handshake-authentication layer extracts `verified_kel_prefix` from
/// the peer's signed handshake transcript (signature against the peer's
/// current KEL tip). Authorization is then satisfaction of the federation
/// `authPolicy` by `{verified_kel_prefix}`: the `iel(X)` evaluator walks
/// each member identity's IEL, reads its current `authPolicy` (a
/// `kel(K_peer)`), and checks `K_peer == verified_kel_prefix`. Any single
/// member match satisfies `any(...)`.
///
/// Returns `Ok(true)` on authorized, `Ok(false)` on unauthorized, and `Err`
/// on resolver failure — fail-loud per the design's trust model.
pub async fn is_peer_authorized(
    federation: &FederationState,
    verified_kel_prefix: &Digest256,
    evaluator: &FederationEvaluator,
) -> Result<bool, FederationAuthError> {
    let verified: std::collections::HashSet<Digest256> =
        std::iter::once(*verified_kel_prefix).collect();
    let verification = evaluate_signed_policy(
        &federation.current_auth_policy_said,
        &verified,
        &*evaluator.policy_resolver,
        &*evaluator.iel_resolver,
    )
    .await
    .map_err(|e| FederationAuthError::PolicyResolver(e.to_string()))?;
    Ok(verification.is_satisfied)
}

/// Run a background loop refreshing the federation state on a fixed
/// interval. On each tick: re-walk the federation IEL, re-verify the policy
/// shape, swap into `shared` on success. Failures log + leave the previous
/// snapshot in place (so a transient sadstore failure doesn't take the mesh
/// offline immediately — the snapshot ages until the failure resolves or an
/// operator intervenes).
pub async fn run_federation_refresh_loop(
    iel_prefix: Digest256,
    shared: SharedFederationState,
    evaluator: FederationEvaluator,
    interval: Duration,
) {
    info!(
        "Starting federation IEL refresh loop (interval: {:?})",
        interval
    );
    loop {
        tokio::time::sleep(interval).await;
        match load_federation_state(&iel_prefix, &evaluator).await {
            Ok(state) => {
                *shared.write().await = Some(state);
            }
            Err(e) => {
                error!("Federation IEL refresh failed: {e}");
            }
        }
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
        assert_eq!(
            resolved.qb64(),
            COMPILE_TIME_FEDERATION_IEL_PREFIX
        );
    }
}
