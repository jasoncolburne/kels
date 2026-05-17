//! Identity primitive reconciliation at startup.
//!
//! Identity service is the source of truth for the node's own peer-identity
//! primitives: KEL, IEL, `peer/services` SEL, `peer/gossip` SEL. At every
//! boot the service reconciles each primitive against the current
//! configuration:
//!
//! - **KEL** — incepted by `server.rs`'s auto-incept path (predates this
//!   module). Not handled here.
//! - **IEL** — degenerate single-KEL IEL with `authPolicy = governancePolicy
//!   = kel(KEL_prefix)`, immune. If absent locally, incept; otherwise reuse
//!   the existing prefix. Identity stores the IEL locally; the gossip
//!   service pushes it to sadstore at its own startup (matches the
//!   established KEL push pattern).
//! - **`peer/services` SEL** and **`peer/gossip` SEL** — Gap 8b-2 and 8b-3.
//!
//! The reconciliation is **idempotent + resumable**: each step checks local
//! state before acting. A partial reconciliation interrupted mid-flow can
//! be safely re-run on the next boot.

use cesr::Digest256;
use tracing::info;
use verifiable_storage::{ChainedRepository, StorageError};

use kels_core::{
    IdentityEvent, KeyEventBuilder, KeyProvider, PeerServicesSad, SadEvent, SadEventKind,
    compute_peer_services_sel_prefix,
};
use kels_policy::Policy;

use crate::repository::{IdentityRepository, SadObjectEntry};

/// Topic for the node's own peer-identity IEL chain. Single value across
/// all KELS deployments; the chain prefix is derived from
/// `(KEL_prefix, this_topic)` so per-node chains are deterministically
/// distinct.
const PEER_IDENTITY_IEL_TOPIC: &str = "kels/iel/v1/peer-identity";

/// Configuration the reconciliation flow consumes. Loaded from env vars at
/// service startup.
#[derive(Debug, Clone)]
pub struct ReconcileConfig {
    /// `PEER_DOMAIN` — base domain published in the peer/services SAD.
    /// Consumers derive service URLs as `http://{service}.{domain}` per
    /// the federation subdomain convention.
    pub domain: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    #[error("policy: {0}")]
    Policy(#[from] kels_policy::PolicyError),
    #[error("kels: {0}")]
    Kels(#[from] kels_core::KelsError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Reconcile the peer-identity IEL. Returns the IEL prefix (the node's
/// peer identity).
///
/// Idempotent: the IEL prefix is deterministic from `(kel_prefix,
/// PEER_IDENTITY_IEL_TOPIC)` — we compute it directly from a tentative
/// Icp and check whether the chain already has an effective SAID at that
/// prefix. If present (linear or contested), return; otherwise incept.
///
/// On first boot: persists the cached policy body, persists the Icp event,
/// and anchors the Icp SAID in the KEL via `Ixn`.
pub async fn reconcile_iel<K: KeyProvider>(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<K>,
    kel_prefix: Digest256,
) -> Result<Digest256, ReconciliationError> {
    // 1. Degenerate policy: `kel(KEL_prefix)`, immune. Identity is
    // single-KEL, so the same policy serves both authPolicy and
    // governancePolicy on the IEL Icp. Deterministic from `kel_prefix`.
    let policy = Policy::build(&format!("kel({})", kel_prefix), None, true)?;

    // 2. Build the (tentative) IEL Icp to derive its prefix. The Icp is
    // deterministic from `(policy.said, policy.said, topic)` — the same
    // KEL boots will always produce the same Icp + the same prefix.
    let icp = IdentityEvent::icp(policy.said, policy.said, PEER_IDENTITY_IEL_TOPIC)?;
    let iel_prefix = icp.prefix;

    // 3. Restart check (sync decision, not trust): does this chain
    // already have events locally? Effective SAID at the deterministic
    // prefix is `Some` iff the chain is present.
    if repo.iel.effective_said(&iel_prefix).await?.is_some() {
        info!(iel_prefix = %iel_prefix, "Reusing existing IEL");
        return Ok(iel_prefix);
    }

    info!(
        kel_prefix = %kel_prefix,
        iel_prefix = %iel_prefix,
        policy_said = %policy.said,
        "No IEL present — incepting peer-identity IEL"
    );

    // 4. Cache the policy body locally. The gossip service will push to
    // sadstore at its own startup; meanwhile readers walking the IEL
    // chain locally can resolve `authPolicy` / `governancePolicy` against
    // this cached body.
    let policy_value = serde_json::to_value(&policy)?;
    let entry = SadObjectEntry::create(policy.said, policy_value)?;
    repo.sad_objects.store(entry).await?;

    // 5. Persist the Icp in identity_iel_events.
    let icp_said = icp.said;
    repo.iel.insert(icp).await?;

    // 6. Anchor the IEL Icp SAID in the KEL via an `Ixn` (tier-1) — the
    // server's `kel(K)` policy check resolves to "is this SAID in K's
    // anchor history?" which an Ixn satisfies.
    builder
        .interact(&icp_said)
        .await
        .map_err(ReconciliationError::Kels)?;

    Ok(iel_prefix)
}

/// Reconcile the peer/services SEL.
///
/// - If the chain is absent locally, incept `[Icp, Upd, Sea]` with a fresh
///   [`PeerServicesSad`] for `config.domain`.
/// - If the chain is present and its tip's published domain matches
///   `config.domain`, no-op.
/// - If the chain is present but the tip's domain differs from
///   `config.domain` (operator changed `PEER_DOMAIN` between boots),
///   rotate `[Upd, Sea]` with a fresh SAD for the new domain.
///
/// Each step persists locally only; gossip propagates to sadstore at its
/// own startup. The IEL Icp's SAID (looked up from the local IEL chain) is
/// used as the `identity_event` binding on Upd/Sea — under the degenerate
/// single-KEL IEL, that event's `authPolicy` = `governancePolicy` =
/// `kel(KEL_prefix)`, satisfied by anchoring each SEL SAID in the KEL via
/// `Ixn`.
pub async fn reconcile_peer_services_sel<K: KeyProvider>(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<K>,
    iel_prefix: Digest256,
    config: &ReconcileConfig,
) -> Result<(), ReconciliationError> {
    let iel_tip = repo
        .iel
        .fetch_tip(&iel_prefix)
        .await?
        .ok_or_else(|| {
            ReconciliationError::Storage(StorageError::StorageError(format!(
                "IEL {iel_prefix} has no events; reconcile_iel must run first"
            )))
        })?;
    let iel_event_said = iel_tip.said;

    let sel_prefix = compute_peer_services_sel_prefix(iel_prefix)?;

    match repo.sel.fetch_tip(&sel_prefix).await? {
        None => {
            info!(
                sel_prefix = %sel_prefix,
                domain = %config.domain,
                "Incepting peer/services SEL"
            );
            incept_peer_services(repo, builder, iel_prefix, iel_event_said, &config.domain)
                .await?;
        }
        Some(tip) => {
            let current_domain = read_services_domain_from_tip(repo, &tip).await?;
            if current_domain.as_deref() == Some(config.domain.as_str()) {
                info!(
                    sel_prefix = %sel_prefix,
                    domain = %config.domain,
                    "peer/services SEL up-to-date"
                );
                return Ok(());
            }
            info!(
                sel_prefix = %sel_prefix,
                current = ?current_domain,
                new = %config.domain,
                "Rotating peer/services SEL"
            );
            rotate_peer_services(repo, builder, &tip, iel_event_said, &config.domain).await?;
        }
    }
    Ok(())
}

/// Inspect the tip's content SAID and return the published domain from the
/// associated [`PeerServicesSad`] body, if both the tip's content and the
/// cached body resolve. Returns `Ok(None)` when the chain's tip is not a
/// `Sea` (non-conforming local state) or the body isn't cached locally —
/// either of those triggers a re-incept / rotate path at the call site.
async fn read_services_domain_from_tip(
    repo: &IdentityRepository,
    tip: &SadEvent,
) -> Result<Option<String>, ReconciliationError> {
    if tip.kind != SadEventKind::Sea {
        return Ok(None);
    }
    let Some(content_said) = tip.content else {
        return Ok(None);
    };
    let Some(entry) = repo.sad_objects.get_by_object_said(&content_said).await? else {
        return Ok(None);
    };
    let sad: PeerServicesSad = serde_json::from_value(entry.object)?;
    Ok(Some(sad.domain))
}

async fn incept_peer_services<K: KeyProvider>(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<K>,
    iel_prefix: Digest256,
    iel_event_said: Digest256,
    domain: &str,
) -> Result<(), ReconciliationError> {
    let sad = PeerServicesSad::create(domain.to_string())?;
    cache_services_body(repo, &sad).await?;

    let icp = SadEvent::icp(iel_prefix, kels_core::PEER_SERVICES_SEL_TOPIC)?;
    let upd = SadEvent::upd(&icp, iel_event_said, sad.said)?;
    let sea = SadEvent::sea(&upd, iel_event_said)?;

    repo.sel.insert(icp.clone()).await?;
    repo.sel.insert(upd.clone()).await?;
    repo.sel.insert(sea.clone()).await?;

    builder.interact(&icp.said).await?;
    builder.interact(&upd.said).await?;
    builder.interact(&sea.said).await?;
    Ok(())
}

async fn rotate_peer_services<K: KeyProvider>(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<K>,
    tip: &SadEvent,
    iel_event_said: Digest256,
    new_domain: &str,
) -> Result<(), ReconciliationError> {
    let sad = PeerServicesSad::create(new_domain.to_string())?;
    cache_services_body(repo, &sad).await?;

    let upd = SadEvent::upd(tip, iel_event_said, sad.said)?;
    let sea = SadEvent::sea(&upd, iel_event_said)?;

    repo.sel.insert(upd.clone()).await?;
    repo.sel.insert(sea.clone()).await?;

    builder.interact(&upd.said).await?;
    builder.interact(&sea.said).await?;
    Ok(())
}

/// Cache the peer/services SAD body in the local SAD object store. Gossip
/// propagates to remote sadstore at its own startup.
async fn cache_services_body(
    repo: &IdentityRepository,
    sad: &PeerServicesSad,
) -> Result<(), ReconciliationError> {
    let value = serde_json::to_value(sad)?;
    let entry = SadObjectEntry::create(sad.said, value)?;
    repo.sad_objects.store(entry).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::repository::{IdentityRepository, KeyEventRepository, tests::get_harness};
    use cesr::VerificationKeyCode;
    use kels_core::{KelStore, RepositoryKelStore, SoftwareKeyProvider};
    use std::sync::Arc;

    /// Build a fresh KEL via `SoftwareKeyProvider` against the harness pool;
    /// returns the builder + the derived KEL prefix. Each test gets its own
    /// signing keys → unique KEL prefix → unique IEL prefix (which means
    /// `effective_said` lookups are scoped per-test by construction, no
    /// cross-test contamination on the shared database).
    async fn fresh_kel(
        repo: &IdentityRepository,
    ) -> (KeyEventBuilder<SoftwareKeyProvider>, cesr::Digest256) {
        let kel_repo = Arc::new(KeyEventRepository {
            pool: repo.kel.pool.clone(),
        });
        let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(kel_repo));
        let provider =
            SoftwareKeyProvider::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa65);
        let mut builder =
            KeyEventBuilder::with_dependencies(provider, None, Some(kel_store), None)
                .await
                .expect("build builder");
        let icp = builder.incept().await.expect("incept KEL");
        let prefix = icp.event.prefix;
        (builder, prefix)
    }

    /// `reconcile_iel` lands the chain on first call; second call short-circuits
    /// via `effective_said` and returns the same prefix without adding events.
    #[tokio::test]
    async fn reconcile_iel_is_idempotent() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;
        let (mut builder, kel_prefix) = fresh_kel(&repo).await;

        let first = reconcile_iel(&repo, &mut builder, kel_prefix)
            .await
            .expect("first reconcile_iel succeeds");

        // After inception: one event (the Icp) at the IEL prefix.
        let chain_after_first = repo.iel.fetch_chain(&first).await.unwrap();
        assert_eq!(chain_after_first.len(), 1, "Icp landed");

        let second = reconcile_iel(&repo, &mut builder, kel_prefix)
            .await
            .expect("second reconcile_iel succeeds");
        assert_eq!(second, first, "deterministic prefix");

        let chain_after_second = repo.iel.fetch_chain(&first).await.unwrap();
        assert_eq!(
            chain_after_second.len(),
            1,
            "no new events on idempotent re-run"
        );
    }

    /// `reconcile_peer_services_sel` lands `[Icp, Upd, Sea]` on first call,
    /// caches the published SAD body, and the Sea tip's content SAID
    /// resolves to a `PeerServicesSad` carrying the configured domain.
    #[tokio::test]
    async fn reconcile_peer_services_sel_incepts_when_absent() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;
        let (mut builder, kel_prefix) = fresh_kel(&repo).await;
        let iel_prefix = reconcile_iel(&repo, &mut builder, kel_prefix)
            .await
            .unwrap();
        let config = ReconcileConfig {
            domain: "alice.example.com".to_string(),
        };

        reconcile_peer_services_sel(&repo, &mut builder, iel_prefix, &config)
            .await
            .unwrap();

        let sel_prefix = compute_peer_services_sel_prefix(iel_prefix).unwrap();
        let chain = repo.sel.fetch_chain(&sel_prefix).await.unwrap();
        assert_eq!(chain.len(), 3, "[Icp, Upd, Sea] inception batch");
        let tip = chain.last().unwrap();
        assert_eq!(tip.kind, SadEventKind::Sea, "tip is Sea");

        let content_said = tip.content.expect("Sea carries content SAID");
        let entry = repo
            .sad_objects
            .get_by_object_said(&content_said)
            .await
            .unwrap()
            .expect("peer/services body is cached locally");
        let sad: PeerServicesSad = serde_json::from_value(entry.object).unwrap();
        assert_eq!(sad.domain, "alice.example.com");
    }

    /// `reconcile_peer_services_sel` is a no-op when the tip's domain
    /// already matches the configured one — chain length unchanged.
    #[tokio::test]
    async fn reconcile_peer_services_sel_is_no_op_when_domain_matches() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;
        let (mut builder, kel_prefix) = fresh_kel(&repo).await;
        let iel_prefix = reconcile_iel(&repo, &mut builder, kel_prefix)
            .await
            .unwrap();
        let config = ReconcileConfig {
            domain: "alice.example.com".to_string(),
        };

        // First call: incept.
        reconcile_peer_services_sel(&repo, &mut builder, iel_prefix, &config)
            .await
            .unwrap();
        let sel_prefix = compute_peer_services_sel_prefix(iel_prefix).unwrap();
        let chain_before = repo.sel.fetch_chain(&sel_prefix).await.unwrap();
        assert_eq!(chain_before.len(), 3);

        // Second call with the same domain: no-op.
        reconcile_peer_services_sel(&repo, &mut builder, iel_prefix, &config)
            .await
            .unwrap();
        let chain_after = repo.sel.fetch_chain(&sel_prefix).await.unwrap();
        assert_eq!(
            chain_after.len(),
            3,
            "no rotation when domain is unchanged"
        );
    }

    /// `reconcile_peer_services_sel` rotates `[Upd, Sea]` onto the chain
    /// when the configured domain differs from the tip's. New tip's content
    /// SAID resolves to a SAD carrying the new domain.
    #[tokio::test]
    async fn reconcile_peer_services_sel_rotates_on_domain_change() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;
        let (mut builder, kel_prefix) = fresh_kel(&repo).await;
        let iel_prefix = reconcile_iel(&repo, &mut builder, kel_prefix)
            .await
            .unwrap();
        let initial = ReconcileConfig {
            domain: "alice.example.com".to_string(),
        };
        reconcile_peer_services_sel(&repo, &mut builder, iel_prefix, &initial)
            .await
            .unwrap();
        let sel_prefix = compute_peer_services_sel_prefix(iel_prefix).unwrap();
        assert_eq!(repo.sel.fetch_chain(&sel_prefix).await.unwrap().len(), 3);

        // Operator changes PEER_DOMAIN between boots: rotation lands.
        let rotated = ReconcileConfig {
            domain: "alice-new.example.com".to_string(),
        };
        reconcile_peer_services_sel(&repo, &mut builder, iel_prefix, &rotated)
            .await
            .unwrap();

        let chain = repo.sel.fetch_chain(&sel_prefix).await.unwrap();
        assert_eq!(chain.len(), 5, "rotation appends [Upd, Sea] → 5 events");
        let new_tip = chain.last().unwrap();
        assert_eq!(new_tip.kind, SadEventKind::Sea);
        let content_said = new_tip.content.expect("Sea carries content");
        let entry = repo
            .sad_objects
            .get_by_object_said(&content_said)
            .await
            .unwrap()
            .expect("rotated SAD body cached");
        let sad: PeerServicesSad = serde_json::from_value(entry.object).unwrap();
        assert_eq!(sad.domain, "alice-new.example.com");
    }
}
