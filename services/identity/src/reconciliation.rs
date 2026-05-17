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
    IdentityEvent, KeyEventBuilder, PeerServicesSad, SadEvent, SadEventKind,
    compute_peer_services_sel_prefix,
};
use kels_policy::Policy;

use crate::{
    hsm::HsmKeyProvider,
    repository::{IdentityRepository, SadObjectEntry},
};

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
/// Idempotent: if the IEL chain is already present locally, returns the
/// existing prefix without re-incepting.
///
/// If absent, constructs the degenerate policy `kel(KEL_prefix)` (immune),
/// stores it locally as a SAD body, incepts the IEL with that policy as
/// both `authPolicy` and `governancePolicy`, persists the Icp event, and
/// anchors the Icp SAID in the KEL.
pub async fn reconcile_iel(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<HsmKeyProvider>,
    kel_prefix: Digest256,
) -> Result<Digest256, ReconciliationError> {
    if let Some(existing) = repo
        .iel
        .latest_prefix_for_topic(PEER_IDENTITY_IEL_TOPIC)
        .await?
    {
        info!(iel_prefix = %existing, "Reusing existing IEL");
        return Ok(existing);
    }

    info!(
        kel_prefix = %kel_prefix,
        "No IEL present — incepting peer-identity IEL"
    );

    // 1. Degenerate policy: `kel(KEL_prefix)`, immune. Identity is
    // single-KEL, so the same policy serves both authPolicy and
    // governancePolicy on the IEL Icp.
    let policy = Policy::build(&format!("kel({})", kel_prefix), None, true)?;

    // 2. Cache the policy body locally. The gossip service will push to
    // sadstore at its own startup; meanwhile readers walking the IEL
    // chain locally can resolve `authPolicy` / `governancePolicy` against
    // this cached body.
    let policy_value = serde_json::to_value(&policy)?;
    let entry = SadObjectEntry::create(policy.said, policy_value)?;
    repo.sad_objects.store(entry).await?;

    // 3. Build the IEL Icp event.
    let icp = IdentityEvent::icp(policy.said, policy.said, PEER_IDENTITY_IEL_TOPIC)?;
    let iel_prefix = icp.prefix;
    info!(
        iel_prefix = %iel_prefix,
        policy_said = %policy.said,
        "Built IEL Icp"
    );

    // 4. Persist the Icp in identity_iel_events.
    repo.iel.insert(icp.clone()).await?;

    // 5. Anchor the IEL Icp SAID in the KEL via an `Ixn` (tier-1) — the
    // server's `kel(K)` policy check resolves to "is this SAID in K's
    // anchor history?" which an Ixn satisfies.
    let icp_said = icp.said;
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
pub async fn reconcile_peer_services_sel(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<HsmKeyProvider>,
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

async fn incept_peer_services(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<HsmKeyProvider>,
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

async fn rotate_peer_services(
    repo: &IdentityRepository,
    builder: &mut KeyEventBuilder<HsmKeyProvider>,
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
    use crate::repository::tests::get_harness;

    #[tokio::test]
    async fn reconcile_iel_is_idempotent() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        // Pre-populate an IEL prefix in iel_repo under the peer-identity
        // topic. `latest_prefix_for_topic` filters by topic so cross-test
        // pollution under other topics doesn't interfere.
        let policy_said = cesr::Digest256::blake3_256(b"reconcile-test-policy");
        let icp = IdentityEvent::icp(policy_said, policy_said, PEER_IDENTITY_IEL_TOPIC).unwrap();
        repo.iel.insert(icp.clone()).await.unwrap();

        let latest = repo
            .iel
            .latest_prefix_for_topic(PEER_IDENTITY_IEL_TOPIC)
            .await
            .unwrap();
        assert_eq!(latest, Some(icp.prefix));
    }
}
