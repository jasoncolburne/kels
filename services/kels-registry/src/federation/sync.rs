//! Background sync tasks for federation state.
//!
//! KEL sync: every node periodically fetches its own identity KEL, verifies and
//! stores it locally, then notifies the federation via Raft so other members can
//! fetch independently.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, sleep};
use tracing::{debug, info};

use kels::IdentityClient;

use super::FederationNode;
use crate::raft_store::MemberKelRepository;

/// Run the KEL sync loop.
///
/// Every node (not leader-only) periodically fetches its own KEL from the
/// identity service, verifies and stores it in the local `MemberKelRepository`,
/// then submits a `SyncMemberKel` trigger to Raft so other members know to
/// fetch from this node.
///
/// Eagerly retries every 2s until the first successful sync (so member KELs
/// are available for anchoring checks as soon as the federation forms), then
/// falls into the regular interval.
pub async fn run_kel_sync_loop(
    node: Arc<FederationNode>,
    identity_client: Arc<IdentityClient>,
    member_kel_repo: MemberKelRepository,
    sync_interval: Duration,
) {
    info!("Starting KEL sync loop (interval: {:?})", sync_interval);

    // Eager sync: retry quickly until the federation is reachable and our
    // KEL is submitted. This avoids a 30s gap between federation formation
    // and member KEL availability.
    loop {
        match sync_own_kel(&node, &identity_client, &member_kel_repo).await {
            Ok(()) => {
                info!("Initial KEL sync completed");
                break;
            }
            Err(e) => {
                debug!("Waiting for federation: {}", e);
                sleep(Duration::from_secs(2)).await;
            }
        }
    }

    // Regular interval
    let mut ticker = interval(sync_interval);

    loop {
        ticker.tick().await;

        if let Err(e) = sync_own_kel(&node, &identity_client, &member_kel_repo).await {
            debug!("KEL sync: {}", e);
        }
    }
}

/// Fetch own KEL from identity, verify and store locally, then notify Raft.
///
/// Uses `transfer_key_events` to fetch from the identity service (HttpKelSource),
/// verify cryptographically, and store in the local MemberKelRepository
/// (RepositoryKelStore as PagedKelSink). If new events are stored, submits a
/// `SyncMemberKel` trigger to Raft so other federation members can fetch.
async fn sync_own_kel(
    node: &FederationNode,
    identity_client: &IdentityClient,
    member_kel_repo: &MemberKelRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Determine own prefix
    let own_prefix = identity_client.get_prefix().await?;

    // Check what we already have locally
    let local_said = member_kel_repo
        .compute_prefix_effective_said(&own_prefix)
        .await
        .ok()
        .flatten();

    // Fetch, verify, and store from identity
    let source = kels::HttpKelSource::new(identity_client.base_url(), "/api/identity/kel");
    let sink = kels::RepositoryKelStore::new(Arc::new(MemberKelRepository::new(
        member_kel_repo.pool.clone(),
    )));

    kels::forward_key_events(
        &own_prefix,
        &source,
        &sink,
        kels::MAX_EVENTS_PER_KEL_RESPONSE,
        kels::max_verification_pages(),
    )
    .await?;

    // Check if there are new events (effective SAID changed)
    let new_said = member_kel_repo
        .compute_prefix_effective_said(&own_prefix)
        .await
        .ok()
        .flatten();

    if new_said != local_said {
        // Notify federation that our KEL has new events
        match node.sync_member_kel(own_prefix.clone()).await {
            Ok(_) => {
                info!("Notified federation of KEL update for {}", own_prefix);
            }
            Err(e) => {
                debug!("Failed to notify federation of KEL update: {}", e);
            }
        }
    }

    Ok(())
}
