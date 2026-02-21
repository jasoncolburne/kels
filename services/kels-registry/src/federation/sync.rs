//! Background sync tasks for federation state.
//!
//! KEL sync: every node periodically submits its own identity KEL to Raft,
//! ensuring member KELs survive restarts and are available for verification.

use std::{sync::Arc, time::Duration};
use tokio::time::interval;
use tracing::{debug, info};

use kels::IdentityClient;

use super::FederationNode;

/// Run the KEL sync loop.
///
/// Every node (not leader-only) periodically fetches its own KEL from the
/// identity service and submits events to Raft. Each member is responsible
/// for syncing its own KEL. Deduplication happens in the Raft apply logic.
pub async fn run_kel_sync_loop(
    node: Arc<FederationNode>,
    identity_client: Arc<IdentityClient>,
    sync_interval: Duration,
) {
    info!("Starting KEL sync loop (interval: {:?})", sync_interval);

    let mut ticker = interval(sync_interval);

    loop {
        ticker.tick().await;

        if let Err(e) = sync_own_kel(&node, &identity_client).await {
            debug!("KEL sync: {}", e);
        }
    }
}

/// Fetch own KEL from identity and submit to Raft if there are new events.
async fn sync_own_kel(
    node: &FederationNode,
    identity_client: &IdentityClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let own_kel = identity_client.get_kel().await?;
    let own_prefix = match own_kel.prefix() {
        Some(p) => p.to_string(),
        None => return Ok(()),
    };

    let identity_count = own_kel.events().len();

    // Check Raft state for current event count
    let raft_count = node
        .get_member_kel(&own_prefix)
        .await
        .map(|k| k.events().len())
        .unwrap_or(0);

    if identity_count > raft_count {
        debug!(
            "Submitting own KEL to Raft ({} new events, Raft has {})",
            identity_count - raft_count,
            raft_count
        );
        // Only submit events Raft doesn't have yet — merge() can't handle
        // re-submission from inception because the inception event's previous
        // is None, which doesn't chain onto the existing KEL tip.
        let events = own_kel.events()[raft_count..].to_vec();
        match node.submit_key_events(events).await {
            Ok(crate::federation::FederationResponse::KeyEventsAccepted { new_count, .. }) => {
                info!(
                    "Synced own KEL to Raft ({} -> {} events, {} new)",
                    raft_count, identity_count, new_count
                );
            }
            Ok(crate::federation::FederationResponse::KeyEventsRejected(reason)) => {
                debug!("KEL sync rejected: {}", reason);
            }
            Ok(_) => {
                debug!("KEL sync: unexpected response");
            }
            Err(e) => {
                debug!("KEL sync submission: {}", e);
            }
        }
    }

    Ok(())
}
