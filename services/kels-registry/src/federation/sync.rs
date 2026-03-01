//! Background sync tasks for federation state.
//!
//! KEL sync: every node periodically submits its own identity KEL to Raft,
//! ensuring member KELs survive restarts and are available for verification.

use std::{sync::Arc, time::Duration};
use tokio::time::{interval, sleep};
use tracing::{debug, info};

use kels::IdentityClient;

use super::FederationNode;

/// Run the KEL sync loop.
///
/// Every node (not leader-only) periodically fetches its own KEL from the
/// identity service and submits events to Raft. Each member is responsible
/// for syncing its own KEL. Deduplication happens in the Raft apply logic.
///
/// Eagerly retries every 2s until the first successful sync (so member KELs
/// are available for anchoring checks as soon as the federation forms), then
/// falls into the regular interval.
pub async fn run_kel_sync_loop(
    node: Arc<FederationNode>,
    identity_client: Arc<IdentityClient>,
    sync_interval: Duration,
) {
    info!("Starting KEL sync loop (interval: {:?})", sync_interval);

    // Eager sync: retry quickly until the federation is reachable and our
    // KEL is submitted. This avoids a 30s gap between federation formation
    // and member KEL availability.
    loop {
        match sync_own_kel(&node, &identity_client).await {
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
    let mut all_events = Vec::new();
    let mut since: Option<String> = None;
    loop {
        let page = identity_client
            .get_key_events(since.as_deref(), kels::MAX_EVENTS_PER_KEL_RESPONSE)
            .await?;
        if page.events.is_empty() {
            break;
        }
        since = page.events.last().map(|e| e.event.said.clone());
        all_events.extend(page.events);
        if !page.has_more {
            break;
        }
    }
    let own_prefix = match all_events.first() {
        Some(e) => e.event.prefix.clone(),
        None => return Ok(()),
    };

    let identity_count = all_events.len();

    // Check Raft state for current tip serial to compute delta
    let raft_event_count = node
        .get_member_context(&own_prefix)
        .await
        .and_then(|ctx| {
            // For non-divergent KELs, tip serial + 1 = event count
            ctx.branch_tips()
                .first()
                .map(|bt| bt.tip.event.serial as usize + 1)
        })
        .unwrap_or(0);

    if identity_count > raft_event_count {
        debug!(
            "Submitting own KEL to Raft ({} new events, Raft has {})",
            identity_count - raft_event_count,
            raft_event_count
        );
        // Only submit events Raft doesn't have yet — KelVerifier::resume
        // expects events starting after the last verified serial.
        let events = all_events[raft_event_count..].to_vec();
        match node.submit_key_events(events).await {
            Ok(crate::federation::FederationResponse::KeyEventsAccepted { new_count, .. }) => {
                info!(
                    "Synced own KEL to Raft ({} -> {} events, {} new)",
                    raft_event_count, identity_count, new_count
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
