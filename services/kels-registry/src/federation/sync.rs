//! Background sync tasks for federation state.
//!
//! Member KEL sync: every node periodically syncs its own identity KEL to local
//! storage, then pushes deltas to members that have stale effective SAIDs.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, sleep};
use tracing::{debug, info, warn};

use kels::IdentityClient;

use super::FederationNode;
use crate::raft_store::MemberKelRepository;

/// Run the member KEL sync loop.
///
/// Every node (not leader-only) periodically:
/// 1. Syncs own KEL from identity service to local `MemberKelRepository`
/// 2. Compares own effective SAID with each member's view
/// 3. Pushes delta events to members with stale state
///
/// Each node only pushes its own KEL — every node pushes its own, so all
/// member KELs get distributed. No need for node A to push node B's KEL.
///
/// Eagerly retries every 2s until the first successful sync, then falls into
/// the regular interval.
pub async fn run_member_kel_sync_loop(
    node: Arc<FederationNode>,
    identity_client: Arc<IdentityClient>,
    member_kel_repo: MemberKelRepository,
    sync_interval: Duration,
) {
    info!(
        "Starting member KEL sync loop (interval: {:?})",
        sync_interval
    );

    // Eager sync: retry quickly until the federation is reachable and our
    // KEL is stored locally.
    loop {
        match sync_own_kel(&identity_client, &member_kel_repo).await {
            Ok(()) => {
                info!("Initial member KEL sync completed");
                break;
            }
            Err(e) => {
                debug!("Waiting for identity service: {}", e);
                sleep(Duration::from_secs(2)).await;
            }
        }
    }

    // Regular interval
    let mut ticker = interval(sync_interval);

    loop {
        ticker.tick().await;

        // 1. Sync own KEL from identity
        if let Err(e) = sync_own_kel(&identity_client, &member_kel_repo).await {
            debug!("KEL sync from identity: {}", e);
            continue;
        }

        // 2. Push to members with stale state
        if let Err(e) = push_to_stale_members(&node, &identity_client, &member_kel_repo).await {
            debug!("KEL push to members: {}", e);
        }
    }
}

/// Fetch own KEL from identity, verify and store locally.
async fn sync_own_kel(
    identity_client: &IdentityClient,
    member_kel_repo: &MemberKelRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let own_prefix = identity_client.get_prefix().await?;

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

    Ok(())
}

/// Compare own effective SAID with each member's view and push deltas.
async fn push_to_stale_members(
    node: &FederationNode,
    identity_client: &IdentityClient,
    member_kel_repo: &MemberKelRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let own_prefix = identity_client.get_prefix().await?;
    let config = node.config();

    let local_said = member_kel_repo
        .compute_prefix_effective_said(&own_prefix)
        .await?;

    let local_said = match local_said {
        Some((said, _)) => said,
        None => return Ok(()), // Nothing to push
    };

    for member in &config.members {
        if member.prefix == config.self_prefix {
            continue;
        }

        let client = kels::KelsClient::with_path_prefix(&member.url, "/api/member-kels");

        // Check member's view of our effective SAID
        let member_said = match client.fetch_effective_said(&own_prefix).await {
            Ok(said) => said.map(|(s, _)| s),
            Err(e) => {
                debug!(member = %member.prefix, error = %e, "Failed to fetch member's effective SAID");
                continue;
            }
        };

        if member_said.as_deref() == Some(&local_said) {
            continue; // Member is up to date
        }

        // Try delta fetch first (events after member's known tip)
        let events = if let Some(ref member_said) = member_said {
            match member_kel_repo
                .get_signed_history_since(
                    &own_prefix,
                    member_said,
                    kels::MAX_EVENTS_PER_KEL_QUERY as u64,
                )
                .await
            {
                Ok((events, _)) if !events.is_empty() => events,
                _ => {
                    // Member SAID not found locally (e.g., composite divergent SAID), fall back to full fetch
                    match member_kel_repo
                        .get_signed_history(&own_prefix, kels::MAX_EVENTS_PER_KEL_QUERY as u64, 0)
                        .await
                    {
                        Ok((events, _)) => events,
                        Err(e) => {
                            warn!(member = %member.prefix, error = %e, "Failed to get own KEL for push");
                            continue;
                        }
                    }
                }
            }
        } else {
            // Member has no data at all, send everything
            match member_kel_repo
                .get_signed_history(&own_prefix, kels::MAX_EVENTS_PER_KEL_QUERY as u64, 0)
                .await
            {
                Ok((events, _)) => events,
                Err(e) => {
                    warn!(member = %member.prefix, error = %e, "Failed to get own KEL for push");
                    continue;
                }
            }
        };

        if events.is_empty() {
            continue;
        }

        match tokio::time::timeout(
            Duration::from_secs(5),
            client.submit_events_no_propagate(&events),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!(member = %member.prefix, events = events.len(), "Pushed KEL delta to member");
            }
            Ok(Err(e)) => {
                warn!(member = %member.prefix, error = %e, "Failed to push KEL to member");
            }
            Err(_) => {
                warn!(member = %member.prefix, "Timed out pushing KEL to member");
            }
        }
    }

    Ok(())
}
