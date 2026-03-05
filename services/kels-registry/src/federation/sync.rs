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
        None,
    )
    .await?;

    Ok(())
}

/// Compare own effective SAID with each member's view and push deltas.
///
/// Uses `forward_key_events` with a repo-backed source and per-member HTTP sink.
/// Delta fetch (via `since` parameter) with automatic full-fetch fallback.
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

    let repo_store = kels::RepositoryKelStore::new(Arc::new(MemberKelRepository::new(
        member_kel_repo.pool.clone(),
    )));
    let repo_source = kels::StoreKelSource::new(&repo_store);

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

        let member_sink = kels::HttpKelSink::new(&member.url, "/api/member-kels/events");

        // Delta fetch with fallback: try since=member_said, fall back to full
        let since = member_said.as_deref();
        let result = if since.is_some() {
            match kels::forward_key_events(
                &own_prefix,
                &repo_source,
                &member_sink,
                kels::MAX_EVENTS_PER_KEL_RESPONSE,
                kels::max_verification_pages(),
                since,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(kels::KelsError::EventNotFound(_)) => {
                    // Member SAID not found locally (e.g., composite divergent SAID)
                    kels::forward_key_events(
                        &own_prefix,
                        &repo_source,
                        &member_sink,
                        kels::MAX_EVENTS_PER_KEL_RESPONSE,
                        kels::max_verification_pages(),
                        None,
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        } else {
            kels::forward_key_events(
                &own_prefix,
                &repo_source,
                &member_sink,
                kels::MAX_EVENTS_PER_KEL_RESPONSE,
                kels::max_verification_pages(),
                None,
            )
            .await
        };

        match result {
            Ok(()) => {
                debug!(member = %member.prefix, "Pushed KEL delta to member");
            }
            Err(e) => {
                warn!(member = %member.prefix, error = %e, "Failed to push KEL to member");
            }
        }
    }

    Ok(())
}
