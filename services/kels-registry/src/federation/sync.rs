//! Background sync tasks for replicating core peers between local DB and Raft.
//!
//! Two-way sync:
//! 1. Leader: local DB -> Raft (so admin CLI can write to DB and changes replicate)
//! 2. All nodes: Raft state machine -> local DB (so verify_and_authorize works)

use super::FederationNode;
use crate::repository::RegistryRepository;
use kels::{Peer, PeerScope};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use verifiable_storage::{ChainedRepository, Order, Query, QueryExecutor, SelfAddressed};

/// Run the core peer sync loop.
///
/// This task runs on all federation members:
/// - Leader: syncs peers from local DB to Raft
/// - All nodes: syncs peers from Raft state machine to local DB
pub async fn run_core_peer_sync_loop(
    node: Arc<FederationNode>,
    repo: Arc<RegistryRepository>,
    sync_interval: Duration,
) {
    info!(
        "Starting core peer sync loop (interval: {:?})",
        sync_interval
    );

    let mut ticker = interval(sync_interval);

    loop {
        ticker.tick().await;

        // All nodes sync from Raft state machine to local DB
        // This ensures verify_and_authorize can find peers on followers
        if let Err(e) = sync_from_raft_to_db(&node, &repo).await {
            error!("Raft->DB sync failed: {}", e);
        }

        // Only the leader syncs peers to Raft
        if !node.is_leader().await {
            debug!("Not the leader, skipping DB->Raft sync");
            continue;
        }

        if let Err(e) = sync_core_peers(&node, &repo).await {
            error!("DB->Raft sync failed: {}", e);
        }
    }
}

/// Sync core peers from Raft state machine to local DB.
///
/// This ensures that verify_and_authorize can find replicated peers
/// in the local PostgreSQL database.
async fn sync_from_raft_to_db(
    node: &FederationNode,
    repo: &RegistryRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get core peers from Raft state machine
    let raft_peers = node.core_peers().await;

    if raft_peers.is_empty() {
        return Ok(());
    }

    // Get existing core peers from local DB (latest version of each)
    let query = Query::<Peer>::new()
        .eq("scope", "core")
        .order_by("peer_id", Order::Asc)
        .order_by("version", Order::Desc);

    let db_peers: Vec<Peer> = repo.peers.pool.fetch(query).await?;

    // Deduplicate to get only the latest version of each peer_id
    let mut seen_peer_ids = HashSet::new();
    let db_peer_map: HashSet<String> = db_peers
        .into_iter()
        .filter(|p| seen_peer_ids.insert(p.peer_id.clone()))
        .map(|p| p.peer_id)
        .collect();

    // Find peers in Raft but not in local DB
    let mut synced = 0;
    for raft_peer in raft_peers {
        if !db_peer_map.contains(&raft_peer.peer_id) {
            // Create a new peer record for local DB
            let mut new_peer = Peer::create(
                raft_peer.peer_id.clone(),
                raft_peer.node_id.clone(),
                raft_peer.active,
                PeerScope::Core,
            )?;

            // Derive SAID for the new record
            new_peer.derive_said()?;

            info!(
                "Syncing core peer from Raft to local DB: {} (node: {})",
                new_peer.peer_id, new_peer.node_id
            );

            repo.peers.insert(new_peer).await?;
            synced += 1;
        }
    }

    if synced > 0 {
        info!("Synced {} core peers from Raft to local DB", synced);
    }

    Ok(())
}

/// Sync core peers from local DB to Raft state machine.
async fn sync_core_peers(
    node: &FederationNode,
    repo: &RegistryRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get core peers from local DB (latest version of each)
    let query = Query::<Peer>::new()
        .eq("scope", "core")
        .order_by("prefix", Order::Asc)
        .order_by("version", Order::Desc);

    let db_peers: Vec<Peer> = repo.peers.pool.fetch(query).await?;

    // Deduplicate to get only the latest version of each peer
    let mut seen_prefixes = HashSet::new();
    let latest_db_peers: Vec<Peer> = db_peers
        .into_iter()
        .filter(|p| seen_prefixes.insert(p.prefix.clone()))
        .collect();

    // Get core peers from Raft state machine
    let raft_peers = node.core_peers().await;
    let raft_peer_ids: HashSet<String> = raft_peers.iter().map(|p| p.peer_id.clone()).collect();

    // Find peers in DB but not in Raft (or with different data)
    let mut synced = 0;
    for db_peer in latest_db_peers {
        if !db_peer.active {
            // Check if we need to remove from Raft
            if raft_peer_ids.contains(&db_peer.peer_id) {
                info!(
                    "Removing deactivated core peer from Raft: {} (node: {})",
                    db_peer.peer_id, db_peer.node_id
                );
                if let Err(e) = node.remove_core_peer(&db_peer.peer_id).await {
                    warn!("Failed to remove core peer {}: {}", db_peer.peer_id, e);
                } else {
                    synced += 1;
                }
            }
            continue;
        }

        // Check if peer needs to be added/updated in Raft
        let needs_sync = match raft_peers.iter().find(|p| p.prefix == db_peer.prefix) {
            None => true, // Not in Raft
            Some(raft_peer) => {
                // In Raft but might need update (peer_id changed, etc.)
                raft_peer.peer_id != db_peer.peer_id
                    || raft_peer.node_id != db_peer.node_id
                    || raft_peer.active != db_peer.active
            }
        };

        if needs_sync {
            info!(
                "Syncing core peer to Raft: {} (node: {})",
                db_peer.peer_id, db_peer.node_id
            );
            // Ensure scope is Core before submitting
            let mut peer = db_peer.clone();
            peer.scope = PeerScope::Core;

            if let Err(e) = node.add_core_peer(peer).await {
                warn!("Failed to sync core peer {}: {}", db_peer.peer_id, e);
            } else {
                synced += 1;
            }
        }
    }

    if synced > 0 {
        info!("Synced {} core peers to Raft", synced);
    } else {
        debug!("Core peers in sync");
    }

    Ok(())
}
