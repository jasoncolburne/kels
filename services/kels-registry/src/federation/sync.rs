//! Background sync task for replicating core peers from local DB to Raft.
//!
//! This runs on the leader only, allowing admin CLI to write to DB
//! and have changes replicate via Raft consensus.
//!
//! Note: Raft->DB sync happens immediately in the state machine apply() method.

use super::FederationNode;
use crate::repository::RegistryRepository;
use kels::{Peer, PeerScope};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use verifiable_storage::{Order, Query, QueryExecutor};

/// Run the DB->Raft sync loop for the leader.
///
/// This allows admin CLI to write peers to local DB, which then
/// get replicated to Raft consensus. Only runs on the leader.
pub async fn run_leader_db_sync_loop(
    node: Arc<FederationNode>,
    repo: Arc<RegistryRepository>,
    sync_interval: Duration,
) {
    info!(
        "Starting leader DB->Raft sync loop (interval: {:?})",
        sync_interval
    );

    let mut ticker = interval(sync_interval);

    loop {
        ticker.tick().await;

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
