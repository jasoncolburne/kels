//! Background sync task for replicating peers from local DB to Raft.
//!
//! This runs on the leader only, allowing admin CLI to write to DB
//! and have changes replicate via Raft consensus.
//!
//! Note: Raft->DB sync happens immediately in the state machine apply() method.

use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use kels::Peer;
use verifiable_storage::{Order, Query, QueryExecutor};

use super::FederationNode;
use crate::repository::RegistryRepository;

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

        if let Err(e) = sync_peers(&node, &repo).await {
            error!("DB->Raft sync failed: {}", e);
        }
    }
}

/// Sync peers from local DB to Raft state machine.
async fn sync_peers(
    node: &FederationNode,
    repo: &RegistryRepository,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get peers from local DB (latest version of each)
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

    // Get peers from Raft state machine
    let raft_peers = node.peers().await;
    let raft_peer_prefixes: HashSet<String> =
        raft_peers.iter().map(|p| p.peer_prefix.clone()).collect();

    // Find peers in DB but not in Raft (or with different data)
    let mut synced = 0;
    for db_peer in latest_db_peers {
        if !db_peer.active {
            // Check if we need to remove from Raft
            if raft_peer_prefixes.contains(&db_peer.peer_prefix) {
                info!(
                    "Removing deactivated peer from Raft: {} (node: {})",
                    db_peer.peer_prefix, db_peer.node_id
                );
                if let Err(e) = node.remove_peer(&db_peer.peer_prefix).await {
                    warn!("Failed to remove peer {}: {}", db_peer.peer_prefix, e);
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
                // In Raft but might need update (peer_prefix changed, etc.)
                raft_peer.peer_prefix != db_peer.peer_prefix
                    || raft_peer.node_id != db_peer.node_id
                    || raft_peer.active != db_peer.active
            }
        };

        if needs_sync {
            info!(
                "Syncing peer to Raft: {} (node: {})",
                db_peer.peer_prefix, db_peer.node_id
            );
            if let Err(e) = node.add_peer(db_peer.clone()).await {
                warn!("Failed to sync peer {}: {}", db_peer.peer_prefix, e);
            } else {
                synced += 1;
            }
        }
    }

    if synced > 0 {
        info!("Synced {} peers to Raft", synced);
    } else {
        debug!("Peers in sync");
    }

    Ok(())
}
