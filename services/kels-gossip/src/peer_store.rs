//! Postgres-backed peer storage for registry fallback.
//!
//! Stores known peers discovered from the registry, allowing nodes to
//! bootstrap from cached peers when the registry is unavailable.

use tracing::{debug, info, warn};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime, StorageError};
use verifiable_storage_postgres::{Filter, Order, PgPool, Query, QueryExecutor, Stored, Value};

/// A known peer discovered from the registry.
/// Versioned to track peer changes over time (e.g., multiaddr changes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, SelfAddressed)]
#[storable(table = "kels_gossip_peers")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    /// The node's identifier (e.g., "node-a")
    pub node_id: String,
    /// libp2p multiaddr for gossip connections
    pub gossip_multiaddr: String,
    /// Whether this peer is currently active (known to be in the registry)
    pub active: bool,
}

#[derive(Stored)]
#[stored(item_type = Peer, table = "kels_gossip_peers")]
pub struct PeerRepository {
    pool: PgPool,
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct KelsGossipRepository {
    pub peers: PeerRepository,
}

impl PeerRepository {
    /// Get all active peers.
    pub async fn get_active_peers(&self) -> Result<Vec<Peer>, StorageError> {
        // Get latest version of each peer where active = true
        let query = Query::<Peer>::new()
            .distinct_on("node_id")
            .filter(Filter::Eq("active".to_string(), Value::Bool(true)))
            .order_by("node_id", Order::Asc)
            .order_by("version", Order::Desc);
        let peers = self.pool.fetch(query).await?;
        debug!("Loaded {} active peers from database", peers.len());
        Ok(peers)
    }

    /// Get a peer by node_id (latest version).
    pub async fn get_by_node_id(&self, node_id: &str) -> Result<Option<Peer>, StorageError> {
        let query = Query::<Peer>::new()
            .eq("node_id", node_id)
            .order_by("version", Order::Desc)
            .limit(1);
        let peers: Vec<Peer> = self.pool.fetch(query).await?;
        Ok(peers.into_iter().next())
    }

    /// Upsert a peer - create new version if multiaddr changed, or update active status.
    pub async fn upsert(
        &self,
        node_id: &str,
        gossip_multiaddr: &str,
        active: bool,
    ) -> Result<Peer, StorageError> {
        let existing = self.get_by_node_id(node_id).await?;

        let peer = match existing {
            Some(mut p) => {
                if p.gossip_multiaddr != gossip_multiaddr || p.active != active {
                    // Content changed - create new version
                    p.gossip_multiaddr = gossip_multiaddr.to_string();
                    p.active = active;
                    p.increment()?;
                    self.pool.insert(&p).await?;
                    p
                } else {
                    // No change
                    p
                }
            }
            None => {
                // New peer
                let peer = Peer::create(node_id.to_string(), gossip_multiaddr.to_string(), active)?;
                self.pool.insert(&peer).await?;
                peer
            }
        };

        if active {
            info!("Stored active peer: {} at {}", node_id, gossip_multiaddr);
        } else {
            info!("Marked peer inactive: {}", node_id);
        }

        Ok(peer)
    }

    /// Mark a peer as inactive (node disappeared from registry).
    pub async fn deactivate(&self, node_id: &str) -> Result<(), StorageError> {
        if let Some(peer) = self.get_by_node_id(node_id).await? {
            if peer.active {
                self.upsert(node_id, &peer.gossip_multiaddr, false).await?;
            }
        }
        Ok(())
    }

    /// Update peers from registry response.
    /// - Upserts all peers from registry as active
    /// - Marks peers not in registry as inactive
    pub async fn sync_from_registry(
        &self,
        registry_peers: &[kels::NodeRegistration],
        our_node_id: &str,
    ) -> Result<(), StorageError> {
        let current_peers = self.get_active_peers().await?;

        let registry_node_ids: std::collections::HashSet<&str> = registry_peers
            .iter()
            .filter(|p| p.node_id != our_node_id)
            .map(|p| p.node_id.as_str())
            .collect();

        for peer in registry_peers {
            if peer.node_id != our_node_id {
                self.upsert(&peer.node_id, &peer.gossip_multiaddr, true)
                    .await?;
            }
        }

        // Mark peers not in registry as inactive
        for peer in current_peers {
            if !registry_node_ids.contains(peer.node_id.as_str()) {
                info!(
                    "Peer {} no longer in registry, marking inactive",
                    peer.node_id
                );
                self.deactivate(&peer.node_id).await?;
            }
        }

        Ok(())
    }

    /// Try to sync from registry, logging errors but not failing.
    pub async fn try_sync_from_registry(
        &self,
        registry_peers: &[kels::NodeRegistration],
        our_node_id: &str,
    ) {
        if let Err(e) = self.sync_from_registry(registry_peers, our_node_id).await {
            warn!("Failed to sync peers to database: {}", e);
        }
    }
}
