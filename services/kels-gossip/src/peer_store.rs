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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use kels::{NodeRegistration, NodeStatus, NodeType};

    // ==================== Peer Unit Tests ====================

    #[test]
    fn test_peer_create() {
        let peer = Peer::create(
            "node-a".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
            true,
        );
        assert!(peer.is_ok());
        let peer = peer.unwrap();
        assert_eq!(peer.node_id, "node-a");
        assert_eq!(peer.gossip_multiaddr, "/ip4/127.0.0.1/tcp/4001");
        assert!(peer.active);
        assert_eq!(peer.version, 0);
        assert!(!peer.said.is_empty());
        assert!(!peer.prefix.is_empty());
    }

    #[test]
    fn test_peer_increment() {
        let mut peer = Peer::create(
            "node-b".to_string(),
            "/ip4/127.0.0.1/tcp/4002".to_string(),
            true,
        )
        .unwrap();

        let original_said = peer.said.clone();
        peer.gossip_multiaddr = "/ip4/127.0.0.1/tcp/5002".to_string();

        let result = peer.increment();
        assert!(result.is_ok());
        assert_eq!(peer.version, 1);
        assert!(peer.previous.is_some());
        assert_eq!(peer.previous.as_ref().unwrap(), &original_said);
        assert_ne!(peer.said, original_said);
    }

    #[test]
    fn test_peer_serialization_roundtrip() {
        let peer = Peer::create(
            "node-c".to_string(),
            "/dns4/node-c.example.com/tcp/4001".to_string(),
            false,
        )
        .unwrap();

        let json = serde_json::to_string(&peer).unwrap();
        let parsed: Peer = serde_json::from_str(&json).unwrap();

        assert_eq!(peer.node_id, parsed.node_id);
        assert_eq!(peer.gossip_multiaddr, parsed.gossip_multiaddr);
        assert_eq!(peer.active, parsed.active);
        assert_eq!(peer.said, parsed.said);
        assert_eq!(peer.version, parsed.version);
    }

    #[test]
    fn test_peer_camel_case_serialization() {
        let peer = Peer::create(
            "node-d".to_string(),
            "/ip4/10.0.0.1/tcp/4001".to_string(),
            true,
        )
        .unwrap();

        let json = serde_json::to_string(&peer).unwrap();
        // Should use camelCase field names
        assert!(json.contains("nodeId"));
        assert!(json.contains("gossipMultiaddr"));
        assert!(json.contains("createdAt"));
    }

    #[test]
    fn test_peer_clone() {
        let peer = Peer::create(
            "node-e".to_string(),
            "/ip4/192.168.1.1/tcp/4001".to_string(),
            true,
        )
        .unwrap();

        let cloned = peer.clone();
        assert_eq!(peer.node_id, cloned.node_id);
        assert_eq!(peer.gossip_multiaddr, cloned.gossip_multiaddr);
        assert_eq!(peer.said, cloned.said);
    }

    #[test]
    fn test_peer_debug() {
        let peer = Peer::create(
            "debug-node".to_string(),
            "/ip4/1.2.3.4/tcp/5555".to_string(),
            false,
        )
        .unwrap();

        let debug_str = format!("{:?}", peer);
        assert!(debug_str.contains("debug-node"));
        assert!(debug_str.contains("5555"));
    }

    // ==================== NodeRegistration Helper Tests ====================

    fn make_node_registration(node_id: &str, multiaddr: &str) -> NodeRegistration {
        NodeRegistration {
            node_id: node_id.to_string(),
            node_type: NodeType::Kels,
            kels_url: format!("http://{}.example.com", node_id),
            kels_url_internal: None,
            gossip_multiaddr: multiaddr.to_string(),
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: NodeStatus::Ready,
        }
    }

    #[test]
    fn test_node_registration_helper() {
        let reg = make_node_registration("node-x", "/ip4/10.0.0.1/tcp/4001");
        assert_eq!(reg.node_id, "node-x");
        assert_eq!(reg.gossip_multiaddr, "/ip4/10.0.0.1/tcp/4001");
    }

    // ==================== Integration Tests with Testcontainers ====================

    use testcontainers::{runners::AsyncRunner, ContainerAsync};
    use testcontainers_modules::postgres::Postgres;
    use verifiable_storage_postgres::RepositoryConnection;

    /// Test harness with container and repository.
    /// Container is cleaned up when harness is dropped.
    struct TestHarness {
        repo: PeerRepository,
        _postgres: ContainerAsync<Postgres>,
    }

    impl TestHarness {
        async fn new() -> Self {
            let postgres = Postgres::default()
                .start()
                .await
                .expect("Failed to start Postgres container");

            let pg_host = postgres
                .get_host()
                .await
                .expect("Failed to get Postgres host");
            let pg_port = postgres
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to get Postgres port");

            let database_url = format!(
                "postgres://postgres:postgres@{}:{}/postgres",
                pg_host, pg_port
            );

            let gossip_repo = KelsGossipRepository::connect(&database_url)
                .await
                .expect("Failed to connect to database");
            gossip_repo
                .initialize()
                .await
                .expect("Failed to run migrations");

            Self {
                repo: gossip_repo.peers,
                _postgres: postgres,
            }
        }
    }

    #[tokio::test]
    async fn test_upsert_and_get_peer() {
        let harness = TestHarness::new().await;

        let peer = harness
            .repo
            .upsert("test-node-1", "/ip4/127.0.0.1/tcp/4001", true)
            .await
            .expect("Failed to upsert peer");

        assert_eq!(peer.node_id, "test-node-1");
        assert_eq!(peer.gossip_multiaddr, "/ip4/127.0.0.1/tcp/4001");
        assert!(peer.active);
        assert_eq!(peer.version, 0);

        let fetched = harness
            .repo
            .get_by_node_id("test-node-1")
            .await
            .expect("Failed to get peer");

        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.said, peer.said);
    }

    #[tokio::test]
    async fn test_upsert_creates_new_version_on_change() {
        let harness = TestHarness::new().await;

        let peer1 = harness
            .repo
            .upsert("test-node-2", "/ip4/10.0.0.1/tcp/4001", true)
            .await
            .expect("Failed to upsert peer");

        assert_eq!(peer1.version, 0);
        let original_said = peer1.said.clone();

        let peer2 = harness
            .repo
            .upsert("test-node-2", "/ip4/10.0.0.2/tcp/4001", true)
            .await
            .expect("Failed to upsert peer");

        assert_eq!(peer2.version, 1);
        assert_eq!(peer2.previous.as_ref().unwrap(), &original_said);
        assert_ne!(peer2.said, original_said);
    }

    #[tokio::test]
    async fn test_upsert_no_change_returns_same_version() {
        let harness = TestHarness::new().await;

        let peer1 = harness
            .repo
            .upsert("test-node-3", "/ip4/192.168.1.1/tcp/4001", true)
            .await
            .expect("Failed to upsert peer");

        let peer2 = harness
            .repo
            .upsert("test-node-3", "/ip4/192.168.1.1/tcp/4001", true)
            .await
            .expect("Failed to upsert peer");

        assert_eq!(peer1.said, peer2.said);
        assert_eq!(peer1.version, peer2.version);
    }

    #[tokio::test]
    async fn test_get_active_peers() {
        let harness = TestHarness::new().await;

        harness
            .repo
            .upsert("active-node-a", "/ip4/1.1.1.1/tcp/4001", true)
            .await
            .expect("Failed to upsert");
        harness
            .repo
            .upsert("active-node-b", "/ip4/2.2.2.2/tcp/4001", true)
            .await
            .expect("Failed to upsert");
        harness
            .repo
            .upsert("inactive-node-c", "/ip4/3.3.3.3/tcp/4001", false)
            .await
            .expect("Failed to upsert");

        let active_peers = harness
            .repo
            .get_active_peers()
            .await
            .expect("Failed to get active peers");

        let active_ids: Vec<&str> = active_peers.iter().map(|p| p.node_id.as_str()).collect();
        assert!(active_ids.contains(&"active-node-a"));
        assert!(active_ids.contains(&"active-node-b"));
        assert!(!active_ids.contains(&"inactive-node-c"));
    }

    #[tokio::test]
    async fn test_deactivate_peer() {
        let harness = TestHarness::new().await;

        harness
            .repo
            .upsert("deactivate-test", "/ip4/5.5.5.5/tcp/4001", true)
            .await
            .expect("Failed to upsert");

        harness
            .repo
            .deactivate("deactivate-test")
            .await
            .expect("Failed to deactivate");

        let peer = harness
            .repo
            .get_by_node_id("deactivate-test")
            .await
            .expect("Failed to get peer");

        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert!(!peer.active);
    }

    #[tokio::test]
    async fn test_deactivate_nonexistent_peer() {
        let harness = TestHarness::new().await;

        let result = harness.repo.deactivate("nonexistent-node").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sync_from_registry() {
        let harness = TestHarness::new().await;

        harness
            .repo
            .upsert("old-peer", "/ip4/9.9.9.9/tcp/4001", true)
            .await
            .expect("Failed to upsert");

        let registry_peers = vec![
            make_node_registration("registry-peer-a", "/ip4/10.0.0.1/tcp/4001"),
            make_node_registration("registry-peer-b", "/ip4/10.0.0.2/tcp/4001"),
            make_node_registration("our-node", "/ip4/10.0.0.3/tcp/4001"),
        ];

        harness
            .repo
            .sync_from_registry(&registry_peers, "our-node")
            .await
            .expect("Failed to sync");

        let peer_a = harness
            .repo
            .get_by_node_id("registry-peer-a")
            .await
            .expect("Failed to get peer")
            .expect("Peer A not found");
        assert!(peer_a.active);

        let peer_b = harness
            .repo
            .get_by_node_id("registry-peer-b")
            .await
            .expect("Failed to get peer")
            .expect("Peer B not found");
        assert!(peer_b.active);

        let old_peer = harness
            .repo
            .get_by_node_id("old-peer")
            .await
            .expect("Failed to get peer")
            .expect("Old peer not found");
        assert!(!old_peer.active);

        let our_node = harness
            .repo
            .get_by_node_id("our-node")
            .await
            .expect("Failed to get peer");
        assert!(our_node.is_none());
    }

    #[tokio::test]
    async fn test_sync_from_registry_updates_multiaddr() {
        let harness = TestHarness::new().await;

        harness
            .repo
            .upsert("update-peer", "/ip4/1.1.1.1/tcp/4001", true)
            .await
            .expect("Failed to upsert");

        let registry_peers = vec![make_node_registration(
            "update-peer",
            "/ip4/2.2.2.2/tcp/4001",
        )];

        harness
            .repo
            .sync_from_registry(&registry_peers, "our-node")
            .await
            .expect("Failed to sync");

        let peer = harness
            .repo
            .get_by_node_id("update-peer")
            .await
            .expect("Failed to get peer")
            .expect("Peer not found");

        assert_eq!(peer.gossip_multiaddr, "/ip4/2.2.2.2/tcp/4001");
        assert!(peer.active);
        assert!(peer.version >= 1);
    }

    #[tokio::test]
    async fn test_try_sync_from_registry() {
        let harness = TestHarness::new().await;

        let registry_peers = vec![make_node_registration(
            "try-sync-peer",
            "/ip4/7.7.7.7/tcp/4001",
        )];

        harness
            .repo
            .try_sync_from_registry(&registry_peers, "our-node")
            .await;

        let peer = harness
            .repo
            .get_by_node_id("try-sync-peer")
            .await
            .expect("Failed to get peer");
        assert!(peer.is_some());
    }

    #[tokio::test]
    async fn test_get_nonexistent_peer() {
        let harness = TestHarness::new().await;

        let peer = harness
            .repo
            .get_by_node_id("definitely-does-not-exist")
            .await
            .expect("Failed to get peer");

        assert!(peer.is_none());
    }

    #[tokio::test]
    async fn test_version_chain_integrity() {
        let harness = TestHarness::new().await;

        let p0 = harness
            .repo
            .upsert("chain-test", "/ip4/1.0.0.0/tcp/4001", true)
            .await
            .expect("Failed to upsert");
        assert_eq!(p0.version, 0);
        assert!(p0.previous.is_none());

        let p1 = harness
            .repo
            .upsert("chain-test", "/ip4/1.0.0.1/tcp/4001", true)
            .await
            .expect("Failed to upsert");
        assert_eq!(p1.version, 1);
        assert_eq!(p1.previous, Some(p0.said.clone()));

        let p2 = harness
            .repo
            .upsert("chain-test", "/ip4/1.0.0.2/tcp/4001", true)
            .await
            .expect("Failed to upsert");
        assert_eq!(p2.version, 2);
        assert_eq!(p2.previous, Some(p1.said.clone()));

        let p3 = harness
            .repo
            .upsert("chain-test", "/ip4/1.0.0.2/tcp/4001", false)
            .await
            .expect("Failed to upsert");
        assert_eq!(p3.version, 3);
        assert_eq!(p3.previous, Some(p2.said.clone()));
    }
}
