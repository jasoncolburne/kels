//! KELS Gossip Service
//!
//! Synchronizes KELs between independent KELS deployments using libp2p gossipsub.
//!
//! # Architecture
//!
//! The service has three main components:
//! - **Redis Subscriber**: Listens for local KEL updates and triggers announcements
//! - **Gossip Layer**: libp2p swarm with gossipsub + request-response protocols
//! - **Sync Handler**: Processes announcements and coordinates KEL fetching
//!
//! # Data Flow
//!
//! ## Outbound (local update → network)
//! 1. KELS updates a KEL, publishes `{prefix}:{said}` to Redis
//! 2. Redis subscriber receives notification
//! 3. Broadcasts `KelAnnouncement` to gossipsub topic
//!
//! ## Inbound (network → local)
//! 1. Receives `KelAnnouncement` from gossipsub
//! 2. Compares announced SAID with local SAID
//! 3. If different, fetches KEL via request-response
//! 4. Submits events to local KELS via HTTP

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod bootstrap;
pub mod gossip;
pub mod peer_store;
pub mod protocol;
pub mod registry_client;
pub mod sync;

use bootstrap::{BootstrapConfig, BootstrapSync};
use gossip::{GossipCommand, GossipEvent};
use libp2p::Multiaddr;
use peer_store::KelsGossipRepository;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info};
use verifiable_storage::StorageError;
use verifiable_storage_postgres::RepositoryConnection;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Gossip error: {0}")]
    Gossip(#[from] gossip::GossipError),
    #[error("Sync error: {0}")]
    Sync(#[from] sync::SyncError),
    #[error("Bootstrap error: {0}")]
    Bootstrap(#[from] bootstrap::BootstrapError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

/// Service configuration
#[derive(Clone)]
pub struct Config {
    /// Unique node identifier (e.g., "node-a")
    pub node_id: String,
    /// Local KELS HTTP endpoint (for this service to use)
    pub kels_url: String,
    /// Advertised KELS HTTP endpoint for external clients
    pub kels_advertise_url: String,
    /// Advertised KELS HTTP endpoint for internal node-to-node sync (defaults to external)
    pub kels_advertise_url_internal: Option<String>,
    /// Redis URL for pub/sub
    pub redis_url: String,
    /// Database URL for peer storage
    pub database_url: String,
    /// Registry service URL (optional - if not set, bootstrap sync is skipped)
    pub registry_url: Option<String>,
    /// libp2p listen address (e.g., /ip4/0.0.0.0/tcp/4001)
    pub listen_addr: Multiaddr,
    /// Advertised address for registry (e.g., /dns4/kels-gossip.kels-node-a.svc.cluster.local/tcp/4001)
    pub advertise_addr: Multiaddr,
    /// Gossipsub topic name
    pub topic: String,
    /// Heartbeat interval in seconds for registry
    pub heartbeat_interval_secs: u64,
    /// Test-only: artificial delay (in ms) before broadcasting announcements.
    /// This simulates slow gossip propagation for adversarial testing scenarios.
    /// Set to 0 in production. Only enable for integration testing.
    pub test_propagation_delay_ms: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ServiceError> {
        let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-unknown".to_string());

        let kels_url = std::env::var("KELS_URL").unwrap_or_else(|_| "http://kels:80".to_string());

        let kels_advertise_url = std::env::var("KELS_ADVERTISE_URL")
            .map_err(|_| ServiceError::Config("KELS_ADVERTISE_URL is required".to_string()))?;

        let kels_advertise_url_internal = std::env::var("KELS_ADVERTISE_URL_INTERNAL").ok();

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ServiceError::Config("DATABASE_URL is required".to_string()))?;

        let registry_url = std::env::var("REGISTRY_URL").ok();

        let listen_addr_str = std::env::var("GOSSIP_LISTEN_ADDR")
            .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string());
        let listen_addr = Multiaddr::from_str(&listen_addr_str)
            .map_err(|e| ServiceError::Config(format!("Invalid listen address: {}", e)))?;

        let advertise_addr_str =
            std::env::var("GOSSIP_ADVERTISE_ADDR").unwrap_or_else(|_| listen_addr_str.clone());
        let advertise_addr = Multiaddr::from_str(&advertise_addr_str)
            .map_err(|e| ServiceError::Config(format!("Invalid advertise address: {}", e)))?;

        let topic =
            std::env::var("GOSSIP_TOPIC").unwrap_or_else(|_| gossip::DEFAULT_TOPIC.to_string());

        let heartbeat_interval_secs = std::env::var("REGISTRY_HEARTBEAT_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let test_propagation_delay_ms = std::env::var("GOSSIP_TEST_PROPAGATION_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Self {
            node_id,
            kels_url,
            kels_advertise_url,
            kels_advertise_url_internal,
            redis_url,
            database_url,
            registry_url,
            listen_addr,
            advertise_addr,
            topic,
            heartbeat_interval_secs,
            test_propagation_delay_ms,
        })
    }
}

/// Run the gossip service
pub async fn run(config: Config) -> Result<(), ServiceError> {
    info!("Starting KELS gossip service");
    info!("Node ID: {}", config.node_id);
    info!("KELS URL (local): {}", config.kels_url);
    info!("KELS URL (advertised): {}", config.kels_advertise_url);
    info!("Redis URL: {}", config.redis_url);
    info!("Registry URL: {:?}", config.registry_url);
    info!("Listen address: {}", config.listen_addr);
    info!("Advertise address: {}", config.advertise_addr);
    info!("Topic: {}", config.topic);
    if config.test_propagation_delay_ms > 0 {
        info!(
            "TEST MODE: Propagation delay enabled: {}ms",
            config.test_propagation_delay_ms
        );
    }

    info!("Connecting to database for peer cache...");
    let gossip_repo = KelsGossipRepository::connect(&config.database_url).await?;
    gossip_repo.initialize().await?;
    let peer_repo = Arc::new(gossip_repo.peers);
    info!("Peer cache database ready");

    // Phase 1: Discover peers and register (before starting gossip)
    let mut peer_multiaddrs: Vec<Multiaddr> = Vec::new();
    let mut bootstrap_state: Option<(BootstrapSync, bootstrap::DiscoveryResult, BootstrapConfig)> =
        None;

    if let Some(ref registry_url) = config.registry_url {
        let bootstrap_config = BootstrapConfig {
            node_id: config.node_id.clone(),
            kels_url: config.kels_url.clone(),
            kels_advertise_url: config.kels_advertise_url.clone(),
            kels_advertise_url_internal: config.kels_advertise_url_internal.clone(),
            gossip_multiaddr: config.advertise_addr.to_string(),
            registry_url: registry_url.clone(),
            page_size: 100,
            heartbeat_interval_secs: config.heartbeat_interval_secs,
        };

        let bootstrap = BootstrapSync::new(bootstrap_config.clone(), peer_repo.clone());
        let discovery = bootstrap.discover_peers().await?;

        for peer in &discovery.peers {
            match Multiaddr::from_str(&peer.gossip_multiaddr) {
                Ok(addr) => {
                    info!("Will connect to peer {} at {}", peer.node_id, addr);
                    peer_multiaddrs.push(addr);
                }
                Err(e) => {
                    error!(
                        "Invalid multiaddr for peer {}: {} - {}",
                        peer.node_id, peer.gossip_multiaddr, e
                    );
                }
            }
        }

        bootstrap_state = Some((bootstrap, discovery, bootstrap_config));
    } else {
        info!("No registry configured - skipping bootstrap sync");
    }

    let (command_tx, command_rx) = mpsc::channel::<GossipCommand>(100);
    let (event_tx, event_rx) = mpsc::channel::<GossipEvent>(100);

    let redis_command_tx = command_tx.clone();

    let redis_url = config.redis_url.clone();
    let propagation_delay_ms = config.test_propagation_delay_ms;
    let redis_handle = tokio::spawn(async move {
        if let Err(e) =
            sync::run_redis_subscriber(&redis_url, redis_command_tx, propagation_delay_ms).await
        {
            error!("Redis subscriber error: {}", e);
        }
    });

    let kels_url = config.kels_url.clone();
    let sync_command_tx = command_tx.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_sync_handler(kels_url, event_rx, sync_command_tx).await {
            error!("Sync handler error: {}", e);
        }
    });

    // Start gossip swarm in background so we receive events during KEL sync
    let gossip_handle = tokio::spawn(async move {
        gossip::run_swarm(
            config.listen_addr,
            peer_multiaddrs,
            &config.topic,
            command_rx,
            event_tx,
        )
        .await
    });

    // Phase 2 & 3: Sync KELs and mark Ready (while gossip is running)
    if let Some((bootstrap, discovery, heartbeat_config)) = bootstrap_state {
        if !discovery.peers.is_empty() {
            if let Err(e) = bootstrap.sync_kels(&discovery.peers).await {
                error!("KEL sync failed: {}", e);
            }
        }
        bootstrap.mark_ready(discovery.registry_available).await;

        tokio::spawn(async move {
            bootstrap::run_heartbeat_loop(heartbeat_config).await;
        });
    }

    // Wait for gossip swarm to complete (blocking)
    let gossip_result = gossip_handle.await;

    redis_handle.abort();
    sync_handle.abort();

    match gossip_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ServiceError::Gossip(e)),
        Err(e) => Err(ServiceError::Config(format!("Gossip task panicked: {}", e))),
    }
}
