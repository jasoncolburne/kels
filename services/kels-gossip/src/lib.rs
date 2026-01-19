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

pub mod gossip;
pub mod protocol;
pub mod sync;

use gossip::{GossipCommand, GossipEvent};
use libp2p::Multiaddr;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Gossip error: {0}")]
    Gossip(#[from] gossip::GossipError),
    #[error("Sync error: {0}")]
    Sync(#[from] sync::SyncError),
}

/// Service configuration
#[derive(Clone)]
pub struct Config {
    /// Local KELS HTTP endpoint
    pub kels_url: String,
    /// Redis URL for pub/sub
    pub redis_url: String,
    /// libp2p listen address
    pub listen_addr: Multiaddr,
    /// Bootstrap peer multiaddrs
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Gossipsub topic name
    pub topic: String,
    /// Test-only: artificial delay (in ms) before broadcasting announcements.
    /// This simulates slow gossip propagation for adversarial testing scenarios.
    /// Set to 0 in production. Only enable for integration testing.
    pub test_propagation_delay_ms: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ServiceError> {
        let kels_url = std::env::var("KELS_URL").unwrap_or_else(|_| "http://kels:80".to_string());

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());

        let listen_addr_str = std::env::var("GOSSIP_LISTEN_ADDR")
            .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string());
        let listen_addr = Multiaddr::from_str(&listen_addr_str)
            .map_err(|e| ServiceError::Config(format!("Invalid listen address: {}", e)))?;

        let bootstrap_peers = std::env::var("GOSSIP_BOOTSTRAP_PEERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                Multiaddr::from_str(s.trim()).map_err(|e| {
                    ServiceError::Config(format!("Invalid bootstrap peer {}: {}", s, e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let topic =
            std::env::var("GOSSIP_TOPIC").unwrap_or_else(|_| gossip::DEFAULT_TOPIC.to_string());

        let test_propagation_delay_ms = std::env::var("GOSSIP_TEST_PROPAGATION_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Self {
            kels_url,
            redis_url,
            listen_addr,
            bootstrap_peers,
            topic,
            test_propagation_delay_ms,
        })
    }
}

/// Run the gossip service
pub async fn run(config: Config) -> Result<(), ServiceError> {
    info!("Starting KELS gossip service");
    info!("KELS URL: {}", config.kels_url);
    info!("Redis URL: {}", config.redis_url);
    info!("Listen address: {}", config.listen_addr);
    info!("Bootstrap peers: {:?}", config.bootstrap_peers);
    info!("Topic: {}", config.topic);
    if config.test_propagation_delay_ms > 0 {
        info!(
            "TEST MODE: Propagation delay enabled: {}ms",
            config.test_propagation_delay_ms
        );
    }

    // Channels for communication between components
    let (command_tx, command_rx) = mpsc::channel::<GossipCommand>(100);
    let (event_tx, event_rx) = mpsc::channel::<GossipEvent>(100);

    // Clone for the Redis subscriber
    let redis_command_tx = command_tx.clone();

    // Spawn the Redis subscriber
    let redis_url = config.redis_url.clone();
    let propagation_delay_ms = config.test_propagation_delay_ms;
    let redis_handle = tokio::spawn(async move {
        if let Err(e) =
            sync::run_redis_subscriber(&redis_url, redis_command_tx, propagation_delay_ms).await
        {
            error!("Redis subscriber error: {}", e);
        }
    });

    // Spawn the sync handler
    let kels_url = config.kels_url.clone();
    let sync_command_tx = command_tx.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_sync_handler(kels_url, event_rx, sync_command_tx).await {
            error!("Sync handler error: {}", e);
        }
    });

    // Run the gossip swarm (blocking)
    let gossip_result = gossip::run_swarm(
        config.listen_addr,
        config.bootstrap_peers,
        &config.topic,
        command_rx,
        event_tx,
    )
    .await;

    // If gossip ends, abort the other tasks
    redis_handle.abort();
    sync_handle.abort();

    gossip_result.map_err(ServiceError::Gossip)
}
