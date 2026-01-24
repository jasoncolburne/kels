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

pub mod allowlist;
pub mod bootstrap;
pub mod gossip;
pub mod hsm_signer;
pub mod peer_store;
pub mod protocol;
pub mod sync;

use allowlist::SharedAllowlist;
use bootstrap::{BootstrapConfig, BootstrapSync};
use gossip::{GossipCommand, GossipEvent};
use hsm_signer::{HsmRegistrySigner, HsmSignerError};
use libp2p::Multiaddr;
use peer_store::KelsGossipRepository;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
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
    #[error("HSM signer error: {0}")]
    HsmSigner(#[from] HsmSignerError),
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
    /// HSM service URL for identity keys
    pub hsm_url: String,
    /// Registry service URL (optional - if not set, bootstrap sync is skipped)
    pub registry_url: Option<String>,
    /// Registry KEL prefix (trust anchor for verifying peer allowlist)
    pub registry_prefix: String,
    /// libp2p listen address (e.g., /ip4/0.0.0.0/tcp/4001)
    pub listen_addr: Multiaddr,
    /// Advertised address for registry (e.g., /dns4/kels-gossip.kels-node-a.svc.cluster.local/tcp/4001)
    pub advertise_addr: Multiaddr,
    /// Gossipsub topic name
    pub topic: String,
    /// Heartbeat interval in seconds for registry
    pub heartbeat_interval_secs: u64,
    /// Allowlist refresh interval in seconds
    pub allowlist_refresh_interval_secs: u64,
    /// Test-only: artificial delay (in ms) before broadcasting announcements.
    /// This simulates slow gossip propagation for adversarial testing scenarios.
    /// Set to 0 in production. Only enable for integration testing.
    pub test_propagation_delay_ms: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ServiceError> {
        let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-unknown".to_string());

        let kels_url = std::env::var("KELS_URL").unwrap_or_else(|_| "http://kels".to_string());

        let kels_advertise_url = std::env::var("KELS_ADVERTISE_URL")
            .map_err(|_| ServiceError::Config("KELS_ADVERTISE_URL is required".to_string()))?;

        let kels_advertise_url_internal = std::env::var("KELS_ADVERTISE_URL_INTERNAL").ok();

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ServiceError::Config("DATABASE_URL is required".to_string()))?;

        let hsm_url = std::env::var("HSM_URL").unwrap_or_else(|_| "http://hsm".to_string());

        let registry_url = std::env::var("REGISTRY_URL").ok();
        let registry_prefix = std::env::var("REGISTRY_PREFIX")
            .map_err(|_| ServiceError::Config("REGISTRY_PREFIX is required".to_string()))?;

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

        let allowlist_refresh_interval_secs = std::env::var("ALLOWLIST_REFRESH_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

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
            hsm_url,
            registry_url,
            registry_prefix,
            listen_addr,
            advertise_addr,
            topic,
            heartbeat_interval_secs,
            allowlist_refresh_interval_secs,
            test_propagation_delay_ms,
        })
    }
}

/// Run the gossip service
///
/// # Bootstrap Algorithm
///
/// The service follows this algorithm to safely join the network:
///
/// 1. **Create identity**: Generate HSM-backed keypair, derive PeerId
/// 2. **Check allowlist**: Query `/api/peers` to check if authorized
/// 3. **If NOT authorized**: Log alert with PeerId, loop:
///    - Preload KELs from Ready peers (read-only sync via HTTP)
///    - Sleep 5 minutes
///    - Recheck allowlist
/// 4. **Once authorized**: Register as Bootstrapping, start gossip swarm
/// 5. **Check for Ready peers**: Query `/api/nodes/bootstrap`
/// 6. **If Ready peers exist**: Wait for first `PeerConnected` event, then resync
///    (This catches events missed between preload and joining gossip)
/// 7. **If no Ready peers**: Skip resync (we're the first/only node)
/// 8. **Mark Ready**: Update status, start heartbeat and allowlist refresh loops
pub async fn run(config: Config) -> Result<(), ServiceError> {
    use kels::KelsRegistryClient;
    use tokio::time::Duration;
    use tracing::warn;

    info!("Starting KELS gossip service");
    info!("Node ID: {}", config.node_id);
    info!("KELS URL (local): {}", config.kels_url);
    info!("KELS URL (advertised): {}", config.kels_advertise_url);
    info!("Redis URL: {}", config.redis_url);
    info!("HSM URL: {}", config.hsm_url);
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

    // Step 1: Create HSM-backed identity keypair
    info!("Creating HSM-backed identity...");
    let keypair = hsm_signer::create_hsm_keypair(&config.hsm_url, &config.node_id).await?;
    let peer_id = keypair.public().to_peer_id();
    info!("Local PeerId: {}", peer_id);

    info!("Connecting to database for peer cache...");
    let gossip_repo = KelsGossipRepository::connect(&config.database_url).await?;
    gossip_repo.initialize().await?;
    let peer_repo = Arc::new(gossip_repo.peers);
    info!("Peer cache database ready");

    // Registry is required - without it we have no way to discover peers
    let registry_url = config.registry_url.as_ref().ok_or_else(|| {
        ServiceError::Config("REGISTRY_URL is required - kels-gossip cannot operate without a registry for peer discovery".to_string())
    })?;

    // Create registry signer for authenticated requests
    info!("Creating HSM registry signer...");
    let registry_signer = HsmRegistrySigner::new(config.hsm_url.clone(), &config.node_id);
    let registry_signer: Arc<dyn kels::RegistrySigner> = Arc::new(registry_signer);
    info!("Registry signer ready");

    // Single registry client with signer (unauthenticated APIs don't use the signer)
    let registry_client = KelsRegistryClient::with_signer(registry_url, registry_signer.clone());

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

    let heartbeat_client = registry_client.clone();
    let bootstrap =
        BootstrapSync::new(bootstrap_config.clone(), peer_repo.clone(), registry_client);

    // Step 2-3: Check allowlist and wait if not authorized
    let peer_id_str = peer_id.to_string();
    loop {
        match bootstrap.is_peer_authorized(&peer_id_str).await {
            Ok(true) => {
                info!("Peer {} is authorized in allowlist", peer_id);
                break;
            }
            Ok(false) => {
                warn!(
                    "=======================================================================\n\
                     AUTHORIZATION REQUIRED: This node is not in the allowlist.\n\
                     PeerId: {}\n\
                     Add this peer via: kels-registry-admin peer add --peer-id {} --node-id {}\n\
                     Preloading KELs while waiting...\n\
                     =======================================================================",
                    peer_id, peer_id, config.node_id
                );

                // Preload KELs from Ready peers (read-only, no registration)
                if let Err(e) = bootstrap.preload_kels().await {
                    warn!("KEL preload failed: {}", e);
                }

                // Wait 5 minutes before checking again
                info!("Sleeping 5 minutes before rechecking allowlist...");
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
            Err(e) => {
                warn!(
                    "Failed to check allowlist: {}. Retrying in 30 seconds...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    // Step 4: Now authorized - discover peers and register as Bootstrapping
    let discovery = bootstrap.discover_peers().await?;

    let mut peer_multiaddrs: Vec<Multiaddr> = Vec::new();
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

    // Check if there are Ready peers before starting gossip
    let has_ready_peers = bootstrap.has_ready_peers().await;
    info!("Ready peers available for resync: {}", has_ready_peers);

    let (command_tx, command_rx) = mpsc::channel::<GossipCommand>(100);
    let (event_tx, mut event_rx) = mpsc::channel::<GossipEvent>(100);

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

    // Create shared allowlist for authorized peers
    let allowlist: SharedAllowlist = Arc::new(RwLock::new(HashSet::new()));
    let allowlist_for_gossip = allowlist.clone();

    // Initial allowlist refresh before starting gossip (so we accept authorized peers)
    match allowlist::refresh_allowlist(registry_url, &config.registry_prefix, &allowlist).await {
        Ok(count) => info!("Initial allowlist loaded with {} authorized peers", count),
        Err(e) => warn!(
            "Initial allowlist refresh failed: {} - starting with empty allowlist",
            e
        ),
    }

    // Start gossip swarm in background
    let listen_addr = config.listen_addr.clone();
    let topic = config.topic.clone();
    let registry_url_for_gossip = registry_url.clone();
    let registry_prefix_for_gossip = config.registry_prefix.clone();
    let gossip_handle = tokio::spawn(async move {
        gossip::run_swarm(
            keypair,
            listen_addr,
            peer_multiaddrs,
            &topic,
            allowlist_for_gossip,
            registry_url_for_gossip,
            registry_prefix_for_gossip,
            command_rx,
            event_tx,
        )
        .await
    });

    // Step 5-6: If Ready peers exist, wait for PeerConnected then resync
    // This catches any events missed between preload (while unauthorized) and joining gossip
    if has_ready_peers {
        info!("Waiting for first peer connection before resync...");

        // Wait for PeerConnected event (with timeout)
        let peer_connected = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match event_rx.recv().await {
                    Some(GossipEvent::PeerConnected(connected_peer)) => {
                        info!("Connected to peer: {}", connected_peer);
                        return true;
                    }
                    Some(_) => continue,  // Ignore other events
                    None => return false, // Channel closed
                }
            }
        })
        .await;

        match peer_connected {
            Ok(true) => {
                // Resync to catch events missed between preload and connection
                info!("Performing resync to catch events missed during unauthorized period...");
                if let Err(e) = bootstrap.resync_kels().await {
                    error!("Resync failed: {}", e);
                }
            }
            Ok(false) => {
                warn!("Event channel closed before peer connected");
            }
            Err(_) => {
                warn!("Timeout waiting for peer connection, skipping resync");
            }
        }
    } else {
        // Step 7: No Ready peers - we're the first/only node, skip resync
        info!("No Ready peers available - skipping resync (first node)");
    }

    // Step 8: Mark Ready and start background tasks
    bootstrap.mark_ready(discovery.registry_available).await;

    // Spawn sync handler (needs ownership of event_rx)
    let kels_url = config.kels_url.clone();
    let sync_command_tx = command_tx.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_sync_handler(kels_url, event_rx, sync_command_tx).await {
            error!("Sync handler error: {}", e);
        }
    });

    // Start heartbeat loop
    let heartbeat_config = bootstrap_config.clone();
    tokio::spawn(async move {
        bootstrap::run_heartbeat_loop(heartbeat_config, heartbeat_client).await;
    });

    // Start allowlist refresh loop
    let allowlist_refresh_interval =
        std::time::Duration::from_secs(config.allowlist_refresh_interval_secs);
    let registry_url_for_allowlist = registry_url.clone();
    let registry_prefix_for_allowlist = config.registry_prefix.clone();
    tokio::spawn(async move {
        allowlist::run_allowlist_refresh_loop(
            registry_url_for_allowlist,
            registry_prefix_for_allowlist,
            allowlist,
            allowlist_refresh_interval,
        )
        .await;
    });

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
