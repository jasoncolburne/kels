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

/// Trusted registry prefixes for verifying registry identity.
/// MUST be set at compile time via TRUSTED_REGISTRY_PREFIXES environment variable.
/// Format: "prefix1,prefix2,..." (comma-separated KELS prefixes)
/// Can be empty string for bootstrap mode (first node in new deployment).
const TRUSTED_REGISTRY_PREFIXES: &str = env!("TRUSTED_REGISTRY_PREFIXES");

mod allowlist;
mod bootstrap;
mod gossip;
mod hsm_signer;
mod http;
mod protocol;
mod sync;

use allowlist::SharedAllowlist;
use bootstrap::{BootstrapConfig, BootstrapSync};
use gossip::{GossipCommand, GossipEvent};
use hsm_signer::{HsmRegistrySigner, HsmSignerError};
use libp2p::Multiaddr;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

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
    /// Advertised KELS HTTP endpoint for clients and node-to-node sync
    pub kels_advertise_url: String,
    /// Redis URL for pub/sub
    pub redis_url: String,
    /// HSM service URL for identity keys
    pub hsm_url: String,
    /// Registry service URL (runtime)
    pub registry_url: String,
    /// Trusted registry prefixes (compiled-in for security)
    pub trusted_prefixes: Vec<String>,
    /// libp2p listen address (e.g., /ip4/0.0.0.0/tcp/4001)
    pub listen_addr: Multiaddr,
    /// Advertised address for registry (e.g., /dns4/kels-gossip.kels-node-a.kels/tcp/4001)
    pub advertise_addr: Multiaddr,
    /// Gossipsub topic name
    pub topic: String,
    /// Allowlist refresh interval in seconds
    pub allowlist_refresh_interval_secs: u64,
    /// HTTP server port for ready status endpoint
    pub http_port: u16,
}

/// Raw environment values before validation
#[derive(Default)]
pub struct EnvValues {
    pub node_id: Option<String>,
    pub kels_url: Option<String>,
    pub kels_advertise_url: Option<String>,
    pub redis_url: Option<String>,
    pub hsm_url: Option<String>,
    pub registry_url: Option<String>,
    pub listen_addr: Option<String>,
    pub advertise_addr: Option<String>,
    pub topic: Option<String>,
    pub allowlist_refresh_interval_secs: Option<u64>,
    pub http_port: Option<u16>,
}

impl Config {
    /// Create config from explicit values (for testing and direct construction)
    pub fn from_values(
        env: EnvValues,
        trusted_prefixes: Vec<String>,
    ) -> Result<Self, ServiceError> {
        if trusted_prefixes.is_empty() {
            return Err(ServiceError::Config(
                "trusted_prefixes must contain at least one prefix".to_string(),
            ));
        }

        let kels_advertise_url = env
            .kels_advertise_url
            .ok_or_else(|| ServiceError::Config("KELS_ADVERTISE_URL is required".to_string()))?;

        let registry_url = env
            .registry_url
            .ok_or_else(|| ServiceError::Config("REGISTRY_URL is required".to_string()))?;

        let listen_addr_str = env
            .listen_addr
            .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/4001".to_string());
        let listen_addr = Multiaddr::from_str(&listen_addr_str)
            .map_err(|e| ServiceError::Config(format!("Invalid listen address: {}", e)))?;

        let advertise_addr_str = env
            .advertise_addr
            .unwrap_or_else(|| listen_addr_str.clone());
        let advertise_addr = Multiaddr::from_str(&advertise_addr_str)
            .map_err(|e| ServiceError::Config(format!("Invalid advertise address: {}", e)))?;

        Ok(Self {
            node_id: env.node_id.unwrap_or_else(|| "node-unknown".to_string()),
            kels_url: env.kels_url.unwrap_or_else(|| "http://kels".to_string()),
            kels_advertise_url,
            redis_url: env
                .redis_url
                .unwrap_or_else(|| "redis://redis:6379".to_string()),
            hsm_url: env.hsm_url.unwrap_or_else(|| "http://hsm".to_string()),
            registry_url,
            trusted_prefixes,
            listen_addr,
            advertise_addr,
            topic: env
                .topic
                .unwrap_or_else(|| gossip::DEFAULT_TOPIC.to_string()),
            allowlist_refresh_interval_secs: env.allowlist_refresh_interval_secs.unwrap_or(60),
            http_port: env.http_port.unwrap_or(80),
        })
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ServiceError> {
        // Parse trusted registry prefixes from compile-time constant (comma-separated)
        let trusted_prefixes: Vec<String> = TRUSTED_REGISTRY_PREFIXES
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if trusted_prefixes.is_empty() {
            return Err(ServiceError::Config(
                "TRUSTED_REGISTRY_PREFIXES must be set at compile time with at least one prefix"
                    .to_string(),
            ));
        }

        let env = EnvValues {
            node_id: std::env::var("NODE_ID").ok(),
            kels_url: std::env::var("KELS_URL").ok(),
            kels_advertise_url: std::env::var("KELS_ADVERTISE_URL").ok(),
            redis_url: std::env::var("REDIS_URL").ok(),
            hsm_url: std::env::var("HSM_URL").ok(),
            registry_url: std::env::var("REGISTRY_URL").ok(),
            listen_addr: std::env::var("GOSSIP_LISTEN_ADDR").ok(),
            advertise_addr: std::env::var("GOSSIP_ADVERTISE_ADDR").ok(),
            topic: std::env::var("GOSSIP_TOPIC").ok(),
            allowlist_refresh_interval_secs: std::env::var("ALLOWLIST_REFRESH_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            http_port: std::env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()),
        };

        Self::from_values(env, trusted_prefixes)
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
    use kels::MultiRegistryClient;
    use tokio::time::Duration;
    use tracing::warn;

    info!("Starting KELS gossip service");
    info!("Node ID: {}", config.node_id);
    info!("KELS URL (local): {}", config.kels_url);
    info!("KELS URL (advertised): {}", config.kels_advertise_url);
    info!("Redis URL: {}", config.redis_url);
    info!("HSM URL: {}", config.hsm_url);
    info!("Registry URL: {:?}", config.registry_url);
    info!("Trusted prefixes: {:?}", config.trusted_prefixes);
    info!("Listen address: {}", config.listen_addr);
    info!("Advertise address: {}", config.advertise_addr);
    info!("Topic: {}", config.topic);

    // Create shared ready state (starts false)
    // Other peers can query our /ready endpoint during bootstrap
    let ready_state = std::sync::Arc::new(tokio::sync::RwLock::new(false));

    // Start HTTP server for ready endpoint immediately
    let http_ready_state = ready_state.clone();
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.http_port));
    info!(
        "Starting HTTP server for ready endpoint on port {}",
        config.http_port
    );
    tokio::spawn(async move {
        http::run_http_server(http_addr, http_ready_state).await;
    });

    // Step 1: Create HSM-backed identity keypair
    info!("Creating HSM-backed identity...");
    let keypair = hsm_signer::create_hsm_keypair(&config.hsm_url, &config.node_id).await?;
    let peer_id = keypair.public().to_peer_id();
    info!("Local PeerId: {}", peer_id);

    // Create registry signer for authenticated requests
    info!("Creating HSM registry signer...");
    let registry_signer = HsmRegistrySigner::new(config.hsm_url.clone(), &config.node_id);
    let registry_signer: Arc<dyn kels::RegistrySigner> = Arc::new(registry_signer);
    info!("Registry signer ready");

    // Single registry URL for client
    let registry_urls: Vec<String> = vec![config.registry_url.clone()];

    // Registry client with signer
    let registry_client =
        MultiRegistryClient::with_signer(registry_urls.clone(), registry_signer.clone());

    // Discover and verify registry prefix from the registry's KEL
    info!("Discovering registry prefix from KEL...");
    let registry_kel = registry_client
        .fetch_registry_kel()
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to fetch registry KEL: {}", e)))?;

    let registry_prefix = registry_kel
        .prefix()
        .ok_or_else(|| ServiceError::Config("Registry KEL has no prefix".to_string()))?
        .to_string();

    // Verify the prefix is in our compiled-in trusted set
    if !config.trusted_prefixes.contains(&registry_prefix) {
        return Err(ServiceError::Config(format!(
            "Registry prefix '{}' is not trusted. Valid prefixes: {:?}",
            registry_prefix, config.trusted_prefixes
        )));
    }

    // Verify the KEL itself is valid
    registry_kel
        .verify()
        .map_err(|e| ServiceError::Config(format!("Registry KEL verification failed: {}", e)))?;

    info!("Registry prefix verified: {}", registry_prefix);

    // Create shared allowlist for authorized peers (used by both bootstrap and gossip)
    let allowlist: SharedAllowlist = Arc::new(RwLock::new(HashMap::new()));

    let bootstrap_config = BootstrapConfig {
        node_id: config.node_id.clone(),
        kels_url: config.kels_url.clone(),
        page_size: 100,
    };

    let bootstrap =
        BootstrapSync::new(bootstrap_config.clone(), registry_client, allowlist.clone());

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

    // Publish bootstrapping state to Redis
    if let Ok(redis_client) = redis::Client::open(config.redis_url.as_str()) {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            if let Err(e) = conn
                .set::<_, _, ()>("kels:gossip:ready", "bootstrapping")
                .await
            {
                error!("Failed to publish bootstrapping state to Redis: {}", e);
            } else {
                info!("Published bootstrapping state to Redis");
            }
        }
    }

    // Initial allowlist refresh - must happen before discover_peers
    // Use a separate client without signing for unauthenticated peer list fetching
    let allowlist_client = MultiRegistryClient::new(registry_urls.clone());
    match allowlist::refresh_allowlist(&allowlist_client, &allowlist).await {
        Ok(count) => info!("Initial allowlist loaded with {} authorized peers", count),
        Err(e) => warn!(
            "Initial allowlist refresh failed: {} - starting with empty allowlist",
            e
        ),
    }

    // Step 4: Now authorized - discover peers from allowlist
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

    // Shared state to prevent Redis feedback loop when gossip stores events
    let recently_stored: sync::RecentlyStoredFromGossip = Arc::new(RwLock::new(HashMap::new()));

    let redis_command_tx = command_tx.clone();
    let redis_url = config.redis_url.clone();
    let redis_allowlist = allowlist.clone();
    let redis_local_peer_id = peer_id;
    let redis_recently_stored = recently_stored.clone();
    let redis_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_redis_subscriber(
            &redis_url,
            redis_command_tx,
            redis_allowlist,
            redis_local_peer_id,
            redis_recently_stored,
        )
        .await
        {
            error!("Redis subscriber error: {}", e);
        }
    });

    let registry_allowlist = allowlist.clone();

    // Start gossip swarm in background
    let listen_addr = config.listen_addr.clone();
    let topic = config.topic.clone();
    let gossip_registry_client = allowlist_client.clone();
    let gossip_handle = tokio::spawn(async move {
        gossip::run_swarm(
            keypair,
            listen_addr,
            peer_multiaddrs,
            &topic,
            registry_allowlist,
            gossip_registry_client,
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

    // Step 8: Mark Ready
    *ready_state.write().await = true;
    info!("Bootstrap complete - node is ready");

    // Publish ready state to Redis for KELS service to read
    if let Ok(redis_client) = redis::Client::open(config.redis_url.as_str()) {
        if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
            if let Err(e) = conn.set::<_, _, ()>("kels:gossip:ready", "true").await {
                error!("Failed to publish ready state to Redis {}", e);
            } else {
                info!("Published ready state to Redis");
            }
        }
    }

    // Spawn sync handler (needs ownership of event_rx)
    let kels_url = config.kels_url.clone();
    let sync_command_tx = command_tx.clone();
    let sync_allowlist = allowlist.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_sync_handler(
            kels_url,
            event_rx,
            sync_command_tx,
            sync_allowlist,
            peer_id,
            recently_stored,
        )
        .await
        {
            error!("Sync handler error: {}", e);
        }
    });

    // Start allowlist refresh loop
    let refresh_interval = std::time::Duration::from_secs(config.allowlist_refresh_interval_secs);
    let refresh_client = MultiRegistryClient::new(registry_urls.clone());
    tokio::spawn(async move {
        allowlist::run_allowlist_refresh_loop(refresh_client, allowlist, refresh_interval).await;
    });

    // Wait for gossip swarm to complete OR shutdown signal
    tokio::select! {
        gossip_result = gossip_handle => {
            redis_handle.abort();
            sync_handle.abort();

            match gossip_result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(ServiceError::Gossip(e)),
                Err(e) => Err(ServiceError::Config(format!("Gossip task panicked: {}", e))),
            }
        }
        _ = kels::shutdown_signal() => {
            info!("Shutdown signal received, cleaning up...");
            redis_handle.abort();
            sync_handle.abort();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_error_display() {
        let config_err = ServiceError::Config("missing variable".to_string());
        assert!(config_err.to_string().contains("Configuration error"));
        assert!(config_err.to_string().contains("missing variable"));

        let gossip_err = ServiceError::Gossip(gossip::GossipError::ChannelClosed);
        assert!(gossip_err.to_string().contains("Gossip error"));

        let sync_err = ServiceError::Sync(sync::SyncError::ChannelClosed);
        assert!(sync_err.to_string().contains("Sync error"));

        let bootstrap_err =
            ServiceError::Bootstrap(bootstrap::BootstrapError::Failed("failed".to_string()));
        assert!(bootstrap_err.to_string().contains("Bootstrap error"));
    }

    #[test]
    fn test_service_error_from_gossip_error() {
        let gossip_err = gossip::GossipError::ChannelClosed;
        let service_err: ServiceError = gossip_err.into();
        assert!(matches!(service_err, ServiceError::Gossip(_)));
    }

    #[test]
    fn test_service_error_from_sync_error() {
        let sync_err = sync::SyncError::ChannelClosed;
        let service_err: ServiceError = sync_err.into();
        assert!(matches!(service_err, ServiceError::Sync(_)));
    }

    #[test]
    fn test_service_error_from_bootstrap_error() {
        let bootstrap_err = bootstrap::BootstrapError::Failed("test".to_string());
        let service_err: ServiceError = bootstrap_err.into();
        assert!(matches!(service_err, ServiceError::Bootstrap(_)));
    }

    fn test_trusted_prefixes() -> Vec<String> {
        vec!["ETestPrefix123456789012345678901234567890123".to_string()]
    }

    #[test]
    fn test_config_missing_required() {
        // Missing kels_advertise_url
        let env = EnvValues {
            registry_url: Some("http://registry.example.com".to_string()),
            ..Default::default()
        };
        let result = Config::from_values(env, test_trusted_prefixes());
        assert!(result.is_err());
        let err_str = result.err().expect("Expected error").to_string();
        assert!(err_str.contains("KELS_ADVERTISE_URL"));

        // Missing registry_url
        let env = EnvValues {
            kels_advertise_url: Some("http://kels.example.com".to_string()),
            ..Default::default()
        };
        let result = Config::from_values(env, test_trusted_prefixes());
        assert!(result.is_err());
        let err_str = result.err().expect("Expected error").to_string();
        assert!(err_str.contains("REGISTRY_URL"));
    }

    #[test]
    fn test_config_with_required_vars() {
        let env = EnvValues {
            kels_advertise_url: Some("http://kels.example.com".to_string()),
            registry_url: Some("http://registry.example.com".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env, test_trusted_prefixes());
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let config = result.unwrap();
        assert_eq!(config.kels_advertise_url, "http://kels.example.com");
        assert_eq!(config.registry_url, "http://registry.example.com");
    }

    #[test]
    fn test_config_defaults() {
        let env = EnvValues {
            kels_advertise_url: Some("http://kels.example.com".to_string()),
            registry_url: Some("http://registry.example.com".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env, test_trusted_prefixes());
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let config = result.unwrap();

        // Check defaults
        assert_eq!(config.node_id, "node-unknown");
        assert_eq!(config.kels_url, "http://kels");
        assert_eq!(config.redis_url, "redis://redis:6379");
        assert_eq!(config.hsm_url, "http://hsm");
        assert_eq!(config.allowlist_refresh_interval_secs, 60);
        assert_eq!(config.http_port, 80);
    }

    #[test]
    fn test_config_invalid_listen_addr() {
        let env = EnvValues {
            kels_advertise_url: Some("http://kels.example.com".to_string()),
            registry_url: Some("http://registry.example.com".to_string()),
            listen_addr: Some("not-a-valid-multiaddr".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env, test_trusted_prefixes());
        assert!(result.is_err(), "Expected error but got Ok");
        let err_str = result.err().unwrap().to_string();
        assert!(
            err_str.contains("Invalid listen address"),
            "Expected 'Invalid listen address' error, got: {}",
            err_str
        );
    }
}
