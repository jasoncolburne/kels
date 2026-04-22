//! KELS Gossip Service
//!
//! Synchronizes KELs between independent KELS deployments using a custom
//! gossip protocol (HyParView membership + PlumTree broadcast over TCP
//! with auto-negotiated ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 encryption).
//!
//! # Architecture
//!
//! The service has four main components:
//! - **Identity**: Fetches the node's KELS prefix from the identity service
//! - **Redis Subscriber**: Listens for local KEL updates and triggers announcements
//! - **Gossip Layer**: Custom protocol with encrypted peer connections
//! - **Sync Handler**: Processes announcements and coordinates KEL fetching
//!
//! # Data Flow
//!
//! ## Outbound (local update → network)
//! 1. KELS updates a KEL, publishes `{prefix}:{said}` to Redis
//! 2. Redis subscriber receives notification
//! 3. Broadcasts `KelAnnouncement` to gossip topic
//!
//! ## Inbound (network → local)
//! 1. Receives `KelAnnouncement` from gossip
//! 2. Compares announced SAID with local SAID
//! 3. If different, fetches KEL via HTTP
//! 4. Submits events to local KELS via HTTP

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

mod allowlist;
mod bootstrap;
mod gossip_layer;
mod hsm_signer;
mod repository;
mod server;
mod sync;
pub(crate) mod types;

use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tokio::{
    sync::{RwLock, mpsc},
    time::Duration,
};
use tracing::{error, info};

use cesr::Matter;
use redis::AsyncCommands;
use thiserror::Error;

use allowlist::SharedAllowlist;
use bootstrap::{BootstrapConfig, BootstrapSync};
use hsm_signer::{IdentityGossipSigner, IdentitySigner, KelsPeerVerifier, SignerError};
use types::{GossipCommand, GossipEvent};

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Gossip error: {0}")]
    Gossip(#[from] gossip_layer::GossipError),
    #[error("Sync error: {0}")]
    Sync(#[from] sync::SyncError),
    #[error("Bootstrap error: {0}")]
    Bootstrap(#[from] bootstrap::BootstrapError),
    #[error("Signer error: {0}")]
    Signer(#[from] SignerError),
}

/// Create a `KelStore` wrapping the registry KEL repository.
fn registry_kel_store(
    repo: &repository::RegistryKelRepository,
) -> kels_core::RepositoryKelStore<repository::RegistryKelRepository> {
    kels_core::RepositoryKelStore::new(std::sync::Arc::new(repo.clone()))
}

/// Service configuration
#[derive(Clone)]
pub struct Config {
    /// Unique node identifier (e.g., "node-a")
    pub node_id: String,
    /// Base domain for service discovery (e.g., "node-a.kels").
    /// KELS URL = http://kels.{base_domain}, SADStore URL = http://sadstore.{base_domain}
    pub base_domain: String,
    /// PostgreSQL database URL for local registry KEL store
    pub database_url: String,
    /// Redis URL for pub/sub
    pub redis_url: String,
    /// HSM service URL for identity keys
    pub hsm_url: String,
    /// Identity service URL for KELS prefix
    pub identity_url: String,
    /// All federation registry URLs (for peer discovery)
    pub federation_registry_urls: Vec<String>,
    /// Gossip listen address (e.g., 0.0.0.0:4001)
    pub listen_addr: SocketAddr,
    /// Advertised gossip address for registry (e.g., gossip.node-a.kels:4001)
    pub advertise_addr: String,
    /// Gossip topic name
    pub topic: String,
    /// Allowlist refresh interval in seconds
    pub allowlist_refresh_interval_secs: u64,
    /// HTTP server listen host (e.g., 0.0.0.0)
    pub http_listen_host: String,
    /// HTTP server listen port (e.g., 80)
    pub http_listen_port: u16,
    /// Periodic anti-entropy interval in seconds (repairs silent divergence)
    pub anti_entropy_interval_secs: u64,
}

impl Config {
    /// Local KELS URL derived from base_domain.
    pub fn kels_url(&self) -> String {
        format!("http://kels.{}", self.base_domain)
    }

    /// Local SADStore URL derived from base_domain.
    pub fn sadstore_url(&self) -> String {
        format!("http://sadstore.{}", self.base_domain)
    }

    /// Local mail service URL derived from base_domain.
    pub fn mail_url(&self) -> String {
        format!("http://mail.{}", self.base_domain)
    }
}

/// Raw environment values before validation
#[derive(Default)]
pub struct EnvValues {
    pub node_id: Option<String>,
    pub base_domain: Option<String>,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub hsm_url: Option<String>,
    pub identity_url: Option<String>,
    pub federation_registry_urls: Option<String>,
    pub listen_addr: Option<String>,
    pub advertise_addr: Option<String>,
    pub topic: Option<String>,
    pub allowlist_refresh_interval_secs: Option<u64>,
    pub http_listen_host: Option<String>,
    pub http_listen_port: Option<u16>,
    pub anti_entropy_interval_secs: Option<u64>,
}

impl Config {
    /// Create config from explicit values (for testing and direct construction)
    pub fn from_values(env: EnvValues) -> Result<Self, ServiceError> {
        let base_domain = env
            .base_domain
            .ok_or_else(|| ServiceError::Config("BASE_DOMAIN is required".to_string()))?;

        let listen_addr_str = env
            .listen_addr
            .unwrap_or_else(|| "0.0.0.0:4001".to_string());
        let listen_addr: SocketAddr = listen_addr_str
            .parse()
            .map_err(|e| ServiceError::Config(format!("Invalid listen address: {}", e)))?;

        let advertise_addr = env
            .advertise_addr
            .unwrap_or_else(|| listen_addr_str.clone());

        let federation_registry_urls: Vec<String> = env
            .federation_registry_urls
            .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
            .unwrap_or_default();

        Ok(Self {
            node_id: env.node_id.unwrap_or_else(|| "node-unknown".to_string()),
            base_domain,
            database_url: env.database_url.unwrap_or_else(|| {
                "postgres://kels_admin:password@postgres:5432/kels_gossip".to_string()
            }),
            redis_url: env
                .redis_url
                .unwrap_or_else(|| "redis://redis:6379".to_string()),
            hsm_url: env.hsm_url.unwrap_or_else(|| "http://hsm".to_string()),
            identity_url: env
                .identity_url
                .unwrap_or_else(|| "http://identity".to_string()),
            federation_registry_urls,
            listen_addr,
            advertise_addr,
            topic: env
                .topic
                .unwrap_or_else(|| gossip_layer::DEFAULT_TOPIC.to_string()),
            allowlist_refresh_interval_secs: env.allowlist_refresh_interval_secs.unwrap_or(60),
            http_listen_host: env
                .http_listen_host
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            http_listen_port: env.http_listen_port.unwrap_or(80),
            anti_entropy_interval_secs: env.anti_entropy_interval_secs.unwrap_or(10),
        })
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ServiceError> {
        let env = EnvValues {
            node_id: env::var("NODE_ID").ok(),
            base_domain: env::var("BASE_DOMAIN").ok(),
            database_url: env::var("DATABASE_URL").ok(),
            redis_url: env::var("REDIS_URL").ok(),
            hsm_url: env::var("HSM_URL").ok(),
            identity_url: env::var("IDENTITY_URL").ok(),
            federation_registry_urls: env::var("FEDERATION_REGISTRY_URLS").ok(),
            listen_addr: env::var("GOSSIP_LISTEN_ADDR").ok(),
            advertise_addr: env::var("GOSSIP_ADVERTISE_ADDR").ok(),
            topic: env::var("GOSSIP_TOPIC").ok(),
            allowlist_refresh_interval_secs: env::var("ALLOWLIST_REFRESH_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            http_listen_host: env::var("HTTP_LISTEN_HOST").ok(),
            http_listen_port: env::var("HTTP_LISTEN_PORT")
                .ok()
                .and_then(|s| s.parse().ok()),
            anti_entropy_interval_secs: env::var("ANTI_ENTROPY_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
        };

        Self::from_values(env)
    }
}

/// Run the gossip service
pub async fn run(config: Config) -> Result<(), ServiceError> {
    use tracing::warn;

    info!("Starting KELS gossip service");
    info!("Node ID: {}", config.node_id);
    info!("Base domain: {}", config.base_domain);
    info!("KELS URL: {}", config.kels_url());
    info!("SADStore URL: {}", config.sadstore_url());
    info!("Connecting to Redis");
    info!("HSM URL: {}", config.hsm_url);
    info!("Identity URL: {}", config.identity_url);
    info!(
        "Federation registry URLs: {:?}",
        config.federation_registry_urls
    );
    info!("Listen address: {}", config.listen_addr);
    info!("Advertise address: {}", config.advertise_addr);
    info!("Topic: {}", config.topic);

    // Create shared ready state (starts false)
    // Other peers can query our /ready endpoint during bootstrap
    let ready_state = std::sync::Arc::new(tokio::sync::RwLock::new(false));

    // Start HTTP server for ready endpoint immediately
    let http_ready_state = ready_state.clone();
    let http_addr: SocketAddr = format!("{}:{}", config.http_listen_host, config.http_listen_port)
        .parse()
        .map_err(|e| ServiceError::Config(format!("Invalid HTTP listen address: {}", e)))?;
    info!("Starting HTTP server for ready endpoint on {}", http_addr);
    tokio::spawn(async move {
        server::run_http_server(http_addr, http_ready_state).await;
    });

    // Clear stale ready state in Redis immediately on startup
    if let Ok(redis_client) = redis::Client::open(config.redis_url.as_str())
        && let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await
        && let Err(e) = conn.set::<_, _, ()>("kels:gossip:ready", "sync").await
    {
        error!("Failed to clear ready state in Redis: {}", e);
    }

    // Step 1: Fetch identity prefix and KEL from the identity service
    info!("Fetching identity prefix...");
    let identity_client = kels_core::IdentityClient::new(&config.identity_url)
        .map_err(|e| ServiceError::Config(format!("Failed to build identity client: {}", e)))?;
    let local_kel_prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to get identity prefix: {}", e)))?;
    info!("Local PeerPrefix: {}", local_kel_prefix);

    // Submit identity KEL to local KELS service so other peers can verify us
    let identity_page = identity_client
        .get_key_events(None, kels_core::page_size())
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to get identity KEL: {}", e)))?;
    let local_kels_client = kels_core::KelsClient::new(&config.kels_url())
        .map_err(|e| ServiceError::Config(format!("Failed to build KELS client: {}", e)))?;
    let events = identity_page.events;
    if !events.is_empty() {
        let _ = local_kels_client
            .submit_events(&events)
            .await
            .map_err(|e| {
                ServiceError::Config(format!(
                    "Failed to submit identity KEL to local KELS: {}",
                    e
                ))
            })?;
        info!("Identity KEL submitted to local KELS service");
    }

    // Create registry signer for authenticated requests (signs via identity service)
    info!("Creating identity registry signer...");
    let registry_signer = IdentitySigner::new(&config.identity_url, local_kel_prefix)
        .map_err(|e| ServiceError::Config(format!("Failed to build identity signer: {}", e)))?;
    let registry_signer: Arc<dyn kels_core::PeerSigner> = Arc::new(registry_signer);
    info!("Registry signer ready");

    // All federation registry URLs for peer discovery and authenticated operations
    let federation_registry_urls = config.federation_registry_urls.clone();

    // Discover and verify registry prefix from the registry's KEL
    info!("Discovering registry prefix from KEL...");
    info!("urls: {:?}", federation_registry_urls);
    let registry_prefixes: Vec<String> = kels_core::trusted_prefixes()
        .iter()
        .map(|p| p.to_string())
        .collect();

    if registry_prefixes.is_empty() {
        return Err(ServiceError::Config(
            "No trusted registry prefixes configured".to_string(),
        ));
    }

    info!("Registry prefixes: {:?}", registry_prefixes);

    // Create shared allowlist for authorized peers (used by both bootstrap and gossip)
    let allowlist: SharedAllowlist = Arc::new(RwLock::new(HashMap::new()));

    // Create Redis connection manager early — used by both bootstrap and retry/anti-entropy loops
    let redis_conn_manager: Option<Arc<redis::aio::ConnectionManager>> =
        match redis::Client::open(config.redis_url.as_str()) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(conn) => {
                    info!("Created Redis connection manager");
                    Some(Arc::new(conn))
                }
                Err(e) => {
                    error!("Failed to create Redis connection manager: {}", e);
                    None
                }
            },
            Err(e) => {
                error!("Failed to open Redis client: {}", e);
                None
            }
        };

    // Initialize PostgreSQL for local registry KEL store
    info!("Connecting to database");
    let gossip_repo = {
        use verifiable_storage_postgres::RepositoryConnection;
        let repo = repository::GossipRepository::connect(&config.database_url)
            .await
            .map_err(|e| ServiceError::Config(format!("Failed to connect to database: {}", e)))?;
        repo.initialize()
            .await
            .map_err(|e| ServiceError::Config(format!("Failed to run migrations: {}", e)))?;
        info!("Database connected and migrations applied");
        Arc::new(repo)
    };

    // Transfer verified registry KELs to local store for anchoring checks
    {
        let registry_kel_store =
            kels_core::RepositoryKelStore::new(Arc::new(gossip_repo.registry_kels.clone()));
        for prefix_str in &registry_prefixes {
            if let Ok(prefix_digest) = cesr::Digest256::from_qb64(prefix_str) {
                kels_core::sync_member_kel(
                    &prefix_digest,
                    &federation_registry_urls,
                    &registry_kel_store,
                )
                .await;
            }
        }
    }
    info!("Registry KELs persisted to local store");

    let bootstrap_config = BootstrapConfig {
        node_id: config.node_id.clone(),
        kels_url: config.kels_url(),
        sadstore_url: config.sadstore_url(),
        http_port: config.http_listen_port,
        page_size: 100,
    };

    let mut bootstrap = BootstrapSync::new(
        bootstrap_config.clone(),
        federation_registry_urls.clone(),
        allowlist.clone(),
        registry_signer.clone(),
    )?;
    if let Some(ref redis) = redis_conn_manager {
        bootstrap = bootstrap.with_redis(redis.clone());
    }

    // Step 2-3: Check allowlist and wait if not authorized
    loop {
        match bootstrap
            .is_peer_authorized(local_kel_prefix.as_ref())
            .await
        {
            Ok(true) => {
                info!("Peer {} is authorized in allowlist", local_kel_prefix);
                break;
            }
            Ok(false) => {
                warn!(
                    "=======================================================================\n\
                     AUTHORIZATION REQUIRED: This node is not in the allowlist.\n\
                     Peer prefix: {}\n\
                     Add this peer via: registry-admin peer add --peer-kel-prefix {} --node-id {}\n\
                     Preloading KELs while waiting...\n\
                     =======================================================================",
                    local_kel_prefix, local_kel_prefix, config.node_id
                );

                // Preload KELs, SAD objects, and SAD records from Ready peers
                if let Err(e) = bootstrap.preload_kels().await {
                    warn!("KEL preload failed: {}", e);
                }
                if let Err(e) = bootstrap.preload_sad_objects().await {
                    warn!("SAD object preload failed: {}", e);
                }
                if let Err(e) = bootstrap.preload_sad_records().await {
                    warn!("SEL preload failed: {}", e);
                }

                // Wait 5 minutes before checking again
                info!("Sleeping 5 minutes before rechecking allowlist...");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(300)) => {}
                    _ = kels_core::shutdown_signal() => {
                        info!("Shutdown signal received during allowlist wait");
                        std::process::exit(0);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to check allowlist: {}. Retrying in 30 seconds...",
                    e
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = kels_core::shutdown_signal() => {
                        info!("Shutdown signal received during allowlist wait");
                        std::process::exit(0);
                    }
                }
            }
        }
    }

    // Publish bootstrapping state to Redis
    if let Ok(redis_client) = redis::Client::open(config.redis_url.as_str())
        && let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await
    {
        if let Err(e) = conn
            .set::<_, _, ()>("kels:gossip:ready", "bootstrapping")
            .await
        {
            error!("Failed to publish bootstrapping state to Redis: {}", e);
        } else {
            info!("Published bootstrapping state to Redis");
        }
    }

    // Initial allowlist refresh — fetch all peers from all registries, exclude self
    let allowlist_store = registry_kel_store(&gossip_repo.registry_kels);
    match allowlist::refresh_allowlist(
        &federation_registry_urls,
        &allowlist_store,
        &allowlist,
        Some(&config.node_id),
    )
    .await
    {
        Ok(count) => info!("Allowlist refreshed with {} peers", count),
        Err(e) => warn!(
            "Initial allowlist refresh failed: {} - starting with empty allowlist",
            e
        ),
    }

    // Probe peer KELS readiness before discovery. This gives peer services
    // time to finish starting — without it, gossip nodes race ahead and try
    // to dial peers before they're listening. Fire-and-forget parallel checks
    // with a 2s per-request timeout.
    {
        let peers: Vec<_> = allowlist.read().await.values().cloned().collect();
        let readiness_futures = peers.iter().filter(|p| p.active).map(|peer| {
            let kels_url = format!("http://kels.{}", peer.base_domain);
            async move {
                if let Ok(client) =
                    kels_core::KelsClient::with_timeout(&kels_url, Duration::from_secs(2))
                {
                    let _ = client.check_ready_status().await;
                }
            }
        });
        futures::future::join_all(readiness_futures).await;
    }

    // Step 4: Now authorized - discover peers from allowlist and build peer addresses
    let discovery = bootstrap.discover_peers().await?;

    let mut peer_addrs: Vec<kels_gossip_core::addr::PeerAddr> = Vec::new();
    for peer in &discovery.peers {
        let peer_uri = format!("kels://{}@{}", peer.kel_prefix, peer.gossip_addr);
        match kels_gossip_core::addr::PeerAddr::parse(&peer_uri) {
            Ok(addr) => {
                info!("Will connect to peer {} at {}", peer.node_id, addr);
                peer_addrs.push(addr);
            }
            Err(e) => {
                error!(
                    "Invalid gossip address for peer {}: {} - {}",
                    peer.node_id, peer.gossip_addr, e
                );
            }
        }
    }

    // Check if there are Ready peers before starting gossip
    let has_ready_peers = bootstrap.has_ready_peers().await;
    info!("Ready peers available for resync: {}", has_ready_peers);

    let (command_tx, command_rx) = mpsc::channel::<GossipCommand>(100);
    let (event_tx, event_rx) = mpsc::channel::<GossipEvent>(100);

    // Shared state to prevent Redis feedback loop when gossip stores events
    let recently_stored: sync::RecentlyStoredFromGossip = Arc::new(RwLock::new(HashMap::new()));

    // Periodic reaper for recently_stored — prevents unbounded growth
    {
        let map = recently_stored.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(sync::RECENTLY_STORED_TTL).await;
                let mut guard = map.write().await;
                guard.retain(|_, instant| instant.elapsed() < sync::RECENTLY_STORED_TTL);
            }
        });
    }

    let redis_command_tx = command_tx.clone();
    let redis_url = config.redis_url.clone();
    let redis_recently_stored = recently_stored.clone();
    let redis_local_kel_prefix = local_kel_prefix;
    let redis_handle = tokio::spawn(async move {
        loop {
            if let Err(e) = sync::run_redis_subscriber(
                &redis_url,
                redis_local_kel_prefix,
                redis_command_tx.clone(),
                redis_recently_stored.clone(),
            )
            .await
            {
                error!("Redis subscriber error: {} — reconnecting in 5s", e);
            } else {
                warn!("Redis subscriber stream ended — reconnecting in 5s");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Start SAD Redis subscriber (listens for SAD object and SEL updates)
    let sad_redis_command_tx = command_tx.clone();
    let sad_redis_url = config.redis_url.clone();
    let sad_redis_recently_stored = recently_stored.clone();
    let sad_redis_local_kel_prefix = local_kel_prefix;
    tokio::spawn(async move {
        loop {
            if let Err(e) = sync::run_sad_redis_subscriber(
                &sad_redis_url,
                sad_redis_local_kel_prefix,
                sad_redis_command_tx.clone(),
                sad_redis_recently_stored.clone(),
            )
            .await
            {
                error!("SAD Redis subscriber error: {} — reconnecting in 5s", e);
            } else {
                warn!("SAD Redis subscriber stream ended — reconnecting in 5s");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Start mail Redis subscriber
    let mail_redis_command_tx = command_tx.clone();
    let mail_redis_url = config.redis_url.clone();
    let mail_redis_recently_stored = recently_stored.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = sync::run_mail_redis_subscriber(
                &mail_redis_url,
                mail_redis_command_tx.clone(),
                mail_redis_recently_stored.clone(),
            )
            .await
            {
                error!("Mail Redis subscriber error: {} — reconnecting in 5s", e);
            } else {
                warn!("Mail Redis subscriber stream ended — reconnecting in 5s");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Create gossip signer and verifier (signer uses identity service)
    let signer = IdentityGossipSigner::new(&config.identity_url, local_kel_prefix)?;
    let verifier_store: std::sync::Arc<dyn kels_core::KelStore> =
        std::sync::Arc::new(registry_kel_store(&gossip_repo.registry_kels));
    let verifier = KelsPeerVerifier::new(
        allowlist.clone(),
        &config.kels_url(),
        federation_registry_urls.clone(),
        config.node_id.clone(),
        verifier_store,
    );

    // Create gossip instance — advertise our address so peers can dial us on demand
    let gossip_config = kels_gossip_core::GossipConfig {
        advertise_data: kels_gossip_core::proto::PeerData::new(
            config.advertise_addr.as_bytes().to_vec(),
        ),
        ..Default::default()
    };
    let (gossip_instance, gossip_handle) =
        kels_gossip_core::Gossip::new(gossip_config, signer, verifier, config.listen_addr)
            .await
            .map_err(|e| ServiceError::Config(format!("Failed to start gossip: {}", e)))?;

    // Derive topic IDs and join with bootstrap peers
    let topic_id = gossip_layer::topic_id_from_name(&config.topic);
    let sad_topic_id = gossip_layer::topic_id_from_name(gossip_layer::SAD_TOPIC);
    let mail_topic_id = gossip_layer::topic_id_from_name(gossip_layer::MAIL_TOPIC);
    gossip_instance
        .join(topic_id, peer_addrs.clone())
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to join KEL gossip topic: {}", e)))?;
    gossip_instance
        .join(sad_topic_id, peer_addrs.clone())
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to join SAD gossip topic: {}", e)))?;
    gossip_instance
        .join(mail_topic_id, peer_addrs)
        .await
        .map_err(|e| ServiceError::Config(format!("Failed to join mail gossip topic: {}", e)))?;

    let local_node_prefix = local_kel_prefix;

    // Start gossip event loop in background
    let gossip_instance_clone = gossip_instance.clone();
    let gossip_event_handle = tokio::spawn(async move {
        gossip_layer::run_gossip(
            gossip_instance_clone,
            topic_id,
            sad_topic_id,
            mail_topic_id,
            command_rx,
            event_tx,
            local_node_prefix,
        )
        .await
    });

    // Reuse the Redis connection manager created earlier for sync and anti-entropy
    let redis_for_sync: sync::OptionalRedis = redis_conn_manager.clone();

    // Start sync handler BEFORE waiting for PeerConnected so no gossip events are dropped.
    // The sync handler processes all events (announcements, peer connects/disconnects) as
    // they arrive. A oneshot channel signals back when the first peer connects.
    let (peer_connected_tx, peer_connected_rx) = tokio::sync::oneshot::channel::<()>();
    let kels_url = config.kels_url().clone();
    let sadstore_url = config.sadstore_url().clone();
    let mail_url = config.mail_url().clone();
    let sync_command_tx = command_tx.clone();
    let sync_allowlist = allowlist.clone();
    let sync_redis = redis_for_sync.clone();
    let sync_signer = registry_signer.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync::run_sync_handler(
            kels_url,
            sadstore_url,
            mail_url,
            event_rx,
            sync_command_tx,
            sync_allowlist,
            recently_stored,
            sync_redis,
            sync_signer,
            if has_ready_peers {
                Some(peer_connected_tx)
            } else {
                None
            },
        )
        .await
        {
            error!("Sync handler error: {}", e);
        }
    });

    // Step 5: If Ready peers exist, wait for first PeerConnected, then preload KELs via HTTP
    if has_ready_peers {
        info!("Waiting for first peer connection...");
        match tokio::time::timeout(Duration::from_secs(60), peer_connected_rx).await {
            Ok(Ok(())) => {
                info!("First peer connected — preloading KELs, SAD objects, and SAD records...");
                if let Err(e) = bootstrap.preload_kels().await {
                    error!("KEL preload failed: {}", e);
                }
                if let Err(e) = bootstrap.preload_sad_objects().await {
                    error!("SAD object preload failed: {}", e);
                }
                if let Err(e) = bootstrap.preload_sad_records().await {
                    error!("SAD record preload failed: {}", e);
                }
            }
            Ok(Err(_)) => {
                warn!("Sync handler dropped peer_connected sender before signaling");
            }
            Err(_) => {
                warn!("Timeout waiting for peer connection");
            }
        }
    } else {
        info!("No ready peers - skipping connection wait");
    }

    // Step 6: Mark Ready
    *ready_state.write().await = true;
    info!("Bootstrap complete - node is ready");

    // Publish ready state to Redis for KELS service to read
    if let Ok(redis_client) = redis::Client::open(config.redis_url.as_str())
        && let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await
    {
        if let Err(e) = conn.set::<_, _, ()>("kels:gossip:ready", "true").await {
            error!("Failed to publish ready state to Redis {}", e);
        } else {
            info!("Published ready state to Redis");
        }
    }

    // Spawn periodic anti-entropy loops (repairs silent divergence and failed gossip fetches)
    if let Some(ref redis) = redis_for_sync {
        let ae_redis = redis.clone();
        let ae_allowlist = allowlist.clone();
        let ae_kels_url = config.kels_url().clone();
        let ae_signer = registry_signer.clone();
        let ae_interval = Duration::from_secs(config.anti_entropy_interval_secs);
        tokio::spawn(async move {
            sync::run_anti_entropy_loop(
                ae_redis,
                ae_allowlist,
                ae_kels_url,
                ae_signer,
                ae_interval,
            )
            .await;
        });

        // SAD anti-entropy loop
        let sad_ae_redis = redis.clone();
        let sad_ae_allowlist = allowlist.clone();
        let sad_ae_signer = registry_signer.clone();
        let sad_ae_sadstore_url = config.sadstore_url().clone();
        let sad_ae_interval = Duration::from_secs(config.anti_entropy_interval_secs);
        tokio::spawn(async move {
            sync::run_sad_anti_entropy_loop(
                sad_ae_redis,
                sad_ae_allowlist,
                sad_ae_signer,
                sad_ae_sadstore_url,
                sad_ae_interval,
            )
            .await;
        });
    }

    // Start allowlist refresh loop
    let refresh_interval = Duration::from_secs(config.allowlist_refresh_interval_secs);
    let refresh_urls = federation_registry_urls.clone();
    let refresh_store = registry_kel_store(&gossip_repo.registry_kels);
    let refresh_node_id = config.node_id.clone();
    tokio::spawn(async move {
        allowlist::run_allowlist_refresh_loop(
            &refresh_urls,
            &refresh_store,
            allowlist,
            refresh_interval,
            &refresh_node_id,
        )
        .await;
    });

    // Wait for gossip event loop to complete OR shutdown signal
    tokio::select! {
        gossip_result = gossip_event_handle => {
            redis_handle.abort();
            sync_handle.abort();

            match gossip_result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(ServiceError::Gossip(e)),
                Err(e) => Err(ServiceError::Config(format!("Gossip task panicked: {}", e))),
            }
        }
        _ = kels_core::shutdown_signal() => {
            info!("Shutdown signal received, cleaning up...");
            let _ = gossip_instance.shutdown().await;
            gossip_handle.finished().await;
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

        let gossip_err = ServiceError::Gossip(gossip_layer::GossipError::ChannelClosed);
        assert!(gossip_err.to_string().contains("Gossip error"));

        let sync_err = ServiceError::Sync(sync::SyncError::ChannelClosed);
        assert!(sync_err.to_string().contains("Sync error"));

        let bootstrap_err =
            ServiceError::Bootstrap(bootstrap::BootstrapError::Failed("failed".to_string()));
        assert!(bootstrap_err.to_string().contains("Bootstrap error"));
    }

    #[test]
    fn test_service_error_from_gossip_error() {
        let gossip_err = gossip_layer::GossipError::ChannelClosed;
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

    #[test]
    fn test_config_missing_required() {
        // Missing base_domain
        let env = EnvValues {
            ..Default::default()
        };
        let result = Config::from_values(env);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_required_vars() {
        let env = EnvValues {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env);
        if let Ok(config) = result {
            assert_eq!(config.base_domain, "example.com");
            assert_eq!(config.kels_url(), "http://kels.example.com");
            assert_eq!(config.sadstore_url(), "http://sadstore.example.com");
        }
    }

    #[test]
    fn test_config_defaults() {
        let env = EnvValues {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env);
        if let Ok(config) = result {
            assert_eq!(config.node_id, "node-unknown");
            assert_eq!(config.kels_url(), "http://kels.example.com");
            assert_eq!(config.sadstore_url(), "http://sadstore.example.com");
            assert_eq!(config.redis_url, "redis://redis:6379");
            assert_eq!(config.hsm_url, "http://hsm");
            assert_eq!(config.allowlist_refresh_interval_secs, 60);
            assert_eq!(config.http_listen_host, "0.0.0.0");
            assert_eq!(config.http_listen_port, 80);
        }
    }

    #[test]
    fn test_config_invalid_listen_addr() {
        let env = EnvValues {
            base_domain: Some("example.com".to_string()),
            listen_addr: Some("not-a-valid-address".to_string()),
            ..Default::default()
        };

        let result = Config::from_values(env);
        assert!(result.is_err(), "Expected error but got Ok");
    }
}
