//! KELS Registry HTTP Server

use axum::{
    Router,
    routing::{get, post},
};
use kels::shutdown_signal;
use redis::Client as RedisClient;
use std::net::SocketAddr;
use std::sync::Arc;
use verifiable_storage::RepositoryConnection;

use crate::federation::{FederationConfig, FederationNode, sync::run_core_peer_sync_loop};
use crate::handlers::{self, AppState, FederationState, RegistryKelState};
use crate::identity_client::IdentityClient;
use crate::repository::RegistryRepository;
use crate::store::RegistryStore;

pub fn create_router(
    state: Arc<AppState>,
    repo: Arc<RegistryRepository>,
    registry_kel_state: Arc<RegistryKelState>,
    federation_state: Option<Arc<FederationState>>,
) -> Router {
    // Base router with health endpoint
    let base_router = Router::new().route("/health", get(handlers::health));

    // Node management routes with AppState
    let node_router = Router::new()
        .route("/api/nodes/register", post(handlers::register_node))
        .route("/api/nodes", get(handlers::list_nodes))
        .route("/api/nodes/bootstrap", get(handlers::get_bootstrap_nodes))
        .route("/api/nodes/:node_id", get(handlers::get_node))
        .route("/api/nodes/deregister", post(handlers::deregister_node))
        .route("/api/nodes/:node_id/heartbeat", post(handlers::heartbeat))
        .route("/api/nodes/status", post(handlers::update_status))
        .with_state(state);

    // Registry KEL route
    let kel_router = Router::new()
        .route("/api/registry-kel", get(handlers::get_registry_kel))
        .with_state(registry_kel_state);

    // Peer routes - different handlers based on federation mode
    let peer_router = if let Some(fed_state) = federation_state {
        // Federation mode: peers come from Raft state machine + regional DB
        Router::new()
            .route("/api/peers", get(handlers::list_peers_federated))
            .route("/api/federation/rpc", post(handlers::federation_rpc))
            .route("/api/federation/status", get(handlers::federation_status))
            .with_state(fed_state)
    } else {
        // Standalone mode: peers come from local database only
        Router::new()
            .route("/api/peers", get(handlers::list_peers))
            .with_state(repo)
    };

    // Merge all routers
    base_router
        .merge(node_router)
        .merge(kel_router)
        .merge(peer_router)
}

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let postgres_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/kels".to_string());

    let heartbeat_timeout_secs: i64 = std::env::var("HEARTBEAT_TIMEOUT_SECS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .map_err(|e| format!("HEARTBEAT_TIMEOUT_SECS must be a valid number: {}", e))?;

    tracing::info!("Connecting to Redis at {}", redis_url);
    let redis_client = RedisClient::open(redis_url.as_str())
        .map_err(|e| format!("Failed to create Redis client: {}", e))?;
    let redis_conn = redis::aio::ConnectionManager::new(redis_client)
        .await
        .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
    tracing::info!("Connected to Redis");

    tracing::info!("Connecting to PostgreSQL");
    let repo = RegistryRepository::connect(&postgres_url)
        .await
        .map_err(|e| format!("Failed to connect to PostgreSQL: {}", e))?;

    tracing::info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    tracing::info!("Database initialized");

    let repo = Arc::new(repo);
    let store = RegistryStore::new(redis_conn, "kels-registry", heartbeat_timeout_secs);
    let state = Arc::new(AppState {
        store,
        repo: repo.clone(),
    });

    // Connect to identity service to get the registry's prefix
    let identity_url =
        std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity:80".to_string());
    tracing::info!("Connecting to identity service at {}", identity_url);
    let identity_client = Arc::new(IdentityClient::new(&identity_url));

    // Fetch the registry prefix from the identity service
    let prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| format!("Failed to get registry prefix from identity service: {}", e))?;
    tracing::info!("Registry prefix from identity service: {}", prefix);

    let registry_kel_state = Arc::new(RegistryKelState {
        identity_client: identity_client.clone(),
        prefix,
    });

    // Initialize federation if configured
    let federation_state = match FederationConfig::from_env() {
        Ok(Some(config)) => {
            tracing::info!(
                "Federation configured with {} members",
                config.members.len()
            );
            match FederationNode::new(config.clone(), identity_client.clone(), &repo).await {
                Ok(node) => {
                    tracing::info!("Federation node initialized");
                    let node = Arc::new(node);

                    // Auto-initialize if this is node 0 (first member)
                    // This bootstraps the Raft cluster for leader election
                    if config.self_node_id().unwrap_or(u64::MAX) == 0 {
                        let init_node = node.clone();
                        tokio::spawn(async move {
                            // Wait for other members to start
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            tracing::info!("Initializing federation cluster (this is node 0)...");
                            if let Err(e) = init_node.initialize().await {
                                tracing::warn!(
                                    "Federation initialization: {} (may already be initialized)",
                                    e
                                );
                            } else {
                                tracing::info!("Federation cluster initialized successfully");
                            }
                        });
                    }

                    // Start the core peer sync loop
                    let sync_node = node.clone();
                    let sync_repo = repo.clone();
                    tokio::spawn(async move {
                        run_core_peer_sync_loop(
                            sync_node,
                            sync_repo,
                            std::time::Duration::from_secs(5),
                        )
                        .await;
                    });

                    Some(Arc::new(FederationState {
                        node,
                        repo: repo.clone(),
                    }))
                }
                Err(e) => {
                    tracing::error!("Failed to initialize federation node: {}", e);
                    return Err(format!("Federation initialization failed: {}", e).into());
                }
            }
        }
        Ok(None) => {
            tracing::info!("Federation not configured, running in standalone mode");
            None
        }
        Err(e) => {
            tracing::error!("Invalid federation configuration: {}", e);
            return Err(format!("Invalid federation configuration: {}", e).into());
        }
    };

    let app = create_router(state, repo, registry_kel_state, federation_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("KELS Registry service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
