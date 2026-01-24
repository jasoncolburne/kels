//! KELS Registry HTTP Server

use axum::{
    Router,
    routing::{get, post},
};
use redis::Client as RedisClient;
use std::net::SocketAddr;
use std::sync::Arc;
use verifiable_storage::RepositoryConnection;

use crate::handlers::{self, AppState};
use crate::identity_client::IdentityClient;
use crate::peer_handlers;
use crate::registry_kel_handlers::{self, RegistryKelState};
use crate::repository::RegistryRepository;
use crate::store::RegistryStore;

pub fn create_router(
    state: Arc<AppState>,
    repo: Arc<RegistryRepository>,
    registry_kel_state: Arc<RegistryKelState>,
) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/nodes/register", post(handlers::register_node))
        .route("/api/nodes", get(handlers::list_nodes))
        .route("/api/nodes/bootstrap", get(handlers::get_bootstrap_nodes))
        .route("/api/nodes/:node_id", get(handlers::get_node))
        .route("/api/nodes/deregister", post(handlers::deregister_node))
        .route("/api/nodes/:node_id/heartbeat", post(handlers::heartbeat))
        .route("/api/nodes/status", post(handlers::update_status))
        .with_state(state)
        .route("/api/peers", get(peer_handlers::list_peers))
        .with_state(repo)
        .route("/api/registry-kel", get(registry_kel_handlers::get_registry_kel))
        .with_state(registry_kel_state)
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
    let state = Arc::new(AppState { store, repo: repo.clone() });

    // Connect to identity service to get the registry's prefix
    let identity_url = std::env::var("IDENTITY_URL")
        .unwrap_or_else(|_| "http://identity:80".to_string());
    tracing::info!("Connecting to identity service at {}", identity_url);
    let identity_client = Arc::new(IdentityClient::new(&identity_url));

    // Fetch the registry prefix from the identity service
    let prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| format!("Failed to get registry prefix from identity service: {}", e))?;
    tracing::info!("Registry prefix from identity service: {}", prefix);

    let registry_kel_state = Arc::new(RegistryKelState {
        identity_client,
        prefix,
    });

    let app = create_router(state, repo, registry_kel_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("KELS Registry service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => tracing::info!("Received Ctrl+C signal"),
            Err(e) => tracing::error!("Failed to listen for Ctrl+C: {}", e),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                tracing::info!("Received SIGTERM signal");
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Starting graceful shutdown...");
}
