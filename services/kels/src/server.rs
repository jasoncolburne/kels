//! KELS HTTP Server

use axum::{
    Router,
    routing::{get, post},
};
use cacheable::create_pubsub_subscriber;
use kels::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel};
use redis::Client as RedisClient;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use verifiable_storage_postgres::RepositoryConnection;

use crate::handlers::{self, AppState};
use crate::repository::KelsRepository;

/// Create and configure the Axum router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(handlers::health))
        // Event operations
        .route("/api/kels/events", post(handlers::submit_events))
        .route("/api/kels/events/:said", get(handlers::get_event))
        // KEL operations
        .route("/api/kels/kel/:prefix", get(handlers::get_kel))
        .route(
            "/api/kels/kel/:prefix/since/:since_version",
            get(handlers::get_kel_since),
        )
        // Batch operations
        .route("/api/kels/kels", post(handlers::get_kels_batch))
        .with_state(state)
}

/// Run the HTTP server
pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/kels".to_string());

    // Connect to database
    tracing::info!("Connecting to database");
    let repo = KelsRepository::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    // Run migrations
    tracing::info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    tracing::info!("Database connected");

    // Initialize Redis connection for stream cache
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    tracing::info!("Connecting to Redis at {}", redis_url);

    let redis_client = RedisClient::open(redis_url.as_str())
        .map_err(|e| format!("Failed to create Redis client: {}", e))?;
    let redis_conn = redis::aio::ConnectionManager::new(redis_client)
        .await
        .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
    tracing::info!("Connected to Redis");

    // Create server-side KEL cache (Redis + local LRU)
    let kel_cache = ServerKelCache::new(redis_conn, "kels:kel");

    // Create app state
    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        kel_cache,
    });

    // Spawn the pub/sub subscriber task for cache sync
    let local_cache = state.kel_cache.local_cache();
    tokio::spawn(cache_sync_subscriber(redis_url.clone(), local_cache));

    // Create router
    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("KELS service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Background task that subscribes to cache update notifications
/// and invalidates local cache when SAIDs don't match
async fn cache_sync_subscriber(redis_url: String, local_cache: Arc<RwLock<LocalCache>>) {
    use futures_util::StreamExt;

    let mut pubsub = match create_pubsub_subscriber(&redis_url, pubsub_channel()).await {
        Ok(ps) => ps,
        Err(e) => {
            tracing::error!("Cache sync: {}", e);
            return;
        }
    };

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Cache sync: Failed to get message payload: {}", e);
                continue;
            }
        };

        if let Some((prefix, _version)) = parse_pubsub_message(&payload) {
            // Invalidate local cache for this prefix
            let mut cache = local_cache.write().await;
            cache.clear(prefix);
        }
    }

    tracing::warn!("Cache sync: Subscriber stream ended");
}

/// Wait for SIGTERM or SIGINT signal
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
                // Wait forever since we can't receive SIGTERM
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
