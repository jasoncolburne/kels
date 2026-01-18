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

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/kels/events", post(handlers::submit_events))
        .route("/api/kels/events/:said", get(handlers::get_event))
        .route("/api/kels/kel/:prefix", get(handlers::get_kel))
        .route("/api/kels/kel/:prefix/since/:since_timestamp", get(handlers::get_kel_since))
        .route("/api/kels/kels", post(handlers::get_kels_batch))
        .with_state(state)
}

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/kels".to_string());

    tracing::info!("Connecting to database");
    let repo = KelsRepository::connect(&database_url).await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;
    tracing::info!("Running migrations");
    repo.initialize().await.map_err(|e| format!("Failed to run migrations: {}", e))?;
    tracing::info!("Database connected");

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    tracing::info!("Connecting to Redis at {}", redis_url);
    let redis_client = RedisClient::open(redis_url.as_str())
        .map_err(|e| format!("Failed to create Redis client: {}", e))?;
    let redis_conn = redis::aio::ConnectionManager::new(redis_client).await
        .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
    tracing::info!("Connected to Redis");

    let kel_cache = ServerKelCache::new(redis_conn, "kels:kel");
    let state = Arc::new(AppState { repo: Arc::new(repo), kel_cache });

    let local_cache = state.kel_cache.local_cache();
    tokio::spawn(cache_sync_subscriber(redis_url.clone(), local_cache));

    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("KELS service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Subscribes to cache updates and invalidates local cache on prefix changes.
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
