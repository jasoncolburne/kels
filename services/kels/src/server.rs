//! KELS HTTP Server

use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use cacheable::create_pubsub_subscriber;
use kels::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel, shutdown_signal};
use redis::Client as RedisClient;
use verifiable_storage_postgres::RepositoryConnection;

use crate::{
    handlers::{self, AppState},
    repository::KelsRepository,
};

pub(crate) fn create_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/api/kels/events", post(handlers::submit_events))
        .route("/api/kels/prefixes", post(handlers::list_prefixes))
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .route("/api/kels/kel/:prefix", get(handlers::get_kel))
        .route("/api/kels/kel/:prefix/audit", get(handlers::get_kel_audit))
        .route("/api/kels/events/:said/exists", get(handlers::event_exists))
        // RESOLVING ONLY — unverified, for sync comparison. See handler doc.
        .route(
            "/api/kels/kel/:prefix/effective-said",
            get(handlers::get_effective_said),
        );

    if handlers::test_endpoints_enabled() {
        tracing::warn!("KELS_TEST_ENDPOINTS enabled — unauthenticated test endpoints active");
        router = router.route("/api/test/prefixes", post(handlers::test_list_prefixes));
    }

    router
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024)) // 5 MiB
        .with_state(state)
}

pub async fn run(
    listener: tokio::net::TcpListener,
    database_url: &str,
    redis_url: Option<&str>,
    registry_urls: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to database");
    let repo = KelsRepository::connect(database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;
    info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    info!("Database connected");

    let (redis_conn, kel_cache) = if let Some(redis_url) = redis_url {
        info!("Connecting to Redis");
        let redis_client = RedisClient::open(redis_url)
            .map_err(|e| format!("Failed to create Redis client: {}", e))?;
        let conn = redis::aio::ConnectionManager::new(redis_client)
            .await
            .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
        info!("Connected to Redis");
        let cache = ServerKelCache::new(conn.clone(), "kels:kel");
        (Some(conn), Some(cache))
    } else {
        info!("Running without Redis (standalone mode)");
        (None, None)
    };

    let repo = Arc::new(repo);
    let kel_store: Arc<dyn kels::KelStore> = {
        let kel_event_repo = Arc::new(crate::repository::KeyEventRepository::new(
            repo.key_events.pool.clone(),
        ));
        Arc::new(kels::RepositoryKelStore::new(kel_event_repo))
    };
    let state = Arc::new(AppState {
        repo,
        kel_store,
        kel_cache,
        redis_conn,
        registry_urls,
        prefix_rate_limits: dashmap::DashMap::new(),
        ip_rate_limits: dashmap::DashMap::new(),
        nonce_cache: dashmap::DashMap::new(),
    });

    if let (Some(cache), Some(redis_url)) = (&state.kel_cache, redis_url) {
        let local_cache = cache.local_cache();
        tokio::spawn(cache_sync_subscriber(redis_url.to_string(), local_cache));
    }

    let app = create_router(state).into_make_service_with_connect_info::<SocketAddr>();

    info!(
        "KELS service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

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
            error!("Failed to subscribe to cache sync channel: {}", e);
            return;
        }
    };

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get cache sync message payload: {}", e);
                continue;
            }
        };

        if let Some((prefix, _said)) = parse_pubsub_message(&payload) {
            let mut cache = local_cache.write().await;
            cache.clear(prefix);
        }
    }

    warn!("Cache sync subscriber ended unexpectedly");
}
