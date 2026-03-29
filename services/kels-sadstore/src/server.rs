//! KELS SADStore HTTP Server

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};
use kels::shutdown_signal;
use tracing::info;
use verifiable_storage_postgres::RepositoryConnection;

use crate::{
    handlers::{self, AppState},
    object_store::ObjectStore,
    repository::SadStoreRepository,
};

static TEST_ENDPOINTS_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("KELS_TEST_ENDPOINTS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
});

pub(crate) fn create_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        // SAD object store (Layer 1 — MinIO)
        .route("/api/v1/sad/:said", put(handlers::put_sad_object))
        .route("/api/v1/sad/:said", get(handlers::get_sad_object))
        .route("/api/v1/sad/:said/exists", get(handlers::sad_object_exists))
        // Chain records (Layer 2 — Postgres)
        .route("/api/v1/sad/records", post(handlers::submit_sad_records))
        .route("/api/v1/sad/chain/:prefix", get(handlers::get_sad_chain))
        .route(
            "/api/v1/sad/chain/:prefix/effective-said",
            get(handlers::get_sad_effective_said),
        )
        // Listing (authenticated — federation peers only)
        .route("/api/v1/sad/objects", post(handlers::list_sad_objects))
        .route("/api/v1/sad/prefixes", post(handlers::list_sad_prefixes));

    if *TEST_ENDPOINTS_ENABLED {
        tracing::warn!("KELS_TEST_ENDPOINTS enabled — unauthenticated test endpoints active");
        router = router
            .route(
                "/api/test/sad/objects",
                post(handlers::test_list_sad_objects),
            )
            .route(
                "/api/test/sad/prefixes",
                post(handlers::test_list_sad_prefixes),
            );
    }

    router
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024)) // 5 MiB
        .with_state(state)
}

pub async fn run(
    listener: tokio::net::TcpListener,
    database_url: &str,
    redis_url: Option<&str>,
    kels_url: &str,
    registry_urls: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to database");
    let repo = SadStoreRepository::connect(database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;
    info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    info!("Database connected");

    let redis_conn = if let Some(redis_url) = redis_url {
        info!("Connecting to Redis");
        let redis_client = redis::Client::open(redis_url)
            .map_err(|e| format!("Failed to create Redis client: {}", e))?;
        let conn = redis::aio::ConnectionManager::new(redis_client)
            .await
            .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
        info!("Connected to Redis");
        Some(conn)
    } else {
        info!("Running without Redis (standalone mode)");
        None
    };

    let minio_endpoint =
        std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
    let minio_region = std::env::var("MINIO_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let minio_access_key = std::env::var("MINIO_ACCESS_KEY")
        .map_err(|_| "MINIO_ACCESS_KEY must be set".to_string())?;
    let minio_secret_key = std::env::var("MINIO_SECRET_KEY")
        .map_err(|_| "MINIO_SECRET_KEY must be set".to_string())?;
    let sad_bucket = std::env::var("KELS_SAD_BUCKET").unwrap_or_else(|_| "kels-sad".to_string());

    info!("Connecting to MinIO at {}", minio_endpoint);
    let object_store = ObjectStore::new(
        &minio_endpoint,
        &minio_region,
        &sad_bucket,
        &minio_access_key,
        &minio_secret_key,
    );
    object_store
        .ensure_bucket()
        .await
        .map_err(|e| format!("Failed to ensure bucket: {}", e))?;
    info!("Object store ready (bucket: {})", sad_bucket);

    let kels_client = kels::KelsClient::new(kels_url);

    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        object_store: Arc::new(object_store),
        kels_client,
        redis_conn,
        registry_urls,
        prefix_rate_limits: dashmap::DashMap::new(),
        ip_rate_limits: dashmap::DashMap::new(),
        nonce_cache: dashmap::DashMap::new(),
    });

    handlers::spawn_rate_limit_reaper(Arc::clone(&state));

    let app = create_router(state).into_make_service_with_connect_info::<SocketAddr>();

    info!(
        "SADStore service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
