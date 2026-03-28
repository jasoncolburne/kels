//! KELS SADStore HTTP Server

use std::{net::SocketAddr, sync::Arc};

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
    repository::SadStoreRepository,
};

pub(crate) fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        // SAD object store (Layer 1 — MinIO)
        .route("/api/v1/sad/:said", put(handlers::put_sad_object))
        .route("/api/v1/sad/:said", get(handlers::get_sad_object))
        // Chain records (Layer 2 — Postgres)
        .route("/api/v1/sad/records", post(handlers::submit_sad_record))
        .route("/api/v1/sad/chain/:prefix", get(handlers::get_sad_chain))
        .route(
            "/api/v1/sad/chain/:prefix/effective-said",
            get(handlers::get_sad_effective_said),
        )
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024)) // 5 MiB
        .with_state(state)
}

pub async fn run(
    listener: tokio::net::TcpListener,
    database_url: &str,
    redis_url: Option<&str>,
    kels_url: &str,
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

    let kels_client = kels::KelsClient::new(kels_url);

    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        kels_client,
        redis_conn,
        prefix_rate_limits: dashmap::DashMap::new(),
        ip_rate_limits: dashmap::DashMap::new(),
    });

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
