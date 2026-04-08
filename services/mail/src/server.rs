//! KELS Mail HTTP Server

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    routing::{get, post},
};
use kels_core::shutdown_signal;
use tracing::info;
use verifiable_storage_postgres::RepositoryConnection;

use crate::{
    blob_store::BlobStore,
    handlers::{self, AppState},
    repository::MailRepository,
};

pub(crate) fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/mail/send", post(handlers::send_mail))
        .route("/api/v1/mail/inbox", post(handlers::inbox))
        .route("/api/v1/mail/fetch", post(handlers::fetch))
        .route("/api/v1/mail/ack", post(handlers::ack))
        .route("/api/v1/mail/replicate", post(handlers::replicate))
        .route("/api/v1/mail/remove", post(handlers::remove))
        .with_state(state)
}

pub async fn run(
    listener: tokio::net::TcpListener,
    database_url: &str,
    redis_url: Option<&str>,
    kels_url: &str,
    node_prefix: &cesr::Digest,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to database");
    let repo = MailRepository::connect(database_url)
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
    let mail_bucket = std::env::var("KELS_MAIL_BUCKET").unwrap_or_else(|_| "kels-mail".to_string());

    info!("Connecting to MinIO at {}", minio_endpoint);
    let blob_store = BlobStore::new(
        &minio_endpoint,
        &minio_region,
        &mail_bucket,
        &minio_access_key,
        &minio_secret_key,
    );
    blob_store
        .ensure_bucket()
        .await
        .map_err(|e| format!("Failed to ensure bucket: {}", e))?;
    info!("Blob store ready (bucket: {})", mail_bucket);

    let kels_client = kels_core::KelsClient::new(kels_url)?;

    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        blob_store: Arc::new(blob_store),
        kels_client,
        redis_conn,
        node_prefix: *node_prefix,
        sender_rate_limits: dashmap::DashMap::new(),
        ip_rate_limits: dashmap::DashMap::new(),
        nonce_cache: dashmap::DashMap::new(),
    });

    handlers::spawn_reaper(Arc::clone(&state));

    let app = create_router(state).into_make_service_with_connect_info::<SocketAddr>();

    info!(
        "Mail service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
