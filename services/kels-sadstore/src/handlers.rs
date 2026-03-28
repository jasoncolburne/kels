//! HTTP handlers for the SADStore service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dashmap::DashMap;
use tracing::{debug, warn};
use verifiable_storage::SelfAddressed;

use crate::{object_store::ObjectStore, repository::SadStoreRepository};

/// Shared application state.
#[allow(dead_code)]
pub struct AppState {
    pub repo: Arc<SadStoreRepository>,
    pub object_store: Arc<ObjectStore>,
    pub kels_client: kels::KelsClient,
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    pub prefix_rate_limits: DashMap<String, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
}

// === Health ===

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn ready() -> impl IntoResponse {
    (StatusCode::OK, "ready")
}

// === Layer 1: SAD Object Store (MinIO) ===

pub async fn put_sad_object(
    Path(said): Path<String>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    // HEAD check — short-circuit if already exists
    match state.object_store.exists(&said).await {
        Ok(true) => {
            debug!("SAD object already exists: {}", said);
            return (StatusCode::OK, "exists").into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!("Failed to check SAD object existence: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    }

    // Parse and verify SAID
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    if value.verify_said().is_err() {
        return (StatusCode::BAD_REQUEST, "SAID verification failed").into_response();
    }

    // Confirm URL SAID matches content SAID
    if value.get_said() != said {
        return (
            StatusCode::BAD_REQUEST,
            "URL SAID does not match content SAID",
        )
            .into_response();
    }

    // Write to MinIO
    if let Err(e) = state.object_store.put(&said, &body).await {
        warn!("Failed to store SAD object: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Publish to Redis for gossip
    if let Some(ref conn) = state.redis_conn {
        let mut conn = conn.clone();
        if let Err(e) = redis::cmd("PUBLISH")
            .arg("sad_updates")
            .arg(&said)
            .query_async::<()>(&mut conn)
            .await
        {
            warn!("Failed to publish SAD update: {}", e);
        }
    }

    (StatusCode::CREATED, "stored").into_response()
}

pub async fn get_sad_object(
    Path(said): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.object_store.get(&said).await {
        Ok(data) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            data,
        )
            .into_response(),
        Err(crate::object_store::ObjectStoreError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => {
            warn!("Failed to retrieve SAD object: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

// === Layer 2: Chain Records (Postgres) ===

pub async fn submit_sad_record(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<kels::SignedSadRecord>,
) -> impl IntoResponse {
    // TODO: Phase 4 — Verify SAID, check content exists, verify KEL signature, store
    (
        StatusCode::NOT_IMPLEMENTED,
        "Chain record submission not yet implemented",
    )
}

pub async fn get_sad_chain(
    Path(_prefix): Path<String>,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // TODO: Phase 4 — Fetch paginated chain from Postgres
    (
        StatusCode::NOT_IMPLEMENTED,
        "Chain fetch not yet implemented",
    )
}

pub async fn get_sad_effective_said(
    Path(_prefix): Path<String>,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // TODO: Phase 4 — Get tip SAID for sync comparison
    (
        StatusCode::NOT_IMPLEMENTED,
        "Effective SAID not yet implemented",
    )
}
