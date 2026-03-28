//! HTTP handlers for the SADStore service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dashmap::DashMap;

use crate::repository::SadStoreRepository;

/// Shared application state.
#[allow(dead_code)]
pub struct AppState {
    pub repo: Arc<SadStoreRepository>,
    pub kels_client: kels::KelsClient,
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    pub prefix_rate_limits: DashMap<String, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
}

// === Health ===

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Ready if database is connected (repo exists) and optionally Redis
    if state.redis_conn.is_some() {
        (StatusCode::OK, "ready")
    } else {
        // Standalone mode — always ready if we got this far
        (StatusCode::OK, "ready")
    }
}

// === Layer 1: SAD Object Store (MinIO) ===

pub async fn put_sad_object(
    Path(_said): Path<String>,
    State(_state): State<Arc<AppState>>,
    _body: String,
) -> impl IntoResponse {
    // TODO: Phase 3 — HEAD check MinIO, verify SAID, write to MinIO
    (
        StatusCode::NOT_IMPLEMENTED,
        "SAD object store not yet implemented",
    )
}

pub async fn get_sad_object(
    Path(_said): Path<String>,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // TODO: Phase 3 — Read from MinIO
    (
        StatusCode::NOT_IMPLEMENTED,
        "SAD object store not yet implemented",
    )
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
