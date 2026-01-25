//! KELS Registry REST API Handlers

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{Peer, SignedRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use verifiable_storage_postgres::{Order, Query as StorageQuery, QueryExecutor};
use crate::repository::RegistryRepository;
use crate::signature::{self, SignatureError};
use crate::store::{
    DeregisterRequest, NodeRegistration, RegisterNodeRequest, RegistryStore, StatusUpdateRequest,
    StoreError,
};

pub struct AppState {
    pub store: RegistryStore,
    pub repo: Arc<RegistryRepository>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::FORBIDDEN,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: msg.into() }),
        )
    }
}

impl From<SignatureError> for ApiError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::PeerIdMismatch { .. } => {
                ApiError::unauthorized(format!("Invalid signature: {}", e))
            }
            SignatureError::VerificationFailed => {
                ApiError::unauthorized("Signature verification failed")
            }
            _ => ApiError::bad_request(format!("Invalid request: {}", e)),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound(id) => ApiError::not_found(format!("Node not found: {}", id)),
            StoreError::Redis(e) => ApiError::internal_error(format!("Storage error: {}", e)),
            StoreError::Serialization(e) => {
                ApiError::internal_error(format!("Serialization error: {}", e))
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

/// Verifies signature and checks peer is in allowlist. Returns the authorized Peer.
async fn verify_and_authorize<T: serde::Serialize>(
    repo: &RegistryRepository,
    signed_request: &SignedRequest<T>,
) -> Result<Peer, ApiError> {
    let payload_json = serde_json::to_vec(&signed_request.payload)
        .map_err(|e| ApiError::internal_error(format!("Failed to serialize payload: {}", e)))?;

    let peer_id = signature::verify_signature(
        &payload_json,
        &signed_request.peer_id,
        &signed_request.public_key,
        &signed_request.signature,
    )?;
    let peer_id_str = peer_id.to_string();

    let query = StorageQuery::<Peer>::new()
        .eq("peer_id", &peer_id_str)
        .order_by("version", Order::Desc)
        .limit(1);

    let peers: Vec<Peer> = repo
        .peers
        .pool
        .fetch(query)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to query allowlist: {}", e)))?;

    match peers.into_iter().next() {
        Some(peer) if peer.active => Ok(peer),
        Some(_) => Err(ApiError::forbidden(format!(
            "Peer {} is not authorized (deactivated)",
            peer_id_str
        ))),
        None => Err(ApiError::forbidden(format!(
            "Peer {} is not in allowlist",
            peer_id_str
        ))),
    }
}

const MAX_PAGE_SIZE: usize = 1000;
const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

impl PaginationQuery {
    fn effective_limit(&self) -> usize {
        self.limit
            .map(|l| l.min(MAX_PAGE_SIZE))
            .unwrap_or(DEFAULT_PAGE_SIZE)
    }
}

#[derive(Debug, Deserialize)]
pub struct BootstrapQuery {
    pub exclude: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

impl BootstrapQuery {
    fn effective_limit(&self) -> usize {
        self.limit
            .map(|l| l.min(MAX_PAGE_SIZE))
            .unwrap_or(DEFAULT_PAGE_SIZE)
    }
}

#[derive(Debug, Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeRegistration>,
    pub next_cursor: Option<String>,
}

pub async fn health() -> StatusCode {
    StatusCode::OK
}

pub async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<RegisterNodeRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let peer = verify_and_authorize(&state.repo, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot register node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }
    if request.kels_url.is_empty() {
        return Err(ApiError::bad_request("kels_url is required"));
    }
    if request.gossip_multiaddr.is_empty() {
        return Err(ApiError::bad_request("gossip_multiaddr is required"));
    }

    let registration = state.store.register(request).await?;
    Ok(Json(registration))
}

pub async fn deregister_node(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<DeregisterRequest>>,
) -> Result<StatusCode, ApiError> {
    let peer = verify_and_authorize(&state.repo, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot deregister node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }

    state.store.deregister(&request.node_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<NodesResponse>, ApiError> {
    let limit = query.effective_limit();
    let (nodes, next_cursor) = state
        .store
        .list_paginated(query.cursor.as_deref(), limit)
        .await?;
    Ok(Json(NodesResponse { nodes, next_cursor }))
}

pub async fn get_bootstrap_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BootstrapQuery>,
) -> Result<Json<NodesResponse>, ApiError> {
    let limit = query.effective_limit();
    let (nodes, next_cursor) = state
        .store
        .get_bootstrap_nodes_paginated(query.exclude.as_deref(), query.cursor.as_deref(), limit)
        .await?;
    Ok(Json(NodesResponse { nodes, next_cursor }))
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let registration = state.store.heartbeat(&node_id).await?;
    Ok(Json(registration))
}

pub async fn update_status(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<StatusUpdateRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let peer = verify_and_authorize(&state.repo, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot update status for node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }

    let registration = state
        .store
        .update_status(&request.node_id, request.status)
        .await?;
    Ok(Json(registration))
}

pub async fn get_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let registration = state
        .store
        .get(&node_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Node not found: {}", node_id)))?;
    Ok(Json(registration))
}
