//! KELS Registry REST API Handlers

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::SignedRequest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use verifiable_storage_postgres::{Order, Query as StorageQuery, QueryExecutor};

use crate::peer::Peer;
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

// ==================== Error Handling ====================

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

// ==================== Authorization ====================

/// Verify a signed request and check that the peer is in the allowlist.
///
/// Returns the peer_id on success.
async fn verify_and_authorize<T: serde::Serialize>(
    repo: &RegistryRepository,
    signed_request: &SignedRequest<T>,
) -> Result<String, ApiError> {
    // Serialize the payload to JSON for signature verification
    let payload_json = serde_json::to_vec(&signed_request.payload)
        .map_err(|e| ApiError::internal_error(format!("Failed to serialize payload: {}", e)))?;

    // Verify signature and derive peer_id
    let peer_id = signature::verify_signature(
        &payload_json,
        &signed_request.peer_id,
        &signed_request.public_key,
        &signed_request.signature,
    )?;
    let peer_id_str = peer_id.to_string();

    // Check that the peer is in the allowlist and active
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

    match peers.first() {
        Some(peer) if peer.active => Ok(peer_id_str),
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

// ==================== Query Parameters ====================

/// Maximum number of nodes allowed per page
const MAX_PAGE_SIZE: usize = 1000;
/// Default page size
const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Cursor for pagination (node_id to start after)
    pub cursor: Option<String>,
    /// Number of items per page (default: 100, max: 1000)
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
    /// Node ID to exclude from bootstrap list (the caller)
    pub exclude: Option<String>,
    /// Cursor for pagination (node_id to start after)
    pub cursor: Option<String>,
    /// Number of items per page (default: 100, max: 1000)
    pub limit: Option<usize>,
}

impl BootstrapQuery {
    fn effective_limit(&self) -> usize {
        self.limit
            .map(|l| l.min(MAX_PAGE_SIZE))
            .unwrap_or(DEFAULT_PAGE_SIZE)
    }
}

/// Paginated response for node listings
#[derive(Debug, Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeRegistration>,
    pub next_cursor: Option<String>,
}

// ==================== Health Check ====================

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// ==================== Node Handlers ====================

/// Register a new node or update existing registration.
///
/// Requires a signed request from an authorized peer.
pub async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<RegisterNodeRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    // Verify signature and check allowlist
    let _peer_id = verify_and_authorize(&state.repo, &signed_request).await?;

    let request = signed_request.payload;

    if request.node_id.is_empty() {
        return Err(ApiError::bad_request("node_id is required"));
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

/// Deregister a node.
///
/// Requires a signed request from an authorized peer.
pub async fn deregister_node(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<DeregisterRequest>>,
) -> Result<StatusCode, ApiError> {
    // Verify signature and check allowlist
    let _peer_id = verify_and_authorize(&state.repo, &signed_request).await?;

    let request = signed_request.payload;
    state.store.deregister(&request.node_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List registered nodes with pagination
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

/// Get bootstrap nodes for a new node joining the network with pagination
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

/// Heartbeat to keep node registration alive
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let registration = state.store.heartbeat(&node_id).await?;
    Ok(Json(registration))
}

/// Update node status (e.g., from Bootstrapping to Ready).
///
/// Requires a signed request from an authorized peer.
pub async fn update_status(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<StatusUpdateRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    // Verify signature and check allowlist
    let _peer_id = verify_and_authorize(&state.repo, &signed_request).await?;

    let request = signed_request.payload;
    let registration = state
        .store
        .update_status(&request.node_id, request.status)
        .await?;
    Ok(Json(registration))
}

/// Get a specific node by ID
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
