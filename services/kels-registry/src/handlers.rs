//! KELS Registry REST API Handlers

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{Kel, Peer, PeerHistory, PeersResponse, SignedRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use verifiable_storage_postgres::{Order, Query as StorageQuery, QueryExecutor};

use crate::identity_client::IdentityClient;
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

// ==================== Peer Handlers ====================

/// Get all peers with their complete version history.
///
/// Each peer is returned with its full history in ascending order (oldest first),
/// matching KEL event ordering. Clients can verify each record's SAID and check
/// that all SAIDs are anchored in the registry's KEL.
pub async fn list_peers(
    State(repo): State<Arc<RegistryRepository>>,
) -> Result<Json<PeersResponse>, ApiError> {
    let query = StorageQuery::<Peer>::new()
        .order_by("prefix", Order::Asc)
        .order_by("version", Order::Asc);

    let all_peers: Vec<Peer> = repo
        .peers
        .pool
        .fetch(query)
        .await
        .map_err(|e| ApiError::internal_error(format!("Storage error: {}", e)))?;

    // Group into histories by prefix
    let mut histories: Vec<PeerHistory> = Vec::new();
    let mut current_prefix: Option<String> = None;
    let mut current_records: Vec<Peer> = Vec::new();

    for peer in all_peers {
        if current_prefix.as_ref() != Some(&peer.prefix) {
            if let Some(prefix) = current_prefix.take()
                && !current_records.is_empty()
            {
                histories.push(PeerHistory {
                    prefix,
                    records: std::mem::take(&mut current_records),
                });
            }
            current_prefix = Some(peer.prefix.clone());
        }
        current_records.push(peer);
    }

    // Don't forget the last history
    if let Some(prefix) = current_prefix
        && !current_records.is_empty()
    {
        histories.push(PeerHistory {
            prefix,
            records: current_records,
        });
    }

    // Filter to only include peers where the latest record is active
    let active_histories: Vec<PeerHistory> = histories
        .into_iter()
        .filter(|h| h.records.last().is_some_and(|r| r.active))
        .collect();

    Ok(Json(PeersResponse {
        peers: active_histories,
    }))
}

// ==================== Registry KEL Handlers ====================

pub struct RegistryKelState {
    pub identity_client: Arc<IdentityClient>,
    pub prefix: String,
}

/// Public endpoint for clients to verify peer records are anchored in the registry's KEL.
pub async fn get_registry_kel(
    State(state): State<Arc<RegistryKelState>>,
) -> Result<Json<Kel>, ApiError> {
    let kel = state
        .identity_client
        .get_kel()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(kel))
}
