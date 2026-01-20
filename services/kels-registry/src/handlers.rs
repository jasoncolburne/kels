//! KELS Registry REST API Handlers

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::store::{
    NodeRegistration, RegisterNodeRequest, RegistryStore, StatusUpdateRequest, StoreError,
};

pub struct AppState {
    pub store: RegistryStore,
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

    pub fn internal_error(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: msg.into() }),
        )
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

// ==================== Query Parameters ====================

#[derive(Debug, Deserialize)]
pub struct BootstrapQuery {
    /// Node ID to exclude from bootstrap list (the caller)
    pub exclude: Option<String>,
}

// ==================== Health Check ====================

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// ==================== Node Handlers ====================

/// Register a new node or update existing registration
pub async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<NodeRegistration>, ApiError> {
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

/// Deregister a node
pub async fn deregister_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.store.deregister(&node_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List all registered nodes
pub async fn list_nodes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NodeRegistration>>, ApiError> {
    let nodes = state.store.list().await?;
    Ok(Json(nodes))
}

/// Get bootstrap nodes for a new node joining the network
pub async fn get_bootstrap_nodes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BootstrapQuery>,
) -> Result<Json<Vec<NodeRegistration>>, ApiError> {
    let nodes = state
        .store
        .get_bootstrap_nodes(query.exclude.as_deref())
        .await?;
    Ok(Json(nodes))
}

/// Heartbeat to keep node registration alive
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let registration = state.store.heartbeat(&node_id).await?;
    Ok(Json(registration))
}

/// Update node status (e.g., from Bootstrapping to Ready)
pub async fn update_status(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(request): Json<StatusUpdateRequest>,
) -> Result<Json<NodeRegistration>, ApiError> {
    let registration = state.store.update_status(&node_id, request.status).await?;
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
