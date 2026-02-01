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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ApiError Tests ====================

    #[test]
    fn test_api_error_not_found() {
        let err = ApiError::not_found("test item");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1.error, "test item");
    }

    #[test]
    fn test_api_error_bad_request() {
        let err = ApiError::bad_request("invalid input");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid input");
    }

    #[test]
    fn test_api_error_unauthorized() {
        let err = ApiError::unauthorized("access denied");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1.error, "access denied");
    }

    #[test]
    fn test_api_error_forbidden() {
        let err = ApiError::forbidden("not allowed");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(err.1.error, "not allowed");
    }

    #[test]
    fn test_api_error_internal_error() {
        let err = ApiError::internal_error("server crash");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.1.error, "server crash");
    }

    // ==================== ApiError From<SignatureError> Tests ====================

    #[test]
    fn test_api_error_from_signature_peer_id_mismatch() {
        let sig_err = SignatureError::PeerIdMismatch {
            expected: "expected".to_string(),
            actual: "actual".to_string(),
        };
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::UNAUTHORIZED);
        assert!(api_err.1.error.contains("Invalid signature"));
    }

    #[test]
    fn test_api_error_from_signature_verification_failed() {
        let sig_err = SignatureError::VerificationFailed;
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(api_err.1.error, "Signature verification failed");
    }

    #[test]
    fn test_api_error_from_signature_invalid_public_key() {
        let sig_err = SignatureError::InvalidPublicKey("bad key".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
    }

    #[test]
    fn test_api_error_from_signature_invalid_signature() {
        let sig_err = SignatureError::InvalidSignature("bad sig".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
    }

    #[test]
    fn test_api_error_from_signature_invalid_peer_id() {
        let sig_err = SignatureError::InvalidPeerId("bad id".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
    }

    // ==================== ApiError From<StoreError> Tests ====================

    #[test]
    fn test_api_error_from_store_not_found() {
        let store_err = StoreError::NotFound("node-123".to_string());
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::NOT_FOUND);
        assert!(api_err.1.error.contains("Node not found: node-123"));
    }

    #[test]
    fn test_api_error_from_store_redis() {
        let redis_err = redis::RedisError::from((redis::ErrorKind::IoError, "connection failed"));
        let store_err = StoreError::Redis(redis_err);
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("Storage error"));
    }

    #[test]
    fn test_api_error_from_store_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let store_err = StoreError::Serialization(json_err);
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("Serialization error"));
    }

    // ==================== PaginationQuery Tests ====================

    #[test]
    fn test_pagination_query_effective_limit_none() {
        let query = PaginationQuery {
            cursor: None,
            limit: None,
        };
        assert_eq!(query.effective_limit(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_query_effective_limit_under_max() {
        let query = PaginationQuery {
            cursor: None,
            limit: Some(50),
        };
        assert_eq!(query.effective_limit(), 50);
    }

    #[test]
    fn test_pagination_query_effective_limit_at_max() {
        let query = PaginationQuery {
            cursor: None,
            limit: Some(MAX_PAGE_SIZE),
        };
        assert_eq!(query.effective_limit(), MAX_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_query_effective_limit_over_max() {
        let query = PaginationQuery {
            cursor: None,
            limit: Some(MAX_PAGE_SIZE + 500),
        };
        assert_eq!(query.effective_limit(), MAX_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_query_effective_limit_zero() {
        let query = PaginationQuery {
            cursor: None,
            limit: Some(0),
        };
        assert_eq!(query.effective_limit(), 0);
    }

    // ==================== BootstrapQuery Tests ====================

    #[test]
    fn test_bootstrap_query_effective_limit_none() {
        let query = BootstrapQuery {
            exclude: None,
            cursor: None,
            limit: None,
        };
        assert_eq!(query.effective_limit(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_bootstrap_query_effective_limit_under_max() {
        let query = BootstrapQuery {
            exclude: Some("node-1".to_string()),
            cursor: None,
            limit: Some(25),
        };
        assert_eq!(query.effective_limit(), 25);
    }

    #[test]
    fn test_bootstrap_query_effective_limit_over_max() {
        let query = BootstrapQuery {
            exclude: None,
            cursor: Some("cursor".to_string()),
            limit: Some(2000),
        };
        assert_eq!(query.effective_limit(), MAX_PAGE_SIZE);
    }

    // ==================== ErrorResponse Tests ====================

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "test error".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("test error"));
    }

    // ==================== NodesResponse Tests ====================

    #[test]
    fn test_nodes_response_serialization() {
        let response = NodesResponse {
            nodes: vec![],
            next_cursor: Some("next".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("nodes"));
        assert!(json.contains("next_cursor"));
        assert!(json.contains("next"));
    }

    #[test]
    fn test_nodes_response_without_cursor() {
        let response = NodesResponse {
            nodes: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("nodes"));
        assert!(json.contains("null"));
    }

    // ==================== health Tests ====================

    #[tokio::test]
    async fn test_health() {
        let status = health().await;
        assert_eq!(status, StatusCode::OK);
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_max_page_size_constant() {
        assert_eq!(MAX_PAGE_SIZE, 1000);
    }

    #[test]
    fn test_default_page_size_constant() {
        assert_eq!(DEFAULT_PAGE_SIZE, 100);
    }

    // ==================== PaginationQuery Serde Tests ====================

    #[test]
    fn test_pagination_query_deserialization_empty() {
        let json = "{}";
        let query: PaginationQuery = serde_json::from_str(json).unwrap();
        assert!(query.cursor.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_pagination_query_deserialization_full() {
        let json = r#"{"cursor": "abc", "limit": 50}"#;
        let query: PaginationQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.cursor, Some("abc".to_string()));
        assert_eq!(query.limit, Some(50));
    }

    // ==================== BootstrapQuery Serde Tests ====================

    #[test]
    fn test_bootstrap_query_deserialization_empty() {
        let json = "{}";
        let query: BootstrapQuery = serde_json::from_str(json).unwrap();
        assert!(query.exclude.is_none());
        assert!(query.cursor.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_bootstrap_query_deserialization_full() {
        let json = r#"{"exclude": "node-1", "cursor": "xyz", "limit": 25}"#;
        let query: BootstrapQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.exclude, Some("node-1".to_string()));
        assert_eq!(query.cursor, Some("xyz".to_string()));
        assert_eq!(query.limit, Some(25));
    }
}
