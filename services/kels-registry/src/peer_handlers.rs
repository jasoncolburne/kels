//! Peer API handlers for the /api/peers endpoint

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use verifiable_storage_postgres::{Order, Query, QueryExecutor, StorageError};

use crate::peer::{Peer, PeerHistory};
use crate::repository::RegistryRepository;

// ==================== Error Handling ====================

#[derive(Debug, Serialize)]
pub struct PeerErrorResponse {
    pub error: String,
}

pub struct PeerApiError(pub StatusCode, pub Json<PeerErrorResponse>);

impl PeerApiError {
    #[allow(dead_code)]
    pub fn not_found(msg: impl Into<String>) -> Self {
        PeerApiError(
            StatusCode::NOT_FOUND,
            Json(PeerErrorResponse { error: msg.into() }),
        )
    }

    #[allow(dead_code)]
    pub fn bad_request(msg: impl Into<String>) -> Self {
        PeerApiError(
            StatusCode::BAD_REQUEST,
            Json(PeerErrorResponse { error: msg.into() }),
        )
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        PeerApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PeerErrorResponse { error: msg.into() }),
        )
    }
}

impl From<StorageError> for PeerApiError {
    fn from(e: StorageError) -> Self {
        PeerApiError::internal_error(format!("Storage error: {}", e))
    }
}

impl IntoResponse for PeerApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

// ==================== Response Types ====================

/// Response containing all peer histories
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersResponse {
    pub peers: Vec<PeerHistory>,
}

// ==================== Handlers ====================

/// Get all peers with their complete version history.
///
/// Each peer is returned with its full history, newest first.
/// Clients can verify each record's SAID and check that all SAIDs
/// are anchored in the registry's KEL.
pub async fn list_peers(
    State(repo): State<Arc<RegistryRepository>>,
) -> Result<Json<PeersResponse>, PeerApiError> {
    let query = Query::<Peer>::new()
        .order_by("prefix", Order::Asc)
        .order_by("version", Order::Desc);

    let all_peers: Vec<Peer> = repo.peers.pool.fetch(query).await?;

    // Group into histories by prefix
    let mut histories: Vec<PeerHistory> = Vec::new();
    let mut current_prefix: Option<String> = None;
    let mut current_records: Vec<Peer> = Vec::new();

    for peer in all_peers {
        if current_prefix.as_ref() != Some(&peer.prefix) {
            if let Some(prefix) = current_prefix.take() {
                if !current_records.is_empty() {
                    histories.push(PeerHistory {
                        prefix,
                        records: std::mem::take(&mut current_records),
                    });
                }
            }
            current_prefix = Some(peer.prefix.clone());
        }
        current_records.push(peer);
    }

    // Don't forget the last history
    if let Some(prefix) = current_prefix {
        if !current_records.is_empty() {
            histories.push(PeerHistory {
                prefix,
                records: current_records,
            });
        }
    }

    // Filter to only include peers where the latest record is active
    let active_histories: Vec<PeerHistory> = histories
        .into_iter()
        .filter(|h| h.records.first().is_some_and(|r| r.active))
        .collect();

    Ok(Json(PeersResponse {
        peers: active_histories,
    }))
}
