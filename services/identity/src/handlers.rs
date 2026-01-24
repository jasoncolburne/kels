//! Identity Service REST API Handlers
//!
//! Provides endpoints for registry key management operations via HSM.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{Kel, KelsError, KeyEventBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::repository::{IdentityRepository, KeyEventRepository};

// ==================== API Types ====================

/// Request to anchor a SAID in the registry's KEL
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    /// The SAID to anchor
    pub said: String,
}

/// Response from anchoring a SAID
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    /// The SAID of the interaction event that was created
    pub event_said: String,
    /// The version of the interaction event
    pub event_version: u64,
}

/// Response containing identity info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    /// The registry's KEL prefix
    pub prefix: String,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

/// Shared application state
pub struct AppState {
    pub repo: Arc<IdentityRepository>,
    pub builder: RwLock<KeyEventBuilder>,
    pub kel_repo: Arc<KeyEventRepository>,
}

// ==================== Error Handling ====================

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::CONFLICT,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: msg.into() }),
        )
    }
}

impl From<KelsError> for ApiError {
    fn from(e: KelsError) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

// ==================== Health Check ====================

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// ==================== Identity Handlers ====================

/// Get current identity info
pub async fn get_identity(
    State(state): State<Arc<AppState>>,
) -> Result<Json<IdentityInfo>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    Ok(Json(IdentityInfo {
        prefix: prefix.to_string(),
    }))
}

/// Get the registry's full KEL
///
/// This fetches fresh from the database to ensure we return all events,
/// including those anchored by other processes (like the admin CLI).
pub async fn get_kel(State(state): State<Arc<AppState>>) -> Result<Json<Kel>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    // Fetch fresh from database
    let kel = state
        .kel_repo
        .get_kel(prefix)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(kel))
}

/// Anchor a SAID in the registry's KEL via an interaction event.
///
/// This creates an ixn event anchoring the given SAID.
/// The RwLock on builder ensures serialized access - only one interact() runs at a time.
pub async fn anchor(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<AnchorResponse>, ApiError> {
    // Write lock ensures exclusive access - only one anchor at a time
    let mut builder = state.builder.write().await;

    let (event, _signature) = builder
        .interact(&request.said)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to create anchor event: {}", e)))?;

    tracing::info!(
        "Anchored {} in registry KEL at version {}",
        request.said,
        event.version
    );

    Ok(Json(AnchorResponse {
        event_said: event.said,
        event_version: event.version,
    }))
}
