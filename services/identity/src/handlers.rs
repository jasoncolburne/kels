//! Identity Service REST API Handlers

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    pub said: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    pub event_said: String,
    pub event_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

pub struct AppState {
    pub repo: Arc<IdentityRepository>,
    pub builder: RwLock<KeyEventBuilder>,
    pub kel_repo: Arc<KeyEventRepository>,
}

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
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

pub async fn health() -> StatusCode {
    StatusCode::OK
}

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

/// Fetches fresh from the database to include events anchored by other processes.
pub async fn get_kel(State(state): State<Arc<AppState>>) -> Result<Json<Kel>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    let kel = state
        .kel_repo
        .get_kel(prefix)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(kel))
}

/// The RwLock on builder ensures only one anchor operation runs at a time.
pub async fn anchor(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<AnchorResponse>, ApiError> {
    let mut builder = state.builder.write().await;

    // Reload KEL from database in case it was modified externally (e.g., by identity-admin CLI)
    builder
        .reload()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to reload KEL: {}", e)))?;

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
