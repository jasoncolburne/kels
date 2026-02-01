//! Identity Service REST API Handlers

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{Kel, KelsError, KeyEventBuilder};

use crate::hsm::HsmKeyProvider;
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
    pub builder: RwLock<KeyEventBuilder<HsmKeyProvider>>,
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

    let ixn = builder
        .interact(&request.said)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to create anchor event: {}", e)))?;

    tracing::info!(
        "Anchored {} in registry KEL at {}",
        request.said,
        ixn.event.said,
    );

    Ok(Json(AnchorResponse {
        event_said: ixn.event.said,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ApiError Tests ====================

    #[test]
    fn test_api_error_internal() {
        let err = ApiError::internal("Something went wrong");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.1.error, "Something went wrong");
    }

    #[test]
    fn test_api_error_internal_impl_into() {
        // Test that impl Into<String> works
        let err = ApiError::internal(format!("Error: {}", 42));
        assert_eq!(err.1.error, "Error: 42");
    }

    #[test]
    fn test_api_error_from_kels_error() {
        let kels_err = KelsError::SigningFailed("HSM unavailable".to_string());
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("HSM unavailable"));
    }

    #[test]
    fn test_api_error_from_kels_validation_error() {
        let kels_err = KelsError::InvalidSignature("bad sig".to_string());
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ==================== Request/Response Serialization Tests ====================

    #[test]
    fn test_anchor_request_deserialization() {
        let json = r#"{"said": "ESAID123456"}"#;
        let request: AnchorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.said, "ESAID123456");
    }

    #[test]
    fn test_anchor_response_serialization() {
        let response = AnchorResponse {
            event_said: "ENEWEVENT789".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("eventSaid")); // camelCase
        assert!(json.contains("ENEWEVENT789"));
    }

    #[test]
    fn test_identity_info_serialization() {
        let info = IdentityInfo {
            prefix: "EPREFIX123".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("prefix"));
        assert!(json.contains("EPREFIX123"));
    }

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "Something failed".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("Something failed"));
    }

    // ==================== health Tests ====================

    #[tokio::test]
    async fn test_health() {
        let status = health().await;
        assert_eq!(status, StatusCode::OK);
    }

    // ==================== More KelsError Conversions ====================

    #[test]
    fn test_api_error_from_kels_key_not_found() {
        let kels_err = KelsError::KeyNotFound("test-key".to_string());
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("test-key"));
    }

    #[test]
    fn test_api_error_from_kels_no_current_key() {
        let kels_err = KelsError::NoCurrentKey;
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_api_error_from_kels_hardware_error() {
        let kels_err = KelsError::HardwareError("HSM failed".to_string());
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("HSM failed"));
    }

    // ==================== Request/Response Roundtrip Tests ====================

    #[test]
    fn test_anchor_request_roundtrip() {
        let original = AnchorRequest {
            said: "ESAID123".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: AnchorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(original.said, parsed.said);
    }

    #[test]
    fn test_anchor_response_roundtrip() {
        let original = AnchorResponse {
            event_said: "EEVENT456".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: AnchorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(original.event_said, parsed.event_said);
    }

    #[test]
    fn test_identity_info_roundtrip() {
        let original = IdentityInfo {
            prefix: "EPREFIX".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: IdentityInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(original.prefix, parsed.prefix);
    }
}
