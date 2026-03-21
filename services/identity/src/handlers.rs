//! Identity Service REST API Handlers

use std::{iter, sync::Arc};
use tokio::sync::RwLock;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{
    IdentityInfo, KelsClient, KelsError, KeyEventBuilder, KeyEventsQuery, ManageKelRequest,
    ManageKelResponse, RepositoryKelStore, SignResponse, SignedKeyEventPage,
};
use serde::{Deserialize, Serialize};

use crate::{
    hsm::HsmKeyProvider,
    repository::{IdentityRepository, KeyEventRepository},
};

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
pub struct SignRequest {
    pub data: String, // JSON string to sign
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
    pub forward_url: Option<String>,
    pub forward_path_prefix: String,
    pub http_client: reqwest::Client,
}

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
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

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<kels::IdentityStatus>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = match builder.prefix() {
        Some(p) => p.to_string(),
        None => {
            return Ok(Json(kels::IdentityStatus {
                initialized: false,
                prefix: None,
                last_said: None,
                current_key_handle: None,
            }));
        }
    };

    let binding = state
        .repo
        .hsm_bindings
        .get_latest_by_kel_prefix(&prefix)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get HSM binding: {}", e)))?;

    let authority = state
        .repo
        .authority
        .get_by_name(crate::repository::AUTHORITY_IDENTITY_NAME)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get authority: {}", e)))?;

    let last_said = authority.map(|a| a.last_said);

    Ok(Json(kels::IdentityStatus {
        initialized: true,
        prefix: Some(prefix),
        last_said,
        current_key_handle: binding.as_ref().map(|b| b.current_key_handle.clone()),
    }))
}

/// Serving endpoint — returns paginated key events. No verification needed; the receiver verifies.
pub async fn get_key_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<KeyEventsQuery>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    let limit = query
        .limit
        .unwrap_or(kels::page_size())
        .min(kels::page_size()) as u64;

    let page = kels::serve_kel_page(
        state.kel_repo.as_ref(),
        prefix,
        query.since.as_deref(),
        limit,
    )
    .await?;

    Ok(Json(page))
}

/// Best-effort forward KEL events to the colocated service (KELS or registry).
pub(crate) async fn forward_kel(state: &AppState, prefix: &str) {
    let forward_url = match state.forward_url.as_ref() {
        Some(url) => url,
        None => return,
    };

    let kel_store = RepositoryKelStore::new(state.kel_repo.clone());
    let source = kels::StoreKelSource::new(&kel_store);
    let client = KelsClient::with_path_prefix(forward_url, &state.forward_path_prefix);
    let sink = client.as_kel_sink();

    match kels::forward_key_events(
        prefix,
        &source,
        &sink,
        kels::page_size(),
        kels::max_pages(),
        None,
    )
    .await
    {
        Ok(_) => tracing::debug!("Forwarded KEL to {}", forward_url),
        Err(e) => tracing::warn!("Failed to forward KEL to {}: {}", forward_url, e),
    }
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

    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?
        .to_string();

    let ixn = builder
        .interact(&request.said)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to create anchor event: {}", e)))?;

    // Release write lock before forwarding
    drop(builder);

    tracing::info!(
        "Anchored {} in identity KEL at {}",
        request.said,
        ixn.event.said,
    );

    // Best-effort forward to colocated service
    forward_kel(&state, &prefix).await;

    Ok(Json(AnchorResponse {
        event_said: ixn.event.said,
    }))
}

/// Sign arbitrary data with the registry's current signing key.
///
/// Used by federation to sign Raft RPC messages.
/// Data is a JSON string, signature is returned as QB64 (CESR).
pub async fn sign(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    use cesr::Matter;
    use kels::KeyProvider;

    let builder = state.builder.read().await;
    let key_provider = builder.key_provider();

    let signature = key_provider
        .sign(request.data.as_bytes())
        .await
        .map_err(|e| ApiError::internal(format!("Signing failed: {}", e)))?;

    Ok(Json(SignResponse {
        signature: signature.qb64(),
    }))
}

pub async fn manage_kel(
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels::SignedRequest<ManageKelRequest>>,
) -> Result<Json<ManageKelResponse>, ApiError> {
    let prefix = {
        let builder = state.builder.read().await;
        builder
            .prefix()
            .ok_or_else(|| ApiError::internal("Builder has no prefix"))?
            .to_string()
    };

    if signed.payload.prefix != prefix {
        return Err(ApiError::bad_request(format!(
            "Prefix mismatch: request has {}, identity has {}",
            signed.payload.prefix, prefix
        )));
    }

    // Consuming: verify full KEL under advisory lock (paginated)
    let mut tx = state
        .kel_repo
        .begin_locked_transaction(&prefix)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to lock prefix: {}", e)))?;

    let kel_verification = kels::completed_verification(
        &mut tx,
        &prefix,
        kels::page_size(),
        kels::max_pages(),
        iter::empty(),
    )
    .await
    .map_err(|e| ApiError::internal(format!("KEL verification failed: {}", e)))?;

    signed
        .verify_signature(&kel_verification)
        .map_err(|e| ApiError::bad_request(format!("Signature verification failed: {}", e)))?;

    // Release advisory lock. This creates a brief window where the lock is not held,
    // but the gap is safe:
    // - The signature check above only answers "was this request signed by a valid key?"
    //   which doesn't go stale even if the KEL changes.
    // - perform_kel_operation re-verifies new events against the current KEL state via
    //   save_with_merge (which acquires its own advisory lock).
    // - The builder's RwLock serializes perform_kel_operation calls within the process.
    // - The identity service is the sole writer to its own prefix.
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to commit: {}", e)))?;

    let response = crate::server::perform_kel_operation(&state, &signed.payload.operation)
        .await
        .map_err(|e| ApiError::internal(format!("Operation failed: {}", e)))?;

    Ok(Json(response))
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
        let kels_err = KelsError::EventNotFound("test-key".to_string());
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
