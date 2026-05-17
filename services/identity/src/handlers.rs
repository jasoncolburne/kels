//! Identity Service REST API Handlers

use std::{iter, sync::Arc};
use tokio::sync::RwLock;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels_core::{
    IdentityInfo, KelsClient, KelsError, KeyEventBuilder, ManageKelRequest, ManageKelResponse,
    RepositoryKelStore, SignResponse, SignedKeyEventPage,
};
use serde::{Deserialize, Serialize};

use crate::{
    hsm::HsmKeyProvider,
    repository::{IdentityRepository, KeyEventRepository},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    pub said: cesr::Digest256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    pub event_said: cesr::Digest256,
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
    /// Populated by the reconciliation step once the node's IEL has been
    /// incepted. `None` before that (initial cold boot, mid-reconciliation).
    pub iel_prefix: RwLock<Option<cesr::Digest256>>,
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
    let kel_prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    let iel_prefix = *state.iel_prefix.read().await;

    Ok(Json(IdentityInfo {
        kel_prefix: *kel_prefix,
        iel_prefix,
    }))
}

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<kels_core::IdentityStatus>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = match builder.prefix() {
        Some(p) => *p,
        None => {
            return Ok(Json(kels_core::IdentityStatus {
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

    Ok(Json(kels_core::IdentityStatus {
        initialized: true,
        prefix: Some(prefix),
        last_said,
        current_key_handle: binding.as_ref().map(|b| b.current_key_handle.clone()),
    }))
}

/// Serving endpoint — returns paginated key events. No verification needed; the receiver verifies.
pub async fn get_key_events(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::IdentityKelPageRequest>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let builder = state.builder.read().await;
    let prefix = builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

    let limit = request
        .limit
        .unwrap_or(kels_core::page_size())
        .min(kels_core::page_size()) as u64;

    let page = kels_core::serve_kel_page(
        state.kel_repo.as_ref(),
        prefix,
        request.since.as_ref(),
        limit,
    )
    .await?;

    Ok(Json(page))
}

/// Serving endpoint — returns paginated IEL events for the node's own
/// peer-identity IEL. No verification needed; the receiver verifies.
///
/// `since` cursor is honored; `prefix` is ignored (the identity service
/// holds exactly one IEL chain — its own — so the prefix is implicit).
pub async fn get_identity_events(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::IdentityKelPageRequest>,
) -> Result<Json<kels_core::IdentityEventPage>, ApiError> {
    let iel_prefix = state.iel_prefix.read().await.ok_or_else(|| {
        ApiError::internal("Identity service has not yet reconciled its IEL")
    })?;

    // Fetch the full chain (single-author, single chain — bounded by the
    // node's authoring activity). `limit` clamps the result; `since`
    // advances the cursor by SAID.
    let chain = state
        .repo
        .iel
        .fetch_chain(&iel_prefix)
        .await
        .map_err(|e| ApiError::internal(format!("IEL fetch: {e}")))?;

    let limit = request
        .limit
        .unwrap_or(kels_core::page_size())
        .min(kels_core::page_size());

    let start = match request.since.as_ref() {
        Some(cursor) => chain
            .iter()
            .position(|e| &e.said == cursor)
            .map(|i| i + 1)
            .unwrap_or(0),
        None => 0,
    };
    let end_inclusive = start.saturating_add(limit);
    let has_more = end_inclusive < chain.len();
    let end = end_inclusive.min(chain.len());

    let page = kels_core::IdentityEventPage {
        events: if start >= chain.len() {
            Vec::new()
        } else {
            chain[start..end].to_vec()
        },
        has_more,
    };
    Ok(Json(page))
}

/// Serving endpoint — returns paginated SEL events for a given chain
/// prefix the identity service owns (peer/services or peer/gossip). No
/// verification needed; the receiver verifies.
pub async fn get_sel_events(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadEventPageRequest>,
) -> Result<Json<kels_core::SadEventPage>, ApiError> {
    let chain = state
        .repo
        .sel
        .fetch_chain(&request.prefix)
        .await
        .map_err(|e| ApiError::internal(format!("SEL fetch: {e}")))?;

    let limit = request
        .limit
        .unwrap_or(kels_core::page_size())
        .min(kels_core::page_size());

    let start = match request.since.as_ref() {
        Some(cursor) => chain
            .iter()
            .position(|e| &e.said == cursor)
            .map(|i| i + 1)
            .unwrap_or(0),
        None => 0,
    };
    let end_inclusive = start.saturating_add(limit);
    let has_more = end_inclusive < chain.len();
    let end = end_inclusive.min(chain.len());

    let page = kels_core::SadEventPage {
        events: if start >= chain.len() {
            Vec::new()
        } else {
            chain[start..end].to_vec()
        },
        has_more,
    };
    Ok(Json(page))
}

/// Serving endpoint — returns a cached SAD body by its SAID. Used at
/// gossip startup to fetch the SAD bodies the node authored (so gossip
/// can push them to sadstore before pushing the referencing SEL `Upd`
/// events).
///
/// Returns `404` if the SAD is not in the local cache (i.e. not authored
/// by this node).
pub async fn get_sad_object(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadFetchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entry = state
        .repo
        .sad_objects
        .get_by_object_said(&request.said)
        .await
        .map_err(|e| ApiError::internal(format!("SAD object fetch: {e}")))?;

    match entry {
        Some(e) => Ok(Json(e.object)),
        None => Err(ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("SAD {} not found", request.said),
            }),
        )),
    }
}

/// Best-effort forward KEL events to the colocated service (KELS or registry).
pub(crate) async fn forward_kel(state: &AppState, prefix: &cesr::Digest256) {
    let forward_url = match state.forward_url.as_ref() {
        Some(url) => url,
        None => return,
    };

    let kel_store = RepositoryKelStore::new(state.kel_repo.clone());
    let source = kels_core::StoreKelSource::new(&kel_store);
    let client = match KelsClient::with_path_prefix(forward_url, &state.forward_path_prefix) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to build KELS client for forwarding");
            return;
        }
    };
    let sink = match client.as_kel_sink() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to build HTTP sink for forwarding");
            return;
        }
    };

    match kels_core::forward_key_events(
        prefix,
        &source,
        &sink,
        kels_core::page_size(),
        kels_core::max_pages(),
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

    let prefix = *builder
        .prefix()
        .ok_or_else(|| ApiError::internal("Builder has no prefix"))?;

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
    use kels_core::KeyProvider;

    let builder = state.builder.read().await;
    let key_provider = builder.key_provider();

    let signature = key_provider
        .sign(request.data.as_bytes())
        .await
        .map_err(|e| ApiError::internal(format!("Signing failed: {}", e)))?;

    Ok(Json(SignResponse { signature }))
}

pub async fn manage_kel(
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels_core::SignedRequest<ManageKelRequest>>,
) -> Result<Json<ManageKelResponse>, ApiError> {
    let prefix = {
        let builder = state.builder.read().await;
        *builder
            .prefix()
            .ok_or_else(|| ApiError::internal("Builder has no prefix"))?
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

    let kel_verification = kels_core::completed_verification(
        &mut tx,
        &prefix,
        kels_core::page_size(),
        kels_core::max_pages(),
        iter::empty(),
    )
    .await
    .map_err(|e| ApiError::internal(format!("KEL verification failed: {}", e)))?;

    // Verify signatures and extract single signer
    let verifications = std::collections::HashMap::from([(prefix, kel_verification)]);
    let verified = signed.verify_signatures(&verifications);
    kels_core::single_signer(&verified)
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
    use cesr::test_digest;

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
        let digest = test_digest("test-anchor");
        let json = serde_json::to_string(&AnchorRequest { said: digest }).unwrap();
        let request: AnchorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.said, digest);
    }

    #[test]
    fn test_anchor_response_serialization() {
        let digest = test_digest("new-event-789");
        let response = AnchorResponse { event_said: digest };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("eventSaid")); // camelCase
        assert!(json.contains(digest.as_ref()));
    }

    #[test]
    fn test_identity_info_serialization() {
        let kel_prefix = test_digest("kel-prefix-123");
        let iel_prefix = test_digest("iel-prefix-123");
        let info = IdentityInfo {
            kel_prefix,
            iel_prefix: Some(iel_prefix),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("kelPrefix"));
        assert!(json.contains("ielPrefix"));
        assert!(json.contains(kel_prefix.as_ref()));
        assert!(json.contains(iel_prefix.as_ref()));
    }

    #[test]
    fn test_identity_info_serialization_pre_iel_inception() {
        let kel_prefix = test_digest("kel-prefix-only");
        let info = IdentityInfo {
            kel_prefix,
            iel_prefix: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("kelPrefix"));
        // iel_prefix is skip_serializing_if = None → absent on the wire.
        assert!(!json.contains("ielPrefix"));
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
        let kels_err = KelsError::NotFound("test-key".to_string());
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
            said: test_digest("said-123"),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: AnchorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(original.said, parsed.said);
    }

    #[test]
    fn test_anchor_response_roundtrip() {
        let original = AnchorResponse {
            event_said: test_digest("event-456"),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: AnchorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(original.event_said, parsed.event_said);
    }

    #[test]
    fn test_identity_info_roundtrip() {
        let original = IdentityInfo {
            kel_prefix: test_digest("kel"),
            iel_prefix: Some(test_digest("iel")),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: IdentityInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(original.kel_prefix, parsed.kel_prefix);
        assert_eq!(original.iel_prefix, parsed.iel_prefix);
    }
}
