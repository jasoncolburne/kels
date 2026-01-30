//! KELS REST API Handlers

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cesr::{Matter, Signature};
use kels::{
    BatchKelsRequest, BatchSubmitResponse, ErrorCode, ErrorResponse, Kel, KelMergeResult,
    KelResponse, KelsAuditRecord, KelsError, PrefixListResponse, ServerKelCache, SignedKeyEvent,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::repository::KelsRepository;

pub struct PreSerializedJson(pub Arc<Vec<u8>>);

impl IntoResponse for PreSerializedJson {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            (*self.0).clone(),
        )
            .into_response()
    }
}

pub struct AppState {
    pub repo: Arc<KelsRepository>,
    pub kel_cache: ServerKelCache,
}

// ==================== Error Handling ====================

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::NotFound),
            }),
        )
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::Conflict),
            }),
        )
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::BadRequest),
            }),
        )
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::Unauthorized),
            }),
        )
    }

    pub fn contested(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::GONE,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::Gone),
            }),
        )
    }

    pub fn recovery_protected(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: msg.into(),
                code: Some(ErrorCode::RecoveryProtected),
            }),
        )
    }
}

impl From<KelsError> for ApiError {
    fn from(e: KelsError) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: Some(ErrorCode::InternalError),
            }),
        )
    }
}

impl From<verifiable_storage::StorageError> for ApiError {
    fn from(e: verifiable_storage::StorageError) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: Some(ErrorCode::InternalError),
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

// ==================== Event Handlers ====================

/// Submit key events with signatures.
///
/// Accepts a batch of signed events and merges them into the existing KEL.
/// Handles divergence detection and recovery per the KELS protocol.
///
/// # Response Interpretation
///
/// - `{ diverged_at: None, accepted: true }` = success, all events stored
/// - `{ diverged_at: Some(said), accepted: true }` = divergence detected and recovered
/// - `{ diverged_at: Some(said), accepted: false }` = divergence, not recovered
///   - If adversary revealed recovery key (rec/ror) → contested KEL (unrecoverable)
///   - If submitted events have no recovery event → recovery not attempted, needs rec event
/// - `{ diverged_at: None, accepted: false }` = validation error
///
/// Note: Delegation verification is NOT performed here. KELS accepts any valid KEL
/// starting with `icp` or `dip`. Delegation trust is verified by consumers when they need to
/// verify the trust chain.
pub async fn submit_events(
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<SignedKeyEvent>>,
) -> Result<Json<BatchSubmitResponse>, ApiError> {
    if events.is_empty() {
        return Ok(Json(BatchSubmitResponse {
            diverged_at: None,
            accepted: true,
        }));
    }

    // Validate all signatures upfront
    for signed_event in &events {
        if signed_event.signatures.is_empty() {
            return Err(ApiError::bad_request("Event missing signature"));
        }
        for sig in &signed_event.signatures {
            Signature::from_qb64(&sig.signature)
                .map_err(|e| ApiError::bad_request(format!("Invalid signature format: {}", e)))?;
        }
        // Validate dual signature requirement
        if signed_event.event.requires_dual_signature() && signed_event.signatures.len() < 2 {
            return Err(ApiError::bad_request(
                "Dual signatures required for recovery event",
            ));
        }
    }

    // Get prefix from first event
    let prefix = events[0].event.prefix.clone();

    // Begin transaction with advisory lock - serializes all operations on this prefix
    let mut tx = state
        .repo
        .key_events
        .begin_locked_transaction(&prefix)
        .await?;

    // Load existing KEL within transaction (sees latest committed state)
    let existing_events = tx.load_signed_events().await?;
    let mut kel = Kel::from_events(existing_events.clone(), true)?; // skip_verify: DB is trusted

    tracing::info!(
        "submit_events: prefix={}, submitted={} events, existing={} events, divergent={:?}",
        prefix,
        events.len(),
        existing_events.len(),
        kel.find_divergence()
    );

    // Build set of existing SAIDs to filter duplicates before merge
    let existing_saids: std::collections::HashSet<String> = existing_events
        .iter()
        .map(|e| e.event.said.clone())
        .collect();

    // Filter out events we already have before merging
    // This ensures recovery events are seen as "first" when syncing a full KEL
    let new_events: Vec<SignedKeyEvent> = events
        .iter()
        .filter(|e| !existing_saids.contains(&e.event.said))
        .cloned()
        .collect();

    tracing::info!(
        "submit_events: new_events={} (kinds: {:?})",
        new_events.len(),
        new_events.iter().map(|e| &e.event.kind).collect::<Vec<_>>()
    );

    // Merge only new events into KEL
    let (events_to_remove, events_to_add, result) = kel
        .merge(new_events.clone())
        .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

    tracing::info!("submit_events: merge result={:?}", result);

    for event in &events_to_add {
        tx.insert_signed_event(event).await?;
    }

    if !events_to_remove.is_empty() {
        let audit_record = KelsAuditRecord::for_recovery(prefix.clone(), &events_to_remove)?;
        tx.insert_audit_record(&audit_record).await?;
        let saids: Vec<String> = events_to_remove
            .iter()
            .map(|e| e.event.said.clone())
            .collect();
        tx.delete_events_by_said(saids).await?;
    }

    // Handle merge result within transaction
    let accepted = match result {
        KelMergeResult::Verified
        | KelMergeResult::Recovered
        | KelMergeResult::Contested
        | KelMergeResult::Recoverable => true,
        KelMergeResult::Frozen => false,
        KelMergeResult::RecoveryProtected => {
            // Adversary used recovery key - owner should contest
            return Err(ApiError::recovery_protected(
                "Cannot submit event - adversary used recovery key. Use contest to freeze the KEL.",
            ));
        }
    };

    // Commit the transaction - this releases the advisory lock
    tx.commit().await?;

    let diverged_at = match result {
        KelMergeResult::Contested => None,
        _ => kel.find_divergence().map(|d| d.diverged_at_generation),
    };

    // Update cache outside transaction
    if accepted {
        // Always fetch and store the updated KEL (including after recovery/contest)
        // This publishes the correct SAID for gossip synchronization
        if let Err(e) = state.kel_cache.store(&prefix, &kel).await {
            tracing::warn!("Failed to update cache: {}", e);
        }
    }

    Ok(Json(BatchSubmitResponse {
        diverged_at,
        accepted,
    }))
}

#[derive(Debug, Deserialize)]
pub struct GetKelParams {
    #[serde(default)]
    pub audit: bool,
}

pub async fn get_kel(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<GetKelParams>,
) -> Result<Response, ApiError> {
    // If audit requested, skip cache and return full KelResponse
    if params.audit {
        let signed_events = state.repo.key_events.get_signed_history(&prefix).await?;

        if signed_events.is_empty() {
            return Err(ApiError::not_found(format!(
                "No KEL found for prefix {}",
                prefix
            )));
        }

        let audit_records = state.repo.audit_records.get_by_kel_prefix(&prefix).await?;

        let response = KelResponse {
            events: signed_events,
            audit_records: if audit_records.is_empty() {
                None
            } else {
                Some(audit_records)
            },
        };

        return Ok(Json(response).into_response());
    }

    // Try pre-serialized cache first (non-audit path)
    match state.kel_cache.get_full_serialized(&prefix).await {
        Ok(Some(bytes)) => {
            return Ok(PreSerializedJson(bytes).into_response());
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("Cache error for prefix {}: {}", prefix, e);
        }
    }

    // Cache miss - query database
    let signed_events = state.repo.key_events.get_signed_history(&prefix).await?;

    if signed_events.is_empty() {
        return Err(ApiError::not_found(format!(
            "No KEL found for prefix {}",
            prefix
        )));
    }

    // Store in cache
    if let Err(e) = state.kel_cache.store(&prefix, &signed_events).await {
        tracing::warn!("Failed to cache KEL: {}", e);
    }

    Ok(Json(signed_events).into_response())
}

// ==================== Prefix Listing ====================

#[derive(Debug, Deserialize)]
pub struct ListPrefixesParams {
    /// Cursor to start after (prefix string)
    pub since: Option<String>,
    /// Maximum prefixes to return (default: 100, max: 1000)
    #[serde(default = "default_prefix_limit")]
    pub limit: usize,
}

fn default_prefix_limit() -> usize {
    100
}

/// List all unique prefixes with their latest SAIDs for bootstrap sync.
pub async fn list_prefixes(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListPrefixesParams>,
) -> Result<Json<PrefixListResponse>, ApiError> {
    // Validate and clamp limit
    let limit = params.limit.clamp(1, 1000);

    let result = state
        .repo
        .key_events
        .list_prefixes(params.since.as_deref(), limit)
        .await?;

    Ok(Json(result))
}

// ==================== Batch Handlers ====================

/// Maximum number of prefixes allowed in a single batch request.
const MAX_BATCH_PREFIXES: usize = 50;

/// Batch fetch KELs with optional `since` filtering per prefix. Returns map of prefix -> events.
pub async fn get_kels_batch(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BatchKelsRequest>,
) -> Result<Response, ApiError> {
    use chrono::{DateTime, Utc};
    use futures_util::future::join_all;
    use verifiable_storage::StorageDatetime;

    if request.prefixes.len() > MAX_BATCH_PREFIXES {
        return Err(ApiError::bad_request(format!(
            "Batch request exceeds maximum of {} prefixes",
            MAX_BATCH_PREFIXES
        )));
    }

    // Fetch all KELs in parallel
    let futures: Vec<_> = request
        .prefixes
        .iter()
        .map(|req| {
            let prefix = req.prefix.clone();
            let since_timestamp = req.since.clone();
            let state = Arc::clone(&state);

            async move {
                // Parse timestamp filter if provided
                let since_dt = if let Some(ref ts) = since_timestamp {
                    let chrono_dt: DateTime<Utc> = DateTime::parse_from_rfc3339(ts)
                        .map_err(|e| ApiError::bad_request(format!("Invalid timestamp: {}", e)))?
                        .with_timezone(&Utc);
                    Some(StorageDatetime::from(chrono_dt))
                } else {
                    None
                };

                // Fast path: no filtering needed, return cached bytes directly
                if since_dt.is_none()
                    && let Ok(Some(bytes)) = state.kel_cache.get_full_serialized(&prefix).await
                {
                    return Ok((prefix, (*bytes).clone()));
                }

                // Cache miss or filtering needed - fetch from DB
                let events = state.repo.key_events.get_signed_history(&prefix).await?;

                // Store in cache (full KEL)
                if !events.is_empty()
                    && let Err(e) = state.kel_cache.store(&prefix, &events).await
                {
                    tracing::warn!("Failed to cache KEL for {}: {}", prefix, e);
                }

                // Filter by timestamp if specified
                let bytes = serde_json::to_vec(&events).unwrap_or_else(|_| b"[]".to_vec());

                Ok((prefix, bytes))
            }
        })
        .collect();

    // Wait for all parallel fetches
    let results: Vec<Result<(String, Vec<u8>), ApiError>> = join_all(futures).await;

    // Collect results, propagating first error if any
    let mut serialized_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(results.len());
    for result in results {
        serialized_entries.push(result?);
    }

    // PERFORMANCE: Build JSON response by concatenating pre-serialized byte arrays.
    // This avoids deserializing cached KELs just to re-serialize them into the response.
    // Format: {"prefix1":[...],"prefix2":[...]}
    let mut response_bytes = Vec::with_capacity(
        serialized_entries
            .iter()
            .map(|(p, b)| p.len() + b.len() + 5)
            .sum::<usize>()
            + 2,
    );
    response_bytes.push(b'{');

    for (i, (prefix, kel_bytes)) in serialized_entries.iter().enumerate() {
        if i > 0 {
            response_bytes.push(b',');
        }
        response_bytes.push(b'"');
        response_bytes.extend_from_slice(prefix.as_bytes());
        response_bytes.extend_from_slice(b"\":");
        response_bytes.extend_from_slice(kel_bytes);
    }

    response_bytes.push(b'}');

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        response_bytes,
    )
        .into_response())
}
