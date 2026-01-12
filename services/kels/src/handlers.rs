//! KELS REST API Handlers
//!
//! Provides endpoints for storing and retrieving key events.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cesr::{Matter, Signature};
use kels::{
    BatchKelsRequest, BatchSubmitResponse, ErrorResponse, Kel, KelMergeResult, KelsAuditRecord,
    KelsError, SerializedKel, ServerKelCache, SignedKeyEvent,
};
use std::sync::Arc;
use verifiable_storage::{UnversionedRepository, VersionedRepository};

use crate::repository::KelsRepository;

/// Response type for pre-serialized JSON bytes
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

/// Shared application state
pub struct AppState {
    pub repo: Arc<KelsRepository>,
    /// Server-side KEL cache (Redis + local LRU)
    pub kel_cache: ServerKelCache,
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

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    /// KEL is contested - both parties have revealed recovery keys (rec/ror events).
    /// This indicates recovery key compromise and the KEL is permanently frozen.
    pub fn contested(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::GONE, Json(ErrorResponse { error: msg.into() }))
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

impl From<verifiable_storage::StorageError> for ApiError {
    fn from(e: verifiable_storage::StorageError) -> Self {
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
/// starting with `icp` or `dip`. Delegation trust is verified by consumers (ADNS, vdig)
/// when they need to verify the trust chain.
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
    }

    // Get prefix from first event
    let prefix = events[0].event.prefix.clone();

    // Check if KEL is already contested
    if state.repo.audit_records.is_contested(&prefix).await? {
        return Err(ApiError::contested(format!(
            "KEL {} is contested and permanently frozen",
            prefix
        )));
    }

    // Fetch existing KEL (empty if new)
    let existing_events = state.repo.key_events.get_signed_history(&prefix).await?;
    let mut kel = Kel::from_events(existing_events, true)?; // skip_verify: DB is trusted

    // Merge submitted events into KEL
    // Returns (old_events_removed, result) - old_events_removed are adversary events to archive
    let (events_to_remove, result) = kel
        .merge(events.clone())
        .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

    let (diverged_at, accepted) = match result {
        KelMergeResult::Verified => {
            if !events_to_remove.is_empty() {
                return Err(ApiError::conflict(
                    "Event to remove but merge successful, aborting",
                ));
            }

            for signed_event in &events {
                if state
                    .repo
                    .key_events
                    .get_by_said(&signed_event.event.said)
                    .await?
                    .is_none()
                {
                    if signed_event.signatures.is_empty() {
                        return Err(ApiError::bad_request("Event missing signature"));
                    }

                    state
                        .repo
                        .key_events
                        .create_with_signatures(
                            signed_event.event.clone(),
                            signed_event.event_signatures(),
                        )
                        .await?;
                }
            }

            // Update cache with full KEL
            let full_kel = state.repo.key_events.get_signed_history(&prefix).await?;
            if let Err(e) = state.kel_cache.store(&prefix, &full_kel).await {
                tracing::warn!("Failed to update cache: {}", e);
            }
            (None, true)
        }
        KelMergeResult::Contested => {
            if events.len() != 1 {
                return Err(ApiError::conflict(
                    "Must submit single cnt (contest) event to freeze contested KEL",
                ));
            }

            if !events_to_remove.is_empty() {
                let from_version = events_to_remove[0].event.version;

                let audit_record = KelsAuditRecord::for_contest(prefix.clone(), &events_to_remove)?;
                state.repo.audit_records.insert(audit_record).await?;

                state
                    .repo
                    .key_events
                    .delete_events_from_version(&prefix, from_version)
                    .await?;
            } else {
                return Err(ApiError::conflict(
                    "Merge result is contested, but no events to remove",
                ));
            }

            for signed_event in events {
                if !signed_event.event.is_contest() {
                    return Err(ApiError::conflict(
                        "Wrong type of event to decommission contested KEL (expected cnt)",
                    ));
                }

                if state
                    .repo
                    .key_events
                    .get_by_said(&signed_event.event.said)
                    .await?
                    .is_none()
                {
                    if signed_event.signatures.is_empty() {
                        return Err(ApiError::bad_request("Event missing signature"));
                    }
                    if signed_event.event.requires_dual_signature()
                        && signed_event.signatures.len() < 2
                    {
                        return Err(ApiError::bad_request(
                            "Dual signatures required for recovery event",
                        ));
                    }

                    state
                        .repo
                        .key_events
                        .create_with_signatures(
                            signed_event.event.clone(),
                            signed_event.event_signatures(),
                        )
                        .await?;
                }
            }

            // Delete cache (contest truncates the KEL)
            if let Err(e) = state.kel_cache.delete(&prefix).await {
                tracing::warn!("Failed to delete cache on contest: {}", e);
            }

            let said = events_to_remove[0].event.said.clone();
            (Some(said), true)
        }
        KelMergeResult::Recoverable => {
            if events_to_remove.is_empty() {
                return Err(ApiError::conflict(
                    "Programmer error, recoverable with no events.",
                ));
            }

            let said = events_to_remove[0].event.said.clone();
            (Some(said), false)
        }
        KelMergeResult::Contestable => {
            if events_to_remove.is_empty() {
                return Err(ApiError::conflict(
                    "Programmer error, contestable with no events.",
                ));
            }

            let said = events_to_remove[0].event.said.clone();
            (Some(said), false)
        }
        KelMergeResult::Recovered => {
            // Handle recovery: archive old events and store new ones
            if !events_to_remove.is_empty() {
                let from_version = events_to_remove[0].event.version;

                // Archive the removed events before deletion
                let audit_record =
                    KelsAuditRecord::for_recovery(prefix.clone(), &events_to_remove)?;
                state.repo.audit_records.insert(audit_record).await?;

                // Delete events from the divergence point onwards
                state
                    .repo
                    .key_events
                    .delete_events_from_version(&prefix, from_version)
                    .await?;
            }

            // Store all new events and collect secondary signatures
            for signed_event in events {
                if state
                    .repo
                    .key_events
                    .get_by_said(&signed_event.event.said)
                    .await?
                    .is_none()
                {
                    if signed_event.signatures.is_empty() {
                        return Err(ApiError::bad_request("Event missing signature"));
                    }
                    if signed_event.event.requires_dual_signature()
                        && signed_event.signatures.len() < 2
                    {
                        return Err(ApiError::bad_request(
                            "Dual signatures required for recovery event",
                        ));
                    }

                    state
                        .repo
                        .key_events
                        .create_with_signatures(
                            signed_event.event.clone(),
                            signed_event.event_signatures(),
                        )
                        .await?;
                }
            }

            // Delete cache (recovery truncates the KEL)
            if let Err(e) = state.kel_cache.delete(&prefix).await {
                tracing::warn!("Failed to delete cache on recovery: {}", e);
            }
            (None, true)
        }
    };

    Ok(Json(BatchSubmitResponse {
        diverged_at,
        accepted,
    }))
}

/// Get the full KEL with signatures for a prefix (returns pre-serialized JSON)
pub async fn get_kel(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<Response, ApiError> {
    // Try pre-serialized cache first
    if let Ok(Some(bytes)) = state.kel_cache.get_full_serialized(&prefix).await {
        return Ok(PreSerializedJson(bytes).into_response());
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

/// Get KEL events since a given version (for incremental client updates).
///
/// Returns only events with version > since_version.
/// If since_version equals the latest version, returns an empty list.
/// This enables efficient client-side caching with differential sync.
pub async fn get_kel_since(
    State(state): State<Arc<AppState>>,
    Path((prefix, since_version)): Path<(String, u64)>,
) -> Result<Response, ApiError> {
    // Try pre-serialized cache (returns pre-serialized for recent tails)
    match state
        .kel_cache
        .get_since_serialized(&prefix, since_version)
        .await
    {
        Ok(Some(SerializedKel::Bytes(bytes))) => {
            return Ok(PreSerializedJson(bytes).into_response());
        }
        Ok(Some(SerializedKel::NeedsProcessing(events))) => {
            return Ok(Json(events).into_response());
        }
        Ok(None) => {} // Cache miss, fall through to DB
        Err(e) => tracing::warn!("Cache error for prefix {}: {}", prefix, e),
    }

    // Cache miss - query database for full KEL
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

    // Filter to events since the requested version
    let filtered: Vec<_> = signed_events
        .into_iter()
        .filter(|e| e.event.version > since_version)
        .collect();

    Ok(Json(filtered).into_response())
}

/// Get a single event by its SAID
pub async fn get_event(
    State(state): State<Arc<AppState>>,
    Path(said): Path<String>,
) -> Result<Json<SignedKeyEvent>, ApiError> {
    // We need to query DB first to get the prefix (SAID doesn't tell us the KEL prefix)
    let event = state
        .repo
        .key_events
        .get_by_said(&said)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("Event {} not found", said)))?;

    let prefix = &event.prefix;

    // Try cache first
    if let Ok(events) = state.kel_cache.get_full(prefix).await
        && !events.is_empty()
        && let Some(cached_event) = events.into_iter().find(|e| e.event.said == said)
    {
        return Ok(Json(cached_event));
    }

    // Cache miss - get full KEL from DB and populate cache
    let signed_events = state.repo.key_events.get_signed_history(prefix).await?;

    // Store in cache
    if let Err(e) = state.kel_cache.store(prefix, &signed_events).await {
        tracing::warn!("Failed to cache KEL for {}: {}", prefix, e);
    }

    // Find and return the requested event
    signed_events
        .into_iter()
        .find(|e| e.event.said == said)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("Event {} not found", said)))
}

// ==================== Batch Handlers ====================

/// Get multiple KELs in a single request.
///
/// Supports incremental updates: each prefix can include a `since` version
/// to only return events newer than the client's cached version.
///
/// Returns a map of prefix -> KEL. Missing prefixes have empty arrays.
/// Uses parallel lookups and manual JSON concatenation for performance.
pub async fn get_kels_batch(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BatchKelsRequest>,
) -> Result<Response, ApiError> {
    use futures_util::future::join_all;
    use std::collections::HashMap;

    // Build since map for filtering
    let since_map: HashMap<&str, u64> = request
        .prefixes
        .iter()
        .filter_map(|r| r.since.map(|s| (r.prefix.as_str(), s)))
        .collect();

    // Fetch all KELs in parallel
    let futures: Vec<_> = request
        .prefixes
        .iter()
        .map(|req| {
            let prefix = req.prefix.clone();
            let since_version = since_map.get(prefix.as_str()).copied();
            let state = Arc::clone(&state);

            async move {
                // Try to get pre-serialized bytes from cache
                let cached_bytes = if let Some(since) = since_version {
                    match state.kel_cache.get_since_serialized(&prefix, since).await {
                        Ok(Some(SerializedKel::Bytes(b))) => Some((*b).clone()),
                        Ok(Some(SerializedKel::NeedsProcessing(events))) => {
                            Some(serde_json::to_vec(&events).unwrap_or_else(|_| b"[]".to_vec()))
                        }
                        _ => None,
                    }
                } else {
                    match state.kel_cache.get_full_serialized(&prefix).await {
                        Ok(Some(b)) => Some((*b).clone()),
                        _ => None,
                    }
                };

                if let Some(b) = cached_bytes {
                    return Ok::<_, ApiError>((prefix, b));
                }

                // Cache miss - fetch from DB
                let full_kel = state.repo.key_events.get_signed_history(&prefix).await?;

                if full_kel.is_empty() {
                    return Ok((prefix, b"[]".to_vec()));
                }

                // Store in cache
                if let Err(e) = state.kel_cache.store(&prefix, &full_kel).await {
                    tracing::warn!("Failed to cache KEL for {}: {}", prefix, e);
                }

                // Filter by since version if specified and serialize
                let bytes = if let Some(since) = since_version {
                    let filtered: Vec<_> = full_kel
                        .into_iter()
                        .filter(|e| e.event.version > since)
                        .collect();
                    serde_json::to_vec(&filtered).unwrap_or_else(|_| b"[]".to_vec())
                } else {
                    serde_json::to_vec(&full_kel).unwrap_or_else(|_| b"[]".to_vec())
                };

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
