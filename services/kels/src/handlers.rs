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
    KelsError, ServerKelCache, SignedKeyEvent,
};
use std::sync::Arc;
use verifiable_storage::VersionedRepository;

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
        // Validate dual signature requirement
        if signed_event.event.requires_dual_signature() && signed_event.signatures.len() < 2 {
            return Err(ApiError::bad_request(
                "Dual signatures required for recovery event",
            ));
        }
    }

    // Get prefix from first event
    let prefix = events[0].event.prefix.clone();

    // Check if KEL is already contested (fast cache/DB check before transaction)
    if state.repo.audit_records.is_contested(&prefix).await? {
        return Err(ApiError::contested(format!(
            "KEL {} is contested and permanently frozen",
            prefix
        )));
    }

    // Begin transaction with advisory lock - serializes all operations on this prefix
    let mut tx = state
        .repo
        .key_events
        .begin_locked_transaction(&prefix)
        .await?;

    // Load existing KEL within transaction (sees latest committed state)
    let existing_events = tx.load_signed_events().await?;
    let mut kel = Kel::from_events(existing_events.clone(), true)?; // skip_verify: DB is trusted

    // Merge submitted events into KEL
    let (events_to_remove, result) = kel
        .merge(events.clone())
        .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

    // Handle merge result within transaction
    let (diverged_at, accepted, should_clear_cache) = match result {
        KelMergeResult::Verified => {
            // Normal append - just insert new events
            for signed_event in &events {
                tx.insert_signed_event(signed_event).await?;
            }
            (None, true, false)
        }
        KelMergeResult::Recovered => {
            // Recovery: archive old events, delete from DB, insert recovery events
            if !events_to_remove.is_empty() {
                let from_version = events_to_remove[0].event.version;
                let audit_record =
                    KelsAuditRecord::for_recovery(prefix.clone(), &events_to_remove)?;
                tx.insert_audit_record(&audit_record).await?;
                tx.delete_from_version(from_version).await?;
            }
            for signed_event in &events {
                tx.insert_signed_event(signed_event).await?;
            }
            (None, true, true) // Clear cache on recovery
        }
        KelMergeResult::Contested => {
            // Contest: archive old events, delete from DB, insert cnt event
            if events.len() != 1 || !events[0].event.is_contest() {
                // Rollback happens automatically when tx is dropped
                return Err(ApiError::conflict(
                    "Must submit single cnt (contest) event to freeze contested KEL",
                ));
            }
            if events_to_remove.is_empty() {
                return Err(ApiError::conflict(
                    "Merge result is contested, but no events to remove",
                ));
            }
            let from_version = events_to_remove[0].event.version;
            let audit_record = KelsAuditRecord::for_contest(prefix.clone(), &events_to_remove)?;
            tx.insert_audit_record(&audit_record).await?;
            tx.delete_from_version(from_version).await?;
            tx.insert_signed_event(&events[0]).await?;
            let said = events_to_remove[0].event.said.clone();
            (Some(said), true, true) // Clear cache on contest
        }
        KelMergeResult::Recoverable | KelMergeResult::Contestable => {
            // Divergence detected - store the divergent event to freeze the KEL
            // events_to_remove contains the divergent event that was added
            if let Some(divergent_event) = events_to_remove.first() {
                tx.insert_signed_event(divergent_event).await?;
            }
            tx.commit().await?;

            // Clear cache since KEL is now divergent
            if let Err(e) = state.kel_cache.delete(&prefix).await {
                tracing::warn!("Failed to clear cache: {}", e);
            }

            let said = events_to_remove
                .first()
                .map(|e| e.event.said.clone())
                .unwrap_or_default();
            return Ok(Json(BatchSubmitResponse {
                diverged_at: Some(said),
                accepted: true, // Event was accepted (stored), but KEL is now frozen
            }));
        }
        KelMergeResult::Frozen => {
            // KEL is already divergent - return response so client can sync
            // Get the SAID at the divergence point
            let diverged_at = kel
                .find_divergence()
                .and_then(|d| {
                    kel.events()
                        .iter()
                        .find(|e| e.event.version == d.diverged_at_version)
                        .map(|e| e.event.said.clone())
                })
                .unwrap_or_default();

            return Ok(Json(BatchSubmitResponse {
                diverged_at: Some(diverged_at),
                accepted: false, // Event was NOT stored - KEL already frozen
            }));
        }
        KelMergeResult::RecoveryProtected => {
            // Can't introduce divergence after recovery event
            return Err(ApiError::conflict(
                "Cannot submit event at this version - KEL has recovery event protecting this position.",
            ));
        }
    };

    // Commit the transaction - this releases the advisory lock
    tx.commit().await?;

    // Update cache outside transaction
    if should_clear_cache {
        if let Err(e) = state.kel_cache.delete(&prefix).await {
            tracing::warn!("Failed to clear cache: {}", e);
        }
    } else if accepted {
        // Fetch updated KEL and store in cache
        let full_kel = state.repo.key_events.get_signed_history(&prefix).await?;
        if let Err(e) = state.kel_cache.store(&prefix, &full_kel).await {
            tracing::warn!("Failed to update cache: {}", e);
        }
    }

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

/// Get KEL events since a given timestamp (for incremental client updates).
///
/// Returns only events with created_at > since_timestamp.
/// The timestamp should be in RFC3339/ISO8601 format (e.g., "2024-01-15T10:30:00Z").
/// This enables efficient client-side caching with differential sync.
///
/// Note: Timestamp-based queries ensure divergent events at earlier versions
/// are still returned if they were created after the client's last sync.
pub async fn get_kel_since(
    State(state): State<Arc<AppState>>,
    Path((prefix, since_timestamp)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    use chrono::{DateTime, Utc};
    use verifiable_storage::StorageDatetime;

    // Parse the timestamp (RFC3339/ISO8601 format)
    let chrono_dt: DateTime<Utc> = DateTime::parse_from_rfc3339(&since_timestamp)
        .map_err(|e| ApiError::bad_request(format!("Invalid timestamp format: {}", e)))?
        .with_timezone(&Utc);
    let since_dt = StorageDatetime::from(chrono_dt);

    // Query database for events since timestamp
    let signed_events: Vec<SignedKeyEvent> = state
        .repo
        .key_events
        .get_signed_history_since(&prefix, &since_dt)
        .await?;

    // Note: We don't error if empty - an empty list means no new events since the timestamp
    Ok(Json(signed_events).into_response())
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
/// Supports incremental updates: each prefix can include a `since` timestamp
/// to only return events created after that time.
///
/// Returns a map of prefix -> KEL. Missing prefixes have empty arrays.
/// Uses parallel lookups and manual JSON concatenation for performance.
///
/// Note: Timestamp-based queries ensure divergent events at earlier versions
/// are still returned if they were created after the client's last sync.
pub async fn get_kels_batch(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BatchKelsRequest>,
) -> Result<Response, ApiError> {
    use chrono::{DateTime, Utc};
    use futures_util::future::join_all;
    use verifiable_storage::StorageDatetime;

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

                // Try cache first
                let full_kel =
                    if let Ok(Some(bytes)) = state.kel_cache.get_full_serialized(&prefix).await {
                        serde_json::from_slice(&bytes).unwrap_or_default()
                    } else {
                        // Cache miss - fetch from DB
                        let events = state.repo.key_events.get_signed_history(&prefix).await?;

                        // Store in cache
                        if !events.is_empty()
                            && let Err(e) = state.kel_cache.store(&prefix, &events).await
                        {
                            tracing::warn!("Failed to cache KEL for {}: {}", prefix, e);
                        }

                        events
                    };

                // Filter by timestamp if specified
                let events: Vec<SignedKeyEvent> = if let Some(ref dt) = since_dt {
                    full_kel
                        .into_iter()
                        .filter(|e| e.event.created_at > *dt)
                        .collect()
                } else {
                    full_kel
                };

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
