//! KELS REST API Handlers

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cesr::{Matter, Signature};
use dashmap::DashMap;
use futures_util::future::join_all;
use kels::{
    BatchKelsRequest, BatchSubmitResponse, BranchTip, ErrorCode, ErrorResponse, KelMergeResult,
    KelVerifier, KelsAuditRecord, KelsError, KeyEventsQuery, MAX_BATCH_PREFIXES,
    MAX_CACHED_KEL_EVENTS, MAX_EVENTS_PER_KEL_QUERY, MAX_EVENTS_PER_KEL_RESPONSE,
    MAX_EVENTS_PER_SUBMISSION, PrefixListResponse, ServerKelCache, SignedKeyEvent,
    SignedKeyEventPage, Verification,
};
use std::{
    collections::HashSet,
    iter, slice,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

use crate::repository::KelsRepository;

/// Maximum submissions per prefix per minute (sliding window).
const MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE: u32 = 32;

/// Maximum write requests per IP per second (token bucket: refill rate).
const MAX_WRITES_PER_IP_PER_SECOND: u32 = 200;

/// Burst capacity for per-IP write rate limiting.
const IP_RATE_LIMIT_BURST: u32 = 1000;

/// Nonce expiry window in seconds (matches the timestamp validation window).
#[cfg(not(feature = "dev-tools"))]
const NONCE_WINDOW_SECS: u64 = 60;

pub(crate) struct AppState {
    pub(crate) repo: Arc<KelsRepository>,
    #[cfg(not(feature = "dev-tools"))]
    pub(crate) kel_store: Arc<dyn kels::KelStore>,
    pub(crate) kel_cache: ServerKelCache,
    pub(crate) redis_conn: redis::aio::ConnectionManager,
    #[cfg_attr(feature = "dev-tools", allow(dead_code))]
    pub(crate) registry_urls: Vec<String>,
    /// Per-prefix rate limiting: maps prefix -> (count, window_start)
    pub(crate) prefix_rate_limits: DashMap<String, (u32, Instant)>,
    /// Per-IP write rate limiting: maps IP -> (tokens_remaining, last_refill)
    pub(crate) ip_rate_limits: DashMap<std::net::IpAddr, (u32, Instant)>,
    /// Nonce deduplication: maps nonce -> first_seen. Entries older than NONCE_WINDOW_SECS are evicted.
    #[cfg_attr(feature = "dev-tools", allow(dead_code))]
    pub(crate) nonce_cache: DashMap<String, Instant>,
}

// ==================== Error Handling ====================

pub(crate) struct ApiError(StatusCode, Json<ErrorResponse>);

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::NotFound,
            }),
        )
    }

    fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::BadRequest,
            }),
        )
    }

    fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::Unauthorized,
            }),
        )
    }

    #[cfg_attr(feature = "dev-tools", allow(dead_code))]
    fn forbidden(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::Unauthorized,
            }),
        )
    }

    #[cfg_attr(feature = "dev-tools", allow(dead_code))]
    fn internal_error(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::InternalError,
            }),
        )
    }

    fn contest_required(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::ContestRequired,
            }),
        )
    }

    fn rate_limited(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::RateLimited,
            }),
        )
    }
}

/// Per-IP write rate limiting using a token bucket.
/// Tokens refill at MAX_WRITES_PER_IP_PER_SECOND, up to IP_RATE_LIMIT_BURST.
fn check_ip_rate_limit(
    limits: &DashMap<std::net::IpAddr, (u32, Instant)>,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(ip).or_insert((IP_RATE_LIMIT_BURST, now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * MAX_WRITES_PER_IP_PER_SECOND as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(IP_RATE_LIMIT_BURST);
        entry.1 = now;
    }
    if entry.0 == 0 {
        return Err(ApiError::rate_limited("Too many requests"));
    }
    entry.0 -= 1;
    Ok(())
}

impl From<KelsError> for ApiError {
    fn from(e: KelsError) -> Self {
        let (status, code) = match &e {
            KelsError::KelDecommissioned | KelsError::Frozen => {
                (StatusCode::FORBIDDEN, ErrorCode::Frozen)
            }
            KelsError::ContestedKel(_) => (StatusCode::FORBIDDEN, ErrorCode::Contested),
            KelsError::ContestRequired => (StatusCode::FORBIDDEN, ErrorCode::ContestRequired),
            KelsError::KeyNotFound(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
            KelsError::NotIncepted => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
            KelsError::InvalidKeyEvent(_)
            | KelsError::InvalidKel(_)
            | KelsError::InvalidSaid(_) => (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
        };
        ApiError(
            status,
            Json(ErrorResponse {
                error: e.to_string(),
                code,
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
                code: ErrorCode::InternalError,
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

pub(crate) async fn health() -> StatusCode {
    StatusCode::OK
}

/// Ready response
#[derive(serde::Serialize)]
pub(crate) struct ReadyResponse {
    ready: bool,
    status: String,
}

/// Check if the node is ready by reading gossip service state from Redis.
pub(crate) async fn ready(State(state): State<Arc<AppState>>) -> (StatusCode, Json<ReadyResponse>) {
    use redis::AsyncCommands;

    let mut conn = state.redis_conn.clone();

    match conn.get::<_, Option<String>>("kels:gossip:ready").await {
        Ok(Some(status)) if status == "true" => (
            StatusCode::OK,
            Json(ReadyResponse {
                ready: true,
                status: "ready".to_string(),
            }),
        ),
        Ok(Some(status)) if status == "bootstrapping" => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                status: "bootstrapping".to_string(),
            }),
        ),
        Ok(Some(status)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                status,
            }),
        ),
        Ok(None) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                status: "unknown".to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ReadyResponse {
                ready: false,
                status: "error".to_string(),
            }),
        ),
    }
}

// ==================== Event Handlers ====================

/// Submit key events with signatures.
///
/// Accepts a batch of signed events and merges them into the existing KEL.
/// Handles divergence detection and recovery per the KELS protocol.
///
/// # Response Interpretation
///
/// - `{ diverged_at: None, applied: true }` = success, all events stored
/// - `{ diverged_at: Some(said), applied: true }` = divergence detected and recovered
/// - `{ diverged_at: Some(said), applied: false }` = divergence, not recovered
///   - If adversary revealed recovery key (rec/ror) → contested KEL (unrecoverable)
///   - If submitted events have no recovery event → recovery not attempted, needs rec event
/// - `{ diverged_at: None, applied: false }` = validation error
///
/// Note: Delegation verification is NOT performed here. KELS accepts any valid KEL
/// starting with `icp` or `dip`. Delegation trust is verified by consumers when they need to
/// verify the trust chain.
pub(crate) async fn submit_events(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(events): Json<Vec<SignedKeyEvent>>,
) -> Result<Json<BatchSubmitResponse>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;

    if events.is_empty() {
        return Ok(Json(BatchSubmitResponse {
            diverged_at: None,
            applied: true,
        }));
    }

    if events.len() > MAX_EVENTS_PER_SUBMISSION {
        return Err(ApiError::bad_request(format!(
            "Batch exceeds maximum of {} events",
            MAX_EVENTS_PER_SUBMISSION
        )));
    }

    // Get prefix from first event
    let prefix = events[0].event.prefix.clone();

    // Per-prefix rate limiting (before expensive signature validation)
    {
        let now = Instant::now();
        let mut entry = state
            .prefix_rate_limits
            .entry(prefix.clone())
            .or_insert((0, now));
        if now.duration_since(entry.1) >= Duration::from_secs(60) {
            // Reset window
            entry.0 = 1;
            entry.1 = now;
        } else {
            entry.0 += 1;
            if entry.0 > MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE {
                return Err(ApiError::rate_limited(
                    "Too many submissions for this prefix",
                ));
            }
        }
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

    // Begin transaction with advisory lock - serializes all operations on this prefix
    let mut tx = state
        .repo
        .key_events
        .begin_locked_transaction(&prefix)
        .await?;

    // Verify existing KEL (paginated, under advisory lock) to get trusted Verification
    let ctx = kels::completed_verification(
        &mut tx,
        &prefix,
        MAX_EVENTS_PER_KEL_QUERY as u64,
        kels::max_verification_pages(),
        iter::empty(),
    )
    .await
    .map_err(|e| ApiError::internal_error(format!("KEL verification failed: {}", e)))?;

    debug!(
        "submit_events: prefix={}, submitted={} events, branches={}, contested={}, diverged_at={:?}",
        prefix,
        events.len(),
        ctx.branch_tips().len(),
        ctx.is_contested(),
        ctx.diverged_at_serial(),
    );

    // Validate event structure before processing
    for signed_event in &events {
        signed_event
            .event
            .validate_structure()
            .map_err(|e| ApiError::bad_request(format!("Invalid event structure: {}", e)))?;
    }

    // Route based on verified context
    let first_previous = events[0].event.previous.clone();
    let is_normal_append = ctx.branch_tips().len() == 1
        && first_previous.as_deref() == Some(ctx.branch_tips()[0].tip.event.said.as_str())
        && !ctx.is_contested();

    // tip_said: for non-divergent results, the last inserted event's SAID.
    // Avoids the expensive compute_prefix_effective_said query (~99% of submits).
    let (result, diverged_at, tip_said) = if is_normal_append {
        // ==================== Normal Append (~99% of submissions) ====================
        if ctx.is_decommissioned() {
            return Err(ApiError::unauthorized(
                "KEL merge failed: KEL is decommissioned".to_string(),
            ));
        }
        if events[0].event.is_contest() {
            return Err(ApiError::unauthorized(
                "KEL merge failed: Contest requires divergence".to_string(),
            ));
        }

        // Resume verification from the verified context
        let mut verifier = KelVerifier::resume(&prefix, &ctx)
            .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;
        verifier
            .verify_page(&events)
            .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

        let tip = events.last().map(|e| e.event.said.clone());
        for event in &events {
            tx.insert_signed_event(event).await?;
        }

        (KelMergeResult::Accepted, None, tip)
    } else if ctx.is_empty() && first_previous.is_none() {
        // ==================== New KEL (inception) ====================
        let mut verifier = KelVerifier::new(&prefix);
        verifier
            .verify_page(&events)
            .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

        let tip = events.last().map(|e| e.event.said.clone());
        for event in &events {
            tx.insert_signed_event(event).await?;
        }

        (KelMergeResult::Accepted, None, tip)
    } else {
        // ==================== Full Path (divergence/recovery/overlap, rare) ====================
        // Bounded DB operations using the verified Verification. No full KEL in memory.
        // Advisory lock held throughout (TOCTOU-safe).

        // Contested KELs reject all submissions
        if ctx.is_contested() {
            return Err(ApiError::unauthorized(
                "KEL is already contested".to_string(),
            ));
        }

        // Filter duplicates (bounded by submission batch size)
        let submitted_saids: Vec<String> = events.iter().map(|e| e.event.said.clone()).collect();
        let existing = tx.existing_saids(&submitted_saids).await?;
        let new_events: Vec<SignedKeyEvent> = events
            .iter()
            .filter(|e| !existing.contains(&e.event.said))
            .cloned()
            .collect();

        if new_events.is_empty() {
            tx.commit().await?;
            return Ok(Json(BatchSubmitResponse {
                diverged_at: ctx.diverged_at_serial(),
                applied: true,
            }));
        }

        // Re-route after dedup based on first non-duplicate event
        let new_first_previous = new_events[0].event.previous.as_deref();

        if new_first_previous.is_none() {
            // Inception overlap with different inception — reject
            return Err(ApiError::unauthorized(
                "Inception event SAID mismatch".to_string(),
            ));
        }

        // Check if dedup turned this into a normal append
        if !ctx.is_divergent()
            && ctx.branch_tips().len() == 1
            && new_first_previous == Some(ctx.branch_tips()[0].tip.event.said.as_str())
        {
            let mut verifier = KelVerifier::resume(&prefix, &ctx)
                .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;
            verifier
                .verify_page(&new_events)
                .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;
            let tip = new_events.last().map(|e| e.event.said.clone());
            for event in &new_events {
                tx.insert_signed_event(event).await?;
            }
            (KelMergeResult::Accepted, None, tip)
        } else if ctx.is_divergent() {
            let (r, d) = handle_divergent_submission(&mut tx, &ctx, &new_events, &prefix).await?;
            (r, d, None)
        } else {
            let (r, d) = handle_overlap_submission(&mut tx, &ctx, &new_events, &prefix).await?;
            (r, d, None)
        }
    };

    // Handle merge result
    let applied = match result {
        KelMergeResult::Accepted
        | KelMergeResult::Recovered
        | KelMergeResult::Contested
        | KelMergeResult::Diverged => true,
        KelMergeResult::RecoverRequired => false,
        KelMergeResult::ContestRequired => {
            return Err(ApiError::contest_required(
                "Contest required: recovery key revealed. Use contest to freeze the KEL.",
            ));
        }
    };

    // Commit the transaction - this releases the advisory lock
    tx.commit().await?;

    // Update cache outside transaction
    if applied {
        // Rebuild cache from DB with post-commit data (bounded to cache limit).
        // This overwrites any stale cache that a concurrent GET may have populated
        // from a pre-commit DB snapshot during the commit window.
        match state
            .repo
            .key_events
            .get_signed_history(&prefix, MAX_CACHED_KEL_EVENTS as u64, 0)
            .await
        {
            Ok((events, has_more)) => {
                if !has_more {
                    if let Err(e) = state.kel_cache.store(&prefix, &events).await {
                        warn!("Failed to cache KEL: {}", e);
                    }
                } else {
                    // Too large to cache — just invalidate
                    if let Err(e) = state.kel_cache.invalidate(&prefix).await {
                        warn!("Failed to invalidate cache: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to rebuild cache for {}: {}", prefix, e);
                if let Err(e) = state.kel_cache.invalidate(&prefix).await {
                    warn!("Failed to invalidate cache: {}", e);
                }
            }
        }

        // Publish effective SAID so gossip nodes can compare it with their
        // own effective SAID for this prefix.
        // For non-divergent results we already know the tip — skip the expensive
        // compute_prefix_effective_said DB query. For divergence/recovery/contest,
        // fall back to computing from tip events.
        let effective_said = if let Some(said) = tip_said {
            Some(said)
        } else {
            match state
                .repo
                .key_events
                .compute_prefix_effective_said(&prefix)
                .await
            {
                Ok(said) => said,
                Err(e) => {
                    warn!("Failed to compute effective SAID for {}: {}", prefix, e);
                    None
                }
            }
        };
        if let Some(ref said) = effective_said
            && let Err(e) = state.kel_cache.publish_update(&prefix, said).await
        {
            warn!("Failed to publish cache update: {}", e);
        }
    }

    Ok(Json(BatchSubmitResponse {
        diverged_at,
        applied,
    }))
}

// ==================== Full merge path helpers ====================

/// Check if any event from `diverged_at` serial onward reveals the recovery key.
/// Paginated scan — never loads full KEL. Fails secure if max_pages exceeded.
async fn recovery_revealed_in_divergent_events(
    tx: &mut crate::repository::KelTransaction,
    diverged_at: u64,
) -> Result<bool, ApiError> {
    let max_pages = kels::max_verification_pages();
    let mut from_serial = diverged_at;
    for _ in 0..max_pages {
        let (page, has_more) = tx
            .get_signed_history_since(from_serial, MAX_EVENTS_PER_KEL_QUERY as u64)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        if page.is_empty() {
            return Ok(false);
        }
        if page.iter().any(|e| e.event.reveals_recovery_key()) {
            return Ok(true);
        }
        if let Some(last) = page.last() {
            from_serial = last.event.serial + 1;
        }
        if !has_more {
            return Ok(false);
        }
    }
    // Fail secure: treat as recovery revealed (most restrictive outcome)
    Err(ApiError::internal_error(
        "Scan exceeded max_pages limit — cannot determine recovery state".to_string(),
    ))
}

/// Walk backward from `start_said` collecting event SAIDs until reaching
/// an event with serial < `stop_serial`. Each step is a single bounded query.
/// Returns the set of owner event SAIDs in the divergent region.
async fn trace_chain_backward_to_serial(
    tx: &mut crate::repository::KelTransaction,
    start_said: &str,
    stop_serial: u64,
) -> Result<HashSet<String>, ApiError> {
    let mut saids = HashSet::new();
    let mut current_said = Some(start_said.to_string());

    while let Some(said) = current_said {
        let event = tx
            .get_event_by_said(&said)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        let Some(event) = event else {
            break;
        };
        if event.event.serial < stop_serial {
            break;
        }
        saids.insert(said);
        current_said = event.event.previous.clone();
    }

    Ok(saids)
}

/// Scan divergent events from `diverged_at` serial onward.
/// Returns (adversary_events, adversary_revealed_recovery).
/// Adversary events are those NOT in `owner_saids`.
/// Fails secure if max_pages exceeded.
async fn scan_divergent_events(
    tx: &mut crate::repository::KelTransaction,
    diverged_at: u64,
    owner_saids: &HashSet<String>,
) -> Result<(Vec<SignedKeyEvent>, bool), ApiError> {
    let max_pages = kels::max_verification_pages();
    let mut adversary = Vec::new();
    let mut revealed = false;
    let mut from_serial = diverged_at;
    for _ in 0..max_pages {
        let (page, has_more) = tx
            .get_signed_history_since(from_serial, MAX_EVENTS_PER_KEL_QUERY as u64)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        if page.is_empty() {
            return Ok((adversary, revealed));
        }
        for event in &page {
            if !owner_saids.contains(&event.event.said) {
                if event.event.reveals_recovery_key() {
                    revealed = true;
                }
                adversary.push(event.clone());
            }
        }
        if let Some(last) = page.last() {
            from_serial = last.event.serial + 1;
        }
        if !has_more {
            return Ok((adversary, revealed));
        }
    }
    Err(ApiError::internal_error(
        "Scan exceeded max_pages limit — cannot scan divergent events".to_string(),
    ))
}

/// Walk backward from `start_said` following `previous` pointers until finding
/// an establishment event. Returns the establishment event on the same branch.
async fn trace_establishment_backward(
    tx: &mut crate::repository::KelTransaction,
    start_said: &str,
) -> Result<SignedKeyEvent, ApiError> {
    let mut current_said = Some(start_said.to_string());

    while let Some(said) = current_said {
        let event = tx
            .get_event_by_said(&said)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?
            .ok_or_else(|| {
                ApiError::internal_error(format!(
                    "Broken chain: event {} not found during establishment trace",
                    said,
                ))
            })?;
        if event.event.is_establishment() {
            return Ok(event);
        }
        current_said = event.event.previous.clone();
    }

    Err(ApiError::internal_error(
        "No establishment event found on branch".to_string(),
    ))
}

/// Verify a sub-chain from serial 0 up to (but not including) `stop_serial`.
/// Uses paginated reads under the advisory lock. Returns the `KelVerifier` state
/// after processing events before `stop_serial` — divergence in the sub-chain is
/// expected and allowed. Fails secure if max_pages exceeded.
async fn verify_chain_before_serial(
    tx: &mut crate::repository::KelTransaction,
    prefix: &str,
    stop_serial: u64,
) -> Result<KelVerifier, ApiError> {
    let max_pages = kels::max_verification_pages();
    let mut verifier = KelVerifier::new(prefix);
    let mut from_serial: u64 = 0;
    let page_size = MAX_EVENTS_PER_KEL_QUERY as u64;

    for _ in 0..max_pages {
        let (page, has_more) = tx
            .get_signed_history_since(from_serial, page_size)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        if page.is_empty() {
            return Ok(verifier);
        }

        // Only include events before stop_serial
        let filtered: Vec<&SignedKeyEvent> = page
            .iter()
            .filter(|e| e.event.serial < stop_serial)
            .collect();
        if filtered.is_empty() {
            return Ok(verifier);
        }

        // Build a contiguous slice for verify_page by collecting clones
        let to_verify: Vec<SignedKeyEvent> = filtered.into_iter().cloned().collect();
        verifier
            .verify_page(&to_verify)
            .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;

        // If any event in this page was at or past stop_serial, we're done
        if page.last().is_some_and(|e| e.event.serial >= stop_serial) {
            return Ok(verifier);
        }
        if let Some(last) = page.last() {
            from_serial = last.event.serial + 1;
        }
        if !has_more {
            return Ok(verifier);
        }
    }

    Err(ApiError::internal_error(
        "Scan exceeded max_pages limit — cannot verify sub-chain".to_string(),
    ))
}

/// Check if any non-contest event at or after `from_serial` reveals the recovery key.
/// Fails secure if max_pages exceeded.
async fn non_contest_recovery_revealed_since(
    tx: &mut crate::repository::KelTransaction,
    from_serial: u64,
) -> Result<bool, ApiError> {
    let max_pages = kels::max_verification_pages();
    let mut serial = from_serial;
    for _ in 0..max_pages {
        let (page, has_more) = tx
            .get_signed_history_since(serial, MAX_EVENTS_PER_KEL_QUERY as u64)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        if page.is_empty() {
            return Ok(false);
        }
        if page
            .iter()
            .any(|e| e.event.reveals_recovery_key() && !e.event.is_contest())
        {
            return Ok(true);
        }
        if let Some(last) = page.last() {
            serial = last.event.serial + 1;
        }
        if !has_more {
            return Ok(false);
        }
    }
    // Fail secure: treat as recovery revealed (most restrictive outcome)
    Err(ApiError::internal_error(
        "Scan exceeded max_pages limit — cannot determine recovery state".to_string(),
    ))
}

/// Handle submission to an already-divergent KEL.
/// Returns (merge_result, diverged_at).
async fn handle_divergent_submission(
    tx: &mut crate::repository::KelTransaction,
    ctx: &Verification,
    new_events: &[SignedKeyEvent],
    prefix: &str,
) -> Result<(KelMergeResult, Option<u64>), ApiError> {
    let Some(diverged_at) = ctx.diverged_at_serial() else {
        return Err(ApiError::internal_error(
            "Divergent KEL missing diverged_at_serial".to_string(),
        ));
    };

    let first = &new_events[0];

    // === Contest ===
    if first.event.is_contest() {
        if new_events.len() > 1 {
            return Err(ApiError::unauthorized(
                "Cannot append events after contest".to_string(),
            ));
        }

        // 1. Ensure not already contested (checked by caller, but be safe)
        if ctx.is_contested() {
            return Err(ApiError::unauthorized(
                "KEL is already contested".to_string(),
            ));
        }

        // 2. Ensure a non-contest recovery-revealing event exists at or after cnt.serial
        let cnt_serial = first.event.serial;
        if !non_contest_recovery_revealed_since(tx, cnt_serial).await? {
            return Err(ApiError::unauthorized(
                "KEL merge failed: KEL is frozen — no recovery key revealed".to_string(),
            ));
        }

        // 3. Verify the full chain
        let full_ctx = kels::completed_verification(
            tx,
            prefix,
            MAX_EVENTS_PER_KEL_QUERY as u64,
            kels::max_verification_pages(),
            iter::empty::<String>(),
        )
        .await
        .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;

        // 4. Confirm cnt.previous is in the KEL at cnt.serial - 1
        let contest_previous =
            first.event.previous.as_deref().ok_or_else(|| {
                ApiError::unauthorized("Contest has no previous pointer".to_string())
            })?;
        let anchor_event = tx
            .get_event_by_said(contest_previous)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?
            .ok_or_else(|| {
                ApiError::unauthorized("Contest does not extend a known event".to_string())
            })?;
        if anchor_event.event.serial != cnt_serial - 1 {
            return Err(ApiError::unauthorized(
                "Contest previous event is not at the expected serial".to_string(),
            ));
        }

        // 5. Verify the contest event against the verified chain
        let mut verifier = KelVerifier::resume(prefix, &full_ctx)
            .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;
        verifier
            .verify_page(slice::from_ref(first))
            .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

        tx.insert_signed_event(first).await?;
        return Ok((KelMergeResult::Contested, Some(diverged_at)));
    }

    // === Recovery (rec event anywhere in batch) ===
    if let Some(rec_idx) = new_events.iter().position(|e| e.event.is_recover()) {
        let pre_rec = &new_events[..rec_idx];
        let post_rec = &new_events[rec_idx..]; // includes rec itself
        let rec_event = &new_events[rec_idx];

        // Determine the first serial of submitted events
        let first_serial = new_events[0].event.serial;

        // 1. Scan from first_serial (not diverged_at) because the pre-divergence
        //    sub-chain is verified separately in step 2. If any event at or after the
        //    submission's starting serial reveals the recovery key, the adversary has
        //    demonstrated recovery-key knowledge and recovery is unsafe — contest instead.
        if recovery_revealed_in_divergent_events(tx, first_serial).await? {
            return Err(ApiError::unauthorized(
                "KEL merge failed: Contest required — recovery key revealed at or after submission serial".to_string(),
            ));
        }

        // 2. Verify the sub-chain before the first submitted serial (divergence is allowed).
        //    This ensures the DB hasn't been tampered with.
        verify_chain_before_serial(tx, prefix, first_serial).await?;

        // 3. Find the event the submitted events chain from and verify them.
        //    The owner's chain-from event may not be at a branch tip (e.g., the owner
        //    chains from below the divergence point). Look it up in the DB — we just
        //    verified the sub-chain so this is trusted.
        let first_event = if pre_rec.is_empty() {
            rec_event
        } else {
            &pre_rec[0]
        };
        let first_previous =
            first_event.event.previous.as_deref().ok_or_else(|| {
                ApiError::unauthorized("Event has no previous pointer".to_string())
            })?;

        let anchor_event = tx
            .get_event_by_said(first_previous)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?
            .ok_or_else(|| {
                ApiError::unauthorized("Recovery does not extend a known event".to_string())
            })?;
        // The anchor must be in the trusted pre-divergence chain (verified in step 2).
        // Reject if it's at or after first_serial — an attacker could craft a recovery
        // that chains from a newly-submitted event, bypassing adversary-event checks.
        if anchor_event.event.serial >= first_serial {
            return Err(ApiError::unauthorized(
                "Recovery chain-from event is not before first submitted serial".to_string(),
            ));
        }

        // Walk backward from the anchor to find the establishment event on the
        // owner's branch (not just any establishment at that serial — the adversary
        // may have rotated at the same serial on a different branch).
        let establishment = trace_establishment_backward(tx, &anchor_event.event.said).await?;
        let anchor_tip = BranchTip {
            tip: anchor_event,
            establishment_tip: establishment,
        };

        let mut event_verifier = KelVerifier::from_branch_tip(prefix, &anchor_tip)
            .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;
        event_verifier
            .verify_page(new_events)
            .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

        // Insert pre-rec events
        for event in pre_rec {
            tx.insert_signed_event(event).await?;
        }

        // 4. Walk backward from rec.previous to collect owner branch SAIDs
        let rec_previous =
            rec_event.event.previous.as_deref().ok_or_else(|| {
                ApiError::unauthorized("Recovery event has no previous".to_string())
            })?;
        let owner_saids = trace_chain_backward_to_serial(tx, rec_previous, diverged_at).await?;

        // 5. Archive adversary events (everything from diverged_at onward NOT on owner's chain)
        let (adversary_events, adversary_revealed) =
            scan_divergent_events(tx, diverged_at, &owner_saids).await?;

        // Double-check: adversary should not have revealed recovery (step 1 checked >= rec_serial,
        // but adversary events could be at earlier serials in the divergent region)
        if adversary_revealed {
            return Err(ApiError::unauthorized(
                "KEL merge failed: Contest required — adversary revealed recovery key".to_string(),
            ));
        }

        if !adversary_events.is_empty() {
            let audit_record =
                KelsAuditRecord::for_recovery(prefix.to_string(), &adversary_events)?;
            tx.insert_audit_record(&audit_record).await?;
            let saids: Vec<String> = adversary_events
                .iter()
                .map(|e| e.event.said.clone())
                .collect();
            tx.delete_events_by_said(saids).await?;
        }

        // 6. Insert rec + post-rec events
        for event in post_rec {
            tx.insert_signed_event(event).await?;
        }

        return Ok((KelMergeResult::Recovered, None));
    }

    // Neither contest nor recovery — frozen KEL rejects non-recovery submissions
    Ok((KelMergeResult::RecoverRequired, Some(diverged_at)))
}

/// Handle submission that overlaps with or creates new divergence in a non-divergent KEL.
/// Returns (merge_result, diverged_at).
async fn handle_overlap_submission(
    tx: &mut crate::repository::KelTransaction,
    ctx: &Verification,
    new_events: &[SignedKeyEvent],
    prefix: &str,
) -> Result<(KelMergeResult, Option<u64>), ApiError> {
    // Sanity: caller should only route here for non-divergent, non-contested KELs
    if ctx.is_divergent() || ctx.is_contested() {
        return Err(ApiError::internal_error(
            "handle_overlap_submission called with divergent or contested KEL".to_string(),
        ));
    }

    let first_previous = new_events[0]
        .event
        .previous
        .as_deref()
        .ok_or_else(|| ApiError::unauthorized("Inception event SAID mismatch".to_string()))?;

    // Verify the branch point exists in the DB
    let branch_point = tx
        .get_event_by_said(first_previous)
        .await
        .map_err(|e| ApiError::internal_error(e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("Events not contiguous".to_string()))?;

    let branch_serial = branch_point.event.serial;

    // No early decommissioned check here — the walk below detects recovery-key
    // revelation (dec/rec/ror/cnt) and returns ContestRequired or allows contest through.
    // The fast path (line 382) handles legitimate decommission for normal appends.

    // Get establishment state at the branch point for verification
    let establishment = tx
        .get_establishment_at_serial(branch_serial)
        .await
        .map_err(|e| ApiError::internal_error(e.to_string()))?
        .ok_or_else(|| {
            ApiError::internal_error("No establishment event found at branch point".to_string())
        })?;

    let branch_tip = BranchTip {
        tip: branch_point,
        establishment_tip: establishment,
    };

    // Verify submitted events against the branch point state
    let mut verifier = KelVerifier::from_branch_tip(prefix, &branch_tip)
        .map_err(|e| ApiError::unauthorized(format!("KEL verification failed: {}", e)))?;
    verifier
        .verify_page(new_events)
        .map_err(|e| ApiError::unauthorized(format!("KEL merge failed: {}", e)))?;

    // Collect old divergent events (existing events from branch_serial+1 onward)
    let max_pages = kels::max_verification_pages();
    let mut old_divergent_events = Vec::new();
    let mut from_serial = branch_serial + 1;
    let mut exhausted = false;
    for _ in 0..max_pages {
        let (page, has_more) = tx
            .get_signed_history_since(from_serial, MAX_EVENTS_PER_KEL_QUERY as u64)
            .await
            .map_err(|e| ApiError::internal_error(e.to_string()))?;
        if page.is_empty() {
            exhausted = true;
            break;
        }
        if let Some(last) = page.last() {
            from_serial = last.event.serial + 1;
        }
        old_divergent_events.extend(page);
        if !has_more {
            exhausted = true;
            break;
        }
    }
    if !exhausted {
        return Err(ApiError::internal_error(
            "Scan exceeded max_pages limit — cannot collect divergent events".to_string(),
        ));
    }

    // Check if old divergent events reveal recovery key
    let old_reveals_recovery = old_divergent_events
        .iter()
        .any(|e| e.event.reveals_recovery_key());

    if old_reveals_recovery {
        // Old branch (potential adversary) revealed recovery key
        let divergent_event = new_events
            .iter()
            .find(|e| e.event.previous.as_deref() == Some(first_previous))
            .ok_or_else(|| ApiError::unauthorized("Cannot find divergent event".to_string()))?;

        if divergent_event.event.is_contest() {
            if new_events.len() > 1 {
                return Err(ApiError::unauthorized(
                    "Cannot append events after contest".to_string(),
                ));
            }
            tx.insert_signed_event(divergent_event).await?;
            return Ok((KelMergeResult::Contested, Some(branch_serial + 1)));
        } else {
            return Ok((KelMergeResult::ContestRequired, None));
        }
    }

    // Check for recovery in submitted events
    if let Some(rec_idx) = new_events.iter().position(|e| e.event.is_recover()) {
        let pre_rec = &new_events[..rec_idx];
        let post_rec = &new_events[rec_idx..];
        let rec_event = &new_events[rec_idx];

        // Insert pre-rec events (extend the new branch before recovery)
        for event in pre_rec {
            tx.insert_signed_event(event).await?;
        }

        // Trace owner chain backward from rec.previous
        let rec_previous =
            rec_event.event.previous.as_deref().ok_or_else(|| {
                ApiError::unauthorized("Recovery event has no previous".to_string())
            })?;
        let owner_saids =
            trace_chain_backward_to_serial(tx, rec_previous, branch_serial + 1).await?;

        // Check if adversary (old branch) revealed recovery
        // (already checked above — old_reveals_recovery was false)
        // But re-check with owner context for correctness
        let adversary_revealed = old_divergent_events
            .iter()
            .any(|e| e.event.reveals_recovery_key() && !owner_saids.contains(&e.event.said));

        if adversary_revealed {
            return Err(ApiError::unauthorized(
                "KEL merge failed: Contest required — adversary revealed recovery key".to_string(),
            ));
        }

        // Archive adversary events (old divergent events not on owner chain)
        let adversary_events: Vec<SignedKeyEvent> = old_divergent_events
            .into_iter()
            .filter(|e| !owner_saids.contains(&e.event.said))
            .collect();

        if !adversary_events.is_empty() {
            let audit_record =
                KelsAuditRecord::for_recovery(prefix.to_string(), &adversary_events)?;
            tx.insert_audit_record(&audit_record).await?;
            let saids: Vec<String> = adversary_events
                .iter()
                .map(|e| e.event.said.clone())
                .collect();
            tx.delete_events_by_said(saids).await?;
        }

        // Insert rec + post-rec events
        for event in post_rec {
            tx.insert_signed_event(event).await?;
        }

        return Ok((KelMergeResult::Recovered, None));
    }

    // No recovery event in the batch — insert only the single forking event to
    // establish divergence and freeze the KEL. Subsequent adversary events in the
    // batch are intentionally dropped: storing more would extend the adversary's
    // branch without benefit. The owner can now submit rec or cnt to resolve.
    let divergent_event = new_events
        .iter()
        .find(|e| e.event.previous.as_deref() == Some(first_previous))
        .ok_or_else(|| ApiError::unauthorized("Cannot find divergent event".to_string()))?;

    tx.insert_signed_event(divergent_event).await?;

    Ok((KelMergeResult::Diverged, Some(branch_serial + 1)))
}

pub(crate) async fn get_kel(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<KeyEventsQuery>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let limit = params
        .limit
        .unwrap_or(MAX_EVENTS_PER_KEL_RESPONSE)
        .clamp(1, MAX_EVENTS_PER_KEL_RESPONSE) as u64;

    // Delta fetch path — canonical since-resolution
    if params.since.is_some() {
        let page = kels::serve_kel_page(
            &state.repo.key_events,
            &prefix,
            params.since.as_deref(),
            limit,
        )
        .await?;
        return Ok(Json(page));
    }

    // Full fetch path — try cache for default limit
    if limit as usize == MAX_EVENTS_PER_KEL_RESPONSE {
        match state.kel_cache.get_full_serialized(&prefix).await {
            Ok(Some(bytes)) => {
                // Cached KELs are ≤ MAX_EVENTS_PER_KEL_RESPONSE, so has_more = false
                let events: Vec<SignedKeyEvent> = serde_json::from_slice(&bytes).map_err(|e| {
                    ApiError::internal_error(format!("Cache deserialization: {}", e))
                })?;
                return Ok(Json(SignedKeyEventPage {
                    events,
                    has_more: false,
                }));
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Cache error for prefix {}: {}", prefix, e);
            }
        }
    }

    // Cache miss or non-default limit — canonical full fetch
    let page = kels::serve_kel_page(&state.repo.key_events, &prefix, None, limit).await?;

    // Store in cache (skips if too large per cache logic)
    if !page.has_more
        && let Err(e) = state.kel_cache.store(&prefix, &page.events).await
    {
        warn!("Failed to cache KEL: {}", e);
    }

    Ok(Json(page))
}

/// Dedicated audit endpoint — returns only audit records for a prefix.
pub(crate) async fn get_kel_audit(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<Json<Vec<KelsAuditRecord>>, ApiError> {
    let audit_records = state.repo.audit_records.get_by_kel_prefix(&prefix).await?;
    Ok(Json(audit_records))
}

// ==================== Event Exists ====================

pub(crate) async fn event_exists(
    State(state): State<Arc<AppState>>,
    Path(said): Path<String>,
) -> Result<StatusCode, ApiError> {
    if state.repo.key_events.event_exists_by_said(&said).await? {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ==================== Effective SAID ====================

/// Get the effective tail SAID for a specific prefix.
///
/// **RESOLVING ONLY — NOT VERIFIED.** This value is computed from unverified DB
/// state and MUST NOT be used for security decisions. Its only purpose is sync
/// comparison: if the local and remote effective SAIDs don't match, trigger a
/// sync (which itself verifies). A wrong value here causes an unnecessary sync,
/// not a security hole.
pub(crate) async fn get_effective_said(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let effective = state
        .repo
        .key_events
        .compute_prefix_effective_said(&prefix)
        .await?;

    match effective {
        Some(said) => Ok(Json(serde_json::json!({ "said": said }))),
        None => Err(ApiError::not_found(format!("Prefix {} not found", prefix))),
    }
}

// ==================== Prefix Listing ====================

/// List all unique prefixes with their latest SAIDs for bootstrap sync.
///
/// Accepts a `SignedRequest<PrefixesRequest>` via POST.
/// When the `dev-tools` feature is enabled, signature and peer verification is skipped.
pub(crate) async fn list_prefixes(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(signed_request): Json<kels::SignedRequest<kels::PrefixesRequest>>,
) -> Result<Json<PrefixListResponse>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;
    #[cfg(not(feature = "dev-tools"))]
    {
        if !kels::validate_timestamp(signed_request.payload.timestamp, 60) {
            return Err(ApiError::forbidden("Request timestamp expired"));
        }

        // Nonce deduplication: evict expired entries, then reject duplicates
        {
            let now = Instant::now();
            state.nonce_cache.retain(|_, seen| {
                now.duration_since(*seen) < Duration::from_secs(NONCE_WINDOW_SECS)
            });
            if state
                .nonce_cache
                .insert(signed_request.payload.nonce.clone(), now)
                .is_some()
            {
                return Err(ApiError::forbidden("Duplicate nonce"));
            }
        }

        // Look up peer to verify they are in the verified allowlist
        let peer = get_verified_peer(&state.redis_conn, &signed_request.peer_prefix).await?;
        let _peer = match peer {
            Some(p) => p,
            None => {
                refresh_verified_peers(&state.redis_conn, &state.registry_urls).await?;
                get_verified_peer(&state.redis_conn, &signed_request.peer_prefix)
                    .await?
                    .ok_or_else(|| ApiError::forbidden("Peer not authorized"))?
            }
        };

        // Consuming: verify peer's KEL (paginated) to extract trusted public key
        let mut loader = kels::StorePageLoader::new(state.kel_store.as_ref());
        let ctx = kels::completed_verification(
            &mut loader,
            &signed_request.peer_prefix,
            MAX_EVENTS_PER_KEL_QUERY as u64,
            kels::max_verification_pages(),
            iter::empty(),
        )
        .await
        .map_err(|_| ApiError::forbidden("Peer KEL verification failed"))?;

        signed_request
            .verify_signature_with_ctx(&ctx)
            .map_err(|_| ApiError::unauthorized("Signature verification failed"))?;
    }

    let limit = signed_request.payload.limit.unwrap_or(100).clamp(1, 1000);
    let result = state
        .repo
        .key_events
        .list_prefixes(signed_request.payload.since.as_deref(), limit)
        .await?;
    Ok(Json(result))
}

/// Look up a verified peer from Redis cache, returning the full Peer data.
#[cfg(not(feature = "dev-tools"))]
async fn get_verified_peer(
    redis_conn: &redis::aio::ConnectionManager,
    peer_prefix: &str,
) -> Result<Option<kels::Peer>, ApiError> {
    use redis::AsyncCommands;
    let mut conn = redis_conn.clone();
    let json: Option<String> = conn
        .get(format!("kels:verified-peer:{}", peer_prefix))
        .await
        .map_err(|e| ApiError::internal_error(format!("Redis error: {}", e)))?;
    match json {
        Some(j) => {
            let peer: kels::Peer = serde_json::from_str(&j)
                .map_err(|e| ApiError::internal_error(format!("Deserialization failed: {}", e)))?;
            Ok(Some(peer))
        }
        None => Ok(None),
    }
}

/// Fetch verified peers from the registry and store records in Redis.
#[cfg(not(feature = "dev-tools"))]
async fn refresh_verified_peers(
    redis_conn: &redis::aio::ConnectionManager,
    registry_urls: &[String],
) -> Result<(), ApiError> {
    use redis::AsyncCommands;

    if registry_urls.is_empty() {
        warn!("No registry URLs configured, skipping peer verification refresh");
        return Ok(());
    }

    let mut registry = kels::MultiRegistryClient::new(registry_urls.to_vec());
    let peers_response = registry
        .fetch_all_verified_peers()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch peers: {}", e)))?;

    let mut conn = redis_conn.clone();
    for history in &peers_response.peers {
        if let Some(peer) = history.records.last()
            && peer.active
        {
            let peer_json = serde_json::to_string(peer)
                .map_err(|e| ApiError::internal_error(format!("Serialization failed: {}", e)))?;
            conn.set_ex::<_, _, ()>(
                format!("kels:verified-peer:{}", peer.peer_prefix),
                peer_json,
                3600,
            )
            .await
            .map_err(|e| ApiError::internal_error(format!("Redis error: {}", e)))?;
        }
    }

    Ok(())
}

// ==================== Batch Handlers ====================

/// Batch fetch KELs. Returns map of prefix -> SignedKeyEventPage.
/// Supports delta fetching: if a since SAID is provided for a prefix,
/// only events after that SAID are returned.
/// Each prefix is limited to MAX_EVENTS_PER_KEL_RESPONSE events; `has_more` indicates truncation.
pub(crate) async fn get_kels_batch(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BatchKelsRequest>,
) -> Result<Response, ApiError> {
    if request.prefixes.len() > MAX_BATCH_PREFIXES {
        return Err(ApiError::bad_request(format!(
            "Batch request exceeds maximum of {} prefixes",
            MAX_BATCH_PREFIXES
        )));
    }

    let limit = MAX_EVENTS_PER_KEL_RESPONSE as u64;

    // Fetch all KELs in parallel
    let futures: Vec<_> = request
        .prefixes
        .into_iter()
        .map(|(prefix, since)| {
            let state = Arc::clone(&state);

            async move {
                match since {
                    // Full fetch path
                    None => {
                        // Fast path: return cached bytes directly (cached KELs ≤ limit)
                        if let Ok(Some(bytes)) = state.kel_cache.get_full_serialized(&prefix).await
                        {
                            let page_bytes = build_page_bytes(&bytes);
                            return Ok((prefix, page_bytes));
                        }

                        // Cache miss - fetch from DB
                        let (events, has_more) = state
                            .repo
                            .key_events
                            .get_signed_history(&prefix, limit, 0)
                            .await?;

                        // Store in cache (skips if too large)
                        if !events.is_empty()
                            && !has_more
                            && let Err(e) = state.kel_cache.store(&prefix, &events).await
                        {
                            warn!("Failed to cache KEL for {}: {}", prefix, e);
                        }

                        let bytes = serde_json::to_vec(&SignedKeyEventPage { events, has_more })
                            .unwrap_or_else(|_| br#"{"events":[],"hasMore":false}"#.to_vec());
                        Ok((prefix, bytes))
                    }
                    // Delta fetch path — canonical since-resolution with fallback
                    Some(since_said) => {
                        let page = match kels::serve_kel_page(
                            &state.repo.key_events,
                            &prefix,
                            Some(&since_said),
                            limit,
                        )
                        .await
                        {
                            Ok(page) => page,
                            Err(KelsError::KeyNotFound(_)) => {
                                warn!(
                                    "Since SAID {} not found for {}, falling back to full fetch",
                                    since_said, prefix
                                );
                                kels::serve_kel_page(&state.repo.key_events, &prefix, None, limit)
                                    .await?
                            }
                            Err(e) => return Err(e.into()),
                        };

                        let bytes = serde_json::to_vec(&page)
                            .unwrap_or_else(|_| br#"{"events":[],"hasMore":false}"#.to_vec());
                        Ok((prefix, bytes))
                    }
                }
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

    // Build JSON response by concatenating pre-serialized byte arrays.
    // Format: {"prefix1":{"events":[...],"hasMore":false},"prefix2":...}
    let mut response_bytes = Vec::with_capacity(
        serialized_entries
            .iter()
            .map(|(p, b)| p.len() + b.len() + 5)
            .sum::<usize>()
            + 2,
    );
    response_bytes.push(b'{');

    for (i, (prefix, page_bytes)) in serialized_entries.iter().enumerate() {
        if i > 0 {
            response_bytes.push(b',');
        }
        response_bytes.push(b'"');
        response_bytes.extend_from_slice(prefix.as_bytes());
        response_bytes.extend_from_slice(b"\":");
        response_bytes.extend_from_slice(page_bytes);
    }

    response_bytes.push(b'}');

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        response_bytes,
    )
        .into_response())
}

/// Wrap cached event bytes (a JSON array) into a SignedKeyEventPage JSON object.
/// Cached KELs are always ≤ MAX_EVENTS_PER_KEL_RESPONSE, so hasMore is always false.
fn build_page_bytes(event_array_bytes: &[u8]) -> Vec<u8> {
    // {"events":<array>,"hasMore":false}
    let mut bytes = Vec::with_capacity(event_array_bytes.len() + 30);
    bytes.extend_from_slice(b"{\"events\":");
    bytes.extend_from_slice(event_array_bytes);
    bytes.extend_from_slice(b",\"hasMore\":false}");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== KeyEventsQuery Tests ====================

    #[test]
    fn test_key_events_query_defaults() {
        let json = "{}";
        let params: KeyEventsQuery = serde_json::from_str(json).unwrap();
        assert!(params.since.is_none());
        assert!(params.limit.is_none());
    }

    #[test]
    fn test_key_events_query_with_values() {
        let json = r#"{"since": "someSAID", "limit": 100}"#;
        let params: KeyEventsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(params.since.as_deref(), Some("someSAID"));
        assert_eq!(params.limit, Some(100));
    }

    // ==================== ApiError Tests ====================

    #[test]
    fn test_api_error_not_found() {
        let err = ApiError::not_found("KEL not found");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1.code, ErrorCode::NotFound);
        assert_eq!(err.1.error, "KEL not found");
    }

    #[test]
    fn test_api_error_bad_request() {
        let err = ApiError::bad_request("Invalid signature");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.code, ErrorCode::BadRequest);
        assert_eq!(err.1.error, "Invalid signature");
    }

    #[test]
    fn test_api_error_unauthorized() {
        let err = ApiError::unauthorized("Merge failed");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn test_api_error_contest_required() {
        let err = ApiError::contest_required("Cannot submit");
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1.code, ErrorCode::ContestRequired);
    }

    #[test]
    fn test_api_error_rate_limited() {
        let err = ApiError::rate_limited("Too many requests");
        assert_eq!(err.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.1.code, ErrorCode::RateLimited);
        assert_eq!(err.1.error, "Too many requests");
    }

    #[test]
    fn test_api_error_from_kels_error() {
        let kels_err = KelsError::SigningFailed("test".to_string());
        let api_err: ApiError = kels_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_err.1.code, ErrorCode::InternalError);
    }

    #[test]
    fn test_api_error_from_storage_error() {
        let storage_err = verifiable_storage::StorageError::NotFound("key_events:abc".to_string());
        let api_err: ApiError = storage_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_err.1.code, ErrorCode::InternalError);
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_max_batch_prefixes_constant() {
        assert_eq!(MAX_BATCH_PREFIXES, 64);
    }

    #[test]
    fn test_max_events_per_submission_constant() {
        assert_eq!(MAX_EVENTS_PER_SUBMISSION, 512);
    }

    #[test]
    fn test_max_submissions_per_prefix_per_minute_constant() {
        assert_eq!(MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE, 32);
    }

    // ==================== health Tests ====================

    #[tokio::test]
    async fn test_health() {
        let status = health().await;
        assert_eq!(status, StatusCode::OK);
    }

    // ==================== Limit Clamping Tests ====================

    #[test]
    fn test_limit_clamp_below_min() {
        // Testing the clamping logic used in list_prefixes
        let limit: usize = 0;
        let clamped = limit.clamp(1, 1000);
        assert_eq!(clamped, 1);
    }

    #[test]
    fn test_limit_clamp_above_max() {
        let limit: usize = 2000;
        let clamped = limit.clamp(1, 1000);
        assert_eq!(clamped, 1000);
    }

    #[test]
    fn test_limit_clamp_within_range() {
        let limit: usize = 500;
        let clamped = limit.clamp(1, 1000);
        assert_eq!(clamped, 500);
    }

    // ==================== BatchKelsRequest Deserialization ====================

    #[test]
    fn test_batch_kels_request_deserialization() {
        let json = r#"{"prefixes": {"prefix1": null, "prefix2": "someSAID", "prefix3": null}}"#;
        let request: BatchKelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.prefixes.len(), 3);
        assert_eq!(request.prefixes.get("prefix1"), Some(&None));
        assert_eq!(
            request.prefixes.get("prefix2"),
            Some(&Some("someSAID".to_string()))
        );
    }

    #[test]
    fn test_batch_kels_request_empty_prefixes() {
        let json = r#"{"prefixes": {}}"#;
        let request: BatchKelsRequest = serde_json::from_str(json).unwrap();
        assert!(request.prefixes.is_empty());
    }
}
