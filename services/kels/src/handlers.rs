//! KELS REST API Handlers

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

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
    BatchKelsRequest, BatchSubmitResponse, EffectiveSaidResponse, ErrorCode, ErrorResponse,
    KelMergeResult, KelsAuditRecord, KelsError, KeyEventsQuery, MAX_BATCH_PREFIXES,
    MAX_CACHED_KEL_EVENTS, MAX_EVENTS_PER_KEL_RESPONSE, MAX_EVENTS_PER_SUBMISSION,
    PrefixListResponse, ServerKelCache, SignedKeyEvent, SignedKeyEventPage,
};
use tracing::warn;

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
            KelsError::EventNotFound(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
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

    // Validate signatures upfront (fast rejection before acquiring advisory lock)
    for signed_event in &events {
        if signed_event.signatures.is_empty() {
            return Err(ApiError::bad_request("Event missing signature"));
        }
        for sig in &signed_event.signatures {
            Signature::from_qb64(&sig.signature)
                .map_err(|e| ApiError::bad_request(format!("Invalid signature format: {}", e)))?;
        }
        if signed_event.event.requires_dual_signature() && signed_event.signatures.len() < 2 {
            return Err(ApiError::bad_request(
                "Dual signatures required for recovery event",
            ));
        }
    }

    // Full merge: verification, divergence detection, recovery, contest, adversary archival.
    // Advisory lock + transaction managed internally by save_with_merge.
    let outcome = state
        .repo
        .key_events
        .save_with_merge(&prefix, &events)
        .await
        .map_err(|e| match e {
            KelsError::VerificationFailed(msg) => ApiError::unauthorized(msg),
            KelsError::InvalidKeyEvent(msg) => ApiError::bad_request(msg),
            KelsError::InvalidSignature(msg) => ApiError::bad_request(msg),
            KelsError::KelDecommissioned => {
                ApiError::unauthorized("KEL is decommissioned".to_string())
            }
            KelsError::ContestedKel(msg) => ApiError::unauthorized(msg),
            // This catches ContestRequired before it reaches the match on
            // outcome.result below, making KelMergeResult::ContestRequired unreachable.
            KelsError::ContestRequired => ApiError::contest_required(
                "Contest required: recovery key revealed. Use contest to freeze the KEL.",
            ),
            _ => ApiError::internal_error(e.to_string()),
        })?;

    let applied = match outcome.result {
        KelMergeResult::Accepted
        | KelMergeResult::Recovered
        | KelMergeResult::Contested
        | KelMergeResult::Diverged => true,
        KelMergeResult::RecoverRequired => false,
        // ContestRequired is returned as Err(KelsError::ContestRequired) by
        // save_with_merge, caught by the .map_err() above — never reaches here.
        KelMergeResult::ContestRequired => unreachable!(),
    };

    // Update cache outside transaction
    if applied {
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
                } else if let Err(e) = state.kel_cache.invalidate(&prefix).await {
                    warn!("Failed to invalidate cache: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to rebuild cache for {}: {}", prefix, e);
                if let Err(e) = state.kel_cache.invalidate(&prefix).await {
                    warn!("Failed to invalidate cache: {}", e);
                }
            }
        }

        let effective_said = if let Some(said) = outcome.tip_said {
            Some(said)
        } else {
            match state
                .repo
                .key_events
                .compute_prefix_effective_said(&prefix)
                .await
            {
                Ok(Some((said, _))) => Some(said),
                Ok(None) => None,
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
        diverged_at: outcome.diverged_at,
        applied,
    }))
}

pub(crate) async fn get_kel(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<KeyEventsQuery>,
) -> Result<Response, ApiError> {
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
        return Ok(Json(page).into_response());
    }

    // Full fetch path — try cache for default limit
    if limit as usize == MAX_EVENTS_PER_KEL_RESPONSE {
        match state.kel_cache.get_full_serialized(&prefix).await {
            Ok(Some(bytes)) => {
                // Zero-copy: wrap cached event array bytes into page JSON directly
                let page_bytes = build_page_bytes(&bytes);
                return Ok(Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(page_bytes))
                    .map_err(|e| ApiError::internal_error(format!("Response build error: {}", e)))?
                    .into_response());
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

    Ok(Json(page).into_response())
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
) -> Result<Json<EffectiveSaidResponse>, ApiError> {
    let effective = state
        .repo
        .key_events
        .compute_prefix_effective_said(&prefix)
        .await?;

    match effective {
        Some((said, divergent)) => Ok(Json(EffectiveSaidResponse { said, divergent })),
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
            kels::MAX_EVENTS_PER_KEL_QUERY as u64,
            kels::max_verification_pages(),
            std::iter::empty::<String>(),
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
                            Err(KelsError::EventNotFound(_)) => {
                                warn!(
                                    "Since SAID {} not found for {}, falling back to full fetch",
                                    since_said, prefix
                                );
                                match kels::serve_kel_page(
                                    &state.repo.key_events,
                                    &prefix,
                                    None,
                                    limit,
                                )
                                .await
                                {
                                    Ok(page) => page,
                                    Err(KelsError::EventNotFound(_)) => SignedKeyEventPage {
                                        events: vec![],
                                        has_more: false,
                                    },
                                    Err(e) => return Err(e.into()),
                                }
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

    // Collect successful results, skipping failed prefixes
    let mut serialized_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(results.len());
    for result in results {
        match result {
            Ok(entry) => serialized_entries.push(entry),
            Err(ApiError(status, Json(ref err))) => {
                warn!("Batch fetch skipping prefix: {} ({})", err.error, status);
            }
        }
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
