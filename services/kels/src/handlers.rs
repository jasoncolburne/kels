//! KELS REST API Handlers

use std::{
    sync::{Arc, LazyLock},
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
use redis::AsyncCommands;
use tracing::warn;

use kels::{
    EffectiveSaidResponse, ErrorCode, ErrorResponse, KelMergeResult, KelsError, KeyEventsQuery,
    PrefixListResponse, RecoveryRecordPage, ServerKelCache, SignedKeyEvent, SignedKeyEventPage,
    SubmitEventsResponse,
};

use crate::repository::KelsRepository;

static TEST_ENDPOINTS_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("KELS_TEST_ENDPOINTS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
});

pub(crate) fn test_endpoints_enabled() -> bool {
    *TEST_ENDPOINTS_ENABLED
}

fn max_events_per_prefix_per_day() -> u32 {
    kels::env_usize("KELS_MAX_EVENTS_PER_PREFIX_PER_DAY", 256) as u32
}

fn max_writes_per_ip_per_second() -> u32 {
    kels::env_usize("KELS_MAX_WRITES_PER_IP_PER_SECOND", 200) as u32
}

fn ip_rate_limit_burst() -> u32 {
    kels::env_usize("KELS_IP_RATE_LIMIT_BURST", 1000) as u32
}

fn nonce_window_secs() -> u64 {
    kels::env_usize("KELS_NONCE_WINDOW_SECS", 60) as u64
}

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn a background task that periodically removes expired entries from
/// rate limit and nonce maps. Prevents unbounded growth from attacker-generated keys.
pub(crate) fn spawn_rate_limit_reaper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let nonce_window = Duration::from_secs(nonce_window_secs());
        loop {
            tokio::time::sleep(RATE_LIMIT_REAP_INTERVAL).await;
            let now = Instant::now();
            let day = Duration::from_secs(SECS_PER_DAY);
            state
                .prefix_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
            state
                .ip_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
            state
                .nonce_cache
                .retain(|_, t| now.duration_since(*t) < nonce_window);
        }
    });
}

/// Per-prefix rate limit: counts events (not submissions) in a daily window.
/// Slows adversary event accumulation. The hard resilience guarantee comes
/// from bounded archival (KELS-71), not from this rate limit.
/// Check whether adding `event_count` new events would exceed the daily limit.
/// Does NOT update the counter — call `accrue_prefix_rate_limit` after merge
/// with the actual number of new events inserted.
///
/// Duplicated in `kels-registry/src/handlers.rs`. Keep in sync.
fn check_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
    event_count: u32,
    max_events: u32,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 + event_count > max_events {
        return Err(ApiError::rate_limited("Too many events for this prefix"));
    }

    Ok(())
}

/// Accrue the actual number of new events after merge completes.
///
/// Duplicated in `kels-registry/src/handlers.rs`. Keep in sync.
fn accrue_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
    new_event_count: u32,
) {
    if new_event_count == 0 {
        return;
    }
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += new_event_count;
}

pub(crate) struct AppState {
    pub(crate) repo: Arc<KelsRepository>,
    pub(crate) kel_store: Arc<dyn kels::KelStore>,
    pub(crate) kel_cache: Option<ServerKelCache>,
    pub(crate) redis_conn: Option<redis::aio::ConnectionManager>,
    pub(crate) registry_urls: Vec<String>,
    /// Per-prefix daily rate limiting: counts events (not submissions).
    pub(crate) prefix_rate_limits: DashMap<String, (u32, Instant)>,
    /// Per-IP write rate limiting: maps IP -> (tokens_remaining, last_refill)
    pub(crate) ip_rate_limits: DashMap<std::net::IpAddr, (u32, Instant)>,
    /// Nonce deduplication: maps nonce -> first_seen. Entries older than nonce_window_secs() are evicted.
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

    fn forbidden(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::Unauthorized,
            }),
        )
    }

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
/// Tokens refill at max_writes_per_ip_per_second(), up to ip_rate_limit_burst().
fn check_ip_rate_limit(
    limits: &DashMap<std::net::IpAddr, (u32, Instant)>,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(ip).or_insert((ip_rate_limit_burst(), now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * max_writes_per_ip_per_second() as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(ip_rate_limit_burst());
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
            KelsError::NotFound(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
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
/// Without Redis (standalone mode), the node is always ready.
pub(crate) async fn ready(State(state): State<Arc<AppState>>) -> (StatusCode, Json<ReadyResponse>) {
    let Some(ref redis_conn) = state.redis_conn else {
        return (
            StatusCode::OK,
            Json(ReadyResponse {
                ready: true,
                status: "standalone".to_string(),
            }),
        );
    };

    let mut conn = redis_conn.clone();

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
) -> Result<Json<SubmitEventsResponse>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;

    if events.is_empty() {
        return Ok(Json(SubmitEventsResponse {
            diverged_at: None,
            applied: true,
        }));
    }

    if events.len() > kels::page_size() {
        return Err(ApiError::bad_request(format!(
            "Batch exceeds maximum of {} events",
            kels::page_size()
        )));
    }

    // Get prefix from first event
    let prefix = events[0].event.prefix.clone();

    // Per-prefix daily rate limiting (counts events, not submissions)
    check_prefix_rate_limit(
        &state.prefix_rate_limits,
        &prefix,
        events.len() as u32,
        max_events_per_prefix_per_day(),
    )?;

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

    // Accrue only the actual new events (duplicates don't count)
    accrue_prefix_rate_limit(
        &state.prefix_rate_limits,
        &prefix,
        outcome.new_event_count as u32,
    );

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

    // Update cache outside transaction (skip if no Redis)
    if applied && let Some(ref kel_cache) = state.kel_cache {
        match state
            .repo
            .key_events
            .get_signed_history(&prefix, kels::page_size() as u64, 0)
            .await
        {
            Ok((events, has_more)) => {
                if !has_more {
                    if let Err(e) = kel_cache.store(&prefix, &events).await {
                        warn!("Failed to cache KEL: {}", e);
                    }
                } else if let Err(e) = kel_cache.invalidate(&prefix).await {
                    warn!("Failed to invalidate cache: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to rebuild cache for {}: {}", prefix, e);
                if let Err(e) = kel_cache.invalidate(&prefix).await {
                    warn!("Failed to invalidate cache: {}", e);
                }
            }
        }

        let effective_said = match state
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
        };
        if let Some(ref said) = effective_said
            && let Err(e) = kel_cache.publish_update(&prefix, said).await
        {
            warn!("Failed to publish cache update: {}", e);
        }
    }

    Ok(Json(SubmitEventsResponse {
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
        .unwrap_or(kels::page_size())
        .clamp(1, kels::page_size()) as u64;

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
    if limit as usize == kels::page_size()
        && let Some(ref kel_cache) = state.kel_cache
    {
        match kel_cache.get_full_serialized(&prefix).await {
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
        && let Some(ref kel_cache) = state.kel_cache
        && let Err(e) = kel_cache.store(&prefix, &page.events).await
    {
        warn!("Failed to cache KEL: {}", e);
    }

    Ok(Json(page).into_response())
}

/// Dedicated audit endpoint — returns paginated recovery history for a prefix.
///
/// `?limit=N` controls page size (1-page_size, default page_size).
/// `?offset=N` skips the first N records.
pub(crate) async fn get_kel_audit(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<ArchivedEventsQuery>,
) -> Result<Json<RecoveryRecordPage>, ApiError> {
    let limit = params
        .limit
        .unwrap_or(kels::page_size())
        .clamp(1, kels::page_size()) as u64;
    let offset = params.offset.unwrap_or(0);

    let (records, has_more) = state
        .repo
        .recovery_records
        .get_by_kel_prefix(&prefix, limit, offset)
        .await?;
    Ok(Json(RecoveryRecordPage { records, has_more }))
}

/// Archived adversary events for a specific recovery — paginated.
///
/// `?limit=N` controls page size (1-page_size, default page_size).
/// `?offset=N` skips the first N events.
pub(crate) async fn get_recovery_events(
    State(state): State<Arc<AppState>>,
    Path((_prefix, recovery_said)): Path<(String, String)>,
    Query(params): Query<ArchivedEventsQuery>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let limit = params
        .limit
        .unwrap_or(kels::page_size())
        .clamp(1, kels::page_size()) as u64;
    let offset = params.offset.unwrap_or(0);

    let (events, has_more) = state
        .repo
        .key_events
        .get_recovery_archived_events(&recovery_said, limit, offset)
        .await?;

    Ok(Json(SignedKeyEventPage { events, has_more }))
}

/// Query parameters for the archived events endpoint.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ArchivedEventsQuery {
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Archived adversary events for a prefix — paginated.
///
/// `?limit=N` controls page size (1-32, default 32).
/// `?offset=N` skips the first N events.
pub(crate) async fn get_kel_archived(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<ArchivedEventsQuery>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let limit = params
        .limit
        .unwrap_or(kels::page_size())
        .clamp(1, kels::page_size()) as u64;
    let offset = params.offset.unwrap_or(0);

    let (events, has_more) = state
        .repo
        .key_events
        .get_archived_events(&prefix, limit, offset)
        .await?;

    Ok(Json(SignedKeyEventPage { events, has_more }))
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

/// Shared query logic for listing prefixes.
async fn query_prefixes(
    state: &AppState,
    since: Option<&str>,
    limit: Option<usize>,
) -> Result<Json<PrefixListResponse>, ApiError> {
    let limit = limit.unwrap_or(100).clamp(1, 1000);
    let result = state.repo.key_events.list_prefixes(since, limit).await?;
    Ok(Json(result))
}

/// List all unique prefixes with their latest SAIDs for bootstrap sync.
///
/// Accepts a `SignedRequest<PrefixesRequest>` via POST.
/// Requires peer authentication: timestamp validation, nonce deduplication,
/// peer allowlist verification, and signed request verification.
pub(crate) async fn list_prefixes(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> Result<Json<PrefixListResponse>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;

    if !kels::validate_timestamp(signed_request.payload.timestamp, 60) {
        return Err(ApiError::forbidden("Request timestamp expired"));
    }

    // Nonce deduplication: evict expired entries, then reject duplicates
    let window = nonce_window_secs();
    if window > 0 {
        let now = Instant::now();
        state
            .nonce_cache
            .retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(window));
        if state
            .nonce_cache
            .insert(signed_request.payload.nonce.clone(), now)
            .is_some()
        {
            return Err(ApiError::forbidden("Duplicate nonce"));
        }
    }

    // Look up peer to verify they are in the verified allowlist (requires Redis)
    let redis_conn = state
        .redis_conn
        .as_ref()
        .ok_or_else(|| ApiError::forbidden("Peer verification unavailable in standalone mode"))?;
    let peer = get_verified_peer(redis_conn, &signed_request.peer_prefix).await?;
    let _peer = match peer {
        Some(p) => p,
        None => {
            refresh_verified_peers(redis_conn, &state.registry_urls).await?;
            get_verified_peer(redis_conn, &signed_request.peer_prefix)
                .await?
                .ok_or_else(|| ApiError::forbidden("Peer not authorized"))?
        }
    };

    // Consuming: verify peer's KEL (paginated) to extract trusted public key
    let mut loader = kels::StorePageLoader::new(state.kel_store.as_ref());
    let kel_verification = kels::completed_verification(
        &mut loader,
        &signed_request.peer_prefix,
        kels::page_size(),
        kels::max_pages(),
        std::iter::empty::<String>(),
    )
    .await
    .map_err(|_| ApiError::forbidden("Peer KEL verification failed"))?;

    signed_request
        .verify_signature(&kel_verification)
        .map_err(|_| ApiError::unauthorized("Signature verification failed"))?;

    query_prefixes(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
}

/// Unauthenticated test endpoint for listing prefixes.
/// Only available when `KELS_TEST_ENDPOINTS=true`.
pub(crate) async fn test_list_prefixes(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> Result<Json<PrefixListResponse>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;
    query_prefixes(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
}

/// Look up a verified peer from Redis cache, returning the full Peer data.
async fn get_verified_peer(
    redis_conn: &redis::aio::ConnectionManager,
    peer_prefix: &str,
) -> Result<Option<kels::Peer>, ApiError> {
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
async fn refresh_verified_peers(
    redis_conn: &redis::aio::ConnectionManager,
    registry_urls: &[String],
) -> Result<(), ApiError> {
    if registry_urls.is_empty() {
        warn!("No registry URLs configured, skipping peer verification refresh");
        return Ok(());
    }

    let peers_response = kels::with_failover(
        registry_urls,
        std::time::Duration::from_secs(10),
        |c| async move { c.fetch_peers().await },
    )
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
    fn test_max_events_per_submission_constant() {
        assert_eq!(kels::page_size(), kels::MINIMUM_PAGE_SIZE);
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
}
