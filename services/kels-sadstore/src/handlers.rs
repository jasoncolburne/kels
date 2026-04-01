//! HTTP handlers for the SADStore service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use cesr::{Matter, Signature, VerificationKey};
use dashmap::DashMap;
use redis::AsyncCommands;
use serde::Deserialize;
use tracing::{debug, warn};
use verifiable_storage::{Chained, SelfAddressed};

use crate::{object_store::ObjectStore, repository::SadStoreRepository};

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

fn nonce_window_secs() -> u64 {
    kels::env_usize("KELS_NONCE_WINDOW_SECS", 60) as u64
}

/// Spawn a background task that periodically removes expired entries from
/// rate limit and nonce maps. Prevents unbounded growth from attacker-generated keys.
pub fn spawn_rate_limit_reaper(state: Arc<AppState>) {
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

/// Max chain records per prefix per day. Low — chains represent stable state.
fn max_records_per_prefix_per_day() -> u32 {
    kels::env_usize("SADSTORE_MAX_RECORDS_PER_PREFIX_PER_DAY", 16) as u32
}

/// Max write operations per IP per second (token bucket refill rate).
fn max_writes_per_ip_per_second() -> u32 {
    kels::env_usize("SADSTORE_MAX_WRITES_PER_IP_PER_SECOND", 100) as u32
}

/// Token bucket burst size per IP.
fn ip_rate_limit_burst() -> u32 {
    kels::env_usize("SADSTORE_IP_RATE_LIMIT_BURST", 500) as u32
}

/// Max SAD object size in bytes (default 1 MiB).
pub fn max_sad_object_size() -> usize {
    kels::env_usize("SADSTORE_MAX_OBJECT_SIZE", 1024 * 1024)
}

/// Per-chain-prefix daily rate limit. Checks whether adding `record_count` new
/// records would exceed the daily limit. Does NOT update the counter — call
/// `accrue_prefix_rate_limit` after storage with the actual new record count.
fn check_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
    record_count: u32,
) -> Result<(), String> {
    let now = Instant::now();
    let max_records = max_records_per_prefix_per_day();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 + record_count > max_records {
        return Err("Too many records for this chain prefix".to_string());
    }

    Ok(())
}

/// Accrue the actual number of new records after storage completes.
fn accrue_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
    new_record_count: u32,
) {
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += new_record_count;
}

/// Per-IP token bucket rate limit. Returns error string on rejection.
fn check_ip_rate_limit(limits: &DashMap<IpAddr, (u32, Instant)>, ip: IpAddr) -> Result<(), String> {
    let now = Instant::now();
    let mut entry = limits.entry(ip).or_insert((ip_rate_limit_burst(), now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * max_writes_per_ip_per_second() as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(ip_rate_limit_burst());
        entry.1 = now;
    }
    if entry.0 == 0 {
        return Err("Too many requests".to_string());
    }
    entry.0 -= 1;
    Ok(())
}

/// Shared application state.
pub struct AppState {
    pub repo: Arc<SadStoreRepository>,
    pub object_store: Arc<ObjectStore>,
    pub kels_client: kels::KelsClient,
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    pub registry_urls: Vec<String>,
    pub prefix_rate_limits: DashMap<String, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
    pub nonce_cache: DashMap<String, Instant>,
}

// ==================== Peer Authentication ====================

/// Look up a verified peer from Redis cache, returning the full Peer data.
async fn get_verified_peer(
    redis_conn: &redis::aio::ConnectionManager,
    peer_prefix: &str,
) -> Result<Option<kels::Peer>, (StatusCode, String)> {
    let mut conn = redis_conn.clone();
    let json: Option<String> = conn
        .get(format!("kels:verified-peer:{}", peer_prefix))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis error: {}", e),
            )
        })?;
    match json {
        Some(j) => {
            let peer: kels::Peer = serde_json::from_str(&j).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Deserialization failed: {}", e),
                )
            })?;
            Ok(Some(peer))
        }
        None => Ok(None),
    }
}

/// Fetch verified peers from the registry and store records in Redis.
async fn refresh_verified_peers(
    redis_conn: &redis::aio::ConnectionManager,
    registry_urls: &[String],
) -> Result<(), (StatusCode, String)> {
    if registry_urls.is_empty() {
        warn!("No registry URLs configured, skipping peer verification refresh");
        return Ok(());
    }

    let (peers_response, _) = kels::with_failover(
        registry_urls,
        std::time::Duration::from_secs(10),
        |c| async move { c.fetch_peers().await },
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch peers: {}", e),
        )
    })?;

    let mut conn = redis_conn.clone();
    for history in &peers_response.peers {
        if let Some(peer) = history.records.last()
            && peer.active
        {
            let peer_json = serde_json::to_string(peer).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Serialization failed: {}", e),
                )
            })?;
            conn.set_ex::<_, _, ()>(
                format!("kels:verified-peer:{}", peer.peer_prefix),
                peer_json,
                3600,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Redis error: {}", e),
                )
            })?;
        }
    }

    Ok(())
}

/// Authenticate a signed request from a federation peer.
///
/// Validates timestamp, deduplicates nonce, verifies peer is in the federation
/// allowlist (via Redis cache), verifies peer's KEL via the KELS service,
/// and verifies the request signature against the peer's current public key.
async fn authenticate_peer_request<T: serde::Serialize>(
    state: &AppState,
    signed_request: &kels::SignedRequest<T>,
    timestamp: i64,
    nonce: &str,
) -> Result<(), (StatusCode, String)> {
    if !kels::validate_timestamp(timestamp, 60) {
        return Err((StatusCode::FORBIDDEN, "Request timestamp expired".into()));
    }

    // Nonce deduplication
    let window = nonce_window_secs();
    if window > 0 {
        let now = Instant::now();
        if state.nonce_cache.insert(nonce.to_string(), now).is_some() {
            return Err((StatusCode::FORBIDDEN, "Duplicate nonce".into()));
        }
    }

    // Peer allowlist verification (requires Redis)
    let redis_conn = state.redis_conn.as_ref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            "Peer verification unavailable in standalone mode".into(),
        )
    })?;

    let peer = get_verified_peer(redis_conn, &signed_request.peer_prefix).await?;
    if peer.is_none() {
        refresh_verified_peers(redis_conn, &state.registry_urls).await?;
        if get_verified_peer(redis_conn, &signed_request.peer_prefix)
            .await?
            .is_none()
        {
            return Err((StatusCode::FORBIDDEN, "Peer not authorized".into()));
        }
    }

    // Verify peer's KEL via KELS service to extract trusted public key
    let verifier = kels::KelVerifier::new(&signed_request.peer_prefix);
    let kel_verification = kels::verify_key_events(
        &signed_request.peer_prefix,
        &state.kels_client.as_kel_source().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build HTTP client: {}", e),
            )
        })?,
        verifier,
        kels::page_size(),
        kels::max_pages(),
    )
    .await
    .map_err(|_| (StatusCode::FORBIDDEN, "Peer KEL verification failed".into()))?;

    // Verify request signature
    signed_request
        .verify_signature(&kel_verification)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Signature verification failed".into(),
            )
        })?;

    Ok(())
}

// === Health ===

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn ready() -> impl IntoResponse {
    (StatusCode::OK, "ready")
}

// === Layer 1: SAD Object Store (MinIO) ===

pub async fn post_sad_object(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    // Per-IP rate limit
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // Size limit
    if body.len() > max_sad_object_size() {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("Object exceeds max size of {} bytes", max_sad_object_size()),
        )
            .into_response();
    }

    // Parse and verify SAID
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    let said = value.get_said();
    if said.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing said field").into_response();
    }

    if value.verify_said().is_err() {
        return (StatusCode::BAD_REQUEST, "SAID verification failed").into_response();
    }

    // HEAD check — short-circuit if already exists
    match state.object_store.exists(&said).await {
        Ok(true) => {
            debug!("SAD object already exists: {}", said);
            return (StatusCode::OK, "exists").into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!("Failed to check SAD object existence: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    }

    // Store in MinIO + track in DB index atomically
    if let Err(e) = state
        .repo
        .sad_objects
        .store(&said, &state.object_store, &body)
        .await
    {
        warn!("Failed to store SAD object: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Publish to Redis for gossip
    if let Some(ref conn) = state.redis_conn {
        let mut conn = conn.clone();
        if let Err(e) = redis::cmd("PUBLISH")
            .arg("sad_updates")
            .arg(&said)
            .query_async::<()>(&mut conn)
            .await
        {
            warn!("Failed to publish SAD update: {}", e);
        }
    }

    (StatusCode::CREATED, "stored").into_response()
}

pub async fn get_sad_object(
    Path(said): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.object_store.get(&said).await {
        Ok(data) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            data,
        )
            .into_response(),
        Err(crate::object_store::ObjectStoreError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => {
            warn!("Failed to retrieve SAD object: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub async fn sad_object_exists(
    Path(said): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.object_store.exists(&said).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            warn!("Failed to check SAD object existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// === Layer 2: Chain Records (Postgres) ===

/// Query parameters for record submission.
#[derive(Deserialize)]
pub struct RecordSubmitQuery {
    /// If true, truncate records at and after the first record's version before
    /// inserting. Used to repair divergent chains.
    pub repair: Option<bool>,
}

/// Submit signed SAD records — unified endpoint for clients, gossip sync, and repair.
///
/// Accepts `Vec<SignedSadRecord>` (with establishment serials from the source node).
/// Verifies the KEL once, collecting establishment keys for all referenced serials,
/// then verifies each record's signature and stores all records.
///
/// With `?repair=true`, truncates all records at version >= the first record's version
/// before inserting. This is the repair mechanism for divergent chains.
pub async fn submit_sad_records(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<RecordSubmitQuery>,
    State(state): State<Arc<AppState>>,
    Json(records): Json<Vec<kels::SignedSadRecord>>,
) -> impl IntoResponse {
    if records.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty batch").into_response();
    }

    // Per-IP rate limit
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // All records must be for the same chain prefix
    let chain_prefix = &records[0].record.prefix;
    if records.iter().any(|r| r.record.prefix != *chain_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            "All records must have the same prefix",
        )
            .into_response();
    }

    // Per-chain-prefix daily rate limit (check before, accrue after)
    if let Err(msg) = check_prefix_rate_limit(
        &state.prefix_rate_limits,
        chain_prefix,
        records.len() as u32,
    ) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // All records must be for the same KEL prefix
    let kel_prefix = &records[0].record.kel_prefix;
    if records.iter().any(|r| r.record.kel_prefix != *kel_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            "All records must have the same kel_prefix",
        )
            .into_response();
    }

    // Verify SAID integrity for all records
    for r in &records {
        if r.record.verify_said().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("Record SAID verification failed: {}", r.record.said),
            )
                .into_response();
        }
    }

    // Collect unique establishment serials from both existing chain and incoming batch
    let mut establishment_serials: std::collections::BTreeSet<u64> =
        records.iter().map(|r| r.establishment_serial).collect();

    match state
        .repo
        .sad_records
        .existing_establishment_serials(chain_prefix)
        .await
    {
        Ok(existing) => establishment_serials.extend(existing),
        Err(e) => {
            warn!("Failed to fetch existing establishment serials: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    // Verify KEL once, collecting establishment keys for all serials
    let verifier = match kels::KelVerifier::new(kel_prefix)
        .with_establishment_key_collection(establishment_serials, kels::max_collected_keys())
    {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("{}", e)).into_response();
        }
    };

    let kel_source = match state.kels_client.as_kel_source() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build HTTP client: {}", e),
            )
                .into_response();
        }
    };

    let (verification, establishment_keys) =
        match kels::verify_key_events_collecting_establishment_keys(
            kel_prefix,
            &kel_source,
            verifier,
            kels::page_size(),
            kels::max_pages(),
        )
        .await
        {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Failed to verify KEL for {}: {}", kel_prefix, e);
                return (
                    StatusCode::BAD_REQUEST,
                    format!("KEL verification failed: {}", e),
                )
                    .into_response();
            }
        };

    if verification.is_divergent() {
        return (StatusCode::CONFLICT, "KEL is divergent").into_response();
    }

    // Verify each record's signature against its establishment key
    for r in &records {
        let Some(public_key_qb64) = establishment_keys.get(&r.establishment_serial) else {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "No establishment key found for serial {} (record {})",
                    r.establishment_serial, r.record.said
                ),
            )
                .into_response();
        };

        let public_key = match VerificationKey::from_qb64(public_key_qb64) {
            Ok(k) => k,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Invalid public key at serial {}: {}",
                        r.establishment_serial, e
                    ),
                )
                    .into_response();
            }
        };

        let sig = match Signature::from_qb64(&r.signature) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid signature on record {}: {}", r.record.said, e),
                )
                    .into_response();
            }
        };

        if public_key.verify(r.record.said.as_bytes(), &sig).is_err() {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "Signature verification failed for record {} at serial {}",
                    r.record.said, r.establishment_serial
                ),
            )
                .into_response();
        }
    }

    // Verify prefix derivation for v0 if present
    if let Some(v0) = records.iter().find(|r| r.record.version == 0)
        && v0.record.verify_prefix().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            "Prefix derivation verification failed",
        )
            .into_response();
    }

    // Build (record, signature) pairs for storage
    let mut pairs = Vec::with_capacity(records.len());
    for r in &records {
        let sig_record = match kels::SadRecordSignature::create(
            r.record.said.clone(),
            r.signature.clone(),
            r.establishment_serial,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create signature record: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            }
        };
        pairs.push((r.record.clone(), sig_record));
    }

    let is_repair = query.repair.unwrap_or(false);

    let new_record_count;
    let gossip_said: Option<String>;

    if is_repair {
        // Repair mode: truncate from the first record's version and replace
        let from_version = records[0].record.version;
        if let Err(e) = state
            .repo
            .sad_records
            .truncate_and_replace(from_version, &pairs)
            .await
        {
            warn!("Failed to repair chain: {}", e);
            return (StatusCode::CONFLICT, format!("{}", e)).into_response();
        }
        new_record_count = pairs.len() as u32;
        gossip_said = pairs.last().map(|(r, _)| r.said.clone());
    } else {
        // Normal mode: store batch with full chain verification and advisory lock
        match state
            .repo
            .sad_records
            .save_batch_with_verified_signatures(&pairs, &establishment_keys)
            .await
        {
            Ok(count) => {
                new_record_count = count;
                if count > 0 {
                    gossip_said = pairs.last().map(|(r, _)| r.said.clone());
                } else {
                    gossip_said = None;
                }
            }
            Err(e) => {
                warn!("Failed to store records: {}", e);
                return (StatusCode::CONFLICT, format!("{}", e)).into_response();
            }
        }
    }

    // Accrue only actual new records to prefix rate limit
    accrue_prefix_rate_limit(&state.prefix_rate_limits, chain_prefix, new_record_count);

    // Publish the effective SAID to Redis for gossip. Using the effective SAID
    // (not the tip record SAID) ensures the gossip feedback loop cache key matches
    // for both divergent and non-divergent chains.
    // Repair updates include a ":repair" suffix so the gossip subscriber
    // can propagate the repair flag to other nodes.
    let effective_said = if gossip_said.is_some() {
        match state.repo.sad_records.effective_said(chain_prefix).await {
            Ok(Some((said, _))) => Some(said),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "Failed to compute effective SAID for {}: {}",
                    chain_prefix, e
                );
                None
            }
        }
    } else {
        None
    };
    if let Some(ref conn) = state.redis_conn
        && let Some(said) = &effective_said
    {
        let mut conn = conn.clone();
        let message = if is_repair {
            format!("{}:{}:repair", chain_prefix, said)
        } else {
            format!("{}:{}", chain_prefix, said)
        };
        if let Err(e) = redis::cmd("PUBLISH")
            .arg("sad_chain_updates")
            .arg(&message)
            .query_async::<()>(&mut conn)
            .await
        {
            warn!("Failed to publish chain update: {}", e);
        }
    }

    (StatusCode::CREATED, "stored").into_response()
}

#[derive(Deserialize)]
pub struct ChainQuery {
    /// Effective SAID cursor — return records after this SAID's position.
    /// If the SAID is not found (e.g. synthetic divergent SAID), returns the full chain.
    pub since: Option<String>,
    pub limit: Option<u64>,
}

pub async fn get_sad_chain(
    Path(prefix): Path<String>,
    Query(query): Query<ChainQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(kels::page_size() as u64);

    match state
        .repo
        .sad_records
        .get_stored_chain(&prefix, query.since.as_deref(), Some(limit + 1))
        .await
    {
        Ok(records) if records.is_empty() => {
            (StatusCode::NOT_FOUND, "Chain not found").into_response()
        }
        Ok(records) => {
            let has_more = records.len() as u64 > limit;
            let records: Vec<_> = records.into_iter().take(limit as usize).collect();
            let page = kels::SadRecordPage { has_more, records };
            (StatusCode::OK, Json(page)).into_response()
        }
        Err(e) => {
            warn!("Failed to get chain: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub async fn get_sad_effective_said(
    Path(prefix): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.repo.sad_records.effective_said(&prefix).await {
        Ok(Some((said, divergent))) => (
            StatusCode::OK,
            Json(kels::EffectiveSaidResponse { said, divergent }),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Chain not found").into_response(),
        Err(e) => {
            warn!("Failed to get effective SAID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

// === Prefix Listing (authenticated — federation peers only) ===

const MAX_PREFIX_PAGE_SIZE: usize = 100;

/// Shared query logic for listing SAD objects.
async fn query_sad_objects(
    state: &AppState,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> impl IntoResponse {
    let limit = limit
        .unwrap_or(MAX_PREFIX_PAGE_SIZE)
        .min(MAX_PREFIX_PAGE_SIZE);

    match state.repo.sad_objects.list(cursor, limit).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            warn!("Failed to list SAD objects: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Shared query logic for listing SAD chain prefixes.
async fn query_sad_prefixes(
    state: &AppState,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> impl IntoResponse {
    let limit = limit
        .unwrap_or(MAX_PREFIX_PAGE_SIZE)
        .min(MAX_PREFIX_PAGE_SIZE);

    match state.repo.sad_records.list_prefixes(cursor, limit).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            warn!("Failed to list prefixes: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Authenticated SAD object listing. Federation peers only.
pub async fn list_sad_objects(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if let Err((status, msg)) = authenticate_peer_request(
        &state,
        &signed_request,
        signed_request.payload.timestamp,
        &signed_request.payload.nonce,
    )
    .await
    {
        return (status, msg).into_response();
    }

    query_sad_objects(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

/// Authenticated SAD chain prefix listing. Federation peers only.
pub async fn list_sad_prefixes(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if let Err((status, msg)) = authenticate_peer_request(
        &state,
        &signed_request,
        signed_request.payload.timestamp,
        &signed_request.payload.nonce,
    )
    .await
    {
        return (status, msg).into_response();
    }

    query_sad_prefixes(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

// === Layer 2: Chain Repair History ===

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

pub(crate) async fn get_sad_repairs(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    Query(params): Query<PaginationQuery>,
) -> impl IntoResponse {
    let page_size = kels::page_size() as u64;
    let limit = params.limit.unwrap_or(page_size).clamp(1, page_size);
    let offset = params.offset.unwrap_or(0);

    match state
        .repo
        .sad_records
        .get_repairs(&prefix, limit, offset)
        .await
    {
        Ok((repairs, has_more)) => (
            StatusCode::OK,
            Json(kels::SadChainRepairPage { repairs, has_more }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to get repairs for {}: {}", prefix, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub(crate) async fn get_repair_records(
    State(state): State<Arc<AppState>>,
    Path((prefix, repair_said)): Path<(String, String)>,
    Query(params): Query<PaginationQuery>,
) -> impl IntoResponse {
    let _ = prefix; // prefix is in the URL for routing clarity but not needed for the query
    let page_size = kels::page_size() as u64;
    let limit = params.limit.unwrap_or(page_size).clamp(1, page_size);
    let offset = params.offset.unwrap_or(0);

    match state
        .repo
        .sad_records
        .get_repair_records(&repair_said, limit, offset)
        .await
    {
        Ok((records, has_more)) => (
            StatusCode::OK,
            Json(kels::SadRecordPage { records, has_more }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to get repair records for {}: {}", repair_said, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Unauthenticated test endpoint for listing SAD objects.
/// Only available when `KELS_TEST_ENDPOINTS=true`.
pub async fn test_list_sad_objects(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    query_sad_objects(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

/// Unauthenticated test endpoint for listing SAD chain prefixes.
/// Only available when `KELS_TEST_ENDPOINTS=true`.
pub async fn test_list_sad_prefixes(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels::SignedRequest<kels::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    query_sad_prefixes(
        &state,
        signed_request.payload.cursor.as_deref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}
