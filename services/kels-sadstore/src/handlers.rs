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
use serde::Deserialize;
use tracing::{debug, warn};
use verifiable_storage::{Chained, SelfAddressed};

use crate::{object_store::ObjectStore, repository::SadStoreRepository};

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn a background task that periodically removes expired entries from
/// rate limit maps. Prevents unbounded growth from attacker-generated keys.
pub fn spawn_rate_limit_reaper(state: Arc<AppState>) {
    tokio::spawn(async move {
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
fn max_sad_object_size() -> usize {
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
    pub prefix_rate_limits: DashMap<String, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
}

// === Health ===

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn ready() -> impl IntoResponse {
    (StatusCode::OK, "ready")
}

// === Layer 1: SAD Object Store (MinIO) ===

pub async fn put_sad_object(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(said): Path<String>,
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

    // Parse and verify SAID
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    if value.verify_said().is_err() {
        return (StatusCode::BAD_REQUEST, "SAID verification failed").into_response();
    }

    // Confirm URL SAID matches content SAID
    if value.get_said() != said {
        return (
            StatusCode::BAD_REQUEST,
            "URL SAID does not match content SAID",
        )
            .into_response();
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

    // Collect unique establishment serials (bounded)
    let establishment_serials: std::collections::BTreeSet<u64> =
        records.iter().map(|r| r.establishment_serial).collect();
    if establishment_serials.len() > kels::page_size() {
        return (
            StatusCode::BAD_REQUEST,
            "Too many unique establishment serials",
        )
            .into_response();
    }

    // Verify KEL once, collecting establishment keys
    let verifier = match kels::KelVerifier::new(kel_prefix)
        .with_establishment_key_collection(establishment_serials, kels::page_size())
    {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("{}", e)).into_response();
        }
    };

    let (verification, establishment_keys) = match kels::verify_key_events_with_establishment_keys(
        kel_prefix,
        &state.kels_client.as_kel_source(),
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
    } else {
        // Normal mode: store records individually with chain integrity checks
        let mut count = 0u32;
        for (record, sig_record) in &pairs {
            match state
                .repo
                .sad_records
                .save_with_verified_signature(record, sig_record)
                .await
            {
                Ok(true) => count += 1,
                Ok(false) => {} // deduplicated
                Err(e) => {
                    warn!("Failed to store record {}: {}", record.said, e);
                }
            }
        }
        new_record_count = count;
    }

    // Accrue only actual new records to prefix rate limit
    accrue_prefix_rate_limit(&state.prefix_rate_limits, chain_prefix, new_record_count);

    // Publish the chain tip to Redis for gossip
    if let Some(ref conn) = state.redis_conn
        && let Some(last) = records.last()
    {
        let mut conn = conn.clone();
        let message = format!("{}:{}", last.record.prefix, last.record.said);
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

// === Prefix Listing (for bootstrap + anti-entropy) ===

const MAX_PREFIX_PAGE_SIZE: u64 = 100;

#[derive(Deserialize)]
pub struct PrefixListQuery {
    pub cursor: Option<String>,
    pub limit: Option<u64>,
}

pub async fn list_sad_objects(
    Query(query): Query<PrefixListQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let limit = query
        .limit
        .unwrap_or(MAX_PREFIX_PAGE_SIZE)
        .min(MAX_PREFIX_PAGE_SIZE);

    match state
        .repo
        .sad_objects
        .list(query.cursor.as_deref(), limit + 1)
        .await
    {
        Ok(saids) => {
            let has_more = saids.len() as u64 > limit;
            let saids: Vec<_> = saids.into_iter().take(limit as usize).collect();
            let next_cursor = if has_more {
                saids.last().cloned()
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(kels::SadObjectListResponse { saids, next_cursor }),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to list SAD objects: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub async fn list_sad_prefixes(
    Query(query): Query<PrefixListQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let limit = query
        .limit
        .unwrap_or(MAX_PREFIX_PAGE_SIZE)
        .min(MAX_PREFIX_PAGE_SIZE) as usize;

    match state
        .repo
        .sad_records
        .list_prefixes(query.cursor.as_deref(), limit)
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            warn!("Failed to list prefixes: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}
