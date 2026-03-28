//! HTTP handlers for the SADStore service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use cesr::{Matter, Signature, VerificationKey};
use dashmap::DashMap;
use tracing::{debug, warn};
use verifiable_storage::{Chained, SelfAddressed};

use crate::{object_store::ObjectStore, repository::SadStoreRepository};

const SECS_PER_DAY: u64 = 86_400;

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

/// Per-chain-prefix daily rate limit. Returns error string on rejection.
fn check_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
) -> Result<(), String> {
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 >= max_records_per_prefix_per_day() {
        return Err("Too many records for this chain prefix".to_string());
    }

    Ok(())
}

/// Accrue one record to the prefix rate limit after successful store.
fn accrue_prefix_rate_limit(limits: &DashMap<String, (u32, Instant)>, prefix: &str) {
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += 1;
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

    // Write to MinIO
    if let Err(e) = state.object_store.put(&said, &body).await {
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

// === Layer 2: Chain Records (Postgres) ===

pub async fn submit_sad_record(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<kels::SadRecordSubmission>,
) -> impl IntoResponse {
    let record = &body.record;
    let signature_str = &body.signature;

    // Per-IP rate limit
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // Per-chain-prefix daily rate limit
    if let Err(msg) = check_prefix_rate_limit(&state.prefix_rate_limits, &record.prefix) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // 1. Verify record SAID integrity
    if record.verify_said().is_err() {
        return (StatusCode::BAD_REQUEST, "Record SAID verification failed").into_response();
    }

    // 2. If content_said present, verify content exists in MinIO
    if let Some(ref content_said) = record.content_said {
        match state.object_store.exists(content_said).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Content SAID not found in object store — PUT content first",
                )
                    .into_response();
            }
            Err(e) => {
                warn!("Failed to check content existence: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
            }
        }
    }

    // 3. Verify signature against KEL — find the most recent establishment event
    let kel_prefix = &record.kel_prefix;
    let verifier = kels::KelVerifier::new(kel_prefix);
    let verification = match kels::verify_key_events(
        kel_prefix,
        &state.kels_client.as_kel_source(),
        verifier,
        kels::page_size(),
        kels::max_pages(),
    )
    .await
    {
        Ok(v) => v,
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

    let Some(public_key_qb64) = verification.current_public_key() else {
        return (StatusCode::BAD_REQUEST, "No public key in verified KEL").into_response();
    };

    // Verify signature over the record's SAID
    let public_key = match VerificationKey::from_qb64(public_key_qb64) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid public key: {}", e),
            )
                .into_response();
        }
    };

    let sig = match Signature::from_qb64(signature_str) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid signature: {}", e)).into_response();
        }
    };

    if public_key.verify(record.said.as_bytes(), &sig).is_err() {
        return (StatusCode::FORBIDDEN, "Signature verification failed").into_response();
    }

    // Get establishment serial from the verification
    let establishment_serial = verification
        .last_establishment_event()
        .map(|e| e.event.serial)
        .unwrap_or(0);

    // 4. Verify prefix derivation for v0
    if record.version == 0 && record.verify_prefix().is_err() {
        return (
            StatusCode::BAD_REQUEST,
            "Prefix derivation verification failed",
        )
            .into_response();
    }

    // 5. Store record + signature atomically (with advisory lock + chain integrity check)
    let sig_record = kels::SadRecordSignature::create(
        record.said.clone(),
        signature_str.clone(),
        establishment_serial,
    );
    let sig_record = match sig_record {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to create signature record: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if let Err(e) = state
        .repo
        .sad_records
        .save_with_chain_check(record, &sig_record)
        .await
    {
        warn!("Failed to store record: {}", e);
        return (StatusCode::CONFLICT, format!("{}", e)).into_response();
    }

    // Accrue to prefix rate limit after successful store
    accrue_prefix_rate_limit(&state.prefix_rate_limits, &record.prefix);

    // 6. Publish to Redis for gossip
    if let Some(ref conn) = state.redis_conn {
        let mut conn = conn.clone();
        let message = format!("{}:{}", record.prefix, record.said);
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

pub async fn get_sad_chain(
    Path(prefix): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.repo.sad_records.get_stored_chain(&prefix).await {
        Ok(records) if records.is_empty() => {
            (StatusCode::NOT_FOUND, "Chain not found").into_response()
        }
        Ok(records) => {
            let page = kels::SadRecordPage {
                has_more: false,
                records,
            };
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
        Ok(Some(said)) => (
            StatusCode::OK,
            Json(kels::EffectiveSaidResponse {
                said,
                divergent: false,
            }),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Chain not found").into_response(),
        Err(e) => {
            warn!("Failed to get effective SAID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}
