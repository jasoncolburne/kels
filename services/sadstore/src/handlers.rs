//! HTTP handlers for the SADStore service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use cesr::Matter;
use dashmap::DashMap;
use redis::AsyncCommands;
use tracing::{debug, warn};
use verifiable_storage::{Chained, QueryExecutor, SelfAddressed, TransactionExecutor};

use crate::{
    object_store::ObjectStore,
    repository::{SadEventRepository, SadStoreRepository},
};

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

fn nonce_window_secs() -> u64 {
    kels_core::env_usize("KELS_NONCE_WINDOW_SECS", 60) as u64
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

/// Default TTL reaper interval in seconds. Override with `SADSTORE_TTL_REAPER_INTERVAL`.
fn ttl_reaper_interval_secs() -> u64 {
    kels_core::env_usize("SADSTORE_TTL_REAPER_INTERVAL", 60) as u64
}

/// Max expired records to reap per cycle.
const TTL_REAPER_BATCH_SIZE: usize = 100;

/// Spawn a background task that periodically deletes TTL-expired records.
/// Queries custodies with TTL, then finds expired sad_objects for each,
/// deletes from DB and MinIO.
pub fn spawn_ttl_reaper(state: Arc<AppState>) {
    let interval = Duration::from_secs(ttl_reaper_interval_secs());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = reap_expired_records(&state).await {
                warn!("TTL reaper error: {}", e);
            }
        }
    });
}

// TODO: periodic custody GC — delete custodies with zero references from sad_objects and events
async fn reap_expired_records(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use verifiable_storage_postgres::QueryExecutor;

    // Fetch all custodies with TTL set
    let query = verifiable_storage_postgres::Query::<kels_core::Custody>::for_table("custodies")
        .filter(verifiable_storage_postgres::Filter::IsNotNull(
            "ttl".to_string(),
        ))
        .limit(TTL_REAPER_BATCH_SIZE as u64);
    let custodies: Vec<kels_core::Custody> = state.repo.custodies.pool.fetch(query).await?;

    let now = verifiable_storage::StorageDatetime::now();

    for custody in &custodies {
        let Some(ttl) = custody.ttl else { continue };

        // Compute the expiry threshold: records created before this time are expired
        let threshold: verifiable_storage::StorageDatetime =
            (*now.inner() - chrono::Duration::seconds(ttl as i64)).into();

        // Find expired records for this custody
        let expired_query =
            verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
                "sad_objects",
            )
            .eq("custody", custody.said.to_string())
            .lt("created_at", threshold)
            .limit(TTL_REAPER_BATCH_SIZE as u64);
        let expired: Vec<kels_core::SadObjectEntry> =
            state.repo.sad_objects.pool.fetch(expired_query).await?;

        for entry in &expired {
            // Delete from DB (via repository method for consistency with `once` path)
            state
                .repo
                .sad_objects
                .delete_by_sad_said(&entry.sad_said)
                .await?;

            // Delete from MinIO (best-effort — if this fails, orphaned object
            // is harmless and will be cleaned up on next cycle or manually)
            if let Err(e) = state.object_store.delete(&entry.sad_said).await {
                warn!(
                    "Failed to delete expired object {} from MinIO: {}",
                    entry.sad_said, e
                );
            } else {
                debug!("Reaped expired SAD object: {}", entry.sad_said);
            }
        }
    }

    Ok(())
}

/// Max chain records per prefix per day. Low — chains represent stable state.
fn max_records_per_prefix_per_day() -> u32 {
    kels_core::env_usize("SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY", 8) as u32
}

/// Max write operations per IP per second (token bucket refill rate).
fn max_writes_per_ip_per_second() -> u32 {
    kels_core::env_usize("SADSTORE_MAX_WRITES_PER_IP_PER_SECOND", 256) as u32
}

/// Token bucket burst size per IP.
fn ip_rate_limit_burst() -> u32 {
    kels_core::env_usize("SADSTORE_IP_RATE_LIMIT_BURST", 1024) as u32
}

/// Max SAD object size in bytes (default 1 MiB).
pub fn max_sad_object_size() -> usize {
    kels_core::env_usize("SADSTORE_MAX_OBJECT_SIZE", 1024 * 1024)
}

/// Per-chain-prefix daily rate limit. Checks whether adding `record_count` new
/// records would exceed the daily limit. Does NOT update the counter — call
/// `accrue_prefix_rate_limit` after storage with the actual new record count.
fn check_prefix_rate_limit(
    limits: &DashMap<cesr::Digest256, (u32, Instant)>,
    prefix: &cesr::Digest256,
    record_count: u32,
) -> Result<(), String> {
    let now = Instant::now();
    let max_records = max_records_per_prefix_per_day();
    let mut entry = limits.entry(*prefix).or_insert((0, now));

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
    limits: &DashMap<cesr::Digest256, (u32, Instant)>,
    prefix: &cesr::Digest256,
    new_record_count: u32,
) {
    let now = Instant::now();
    let mut entry = limits.entry(*prefix).or_insert((0, now));
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
    pub kels_client: kels_core::KelsClient,
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    pub registry_urls: Vec<String>,
    pub prefix_rate_limits: DashMap<cesr::Digest256, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
    pub nonce_cache: DashMap<cesr::Nonce256, Instant>,
}

// ==================== Peer Authentication ====================

/// Look up a verified peer from Redis cache, returning the full Peer data.
async fn get_verified_peer(
    redis_conn: &redis::aio::ConnectionManager,
    peer_kel_prefix: &cesr::Digest256,
) -> Result<Option<kels_core::Peer>, (StatusCode, String)> {
    let mut conn = redis_conn.clone();
    let json: Option<String> = conn
        .get(format!("kels:verified-peer:{}", peer_kel_prefix))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis error: {}", e),
            )
        })?;
    json.map(|j| {
        serde_json::from_str::<kels_core::Peer>(&j).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Deserialization failed: {}", e),
            )
        })
    })
    .transpose()
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

    let peers_response = kels_core::with_failover(
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
                format!("kels:verified-peer:{}", peer.kel_prefix),
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
/// and verifies the request signature against the peer's current verification key.
// TODO(#82): filter signatures down to only prefixes referenced by the applicable
// policy before iterating — prevents amplification
async fn authenticate_peer_request<T: verifiable_storage::SelfAddressed + serde::Serialize>(
    state: &AppState,
    signed_request: &kels_core::SignedRequest<T>,
    created_at: &verifiable_storage::StorageDatetime,
    nonce: &cesr::Nonce256,
) -> Result<std::collections::HashSet<cesr::Digest256>, (StatusCode, String)> {
    if !kels_core::validate_timestamp(created_at.inner().timestamp(), 60) {
        return Err((StatusCode::FORBIDDEN, "Request timestamp expired".into()));
    }

    // Nonce deduplication
    let window = nonce_window_secs();
    if window > 0 {
        let now = Instant::now();
        if state.nonce_cache.insert(*nonce, now).is_some() {
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

    let kel_source = state.kels_client.as_kel_source().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to build HTTP client: {}", e),
        )
    })?;

    // Check if any prefix is unknown, and refresh the peer cache at most once
    let mut needs_refresh = false;
    for prefix in signed_request.signatures.keys() {
        if get_verified_peer(redis_conn, prefix).await?.is_none() {
            needs_refresh = true;
            break;
        }
    }
    if needs_refresh {
        refresh_verified_peers(redis_conn, &state.registry_urls).await?;
    }

    let mut verifications = std::collections::HashMap::new();
    for prefix in signed_request.signatures.keys() {
        if get_verified_peer(redis_conn, prefix).await?.is_none() {
            continue; // Skip unauthorized peer
        }

        // Verify peer's KEL via KELS service
        let verifier = kels_core::KelVerifier::new(prefix);
        match kels_core::verify_key_events(
            prefix,
            &kel_source,
            verifier,
            kels_core::page_size(),
            kels_core::max_pages(),
        )
        .await
        {
            Ok(kel_verification) => {
                verifications.insert(*prefix, kel_verification);
            }
            Err(_) => continue, // Skip signers whose KEL can't be verified
        }
    }

    let verified = signed_request.verify_signatures(&verifications);

    if verified.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "No valid signatures from authorized peers".into(),
        ));
    }

    Ok(verified)
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

    // Parse JSON
    let mut value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    // Verify SAID — reject tampered or malformed documents
    if value.verify_said().is_err() {
        return (StatusCode::BAD_REQUEST, "SAID verification failed").into_response();
    }

    // Phase 1: compact in memory — compute SAIDs, build compacted JSON, collect
    // nested SAD bytes. No MinIO writes yet (prevents resource amplification).
    let collected = match crate::compaction::compact_sad(&mut value) {
        Ok(c) => c,
        Err(e) => {
            warn!("Compaction failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "compaction error").into_response();
        }
    };

    // Derive canonical SAID on the fully compacted form
    if value.derive_said().is_err() {
        return (StatusCode::BAD_REQUEST, "SAID derivation failed").into_response();
    }

    let said = value.get_said();

    // HEAD check — short-circuit if already exists (before any MinIO writes)
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

    // Phase 2: commit nested SADs to MinIO (only after HEAD check passes)
    if let Err(e) = crate::compaction::commit_compacted(&collected, &state.object_store).await {
        warn!("Failed to commit nested SADs: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Extract and validate custody if present
    let custody_said =
        match extract_and_cache_custody(&value, kels_core::SadCustodyContext::Object, &state).await
        {
            Ok(said) => said,
            Err(response) => return response,
        };

    // Store compacted parent SAD in MinIO + track in DB index with custody
    let compacted_bytes = match serde_json::to_vec(&value) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to serialize compacted SAD: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "serialization error").into_response();
        }
    };

    if let Err(e) = state
        .repo
        .sad_objects
        .store(&said, custody_said, &state.object_store, &compacted_bytes)
        .await
    {
        warn!("Failed to store SAD object: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Gossip: check nodes replication policy before publishing
    match resolve_gossip_policy(&custody_said, &state).await {
        GossipPolicy::BroadcastAll => {
            if let Some(ref conn) = state.redis_conn {
                let mut conn = conn.clone();
                if let Err(e) = redis::cmd("PUBLISH")
                    .arg("sad_updates")
                    .arg(said.as_ref())
                    .query_async::<()>(&mut conn)
                    .await
                {
                    warn!("Failed to publish SAD update: {}", e);
                }
            }
        }
        GossipPolicy::LocalOnly => {
            debug!("Skipping gossip: custody.nodes restricts to local/home-node");
        }
    }

    (StatusCode::CREATED, "stored").into_response()
}

/// Gossip replication decision for a record.
enum GossipPolicy {
    /// No nodes restriction — broadcast to all peers (default).
    BroadcastAll,
    /// Nodes present with 0 or 1 entries — keep at origin, no gossip.
    LocalOnly,
}

/// Resolve the gossip policy from a custody SAID.
///
/// No `nodes` field → BroadcastAll. If `nodes` is present, resolves the
/// NodeSet from MinIO: 0 prefixes → LocalOnly (local cache), 1 prefix →
/// LocalOnly (home-node), >1 prefixes → LocalOnly (selective multi-node
/// gossip not yet implemented — records are accepted but not replicated).
///
/// Fails secure: if `nodes` is set but can't be resolved, skip gossip
/// (LocalOnly) to avoid leaking restricted data to unauthorized peers.
async fn resolve_gossip_policy(
    custody_said: &Option<cesr::Digest256>,
    state: &AppState,
) -> GossipPolicy {
    let Some(said) = custody_said else {
        return GossipPolicy::BroadcastAll;
    };

    let custody = match state.repo.custodies.get_by_said(said).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            warn!(
                "Custody {} referenced but not cached — skipping gossip (fail secure)",
                said
            );
            return GossipPolicy::LocalOnly;
        }
        Err(e) => {
            warn!(
                "Failed to resolve custody {} — skipping gossip (fail secure): {}",
                said, e
            );
            return GossipPolicy::LocalOnly;
        }
    };

    let Some(nodes_said) = custody.nodes else {
        return GossipPolicy::BroadcastAll;
    };

    // Resolve the NodeSet from MinIO to check prefix count.
    // Fail secure: if resolution fails, skip gossip rather than broadcasting
    // restricted data to all peers.
    match state.object_store.get(&nodes_said).await {
        Ok(data) => {
            if let Ok(node_set) = serde_json::from_slice::<kels_core::NodeSet>(&data) {
                if node_set.prefixes.len() <= 1 {
                    GossipPolicy::LocalOnly
                } else {
                    // TODO: selective multi-node gossip — resolve target peers
                    // from the NodeSet prefix list and forward only to them.
                    // For now, skip gossip; the record is stored locally and
                    // will be available when selective replication is implemented.
                    debug!(
                        "NodeSet {} has {} prefixes — skipping gossip until selective multi-node replication is implemented",
                        nodes_said,
                        node_set.prefixes.len()
                    );
                    GossipPolicy::LocalOnly
                }
            } else {
                warn!(
                    "Failed to parse NodeSet {} — skipping gossip (fail secure)",
                    nodes_said
                );
                GossipPolicy::LocalOnly
            }
        }
        Err(e) => {
            warn!(
                "Failed to resolve NodeSet {} — skipping gossip (fail secure): {}",
                nodes_said, e
            );
            GossipPolicy::LocalOnly
        }
    }
}

/// Extract the `custody` key from a compacted SAD, validate it, and cache
/// the custody and any referenced policies in Postgres.
/// Returns `Ok(Some(custody_said))` if custody is present and enforced,
/// `Ok(None)` if absent or safety-valve disengaged.
async fn extract_and_cache_custody(
    value: &serde_json::Value,
    context: kels_core::SadCustodyContext,
    state: &AppState,
) -> Result<Option<cesr::Digest256>, axum::response::Response> {
    let custody_value = match value.get("custody") {
        Some(v) if v.is_string() => {
            // Already compacted to a SAID string — resolve from cache/MinIO,
            // validate, and cache before accepting.
            let custody_said_str = v.as_str().unwrap_or_default();
            let custody_said = cesr::Digest256::from_qb64(custody_said_str)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid custody SAID").into_response())?;
            return resolve_and_cache_custody_by_said(&custody_said, context, state).await;
        }
        Some(v) if v.is_object() => v.clone(),
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "custody must be an object or SAID string",
            )
                .into_response());
        }
        None => return Ok(None),
    };

    // Validate the custody object
    let custody = match kels_core::parse_and_validate_custody(&custody_value, context) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None), // Safety valve — unknown fields, no enforcement
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string()).into_response()),
    };

    // Verify custody SAID
    if custody.verify_said().is_err() {
        return Err((StatusCode::BAD_REQUEST, "Custody SAID verification failed").into_response());
    }

    let custody_said = custody.said;

    // Cache custody in Postgres (idempotent)
    state.repo.custodies.store(&custody).await.map_err(|e| {
        warn!("Failed to cache custody: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
    })?;

    cache_referenced_policies(&custody, state).await?;

    Ok(Some(custody_said))
}

/// Resolve a pre-compacted custody SAID: fetch from cache (or MinIO fallback),
/// validate the allowlist for the given context, and cache custody + policies.
/// Rejects if the custody is unresolvable or fails context validation.
async fn resolve_and_cache_custody_by_said(
    custody_said: &cesr::Digest256,
    context: kels_core::SadCustodyContext,
    state: &AppState,
) -> Result<Option<cesr::Digest256>, axum::response::Response> {
    // Try Postgres cache first
    let custody = if let Ok(Some(c)) = state.repo.custodies.get_by_said(custody_said).await {
        c
    } else {
        // Fallback: fetch from MinIO
        let data = state
            .object_store
            .get(custody_said)
            .await
            .map_err(|e| match e {
                crate::object_store::ObjectStoreError::NotFound(_) => (
                    StatusCode::BAD_REQUEST,
                    format!("Referenced custody {} not found in SADStore", custody_said),
                )
                    .into_response(),
                other => {
                    warn!("Failed to fetch custody {}: {}", custody_said, other);
                    (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
                }
            })?;

        let custody: kels_core::Custody = serde_json::from_slice(&data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse custody {}: {}", custody_said, e),
            )
                .into_response()
        })?;

        if custody.verify_said().is_err() {
            return Err(
                (StatusCode::BAD_REQUEST, "Custody SAID verification failed").into_response(),
            );
        }

        // Cache for future lookups
        if let Err(e) = state.repo.custodies.store(&custody).await {
            warn!("Failed to cache custody {}: {}", custody_said, e);
        }

        custody
    };

    // Validate context-specific allowlist
    let custody_json = serde_json::to_value(&custody).map_err(|e| {
        warn!("Failed to serialize custody for validation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    })?;
    match kels_core::parse_and_validate_custody(&custody_json, context) {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None), // Safety valve
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string()).into_response()),
    }

    cache_referenced_policies(&custody, state).await?;

    Ok(Some(*custody_said))
}

/// Cache the write_policy and read_policy SADs referenced by a custody.
/// Fetches each from MinIO if not already cached in Postgres.
async fn cache_referenced_policies(
    custody: &kels_core::Custody,
    state: &AppState,
) -> Result<(), axum::response::Response> {
    for policy_said in [custody.write_policy, custody.read_policy]
        .into_iter()
        .flatten()
    {
        if state
            .repo
            .policies
            .get_by_said(&policy_said)
            .await
            .unwrap_or(None)
            .is_some()
        {
            continue;
        }

        match state.object_store.get(&policy_said).await {
            Ok(data) => {
                if let Ok(policy) = serde_json::from_slice::<kels_policy::Policy>(&data)
                    && policy.verify_said().is_ok()
                    && let Err(e) = state.repo.policies.store(&policy).await
                {
                    warn!("Failed to cache policy {}: {}", policy_said, e);
                }
            }
            Err(crate::object_store::ObjectStoreError::NotFound(_)) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Referenced policy {} not found in SADStore", policy_said),
                )
                    .into_response());
            }
            Err(e) => {
                warn!("Failed to fetch policy {}: {}", policy_said, e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response());
            }
        }
    }

    Ok(())
}

pub async fn fetch_sad_object(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    // Try parsing as SignedRequest<SadFetchRequest> first, fall back to SadRequest
    let (object_said, signed_request, disclosure) = match parse_fetch_request(&body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };

    // Validate disclosure expression early — before custody consumption logic.
    // An invalid expression must not consume a once-use object.
    if let Some(ref d) = disclosure
        && let Err(e) = kels_core::parse_disclosure(d)
    {
        return (StatusCode::BAD_REQUEST, format!("invalid disclosure: {e}")).into_response();
    }

    // Look up the record in sad_objects to get custody info
    let entry = match state.repo.sad_objects.get_by_sad_said(&object_said).await {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
        Err(e) => {
            warn!("Failed to look up SAD object: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    };

    // No custody → serve directly
    let Some(custody_said) = entry.custody else {
        return serve_sad(&state.object_store, &object_said, disclosure.as_deref()).await;
    };

    // Fetch cached custody
    let custody = match state.repo.custodies.get_by_said(&custody_said).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            warn!("Custody {} referenced but not cached", custody_said);
            return (StatusCode::INTERNAL_SERVER_ERROR, "custody not found").into_response();
        }
        Err(e) => {
            warn!("Failed to fetch custody: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    };

    // readPolicy enforcement
    if let Some(ref record_read_policy) = custody.read_policy {
        let Some(ref signed) = signed_request else {
            return (
                StatusCode::FORBIDDEN,
                "readPolicy requires authenticated request",
            )
                .into_response();
        };

        // Verify signatures and evaluate policy
        let verified = match authenticate_fetch_request(&state, signed).await {
            Ok(v) => v,
            Err(response) => return response,
        };

        let policy_resolver = SadStorePolicyResolver {
            policies: state.repo.clone(),
            object_store: state.object_store.clone(),
        };

        match kels_policy::evaluate_signed_policy(record_read_policy, &verified, &policy_resolver)
            .await
        {
            Ok(v) if v.is_satisfied => {}
            Ok(_) => {
                return (StatusCode::FORBIDDEN, "readPolicy not satisfied").into_response();
            }
            Err(e) => {
                warn!("Policy evaluation failed: {}", e);
                return (StatusCode::FORBIDDEN, "policy evaluation failed").into_response();
            }
        }
    }

    // TTL check (per-record: sad_objects.created_at + custodies.ttl)
    if let Some(ttl) = custody.ttl {
        let created = entry.created_at.inner().timestamp();
        let now = verifiable_storage::StorageDatetime::now()
            .inner()
            .timestamp();
        if now > created + ttl as i64 {
            return (StatusCode::NOT_FOUND, "expired").into_response();
        }
    }

    // once: atomic delete — if we delete the row, we serve; if count=0, already consumed
    if custody.once == Some(true) {
        match state
            .repo
            .sad_objects
            .delete_by_sad_said(&object_said)
            .await
        {
            Ok(1) => {
                // We consumed it — serve from MinIO. If MinIO fetch fails after
                // the PG delete, the record becomes inaccessible. Acceptable for
                // ephemeral records — that's the semantics of once.
                let response =
                    serve_sad(&state.object_store, &object_said, disclosure.as_deref()).await;

                // Best-effort MinIO cleanup — prevents orphaned objects from
                // accumulating. The reaper catches failures on its next cycle.
                let os = state.object_store.clone();
                let said = object_said;
                tokio::spawn(async move {
                    if let Err(e) = os.delete(&said).await {
                        warn!("Failed to delete consumed once object {}: {}", said, e);
                    }
                });

                return response;
            }
            Ok(0) => {
                return (StatusCode::NOT_FOUND, "already consumed").into_response();
            }
            Ok(_) => {
                warn!("Unexpected delete count for once object {}", object_said);
                return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
            }
            Err(e) => {
                warn!("Failed to delete once object: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
            }
        }
    }

    serve_sad(&state.object_store, &object_said, disclosure.as_deref()).await
}

/// Parse a fetch request body as either `SignedRequest<SadFetchRequest>` or `SadRequest`.
/// Returns `(object_said, signed_request, disclosure)`.
#[allow(clippy::result_large_err, clippy::type_complexity)]
fn parse_fetch_request(
    body: &[u8],
) -> Result<
    (
        cesr::Digest256,
        Option<kels_core::SignedRequest<kels_core::SignedSadFetchRequest>>,
        Option<String>,
    ),
    axum::response::Response,
> {
    // Try authenticated request first
    if let Ok(signed) =
        serde_json::from_slice::<kels_core::SignedRequest<kels_core::SignedSadFetchRequest>>(body)
    {
        let disclosure = signed.payload.disclosure.clone();
        return Ok((signed.payload.object_said, Some(signed), disclosure));
    }

    // Fall back to unauthenticated request
    if let Ok(request) = serde_json::from_slice::<kels_core::SadFetchRequest>(body) {
        let disclosure = request.disclosure.clone();
        return Ok((request.said, None, disclosure));
    }

    Err((StatusCode::BAD_REQUEST, "Invalid request body").into_response())
}

/// Verify signatures on a fetch request and return verified prefixes.
async fn authenticate_fetch_request(
    state: &AppState,
    signed: &kels_core::SignedRequest<kels_core::SignedSadFetchRequest>,
) -> Result<std::collections::HashSet<cesr::Digest256>, axum::response::Response> {
    authenticate_peer_request(
        state,
        signed,
        &signed.payload.created_at,
        &signed.payload.nonce,
    )
    .await
    .map_err(|(status, msg)| (status, msg).into_response())
}

/// Serve a SAD object, applying disclosure expansion if requested.
///
/// If `disclosure` is None, serves raw bytes from MinIO (no parsing overhead).
/// If `disclosure` is Some, applies heuristic expansion via the disclosure DSL.
async fn serve_sad(
    object_store: &ObjectStore,
    said: &cesr::Digest256,
    disclosure: Option<&str>,
) -> axum::response::Response {
    let Some(disclosure) = disclosure else {
        return serve_from_minio(object_store, said).await;
    };

    match crate::expansion::apply_disclosure_to_sad(said, disclosure, object_store).await {
        Ok(expanded) => match serde_json::to_vec(&expanded) {
            Ok(data) => (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                data,
            )
                .into_response(),
            Err(e) => {
                warn!("Failed to serialize expanded SAD: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "serialization error").into_response()
            }
        },
        Err(kels_core::KelsError::InvalidDisclosure(msg)) => (
            StatusCode::BAD_REQUEST,
            format!("invalid disclosure: {msg}"),
        )
            .into_response(),
        Err(kels_core::KelsError::NotFound(msg)) => {
            (StatusCode::NOT_FOUND, format!("not found: {msg}")).into_response()
        }
        Err(e) => {
            warn!("Disclosure expansion failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "expansion error").into_response()
        }
    }
}

/// Serve a SAD object directly from MinIO (no disclosure expansion).
async fn serve_from_minio(
    object_store: &ObjectStore,
    said: &cesr::Digest256,
) -> axum::response::Response {
    match object_store.get(said).await {
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

/// Policy resolver backed by the Postgres `policies` cache with MinIO fallback.
/// Fail secure: if a policy can't be resolved, return an error.
struct SadStorePolicyResolver {
    policies: Arc<SadStoreRepository>,
    object_store: Arc<ObjectStore>,
}

#[async_trait::async_trait]
impl kels_policy::PolicyResolver for SadStorePolicyResolver {
    async fn resolve_policy(
        &self,
        said: &cesr::Digest256,
    ) -> Result<kels_policy::Policy, kels_policy::PolicyError> {
        // Hot path: Postgres cache
        if let Ok(Some(policy)) = self.policies.policies.get_by_said(said).await {
            return Ok(policy);
        }

        // Fallback: MinIO
        let data = self
            .object_store
            .get(said)
            .await
            .map_err(|e| kels_policy::PolicyError::ResolutionError(e.to_string()))?;

        let policy: kels_policy::Policy = serde_json::from_slice(&data)
            .map_err(|e| kels_policy::PolicyError::ResolutionError(e.to_string()))?;

        policy.verify_said().map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!("SAID verification failed: {}", e))
        })?;

        // Cache for next time (best-effort)
        let _ = self.policies.policies.store(&policy).await;

        Ok(policy)
    }
}

pub async fn sad_object_exists(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadFetchRequest>,
) -> impl IntoResponse {
    match state.object_store.exists(&request.said).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            warn!("Failed to check SAD object existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn sad_event_exists(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadFetchRequest>,
) -> impl IntoResponse {
    match state.repo.sad_events.exists(&request.said).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            warn!("Failed to check event existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// === Layer 2: Chain Records (Postgres) ===

/// Page through existing chain records in a transaction, feeding each page to the verifier.
async fn verify_existing_chain<Tx: TransactionExecutor>(
    tx: &mut Tx,
    repo: &SadEventRepository,
    prefix: &cesr::Digest256,
    verifier: &mut kels_core::SelVerifier<'_>,
) -> Result<(), axum::response::Response> {
    let page_size = kels_core::page_size() as u64;
    let mut since: Option<cesr::Digest256> = None;
    loop {
        let page = repo
            .get_stored_in(
                tx,
                prefix.as_ref(),
                since.as_ref().map(|s| s.as_ref()),
                Some(page_size),
            )
            .await
            .map_err(|e| {
                warn!("Failed to fetch chain for verification: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
            })?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        since = page.last().map(|r| r.said);
        verifier.verify_page(&page).await.map_err(|e| {
            warn!("Chain verification failed: {}", e);
            (
                StatusCode::CONFLICT,
                format!("Chain verification failed: {}", e),
            )
                .into_response()
        })?;
        if (page_len as u64) < page_size {
            break;
        }
    }
    Ok(())
}

/// Submit SAD event records — unified endpoint for clients, gossip sync, and repair.
///
/// Accepts `Vec<SadEvent>`. Validates structure (SAID, prefix consistency)
/// and write_policy authorization via verify-then-extend: re-verifies the entire
/// existing chain from scratch, then verifies new records in context. Rejects
/// unauthorized write_policy advances with 403.
///
/// When any submitted record has `kind: Rpr`, the handler takes the repair path:
/// truncates all records at version >= the first record's version, then re-verifies
/// the entire chain including the repair records.
pub async fn submit_sad_event(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(records): Json<Vec<kels_core::SadEvent>>,
) -> impl IntoResponse {
    if records.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty batch").into_response();
    }

    // Per-IP rate limit
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // All records must be for the same chain prefix
    let chain_prefix = &records[0].prefix;
    if records.iter().any(|r| r.prefix != *chain_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            "All records must have the same prefix",
        )
            .into_response();
    }

    // Verify SAID integrity for all records
    for r in &records {
        if r.verify_said().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("Record SAID verification failed: {}", r.said),
            )
                .into_response();
        }
    }

    // Verify prefix derivation for v0 if present
    if let Some(v0) = records.iter().find(|r| r.version == 0)
        && v0.verify_prefix().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            "Prefix derivation verification failed",
        )
            .into_response();
    }

    // Validate custody for event context — reject ttl/once (structurally
    // incompatible with chained data). This is a hard design requirement.
    // Check every unique custody SAID in the batch, not just the first record.
    {
        let mut validated_custodies = std::collections::HashSet::new();
        for record in &records {
            if let Some(custody_said) = record.custody
                && validated_custodies.insert(custody_said)
                && let Err(response) = resolve_and_cache_custody_by_said(
                    &custody_said,
                    kels_core::SadCustodyContext::Event,
                    &state,
                )
                .await
            {
                return response;
            }
        }
    }

    // Transactional verify-then-extend: advisory lock + verification + write in one transaction.
    // Follows the KEL merge engine pattern (merge.rs). Rollback on any failure.
    let new_record_count;
    let should_publish;
    let mut diverged_at_version: Option<u64> = None;
    let is_repair;

    {
        let kel_source = match state.kels_client.as_kel_source() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to build KEL source: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build KEL source",
                )
                    .into_response();
            }
        };
        let policy_resolver = SadStorePolicyResolver {
            policies: state.repo.clone(),
            object_store: state.object_store.clone(),
        };

        let mut tx = match state.repo.sad_events.pool.begin_transaction().await {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Failed to begin transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };

        if let Err(e) = tx.acquire_advisory_lock(chain_prefix.as_ref()).await {
            warn!("Failed to acquire advisory lock: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }

        // Dedup first: filter out records that already exist in the DB.
        // This is a SAID existence check — no verification needed.
        // Historical Rpr records dedup out; only genuinely new Rpr records trigger repair.
        let new_records: Vec<kels_core::SadEvent> = {
            let submitted_saids: Vec<String> = records.iter().map(|r| r.said.to_string()).collect();
            let query =
                verifiable_storage_postgres::Query::<kels_core::SadEvent>::for_table("sad_events")
                    .r#in("said", submitted_saids);
            let existing_saids: std::collections::HashSet<cesr::Digest256> =
                match tx.fetch(query).await {
                    Ok(existing) => existing
                        .into_iter()
                        .map(|r: kels_core::SadEvent| r.said)
                        .collect(),
                    Err(e) => {
                        warn!("Failed to query existing SAIDs: {}", e);
                        let _ = tx.rollback().await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e))
                            .into_response();
                    }
                };
            records
                .iter()
                .filter(|r| !existing_saids.contains(&r.said))
                .cloned()
                .collect()
        };

        if new_records.is_empty() {
            if let Err(e) = tx.commit().await {
                warn!("Failed to commit transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
            let response = kels_core::SubmitSadEventsResponse {
                diverged_at: None,
                applied: false,
            };
            return (StatusCode::CREATED, Json(response)).into_response();
        }

        // Per-chain-prefix daily rate limit (check before, accrue after dedup)
        if let Err(msg) = check_prefix_rate_limit(
            &state.prefix_rate_limits,
            chain_prefix,
            new_records.len() as u32,
        ) {
            let _ = tx.rollback().await;
            return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
        }

        // Detect repair from post-dedup records — only genuinely new Rpr records trigger repair.
        is_repair = new_records.iter().any(|r| r.kind.is_repair());

        if is_repair {
            // Query the checkpoint seal before truncation — reject repairs behind the seal.
            let last_cp_version = match state
                .repo
                .sad_events
                .last_governance_version(&mut tx, chain_prefix)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to query last checkpoint version: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
                }
            };

            // Repair path: truncate/archive first, then verify remaining + repair records.
            // truncate_and_replace does the archival within this transaction.
            let from_version = match state
                .repo
                .sad_events
                .truncate_and_replace(&mut tx, &records)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to truncate for repair: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::CONFLICT, format!("{}", e)).into_response();
                }
            };

            // Repair must not truncate behind the checkpoint seal
            if let Some(cp_version) = last_cp_version
                && from_version <= cp_version
            {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Cannot repair at version {} — sealed by checkpoint at version {}",
                        from_version, cp_version
                    ),
                )
                    .into_response();
            }

            // Repair must include a checkpoint at or after the divergence point —
            // an attacker who can only satisfy write_policy cannot repair
            // (governance_policy is a higher bar).
            if !new_records
                .iter()
                .any(|r| r.version >= from_version && r.kind.evaluates_governance())
            {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    "repair must include a checkpoint at or after the divergence point",
                )
                    .into_response();
            }

            // Now verify the entire chain (post-truncation + repair records) from scratch.
            let checker = kels_policy::AnchoredPolicyChecker::new(&kel_source, &policy_resolver);
            let mut verifier = kels_core::SelVerifier::new(chain_prefix, &checker);
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, chain_prefix, &mut verifier)
                    .await
            {
                let _ = tx.rollback().await;
                return response;
            }

            let verification = match verifier.finish().await {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.rollback().await;
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Chain verification failed: {}", e),
                    )
                        .into_response();
                }
            };

            if !verification.policy_satisfied() {
                let _ = tx.rollback().await;
                return (StatusCode::FORBIDDEN, "write_policy not authorized").into_response();
            }

            // Repair must not truncate at or before the establishment point
            if let Some(est_version) = verification.establishment_version()
                && from_version <= est_version
            {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Cannot repair at version {} — establishment record at version {}",
                        from_version, est_version
                    ),
                )
                    .into_response();
            }

            new_record_count = new_records.len() as u32;
            should_publish = true;
        } else {
            // Normal path: verify existing chain + new records, then save.
            let checker = kels_policy::AnchoredPolicyChecker::new(&kel_source, &policy_resolver);
            let mut verifier = kels_core::SelVerifier::new(chain_prefix, &checker);
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, chain_prefix, &mut verifier)
                    .await
            {
                let _ = tx.rollback().await;
                return response;
            }

            if let Err(e) = verifier.verify_page(&new_records).await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Record verification failed: {}", e),
                )
                    .into_response();
            }

            let verification = match verifier.finish().await {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.rollback().await;
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Chain verification failed: {}", e),
                    )
                        .into_response();
                }
            };

            if !verification.policy_satisfied() {
                let _ = tx.rollback().await;
                return (StatusCode::FORBIDDEN, "write_policy not authorized").into_response();
            }

            match state
                .repo
                .sad_events
                .save_batch(
                    &mut tx,
                    &new_records,
                    verification.last_governance_version(),
                )
                .await
            {
                Ok(result) => {
                    let count = match &result {
                        crate::repository::SaveBatchResult::Accepted { new_count } => *new_count,
                        crate::repository::SaveBatchResult::DivergenceCreated {
                            new_count,
                            diverged_at_version: version,
                        } => {
                            diverged_at_version = Some(*version);
                            *new_count
                        }
                    };
                    new_record_count = count;
                    should_publish = count > 0;
                }
                Err(e) => {
                    warn!("Failed to store records: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::CONFLICT, format!("{}", e)).into_response();
                }
            }
        }

        if let Err(e) = tx.commit().await {
            warn!("Failed to commit transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }
    }

    // Accrue only actual new records to prefix rate limit
    accrue_prefix_rate_limit(&state.prefix_rate_limits, chain_prefix, new_record_count);

    // Check nodes replication policy for gossip
    let event_custody = records.first().and_then(|r| r.custody);
    if matches!(
        resolve_gossip_policy(&event_custody, &state).await,
        GossipPolicy::LocalOnly
    ) {
        debug!("Skipping event gossip: custody.nodes restricts to local/home-node");
        let response = kels_core::SubmitSadEventsResponse {
            diverged_at: diverged_at_version,
            applied: new_record_count > 0,
        };
        return (StatusCode::CREATED, Json(response)).into_response();
    }

    // Publish the effective SAID to Redis for gossip.
    let effective_said = if should_publish {
        match state.repo.sad_events.effective_said(chain_prefix).await {
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
    match (&state.redis_conn, &effective_said) {
        (Some(conn), Some(said)) => {
            let mut conn = conn.clone();
            let message = format!("{}:{}", chain_prefix, said);
            if let Err(e) = redis::cmd("PUBLISH")
                .arg("sel_updates")
                .arg(&message)
                .query_async::<()>(&mut conn)
                .await
            {
                warn!("Failed to publish chain update: {}", e);
            } else {
                debug!(
                    chain_prefix = %chain_prefix,
                    effective_said = %said,
                    "Published chain update to Redis"
                );
            }
        }
        (None, _) => {
            debug!("Skipping chain publish: no Redis connection");
        }
        (_, None) => {
            debug!(
                chain_prefix = %chain_prefix,
                should_publish = should_publish,
                "Skipping chain publish: no effective SAID"
            );
        }
    }

    let response = kels_core::SubmitSadEventsResponse {
        diverged_at: diverged_at_version,
        applied: new_record_count > 0,
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

pub async fn get_sad_event(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadEventPageRequest>,
) -> impl IntoResponse {
    let prefix = request.prefix;
    let page_size = kels_core::page_size();
    let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
    let since_str = request.since.as_ref().map(|s| s.as_ref());

    match state
        .repo
        .sad_events
        .get_stored(prefix.as_ref(), since_str, Some(limit + 1))
        .await
    {
        Ok(records) if records.is_empty() => {
            (StatusCode::NOT_FOUND, "Chain not found").into_response()
        }
        Ok(events) => {
            let has_more = events.len() as u64 > limit;
            let records: Vec<_> = events.into_iter().take(limit as usize).collect();
            let page = kels_core::SadEventPage {
                has_more,
                events: records,
            };
            (StatusCode::OK, Json(page)).into_response()
        }
        Err(e) => {
            warn!("Failed to get chain: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub async fn get_sad_event_effective_said(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadEventEffectiveSaidRequest>,
) -> impl IntoResponse {
    match state.repo.sad_events.effective_said(&request.prefix).await {
        Ok(Some((said, divergent))) => (
            StatusCode::OK,
            Json(kels_core::EffectiveSaidResponse { said, divergent }),
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
    cursor: Option<&cesr::Digest256>,
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

/// Shared query logic for listing SAD Event Log prefixes.
async fn query_sad_prefixes(
    state: &AppState,
    cursor: Option<&cesr::Digest256>,
    limit: Option<usize>,
) -> impl IntoResponse {
    let limit = limit
        .unwrap_or(MAX_PREFIX_PAGE_SIZE)
        .min(MAX_PREFIX_PAGE_SIZE);

    match state.repo.sad_events.list_prefixes(cursor, limit).await {
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
    Json(signed_request): Json<kels_core::SignedRequest<kels_core::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if let Err((status, msg)) = authenticate_peer_request(
        &state,
        &signed_request,
        &signed_request.payload.created_at,
        &signed_request.payload.nonce,
    )
    .await
    {
        return (status, msg).into_response();
    }

    query_sad_objects(
        &state,
        signed_request.payload.cursor.as_ref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

/// Authenticated SAD Event Log prefix listing. Federation peers only.
pub async fn list_sad_event_prefixes(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels_core::SignedRequest<kels_core::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if let Err((status, msg)) = authenticate_peer_request(
        &state,
        &signed_request,
        &signed_request.payload.created_at,
        &signed_request.payload.nonce,
    )
    .await
    {
        return (status, msg).into_response();
    }

    query_sad_prefixes(
        &state,
        signed_request.payload.cursor.as_ref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

// === Layer 2: Chain Repair History ===

pub(crate) async fn get_sad_event_repairs(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadRepairsRequest>,
) -> impl IntoResponse {
    let page_size = kels_core::page_size();
    let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
    let offset = request.offset.unwrap_or(0);

    match state
        .repo
        .sad_events
        .get_repairs(request.prefix.as_ref(), limit, offset)
        .await
    {
        Ok((repairs, has_more)) => (
            StatusCode::OK,
            Json(kels_core::SadEventRepairPage { repairs, has_more }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to get repairs for {}: {}", request.prefix, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub(crate) async fn get_sad_event_repair_records(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadRepairPageRequest>,
) -> impl IntoResponse {
    let page_size = kels_core::page_size();
    let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
    let offset = request.offset.unwrap_or(0);

    match state
        .repo
        .sad_events
        .get_repair_records(request.said.as_ref(), limit, offset)
        .await
    {
        Ok((records, has_more)) => (
            StatusCode::OK,
            Json(kels_core::SadEventPage {
                events: records,
                has_more,
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to get repair records for {}: {}", request.said, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Unauthenticated test endpoint for listing SAD objects.
/// Only available when `KELS_TEST_ENDPOINTS=true`.
pub async fn test_list_sad_objects(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels_core::SignedRequest<kels_core::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    query_sad_objects(
        &state,
        signed_request.payload.cursor.as_ref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}

/// Unauthenticated test endpoint for listing SAD Event Log prefixes.
/// Only available when `KELS_TEST_ENDPOINTS=true`.
pub async fn test_list_sad_event_prefixes(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<kels_core::SignedRequest<kels_core::PaginatedSelfAddressedRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    query_sad_prefixes(
        &state,
        signed_request.payload.cursor.as_ref(),
        signed_request.payload.limit,
    )
    .await
    .into_response()
}
