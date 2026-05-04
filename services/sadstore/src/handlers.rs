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
use dashmap::DashMap;
use kels_core::IelResolver;
use redis::AsyncCommands;
use tracing::{debug, warn};
use verifiable_storage::{Chained, QueryExecutor, SelfAddressed, TransactionExecutor};

use crate::{
    object_store::ObjectStore,
    repository::{SadEventRepository, SadStoreRepository},
};

use crate::iel_resolver::RepositoryIelResolver;

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

/// Max expired objects to reap per cycle.
const TTL_REAPER_BATCH_SIZE: usize = 100;

/// Spawn a background task that periodically deletes TTL-expired objects.
/// Queries `sad_object_lifecycles` for rows with `availability_ttl` set,
/// joins to the index entry's `created_at`, and reaps expired SADs from DB
/// and object store.
pub fn spawn_ttl_reaper(state: Arc<AppState>) {
    let interval = Duration::from_secs(ttl_reaper_interval_secs());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = reap_expired_objects(&state).await {
                warn!("TTL reaper error: {}", e);
            }
        }
    });
}

async fn reap_expired_objects(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = verifiable_storage::StorageDatetime::now();
    let now_ts = now.inner().timestamp();

    let candidates = state
        .repo
        .sad_objects
        .fetch_ttl_set(TTL_REAPER_BATCH_SIZE as u64)
        .await?;

    for (sad_said, ttl, created_at) in candidates {
        let created = created_at.inner().timestamp();
        if now_ts <= created + ttl as i64 {
            continue;
        }

        // Expired — delete the index entry and the object store blob
        // (best-effort on the blob).
        state.repo.sad_objects.delete_by_sad_said(&sad_said).await?;

        if let Err(e) = state.object_store.delete(&sad_said).await {
            warn!(
                "Failed to delete expired object {} from object store: {}",
                sad_said, e
            );
        } else {
            debug!("Reaped expired SAD object: {}", sad_said);
        }
    }

    Ok(())
}

/// Max SAD events per SEL prefix per day per pod. SELs are the foundational
/// chains (identity built from them, content updates flow through them); a
/// higher ceiling matches their write profile and parallels the KEL daily
/// per-prefix limit.
fn max_sel_events_per_prefix_per_day() -> u32 {
    kels_core::env_usize("SADSTORE_MAX_SEL_EVENTS_PER_PREFIX_PER_DAY", 256) as u32
}

/// Max IEL events per identity prefix per day per pod. IELs evolve slowly
/// (auth/governance policy changes are rare); the tighter ceiling bounds
/// adversary churn at the identity boundary.
fn max_iel_events_per_prefix_per_day() -> u32 {
    kels_core::env_usize("SADSTORE_MAX_IEL_EVENTS_PER_PREFIX_PER_DAY", 8) as u32
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

/// Per-prefix daily rate limit. Checks whether adding `event_count` units
/// of budget would exceed `max_events` over a 24h window. Caller supplies
/// the limit so SEL and IEL submit paths can enforce different ceilings
/// (see `max_sel_events_per_prefix_per_day` and
/// `max_iel_events_per_prefix_per_day`). When `accrue` is `true`, also
/// charges the budget on success — used by the request gate above the
/// dedup branch so duplicate-submit campaigns still consume budget.
fn check_prefix_rate_limit(
    limits: &DashMap<cesr::Digest256, (u32, Instant)>,
    prefix: &cesr::Digest256,
    event_count: u32,
    max_events: u32,
    accrue: bool,
) -> Result<(), String> {
    let now = Instant::now();
    let mut entry = limits.entry(*prefix).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 + event_count > max_events {
        return Err("Too many events for this prefix".to_string());
    }

    if accrue {
        entry.0 += event_count;
    }

    Ok(())
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

/// Fetch verified peers from the registry and store entries in Redis.
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

// === Layer 1: SAD Object Store (object store) ===

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
    // nested SAD bytes. No object store writes yet (prevents resource amplification).
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

    let canonical_said = value.get_said();

    // HEAD check — short-circuit if already exists (before any object store writes)
    match state.object_store.exists(&canonical_said).await {
        Ok(true) => {
            debug!("SAD object already exists: {}", canonical_said);
            return (
                StatusCode::OK,
                Json(kels_core::PostSadObjectResponse {
                    said: canonical_said,
                }),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!("Failed to check SAD object existence: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    }

    // Phase 2: commit nested SADs to object store (only after HEAD check passes)
    if let Err(e) = crate::compaction::commit_compacted(&collected, &state.object_store).await {
        warn!("Failed to commit nested SADs: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Parse inline custody and availability from the (compacted) parent SAD.
    // #167: both are inline JSON objects on the parent — not
    // separately-addressable SADs. Compaction leaves them in place because
    // they have no `said` field.
    let (custody, availability) = match parse_inline_custody_and_availability(&value) {
        Ok(pair) => pair,
        Err(response) => return response,
    };

    // #167 write enforcement: if `custody.write` is set, the named IEL event's
    // `auth_policy` must be satisfied (the canonical SAD's SAID anchored under
    // it). Missing IEL event surfaces as `MissingIelEvent` (deferrable) or
    // `IdentityBindingViolation` (permanent) — both currently map to 400;
    // #156 Gap 4 retrofits the deferrable case to typed 422 with `iel_event`
    // dep type in the deferred-deps protocol.
    if let Some(write_iel_said) = custody.as_ref().and_then(|c| c.write)
        && let Err(response) = verify_custody_write(&state, &canonical_said, &write_iel_said).await
    {
        return response;
    }

    // Store compacted parent SAD in object store + track in DB index. The
    // index entry's columns denormalize the parent SAD's inline
    // `custody.read` and `availability.{nodes,ttl,once}`; all four
    // contribute to the entry's SAID, so the index row is reverifiable
    // against the parent SAD's bytes.
    let compacted_bytes = match serde_json::to_vec(&value) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to serialize compacted SAD: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "serialization error").into_response();
        }
    };

    let custody_read = custody.as_ref().and_then(|c| c.read);
    let availability_nodes = availability.as_ref().and_then(|a| a.nodes);
    let availability_ttl = availability.as_ref().and_then(|a| a.ttl);
    let availability_once = availability.as_ref().and_then(|a| a.once);

    if let Err(e) = state
        .repo
        .sad_objects
        .store(
            &canonical_said,
            custody_read,
            availability_nodes,
            availability_ttl,
            availability_once,
            &state.object_store,
            &compacted_bytes,
        )
        .await
    {
        warn!("Failed to store SAD object: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

    // Gossip: route per inline `availability.nodes`.
    match resolve_gossip_policy(availability.as_ref(), &state).await {
        GossipPolicy::BroadcastAll => {
            if let Some(ref conn) = state.redis_conn {
                let mut conn = conn.clone();
                if let Err(e) = redis::cmd("PUBLISH")
                    .arg("sad_updates")
                    .arg(canonical_said.as_ref())
                    .query_async::<()>(&mut conn)
                    .await
                {
                    warn!("Failed to publish SAD update: {}", e);
                }
            }
        }
        GossipPolicy::LocalOnly => {
            debug!("Skipping gossip: availability.nodes restricts to local/home-node");
        }
    }

    (
        StatusCode::CREATED,
        Json(kels_core::PostSadObjectResponse {
            said: canonical_said,
        }),
    )
        .into_response()
}

/// Parse the inline `custody` and `availability` JSON objects from a SAD
/// value. Both are independently optional. Returns `(None, None)` when both
/// keys are absent. Bad shapes return a 400 response.
#[allow(clippy::result_large_err)]
fn parse_inline_custody_and_availability(
    value: &serde_json::Value,
) -> Result<(Option<kels_core::Custody>, Option<kels_core::Availability>), axum::response::Response>
{
    let custody = match value.get("custody") {
        None => None,
        Some(v) => match kels_core::parse_and_validate_custody(v) {
            Ok(Some(c)) if c.is_empty() => None,
            Ok(Some(c)) => Some(c),
            Ok(None) => None, // safety valve — unknown fields, no enforcement
            Err(e) => {
                return Err((StatusCode::BAD_REQUEST, e.to_string()).into_response());
            }
        },
    };

    let availability = match value.get("availability") {
        None => None,
        Some(v) => match kels_core::parse_and_validate_availability(v) {
            Ok(Some(a)) if a.is_empty() => None,
            Ok(Some(a)) => Some(a),
            Ok(None) => None,
            Err(e) => {
                return Err((StatusCode::BAD_REQUEST, e.to_string()).into_response());
            }
        },
    };

    Ok((custody, availability))
}

/// Gossip replication decision for an object.
enum GossipPolicy {
    /// No nodes restriction — broadcast to all peers (default).
    BroadcastAll,
    /// Nodes present with 0 or 1 entries — keep at origin, no gossip.
    LocalOnly,
}

/// #167 `custody.write` enforcement. Resolves the named IEL event's
/// `auth_policy` and confirms the SAD's canonical SAID is anchored under it.
///
/// Errors map to HTTP responses:
/// - Missing IEL event (`MissingIelEvent` / `IdentityBindingViolation`) →
///   400 with stable shape; #156 (Gap 4) retrofits this to a typed 422
///   with `iel_event` dep type via the deferred-deps protocol.
/// - Divergent / contested / decommissioned IEL → 400 (the chain can't
///   authoritatively prove auth_policy was satisfied at the named event).
/// - Anchor not satisfied → 403.
/// - Storage / resolver failure → 500.
#[allow(clippy::result_large_err)]
async fn verify_custody_write(
    state: &AppState,
    canonical_said: &cesr::Digest256,
    write_iel_said: &cesr::Digest256,
) -> Result<(), axum::response::Response> {
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = state
        .kels_client
        .as_kel_source()
        .map(Arc::new)
        .map_err(|e| {
            warn!("Failed to build KEL source for custody.write check: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build KEL source",
            )
                .into_response()
        })?;
    let policy_resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
        Arc::new(SadStorePolicyResolver {
            policies: state.repo.clone(),
            object_store: state.object_store.clone(),
        });
    let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> =
        Arc::new(kels_policy::AnchoredPolicyChecker::new(
            Arc::clone(&kel_source),
            Arc::clone(&policy_resolver),
        ));
    let resolver = RepositoryIelResolver::new(state.repo.clone(), Arc::clone(&checker))
        .with_queried_saids(std::iter::once(*write_iel_said));

    let identity = resolver
        .resolve_identity_for_event(write_iel_said)
        .await
        .map_err(custody_write_resolver_error)?;
    let auth_policy = resolver
        .resolve_auth_policy_at(&identity, write_iel_said)
        .await
        .map_err(custody_write_resolver_error)?;

    let evaluation = checker
        .evaluate(canonical_said, &auth_policy)
        .await
        .map_err(|e| {
            warn!("custody.write anchor check failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "anchor check failed").into_response()
        })?;
    if !evaluation.satisfied {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "custody.write auth_policy {} not anchored for SAD {}",
                auth_policy, canonical_said
            ),
        )
            .into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn custody_write_resolver_error(err: kels_core::KelsError) -> axum::response::Response {
    use kels_core::KelsError;
    match err {
        KelsError::MissingIelEvent(dep) => (
            StatusCode::BAD_REQUEST,
            format!(
                "custody.write IEL event not locally known: {} (in IEL {})",
                dep.event_said, dep.iel_prefix
            ),
        )
            .into_response(),
        KelsError::IdentityBindingViolation(violation) => (
            StatusCode::BAD_REQUEST,
            // "not locally known" is preserved in the prefix for callers
            // that match on the substring; the violation Display carries
            // the resolver's specific reason (cross-IEL contamination,
            // SAID-not-found-in-any-IEL, walk-back failure, etc.).
            format!("custody.write IEL event not locally known: {}", violation),
        )
            .into_response(),
        KelsError::IelDivergent(msg) => (
            StatusCode::BAD_REQUEST,
            format!("custody.write IEL event sits past divergence: {}", msg),
        )
            .into_response(),
        KelsError::ContestedIel(msg) | KelsError::IelDecommissioned(msg) => (
            StatusCode::BAD_REQUEST,
            format!("custody.write IEL is terminal: {}", msg),
        )
            .into_response(),
        other => {
            warn!("custody.write resolver failure: {}", other);
            (StatusCode::INTERNAL_SERVER_ERROR, "resolver failure").into_response()
        }
    }
}

/// Resolve the gossip policy from a SAD's inline `availability` block.
///
/// No `availability` / no `nodes` field → BroadcastAll. If `nodes` is present,
/// resolves the referenced NodeSet from object store and decides:
/// 0 prefixes → LocalOnly (local cache), 1 prefix → LocalOnly (home-node),
/// >1 prefixes → LocalOnly (selective multi-node gossip not yet implemented).
///
/// Fails secure: if `nodes` is set but can't be resolved, skip gossip rather
/// than broadcasting restricted data to unauthorized peers.
async fn resolve_gossip_policy(
    availability: Option<&kels_core::Availability>,
    state: &AppState,
) -> GossipPolicy {
    let Some(av) = availability else {
        return GossipPolicy::BroadcastAll;
    };

    let Some(nodes_said) = av.nodes else {
        return GossipPolicy::BroadcastAll;
    };

    match state.object_store.get(&nodes_said).await {
        Ok(data) => {
            if let Ok(node_set) = serde_json::from_slice::<kels_core::NodeSet>(&data) {
                if node_set.prefixes.len() <= 1 {
                    GossipPolicy::LocalOnly
                } else {
                    // TODO: selective multi-node gossip — resolve target peers
                    // from the NodeSet prefix list and forward only to them.
                    // For now, skip gossip; the object is stored locally and
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

    // Look up the object in sad_objects to confirm presence.
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

    // #167: per-SAD constraints (custody.read, availability.ttl,
    // availability.once) live on the index entry directly — denormalized
    // from the parent SAD's inline `custody` and `availability` fields and
    // covered by the entry's SAID.

    // #167 read enforcement: when `custody.read = Some(prefix)`, gate user
    // reads on the IEL's current `auth_policy`. The verifier resolves the
    // tip's auth_policy and confirms the request's signers satisfy it.
    if let Some(read_prefix) = entry.custody_read {
        let Some(signed) = signed_request.as_ref() else {
            return (
                StatusCode::FORBIDDEN,
                "custody.read requires authenticated request",
            )
                .into_response();
        };
        match verify_custody_read(&state, &read_prefix, signed).await {
            Ok(()) => {}
            Err(response) => return response,
        }
    }

    // TTL check (per-object: sad_objects.created_at + availability.ttl)
    if let Some(ttl) = entry.availability_ttl {
        let created = entry.created_at.inner().timestamp();
        let now = verifiable_storage::StorageDatetime::now()
            .inner()
            .timestamp();
        if now > created + ttl as i64 {
            return (StatusCode::NOT_FOUND, "expired").into_response();
        }
    }

    // once: atomic delete — if we delete the row, we serve; if count=0,
    // already consumed. The reaper bypasses already-empty entries on its
    // next cycle.
    if entry.availability_once == Some(true) {
        match state
            .repo
            .sad_objects
            .delete_by_sad_said(&object_said)
            .await
        {
            Ok(1) => {
                let response =
                    serve_sad(&state.object_store, &object_said, disclosure.as_deref()).await;

                // Best-effort object store cleanup — prevents orphaned objects from
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

/// #167 `custody.read` enforcement. Authenticates the fetch request,
/// resolves the IEL's current `auth_policy` (via the prefix-to-current
/// resolver), and evaluates it against the verified signers.
///
/// Status mapping per #167:
/// - IEL not locally known (`NotFound`) → 403 (clients can't distinguish
///   from terminal cases; uniform "no read access" signal).
/// - `IelDivergent` → 503 (transient — divergence resolves to either Cnt
///   terminal or recovers linear).
/// - `ContestedIel` / `IelDecommissioned` → 403.
/// - Policy not satisfied → 403.
#[allow(clippy::result_large_err)]
async fn verify_custody_read(
    state: &AppState,
    read_prefix: &cesr::Digest256,
    signed: &kels_core::SignedRequest<kels_core::SignedSadFetchRequest>,
) -> Result<(), axum::response::Response> {
    let verified = authenticate_fetch_request(state, signed).await?;

    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = state
        .kels_client
        .as_kel_source()
        .map(Arc::new)
        .map_err(|e| {
            warn!("Failed to build KEL source for custody.read check: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build KEL source",
            )
                .into_response()
        })?;
    let policy_resolver = SadStorePolicyResolver {
        policies: state.repo.clone(),
        object_store: state.object_store.clone(),
    };
    let policy_resolver_arc: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
        Arc::new(SadStorePolicyResolver {
            policies: state.repo.clone(),
            object_store: state.object_store.clone(),
        });
    let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> = Arc::new(
        kels_policy::AnchoredPolicyChecker::new(kel_source, Arc::clone(&policy_resolver_arc)),
    );
    let resolver = RepositoryIelResolver::new(state.repo.clone(), checker);

    let auth_policy = resolver
        .resolve_current_auth_policy(read_prefix)
        .await
        .map_err(custody_read_resolver_error)?;

    match kels_policy::evaluate_signed_policy(&auth_policy, &verified, &policy_resolver).await {
        Ok(v) if v.is_satisfied => Ok(()),
        Ok(_) => Err((StatusCode::FORBIDDEN, "custody.read not satisfied").into_response()),
        Err(e) => {
            warn!("custody.read policy evaluation failed: {}", e);
            Err((StatusCode::FORBIDDEN, "policy evaluation failed").into_response())
        }
    }
}

#[allow(clippy::result_large_err)]
fn custody_read_resolver_error(err: kels_core::KelsError) -> axum::response::Response {
    use kels_core::KelsError;
    match err {
        KelsError::NotFound(_) => {
            (StatusCode::FORBIDDEN, "custody.read IEL not locally known").into_response()
        }
        KelsError::IelDivergent(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "custody.read IEL is divergent — retry after resolution",
        )
            .into_response(),
        KelsError::ContestedIel(_) | KelsError::IelDecommissioned(_) => {
            (StatusCode::FORBIDDEN, "custody.read IEL is terminal").into_response()
        }
        other => {
            warn!("custody.read resolver failure: {}", other);
            (StatusCode::INTERNAL_SERVER_ERROR, "resolver failure").into_response()
        }
    }
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
/// If `disclosure` is None, serves raw bytes from object store (no parsing overhead).
/// If `disclosure` is Some, applies heuristic expansion via the disclosure DSL.
async fn serve_sad(
    object_store: &ObjectStore,
    said: &cesr::Digest256,
    disclosure: Option<&str>,
) -> axum::response::Response {
    let Some(disclosure) = disclosure else {
        return serve_from_object_store(object_store, said).await;
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

/// Serve a SAD object directly from object store (no disclosure expansion).
async fn serve_from_object_store(
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

/// Policy resolver backed by the Postgres `policies` cache with object store fallback.
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

        // Fallback: object store
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

// === Layer 2: SAD Events (Postgres) ===

/// Stream the SE chain inside the submit transaction and accumulate the
/// unique `event.identity_event` SAIDs (drops events). Mirrors
/// `kels_core::collect_identity_event_saids[_from_loader]` for the
/// transactional repository path. Bounded by `max_pages × page_size × 32B`;
/// fail-secure on overrun (returns `INTERNAL_SERVER_ERROR` rather than
/// silently using a partial set, which would soft-fail every binding for
/// SAIDs past the limit).
///
/// Used by the SE submit handler to pre-walk the chain before constructing
/// the `IelResolver` with a `queried_saids` set, so `is_satisfied` answers
/// reflect the full SE chain's bindings.
async fn collect_se_chain_identity_event_saids_via_tx<Tx: TransactionExecutor>(
    tx: &mut Tx,
    repo: &SadEventRepository,
    prefix: &cesr::Digest256,
    new_events: &[kels_core::SadEvent],
) -> Result<std::collections::BTreeSet<cesr::Digest256>, axum::response::Response> {
    let mut saids: std::collections::BTreeSet<cesr::Digest256> = std::collections::BTreeSet::new();
    let page_size = kels_core::page_size() as u64;
    let max_pages = kels_core::max_pages();
    let mut since: Option<cesr::Digest256> = None;
    let mut exhausted = false;
    for _ in 0..max_pages {
        let page = repo
            .get_stored_in(
                tx,
                prefix.as_ref(),
                since.as_ref().map(|s| s.as_ref()),
                Some(page_size),
            )
            .await
            .map_err(|e| {
                warn!("Failed to pre-walk SE chain for queried_saids: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
            })?;
        if page.is_empty() {
            exhausted = true;
            break;
        }
        let page_len = page.len();
        since = page.last().map(|r| r.said);
        for ev in &page {
            if let Some(s) = ev.identity_event {
                saids.insert(s);
            }
        }
        if (page_len as u64) < page_size {
            exhausted = true;
            break;
        }
    }
    if !exhausted {
        let msg = format!(
            "SE pre-walk for queried_saids exceeded max_pages limit ({}) for {}",
            max_pages, prefix
        );
        warn!("{}", msg);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, msg).into_response());
    }
    for ev in new_events {
        if let Some(s) = ev.identity_event {
            saids.insert(s);
        }
    }
    Ok(saids)
}

/// Page through existing SAD events in a transaction, feeding each page to the verifier.
async fn verify_existing_chain<Tx: TransactionExecutor>(
    tx: &mut Tx,
    repo: &SadEventRepository,
    prefix: &cesr::Digest256,
    verifier: &mut kels_core::SelVerifier,
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
            // Re-verifying *already-stored* events should always pass — these
            // are events the receiver itself wrote earlier under the same
            // verifier rules. A failure here means DB integrity loss /
            // tampering, not a client-vs-state conflict — surface as 500
            // via `KelsError::ChainVerificationFailed` so federation peers
            // and operators can distinguish server-internal failures from
            // routine 409 conflict responses.
            warn!("SE existing-chain re-verification failed: {}", e);
            let err = kels_core::KelsError::ChainVerificationFailed(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        })?;
        if (page_len as u64) < page_size {
            break;
        }
    }
    Ok(())
}

/// Submit SAD events — unified endpoint for clients, gossip sync, and repair.
///
/// Accepts `Vec<SadEvent>`. Validates structure (SAID, prefix consistency)
/// and IEL-resolved authorization via verify-then-extend: re-verifies the
/// entire existing chain from scratch, then verifies new events in context.
/// Rejects unauthorized advances with 403.
///
/// When any submitted event has `kind: Rpr`, the handler takes the repair path:
/// truncates all events at version >= the first event's version, then re-verifies
/// the entire chain including the repair events.
pub async fn submit_sad_events(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<kels_core::SadEvent>>,
) -> impl IntoResponse {
    if events.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty batch").into_response();
    }

    // Per-IP rate limit
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // All events must be for the same SEL prefix
    let sel_prefix = &events[0].prefix;
    if events.iter().any(|r| r.prefix != *sel_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            "All events must have the same prefix",
        )
            .into_response();
    }

    // Verify SAID integrity for all events
    for r in &events {
        if r.verify_said().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("SAD event SAID verification failed: {}", r.said),
            )
                .into_response();
        }
    }

    // Verify prefix derivation for v0 if present
    if let Some(v0) = events.iter().find(|r| r.version == 0)
        && v0.verify_prefix().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            "Prefix derivation verification failed",
        )
            .into_response();
    }

    // #167: SE events reject `custody` and `availability`
    // entirely — chains replicate as a unit; differential authority or
    // lifecycle across links breaks descendant verification. The struct
    // doesn't carry these fields anymore, so a well-formed
    // `Vec<SadEvent>` deserialize already rejects them; the upcoming
    // `deny_unknown_fields` hardening (Gap 1 polish) tightens this further.

    // Per-SEL-prefix request gate. Runs BEFORE the transaction setup and
    // dedup query so duplicate-submit campaigns consume budget proportional
    // to the request's claimed event count, regardless of whether anything
    // commits server-side. Charges `events.len()` to the per-prefix budget;
    // a failed request over-charges relative to its commits, which is the
    // conservative shape we want for an unauthenticated entry point.
    if let Err(msg) = check_prefix_rate_limit(
        &state.prefix_rate_limits,
        sel_prefix,
        events.len() as u32,
        max_sel_events_per_prefix_per_day(),
        true,
    ) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // #147 inception batch rule: a batch that contains an `Icp` MUST
    // also contain an `Upd` at v1. Enforced here at the submit handler
    // (per-batch rule, not per-event — `validate_structure` can't see this).
    // The Icp itself stays dedup-idempotent across submitters; only fresh
    // inceptions without their paired v1 Upd are rejected.
    //
    // The HTTP response body matches `KelsError::IncompleteInception`'s
    // Display prefix ("Incomplete inception: …") so client-side code that
    // maps server errors back to KelsError can match on the prefix.
    let has_icp = events.iter().any(|e| e.kind.is_inception());
    let has_v1_upd = events
        .iter()
        .any(|e| e.version == 1 && e.kind == kels_core::SadEventKind::Upd);
    if has_icp && !has_v1_upd {
        let err = kels_core::KelsError::IncompleteInception(
            "a batch containing Icp must also contain an Upd at v1".to_string(),
        );
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }

    // Transactional verify-then-extend: advisory lock + verification + write in one transaction.
    // Follows the KEL merge engine pattern (merge.rs). Rollback on any failure.
    let new_event_count;
    let should_publish;
    let mut diverged_at_version: Option<u64> = None;

    {
        let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> =
            match state.kels_client.as_kel_source() {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!("Failed to build KEL source: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build KEL source",
                    )
                        .into_response();
                }
            };
        let policy_resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
            Arc::new(SadStorePolicyResolver {
                policies: state.repo.clone(),
                object_store: state.object_store.clone(),
            });

        let mut tx = match state.repo.sad_events.pool.begin_transaction().await {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Failed to begin transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };

        if let Err(e) = tx.acquire_advisory_lock(sel_prefix.as_ref()).await {
            warn!("Failed to acquire advisory lock: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }

        // Dedup first: filter out events that already exist in the DB.
        // This is a SAID existence check — no verification needed.
        // Historical Rpr events dedup out; only genuinely new Rpr events trigger repair.
        let new_events: Vec<kels_core::SadEvent> = {
            let submitted_saids: Vec<String> = events.iter().map(|r| r.said.to_string()).collect();
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
            events
                .iter()
                .filter(|r| !existing_saids.contains(&r.said))
                .cloned()
                .collect()
        };

        if new_events.is_empty() {
            // Report the chain's *current* divergence state, not "what this
            // submit changed." A client retrying after a phase-2 / phase-3
            // failure (Round 4 M1's terminology) has otherwise lost the
            // original `Some(version)` signal — the first submit's response
            // never made it to the local token. The normal-path response
            // populates `diverged_at` from `save_batch`'s `DivergenceCreated`
            // outcome; this is the symmetric read-side mechanism on the
            // dedup path. The dedup short-circuit performs no writes, so a
            // pool-level read alongside the in-flight tx is fine.
            let diverged_at = match state
                .repo
                .sad_events
                .first_divergent_version(sel_prefix)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to query first divergent version: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
                }
            };
            if let Err(e) = tx.commit().await {
                warn!("Failed to commit transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
            let response = kels_core::SubmitSadEventsResponse {
                diverged_at,
                applied: false,
                terminal: None,
            };
            return (StatusCode::CREATED, Json(response)).into_response();
        }

        // #147 pre-batch state snapshots. The verifier sees existing+new
        // events together, so a batch that *creates* a fork (overlap) shows
        // up as divergent post-finish; we route based on the chain state
        // BEFORE the new batch lands. Mirrors the IEL handler's hygiene
        // (IEL fix that surfaced this self-triggering trap).
        let pre_batch_first_divergent = match state
            .repo
            .sad_events
            .first_divergent_version(sel_prefix)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query first divergent version: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        let pre_batch_seal = match state
            .repo
            .sad_events
            .last_governance_version(&mut tx, sel_prefix)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query SE pre-batch seal: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        let pre_batch_contested = match state.repo.sad_events.is_contested(sel_prefix).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query SE is_contested: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        let pre_batch_decommissioned =
            match state.repo.sad_events.is_decommissioned(sel_prefix).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to query SE is_decommissioned: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
                }
            };

        // Terminal-state gates: a contested or decommissioned SE chain
        // accepts no further events of any kind. Mirrors the IEL handler:
        // 200 OK with `terminal: Some(_)` so gossip forwarders see
        // idempotent success; owner-side callers branch on `terminal` to
        // distinguish "your work is moot" from dedup-short-circuit.
        if pre_batch_contested || pre_batch_decommissioned {
            let _ = tx.rollback().await;
            let terminal = if pre_batch_contested {
                kels_core::SadEventTerminalState::Contested
            } else {
                kels_core::SadEventTerminalState::Decommissioned
            };
            let response = kels_core::SubmitSadEventsResponse {
                diverged_at: pre_batch_first_divergent,
                applied: false,
                terminal: Some(terminal),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }

        // Sealed/unsealed predicate per
        // `docs/design/sel/reconciliation.md §Local Submissions Matrix`:
        // a chain is *sealed-divergent* iff the divergence point is at-or-
        // before the most recent governance evaluation
        // (`first_divergent_version <= last_governance_version`). The seal
        // freezes the chain past that version, so `Rpr` (which truncates)
        // can no longer resolve the divergence — only `Cnt` can.
        let is_divergent = pre_batch_first_divergent.is_some();
        let is_sealed_divergent = matches!(
            (pre_batch_first_divergent, pre_batch_seal),
            (Some(div), Some(seal)) if seal >= div
        );

        // Per-kind detection on the batch (post-dedup). For `is_repair` we
        // intentionally use post-dedup events: only genuinely new `Rpr`
        // events trigger the repair path. `is_contest` / `is_decommission`
        // follow the same convention.
        let is_repair = new_events.iter().any(|e| e.kind.is_repair());
        let is_contest = new_events.iter().any(|e| e.kind.is_contest());
        let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

        // Build the verifier (shared across all routing branches that need
        // to verify the chain). `RepositoryIelResolver` reads the in-process
        // IEL repository directly so cross-chain auth works without HTTP.
        let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> =
            Arc::new(kels_policy::AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
            ));

        // SE pre-walk: stream the SE chain (storage + new events), accumulate
        // unique `identity_event` SAIDs. The set is forwarded as
        // `queried_saids` to the `IelResolver` so its `is_satisfied`
        // answers reflect IEL verification of these SAIDs. Bounded by
        // `max_pages × page_size × 32 B`; fail-secure on max_pages overrun.
        let queried_iel_saids = match collect_se_chain_identity_event_saids_via_tx(
            &mut tx,
            &state.repo.sad_events,
            sel_prefix,
            &new_events,
        )
        .await
        {
            Ok(s) => s,
            Err(response) => {
                let _ = tx.rollback().await;
                return response;
            }
        };

        let iel_resolver: Arc<dyn kels_core::IelResolver + Send + Sync> = Arc::new(
            RepositoryIelResolver::new(state.repo.clone(), Arc::clone(&checker))
                .with_queried_saids(queried_iel_saids),
        );

        if is_repair {
            // Routing matrix step 1: `is_repair`.
            // - Divergent-sealed → `ContestRequired` (Rpr can't truncate
            //   at-or-behind the seal).
            // - Linear (clean or seal-past-tip) and divergent-unsealed →
            //   `truncate_and_replace`. The linear-seal-past-tip case
            //   keeps the generic "Cannot repair at version X — sealed
            //   by evaluation at version Y" error; only the
            //   divergent-sealed case converts to `ContestRequired`.
            if is_sealed_divergent {
                let _ = tx.rollback().await;
                return (
                    StatusCode::FORBIDDEN,
                    format!(
                        "Contest required: SE {} is sealed-divergent at version {} (seal {}) \
                         — Rpr cannot truncate behind the seal; must Cnt instead",
                        sel_prefix,
                        pre_batch_first_divergent.unwrap_or(0),
                        pre_batch_seal.unwrap_or(0),
                    ),
                )
                    .into_response();
            }

            // Truncate / archive within this tx, then verify the
            // post-truncation chain (which is now linear from v0 to the
            // Rpr).
            let from_version = match state
                .repo
                .sad_events
                .truncate_and_replace(&mut tx, &events)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to truncate for repair: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::CONFLICT, format!("{}", e)).into_response();
                }
            };

            // Repair must not truncate behind the seal — guards the
            // linear-seal-past-tip case. Generic error message preserved.
            if let Some(seal) = pre_batch_seal
                && from_version <= seal
            {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Cannot repair at version {} — sealed by evaluation at version {}",
                        from_version, seal
                    ),
                )
                    .into_response();
            }

            // Now verify the entire chain (post-truncation + repair events) from scratch.
            let mut verifier = kels_core::SelVerifier::new(
                Some(sel_prefix),
                Arc::clone(&checker),
                Arc::clone(&iel_resolver),
            );
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, sel_prefix, &mut verifier)
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
                return (
                    StatusCode::FORBIDDEN,
                    "SE Rpr not anchored under IEL-resolved governance_policy",
                )
                    .into_response();
            }

            new_event_count = new_events.len() as u32;
            should_publish = true;
        } else if is_contest {
            // Routing matrix step 2: `is_contest`.
            // - Linear → contest path (works always).
            // - Divergent-unsealed → `RepairRequired` (Rpr is the natural
            //   resolver; Cnt is reserved for sealed-divergent).
            // - Divergent-sealed → contest path (Rpr can't truncate
            //   behind the seal, so Cnt is the only legitimate resolver).
            if is_divergent && !is_sealed_divergent {
                let _ = tx.rollback().await;
                return (
                    StatusCode::FORBIDDEN,
                    format!(
                        "Repair required: SE {} is unsealed-divergent — must Rpr, not Cnt",
                        sel_prefix
                    ),
                )
                    .into_response();
            }

            // Verify chain with new events. Cnt has SOFT governance auth —
            // a govfailed Cnt still lands; the verifier surfaces the
            // chain-content-based `is_contested=true` and propagates
            // `policy_satisfied=false`. We do NOT gate on
            // `policy_satisfied` here.
            let mut verifier = kels_core::SelVerifier::new(
                Some(sel_prefix),
                Arc::clone(&checker),
                Arc::clone(&iel_resolver),
            );
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, sel_prefix, &mut verifier)
                    .await
            {
                let _ = tx.rollback().await;
                return response;
            }
            if let Err(e) = verifier.verify_page(&new_events).await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("SAD event verification failed: {}", e),
                )
                    .into_response();
            }
            if let Err(e) = verifier.finish().await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Chain verification failed: {}", e),
                )
                    .into_response();
            }

            // Insert each Cnt with `insert_event` (mirrors IEL Cnt path):
            // bypasses `save_batch`'s divergent-rejection so a Cnt can land
            // on a sealed-divergent chain. A failure here is post-dedup,
            // post-advisory-lock, post-verifier — there's no client-vs-state
            // conflict left to surface; the only realistic cause is a DB
            // integrity issue. Surface as 500 via `ChainVerificationFailed`.
            for event in &new_events {
                if let Err(e) = state.repo.sad_events.insert_event(&mut tx, event).await {
                    warn!("Failed to insert SE Cnt (post-dedup-locked): {}", e);
                    let _ = tx.rollback().await;
                    let err = kels_core::KelsError::ChainVerificationFailed(format!(
                        "post-dedup-locked Cnt insert failed: {}",
                        e
                    ));
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
            }
            new_event_count = new_events.len() as u32;
            should_publish = true;
        } else if is_decommission {
            // Routing matrix step 3: `is_decommission`.
            // - Linear → decommission path.
            // - Divergent-unsealed → `RepairRequired`.
            // - Divergent-sealed → `ContestRequired` (Dec can't resolve a
            //   sealed divergence; operator must Cnt instead).
            if is_divergent && !is_sealed_divergent {
                let _ = tx.rollback().await;
                return (
                    StatusCode::FORBIDDEN,
                    format!(
                        "Repair required: SE {} is unsealed-divergent — must Rpr, not Dec",
                        sel_prefix
                    ),
                )
                    .into_response();
            }
            if is_sealed_divergent {
                let _ = tx.rollback().await;
                return (
                    StatusCode::FORBIDDEN,
                    format!(
                        "Contest required: SE {} is sealed-divergent — Dec cannot \
                         resolve a sealed divergence; must Cnt instead",
                        sel_prefix
                    ),
                )
                    .into_response();
            }

            // Linear path: verify chain + new events (SOFT for Dec — same
            // reasoning as Cnt above), then insert.
            let mut verifier = kels_core::SelVerifier::new(
                Some(sel_prefix),
                Arc::clone(&checker),
                Arc::clone(&iel_resolver),
            );
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, sel_prefix, &mut verifier)
                    .await
            {
                let _ = tx.rollback().await;
                return response;
            }
            if let Err(e) = verifier.verify_page(&new_events).await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("SAD event verification failed: {}", e),
                )
                    .into_response();
            }
            if let Err(e) = verifier.finish().await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Chain verification failed: {}", e),
                )
                    .into_response();
            }

            // Same shape as the SE Cnt insert above — failure post-dedup-
            // locked-verified is server-internal integrity, not 409.
            for event in &new_events {
                if let Err(e) = state.repo.sad_events.insert_event(&mut tx, event).await {
                    warn!("Failed to insert SE Dec (post-dedup-locked): {}", e);
                    let _ = tx.rollback().await;
                    let err = kels_core::KelsError::ChainVerificationFailed(format!(
                        "post-dedup-locked Dec insert failed: {}",
                        e
                    ));
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
            }
            new_event_count = new_events.len() as u32;
            should_publish = true;
        } else {
            // Routing matrix step 4 + 5 + 6/7: non-terminal, non-Rpr —
            // `Upd` and `Sea` only at this point (Icp landed alone or
            // alongside its v1 Upd is also handled here; the inception
            // batch rule already enforced the v1-Upd requirement).
            //
            // Step 4 (chain divergent + non-terminal + non-Rpr):
            //   - divergent-unsealed → RepairRequired
            //   - divergent-sealed → ContestRequired
            if is_divergent {
                if is_sealed_divergent {
                    let _ = tx.rollback().await;
                    return (
                        StatusCode::FORBIDDEN,
                        format!(
                            "Contest required: SE {} is sealed-divergent — neither Rpr \
                             nor normal append can resolve; must Cnt instead",
                            sel_prefix
                        ),
                    )
                        .into_response();
                } else {
                    let _ = tx.rollback().await;
                    return (
                        StatusCode::FORBIDDEN,
                        format!(
                            "Repair required: SE {} is unsealed-divergent — \
                             cannot extend a divergent chain; must Rpr first",
                            sel_prefix
                        ),
                    )
                        .into_response();
                }
            }

            // Linear chain. Verify existing + new; HARD for Upd/Sea so
            // policy_satisfied=false aborts.
            let mut verifier = kels_core::SelVerifier::new(
                Some(sel_prefix),
                Arc::clone(&checker),
                Arc::clone(&iel_resolver),
            );
            if let Err(response) =
                verify_existing_chain(&mut tx, &state.repo.sad_events, sel_prefix, &mut verifier)
                    .await
            {
                let _ = tx.rollback().await;
                return response;
            }
            if let Err(e) = verifier.verify_page(&new_events).await {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("SAD event verification failed: {}", e),
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
                return (
                    StatusCode::FORBIDDEN,
                    "SE event not anchored under IEL-resolved policy",
                )
                    .into_response();
            }

            // Step 5 (algorithmic ContestRequired): non-terminal AND
            // non-Rpr AND `event.version <= last_governance_version` AND
            // kind-relevant authorization passed (verifier returned
            // policy_satisfied=true above) AND not divergent.
            // This catches the linear-sealed-past-version case
            // — the divergent-sealed case is already caught above.
            if let Some(seal) = pre_batch_seal {
                for event in &new_events {
                    if !event.kind.is_terminal() && !event.kind.is_repair() && event.version <= seal
                    {
                        let _ = tx.rollback().await;
                        return (
                            StatusCode::FORBIDDEN,
                            format!(
                                "Contest required: SE {} event at version {} lands at-or-before \
                                 governance seal {} — must Cnt instead",
                                event.kind, event.version, seal
                            ),
                        )
                            .into_response();
                    }
                }
            }

            // Step 6 / 7: save_batch. `save_batch` handles the
            // overlap-creates-fork case (a single forking event lands and
            // the chain freezes); on a clean linear chain it's a
            // straight append.
            match state
                .repo
                .sad_events
                .save_batch(&mut tx, &new_events, pre_batch_seal)
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
                    new_event_count = count;
                    should_publish = count > 0;
                }
                Err(e) => {
                    warn!("Failed to store events: {}", e);
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

    // Per-prefix budget was charged pre-flight by `check_prefix_rate_limit`
    // above — duplicate submits and rejected requests both consume budget at
    // the rate of their claimed event count, so no post-commit accrual here.

    // #167: SE events broadcast unconditionally. Replication
    // gating is a SAD-object concern (via `availability.nodes`); chains
    // replicate as a unit because a chain's events all participate in the
    // same identity-rooted history. The pre-#167 per-event custody-routing
    // is gone.

    // Publish the effective SAID to Redis for gossip.
    let effective_said = if should_publish {
        match state.repo.sad_events.effective_said(sel_prefix).await {
            Ok(Some((said, _))) => Some(said),
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to compute effective SAID for {}: {}", sel_prefix, e);
                None
            }
        }
    } else {
        None
    };
    match (&state.redis_conn, &effective_said) {
        (Some(conn), Some(said)) => {
            let mut conn = conn.clone();
            let message = format!("{}:{}", sel_prefix, said);
            if let Err(e) = redis::cmd("PUBLISH")
                .arg("sel_updates")
                .arg(&message)
                .query_async::<()>(&mut conn)
                .await
            {
                warn!("Failed to publish SEL update: {}", e);
            } else {
                debug!(
                    sel_prefix = %sel_prefix,
                    effective_said = %said,
                    "Published SEL update to Redis"
                );
            }
        }
        (None, _) => {
            debug!("Skipping SEL publish: no Redis connection");
        }
        (_, None) => {
            debug!(
                sel_prefix = %sel_prefix,
                should_publish = should_publish,
                "Skipping SEL publish: no effective SAID"
            );
        }
    }

    let response = kels_core::SubmitSadEventsResponse {
        diverged_at: diverged_at_version,
        applied: new_event_count > 0,
        terminal: None,
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

pub async fn get_sad_events(
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
        Ok(events) if events.is_empty() => {
            (StatusCode::NOT_FOUND, "SAD Event Log not found").into_response()
        }
        Ok(events) => {
            let has_more = events.len() as u64 > limit;
            let events: Vec<_> = events.into_iter().take(limit as usize).collect();
            let page = kels_core::SadEventPage { has_more, events };
            (StatusCode::OK, Json(page)).into_response()
        }
        Err(e) => {
            warn!("Failed to get SAD Event Log: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Fetch the tail of a SAD Event Log — the last `limit` events ordered by
/// `(version ASC, said ASC)`, capped at `MINIMUM_PAGE_SIZE` server-side.
///
/// The boundary that `SadEventBuilder::repair`'s adversary-extension walk-back
/// is searching for is at most `MAX_NON_EVALUATION_EVENTS = 63` hops from the
/// tip, so this single fetch always suffices regardless of chain length.
/// Capping at the constant (rather than the operator-tunable `page_size()`)
/// keeps an attacker probing this endpoint from amplifying response size when
/// `KELS_PAGE_SIZE` is set higher than the default.
pub async fn get_sad_events_tail(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadEventTailRequest>,
) -> impl IntoResponse {
    let prefix = request.prefix;
    let max_limit = kels_core::MINIMUM_PAGE_SIZE;
    let limit = request.limit.unwrap_or(max_limit).clamp(1, max_limit) as u64;

    match state
        .repo
        .sad_events
        .get_stored_tail(prefix.as_ref(), limit)
        .await
    {
        Ok(events) if events.is_empty() => {
            (StatusCode::NOT_FOUND, "SAD Event Log not found").into_response()
        }
        Ok(events) => {
            // The tail fetch returns the entire suffix the caller asked for —
            // there is no further page beyond what they got, by definition of
            // "fetch the last N events." `has_more` is always false.
            let page = kels_core::SadEventPage {
                has_more: false,
                events,
            };
            (StatusCode::OK, Json(page)).into_response()
        }
        Err(e) => {
            warn!("Failed to get SAD Event Log tail: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

pub async fn get_sel_effective_said(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadEventEffectiveSaidRequest>,
) -> impl IntoResponse {
    match state.repo.sad_events.effective_said(&request.prefix).await {
        Ok(Some((said, divergent))) => (
            StatusCode::OK,
            Json(kels_core::EffectiveSaidResponse { said, divergent }),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "SAD Event Log not found").into_response(),
        Err(e) => {
            warn!("Failed to get effective SAID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

// ==================== Identity Event Log (IEL) handlers ====================

/// Page through existing IEL events in a transaction, feeding each page to the
/// verifier. Mirrors `verify_existing_chain` for the IEL primitive.
async fn verify_existing_iel_chain<Tx: TransactionExecutor>(
    tx: &mut Tx,
    repo: &crate::repository::IdentityEventRepository,
    prefix: &cesr::Digest256,
    verifier: &mut kels_core::IelVerifier,
) -> Result<(), axum::response::Response> {
    let page_size = kels_core::page_size() as u64;
    let mut since: Option<cesr::Digest256> = None;
    loop {
        let prefix_str = prefix.to_string();
        let page = repo
            .fetch_iel_page(
                tx,
                crate::repository::IelChainSelector::Prefix(&prefix_str),
                since.as_ref().map(|s| s.as_ref()),
                Some(page_size),
            )
            .await
            .map_err(|e| {
                warn!("Failed to fetch IEL chain for verification: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
            })?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        since = page.last().map(|e| e.said);
        verifier.verify_page(&page).await.map_err(|e| {
            // Same shape as `verify_existing_chain` for SE — re-verification
            // of already-stored IEL events is a server-internal integrity
            // contract, not a client-vs-state conflict. Surface as 500 via
            // `KelsError::ChainVerificationFailed`.
            warn!("IEL existing-chain re-verification failed: {}", e);
            let err = kels_core::KelsError::ChainVerificationFailed(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        })?;
        if (page_len as u64) < page_size {
            break;
        }
    }
    Ok(())
}

/// Describe the soft-fail that flipped `verification.policy_satisfied=false`,
/// branching on which kind in `new_events` triggered it. The verifier soft-fails
/// on Icp anchor (against declared `auth_policy`) and on Cnt/Dec governance
/// anchor (against the chain's tracked `governance_policy`); Evl governance is
/// hard-fail and surfaces earlier as a verification error rather than via this
/// gate. The previous one-line message hard-coded the Icp shape and misled
/// operators when an unauthorized Cnt/Dec landed.
fn describe_iel_policy_failure(
    new_events: &[kels_core::IdentityEvent],
    iel_prefix: &cesr::Digest256,
) -> String {
    let mut clauses: Vec<String> = Vec::new();
    for event in new_events {
        match event.kind {
            kels_core::IdentityEventKind::Icp => clauses.push(format!(
                "Icp {} must be anchored under its declared auth_policy",
                event.said
            )),
            kels_core::IdentityEventKind::Cnt => clauses.push(format!(
                "Cnt {} must be authorized under the chain's tracked governance_policy",
                event.said
            )),
            kels_core::IdentityEventKind::Dec => clauses.push(format!(
                "Dec {} must be authorized under the chain's tracked governance_policy",
                event.said
            )),
            // Evl governance failure aborts verification with a hard error
            // before reaching the policy_satisfied gate.
            kels_core::IdentityEventKind::Evl => {}
        }
    }
    if clauses.is_empty() {
        return format!(
            "IEL {} re-verification surfaced an anchor failure on the existing chain",
            iel_prefix
        );
    }
    clauses.join("; ")
}

/// Submit IEL events. Routes per `docs/design/iel/merge.md §4`:
///
/// 1. Structural validation (SAID, prefix, `validate_structure`, Icp prefix).
/// 2. Terminal-state gate (Cnt → `ContestedIel`, Dec → `IelDecommissioned`).
/// 3. Dedup.
/// 4. Verify existing chain + new events (catches immunity violations,
///    Cnt/Dec policy preservation, Icp self-anchoring soft-fail, Evl/Cnt/Dec
///    governance anchoring).
/// 5. Routing — Cnt always wins; divergent rejects non-Cnt; Dec only on
///    non-divergent; sealed-Evl gets `ContestRequired`; otherwise normal
///    append (overlap creates fork).
/// 6. Publish effective SAID to gossip on state mutation.
pub async fn submit_identity_events(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<kels_core::IdentityEvent>>,
) -> impl IntoResponse {
    if events.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty batch").into_response();
    }

    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    let iel_prefix = &events[0].prefix;
    if events.iter().any(|e| e.prefix != *iel_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            "All IEL events must have the same prefix",
        )
            .into_response();
    }

    // SAID + per-kind structural validation.
    for e in &events {
        if e.verify_said().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("IEL event SAID verification failed: {}", e.said),
            )
                .into_response();
        }
        if let Err(reason) = e.validate_structure() {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid IEL event {}: {}", e.said, reason),
            )
                .into_response();
        }
    }

    // Verify Icp prefix derivation if v0 is present in the batch.
    if let Some(v0) = events.iter().find(|e| e.version == 0)
        && v0.verify_prefix().is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            "IEL Icp prefix derivation verification failed",
        )
            .into_response();
    }

    if let Err(msg) = check_prefix_rate_limit(
        &state.prefix_rate_limits,
        iel_prefix,
        events.len() as u32,
        max_iel_events_per_prefix_per_day(),
        true,
    ) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    let new_event_count;
    let should_publish;
    let mut diverged_at_version: Option<u64> = None;

    {
        let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> =
            match state.kels_client.as_kel_source() {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!("Failed to build KEL source: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build KEL source",
                    )
                        .into_response();
                }
            };
        let policy_resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
            Arc::new(SadStorePolicyResolver {
                policies: state.repo.clone(),
                object_store: state.object_store.clone(),
            });

        let mut tx = match state.repo.iel_events.pool.begin_transaction().await {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Failed to begin transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };

        if let Err(e) = tx.acquire_advisory_lock(iel_prefix.as_ref()).await {
            warn!("Failed to acquire advisory lock: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }

        // Dedup: filter events whose SAIDs are already in the chain.
        let new_events: Vec<kels_core::IdentityEvent> = {
            let submitted_saids: Vec<String> = events.iter().map(|e| e.said.to_string()).collect();
            let query = verifiable_storage_postgres::Query::<kels_core::IdentityEvent>::for_table(
                "iel_events",
            )
            .r#in("said", submitted_saids);
            let existing_saids: std::collections::HashSet<cesr::Digest256> =
                match tx.fetch(query).await {
                    Ok(existing) => existing
                        .into_iter()
                        .map(|e: kels_core::IdentityEvent| e.said)
                        .collect(),
                    Err(e) => {
                        warn!("Failed to query existing IEL SAIDs: {}", e);
                        let _ = tx.rollback().await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e))
                            .into_response();
                    }
                };
            events
                .iter()
                .filter(|e| !existing_saids.contains(&e.said))
                .cloned()
                .collect()
        };

        if new_events.is_empty() {
            // All-duplicates short-circuit: report current divergence.
            let diverged_at = match state
                .repo
                .iel_events
                .first_divergent_version(iel_prefix)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to query first divergent version: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
                }
            };
            if let Err(e) = tx.commit().await {
                warn!("Failed to commit transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
            let response = kels_core::SubmitIdentityEventsResponse {
                applied: false,
                diverged_at,
                terminal: None,
            };
            return (StatusCode::CREATED, Json(response)).into_response();
        }

        // Terminal-state gate. These checks fire before routing — terminal
        // chains accept no further events of any kind. The response is 200
        // OK with `terminal: Some(_)` (rather than 4xx) so gossip
        // forwarders see idempotent success on the gossip-race-already-
        // terminal case; owner-side callers branch on `terminal` to
        // distinguish "your work is moot — chain is already terminal" from
        // the dedup short-circuit (also `applied=false`, `terminal=None`).
        let is_contested = match state.repo.iel_events.is_contested(iel_prefix).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query is_contested: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        let is_decommissioned = match state.repo.iel_events.is_decommissioned(iel_prefix).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query is_decommissioned: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        if is_contested || is_decommissioned {
            let diverged_at = match state
                .repo
                .iel_events
                .first_divergent_version(iel_prefix)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to query first divergent version: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
                }
            };
            let _ = tx.rollback().await;
            let terminal = if is_contested {
                kels_core::IdentityEventTerminalState::Contested
            } else {
                kels_core::IdentityEventTerminalState::Decommissioned
            };
            let response = kels_core::SubmitIdentityEventsResponse {
                applied: false,
                diverged_at,
                terminal: Some(terminal),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }

        // Snapshot pre-batch chain state BEFORE running the verifier. The
        // verifier sees `existing + new_events` and would mark the chain
        // divergent if the new batch creates a fork (overlap-creates-fork is
        // a *normal* path, not divergent-rejection). The design's
        // "divergent → ContestRequired" rule applies to chains that were
        // *already* divergent before this batch, not to batches that create
        // divergence. Same shape for the seal: the post-finish seal includes
        // the new batch's Evls and would self-trigger the algorithmic
        // ContestRequired check.
        let pre_batch_seal = match state
            .repo
            .iel_events
            .last_governance_version(&mut tx, iel_prefix)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query IEL pre-batch seal: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };
        let pre_batch_divergent = match state.repo.iel_events.is_divergent(iel_prefix).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to query IEL pre-batch divergence: {}", e);
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
        };

        // Build verifier; verify the existing chain + the new batch. The
        // verifier surfaces immunity violations, Cnt/Dec policy preservation,
        // Icp self-anchoring (soft), and Evl/Cnt/Dec governance anchoring.
        let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> =
            Arc::new(kels_policy::AnchoredPolicyChecker::new(
                Arc::clone(&kel_source),
                Arc::clone(&policy_resolver),
            ));
        let mut verifier = kels_core::IelVerifier::new(Some(iel_prefix), checker);
        if let Err(response) =
            verify_existing_iel_chain(&mut tx, &state.repo.iel_events, iel_prefix, &mut verifier)
                .await
        {
            let _ = tx.rollback().await;
            return response;
        }
        if let Err(e) = verifier.verify_page(&new_events).await {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                format!("IEL event verification failed: {}", e),
            )
                .into_response();
        }
        let verification = match verifier.finish().await {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    format!("IEL chain verification failed: {}", e),
                )
                    .into_response();
            }
        };

        if !verification.policy_satisfied() {
            let _ = tx.rollback().await;
            let reason = describe_iel_policy_failure(&new_events, iel_prefix);
            return (
                StatusCode::FORBIDDEN,
                format!("IEL anchoring not satisfied — {}", reason),
            )
                .into_response();
        }

        // Routing per `docs/design/iel/merge.md §4`. Order matters: Cnt always
        // wins (works on divergent or linear chains, the only divergence
        // resolver). Divergent-rejection comes BEFORE Dec so Dec on a divergent
        // chain returns ContestRequired. Sealed-Evl returns ContestRequired
        // (algorithmic). Otherwise normal append (overlap creates fork).
        let is_contest = new_events.iter().any(|e| e.kind.is_contest());
        let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());
        // Use the pre-batch divergence + seal state for routing, not the
        // post-finish view: the verifier processes existing + new events
        // together, so a batch that *creates* a fork (overlap, valid) shows
        // up as divergent post-finish, but the design routes it via
        // save_batch's overlap-creates-fork path, not divergent-rejection.
        let chain_divergent = pre_batch_divergent;
        let last_gp_version = pre_batch_seal;

        if is_contest {
            // A failure here is post-dedup, post-advisory-lock, post-verifier
            // — server-internal integrity, not 409. Surface as 500 via
            // `ChainVerificationFailed` (mirrors the SE Cnt/Dec sites).
            for event in &new_events {
                if let Err(e) = state.repo.iel_events.insert_event(&mut tx, event).await {
                    warn!("Failed to insert IEL Cnt (post-dedup-locked): {}", e);
                    let _ = tx.rollback().await;
                    let err = kels_core::KelsError::ChainVerificationFailed(format!(
                        "post-dedup-locked IEL Cnt insert failed: {}",
                        e
                    ));
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
            }
            new_event_count = new_events.len() as u32;
            should_publish = true;
        } else if chain_divergent {
            let _ = tx.rollback().await;
            return (
                StatusCode::FORBIDDEN,
                "Contest required: IEL is divergent — only Cnt resolves a divergent IEL",
            )
                .into_response();
        } else if is_decommission {
            for event in &new_events {
                if let Err(e) = state.repo.iel_events.insert_event(&mut tx, event).await {
                    warn!("Failed to insert IEL Dec (post-dedup-locked): {}", e);
                    let _ = tx.rollback().await;
                    let err = kels_core::KelsError::ChainVerificationFailed(format!(
                        "post-dedup-locked IEL Dec insert failed: {}",
                        e
                    ));
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
            }
            new_event_count = new_events.len() as u32;
            should_publish = true;
        } else {
            // Algorithmic ContestRequired: Evl at version <= seal AND chain not divergent.
            if let Some(seal) = last_gp_version {
                for event in &new_events {
                    if !event.kind.is_terminal() && event.version <= seal {
                        let _ = tx.rollback().await;
                        return (
                            StatusCode::FORBIDDEN,
                            format!(
                                "Contest required: IEL Evl at version {} lands at or before evaluation seal {}",
                                event.version, seal
                            ),
                        )
                            .into_response();
                    }
                }
            }

            // Normal append. `save_batch` handles overlap-creates-fork.
            match state
                .repo
                .iel_events
                .save_batch(&mut tx, &new_events, last_gp_version)
                .await
            {
                Ok(crate::repository::SaveBatchResult::Accepted { new_count }) => {
                    new_event_count = new_count;
                    should_publish = new_count > 0;
                }
                Ok(crate::repository::SaveBatchResult::DivergenceCreated {
                    new_count,
                    diverged_at_version: v,
                }) => {
                    diverged_at_version = Some(v);
                    new_event_count = new_count;
                    should_publish = new_count > 0;
                }
                Err(e) => {
                    warn!("Failed to save IEL batch: {}", e);
                    let _ = tx.rollback().await;
                    return (StatusCode::CONFLICT, format!("{}", e)).into_response();
                }
            }
        }

        if let Err(e) = tx.commit().await {
            warn!("Failed to commit IEL transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }
    }

    if should_publish {
        let effective_said = match state.repo.iel_events.effective_said(iel_prefix).await {
            Ok(Some((said, _))) => Some(said),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "Failed to compute IEL effective SAID for {}: {}",
                    iel_prefix, e
                );
                None
            }
        };
        if let (Some(conn), Some(said)) = (&state.redis_conn, &effective_said) {
            let mut conn = conn.clone();
            let message = format!("{}:{}", iel_prefix, said);
            if let Err(e) = redis::cmd("PUBLISH")
                .arg("iel_updates")
                .arg(&message)
                .query_async::<()>(&mut conn)
                .await
            {
                warn!("Failed to publish IEL update: {}", e);
            } else {
                debug!(
                    iel_prefix = %iel_prefix,
                    effective_said = %said,
                    "Published IEL update to Redis"
                );
            }
        }
    }

    let response = kels_core::SubmitIdentityEventsResponse {
        diverged_at: diverged_at_version,
        applied: new_event_count > 0,
        terminal: None,
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

/// Fetch a page of IEL events ordered
/// `(version ASC, kind sort_priority ASC, said ASC)`.
///
/// Identifies the chain by either `request.prefix` (direct lookup) or
/// `request.said` (event-SAID lookup; server resolves prefix via subquery,
/// per #167). Exactly one must be set; both/neither → 400.
pub async fn get_identity_events(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::IdentityEventPageRequest>,
) -> impl IntoResponse {
    let page_size = kels_core::page_size();
    let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
    let since_str = request.since.as_ref().map(|s| s.as_ref());

    let mut tx = match state.repo.iel_events.pool.begin_transaction().await {
        Ok(tx) => tx,
        Err(e) => {
            warn!("Failed to begin IEL fetch transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }
    };

    // Build the chain selector. Exactly one of `prefix` / `said` must be set.
    let prefix_string;
    let said_string;
    let selector = match (&request.prefix, &request.said) {
        (Some(p), None) => {
            prefix_string = p.to_string();
            crate::repository::IelChainSelector::Prefix(&prefix_string)
        }
        (None, Some(s)) => {
            said_string = s.to_string();
            crate::repository::IelChainSelector::EventSaid(&said_string)
        }
        _ => {
            let _ = tx.commit().await;
            return (
                StatusCode::BAD_REQUEST,
                "exactly one of `prefix` or `said` must be set",
            )
                .into_response();
        }
    };

    let result = state
        .repo
        .iel_events
        .fetch_iel_page(&mut tx, selector, since_str, Some(limit + 1))
        .await;
    let _ = tx.commit().await;

    match result {
        Ok(events) if events.is_empty() => (StatusCode::NOT_FOUND, "IEL not found").into_response(),
        Ok(events) => {
            let has_more = events.len() as u64 > limit;
            let events: Vec<_> = events.into_iter().take(limit as usize).collect();
            let page = kels_core::IdentityEventPage { has_more, events };
            (StatusCode::OK, Json(page)).into_response()
        }
        Err(e) => {
            warn!("Failed to fetch IEL events: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Check whether a specific IEL event SAID exists on the server.
pub async fn identity_event_exists(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::IdentityEventExistsRequest>,
) -> impl IntoResponse {
    match state.repo.iel_events.event_exists(&request.said).await {
        Ok(true) => (StatusCode::OK, "exists").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            warn!("Failed to check IEL event exists: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Fetch the effective SAID of an IEL chain.
pub async fn get_iel_effective_said(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::IdentityEventEffectiveSaidRequest>,
) -> impl IntoResponse {
    match state.repo.iel_events.effective_said(&request.prefix).await {
        Ok(Some((said, divergent))) => (
            StatusCode::OK,
            Json(kels_core::EffectiveSaidResponse { said, divergent }),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "IEL not found").into_response(),
        Err(e) => {
            warn!("Failed to get IEL effective SAID: {}", e);
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
pub async fn list_sel_prefixes(
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

// === Layer 2: SEL Repair History ===

pub(crate) async fn get_sel_repairs(
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

pub(crate) async fn get_sel_repair_events(
    State(state): State<Arc<AppState>>,
    Json(request): Json<kels_core::SadRepairPageRequest>,
) -> impl IntoResponse {
    let page_size = kels_core::page_size();
    let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
    let offset = request.offset.unwrap_or(0);

    match state
        .repo
        .sad_events
        .get_repair_events(request.said.as_ref(), limit, offset)
        .await
    {
        Ok((events, has_more)) => (
            StatusCode::OK,
            Json(kels_core::SadEventPage { events, has_more }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to get repair events for {}: {}", request.said, e);
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
pub async fn test_list_sel_prefixes(
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
