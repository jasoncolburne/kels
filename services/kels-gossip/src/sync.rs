//! Synchronization logic between Redis pub/sub and gossip network.
//!
//! Handles:
//! - Subscribing to Redis for local KEL updates
//! - Broadcasting announcements to gossip network
//! - Processing incoming announcements and fetching missing KELs via HTTP
//! - Delta-based sync (fetch only events after local state) with full-fetch fallback
//! - Recovery-aware audit fetch: when delta fails due to recovery, fetches archived
//!   adversary events and submits them in stages so merge() resolves divergence correctly
//! - Event partitioning: separates adversary and recovery branches for proper merge ordering

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc, oneshot};
use tracing::{debug, error, info, warn};

use futures::StreamExt;
use kels::{
    KelsClient, KelsError, MAX_EVENTS_PER_KEL_RESPONSE, MAX_EVENTS_PER_SUBMISSION, RegistrySigner,
    SignedKeyEvent,
};
use rand::seq::SliceRandom;
use thiserror::Error;

use crate::{
    allowlist::SharedAllowlist,
    gossip_layer::{GossipCommand, GossipEvent},
    protocol::KelAnnouncement,
};

/// Tracks prefix:said pairs recently stored via gossip to prevent feedback loops.
/// When gossip stores events, KELS publishes to Redis, which would re-trigger announcement.
pub type RecentlyStoredFromGossip = Arc<RwLock<HashMap<String, Instant>>>;

/// Shared Redis connection manager.
pub type RedisConnection = Arc<redis::aio::ConnectionManager>;

/// Optional Redis connection — None in tests where Redis is unavailable.
pub type OptionalRedis = Option<RedisConnection>;

const RECENTLY_STORED_TTL: Duration = Duration::from_secs(60);

/// Redis pub/sub channel name (same as libkels uses)
const PUBSUB_CHANNEL: &str = "kel_updates";

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("KELS client error: {0}")]
    Kels(#[from] KelsError),
    #[error("Channel closed")]
    ChannelClosed,
}

/// Runs the Redis subscriber that listens for local KEL updates
/// and broadcasts them to the gossip network.
pub async fn run_redis_subscriber(
    redis_url: &str,
    local_peer_prefix: String,
    command_tx: mpsc::Sender<GossipCommand>,
    recently_stored: RecentlyStoredFromGossip,
) -> Result<(), SyncError> {
    let client = redis::Client::open(redis_url)?;
    let mut pubsub = client.get_async_pubsub().await?;

    pubsub.subscribe(PUBSUB_CHANNEL).await?;
    info!("Subscribed to Redis channel: {}", PUBSUB_CHANNEL);

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get Redis message payload: {}", e);
                continue;
            }
        };

        debug!("Received Redis pub/sub message: {}", payload);

        // Check if this was recently stored via gossip (feedback loop prevention)
        {
            let mut guard = recently_stored.write().await;
            // Clean up expired entries
            guard.retain(|_, instant| instant.elapsed() < RECENTLY_STORED_TTL);
            // Check if this payload is in the cache
            if guard.contains_key(&payload) {
                debug!(
                    "Skipping Redis message {} (recently stored from gossip)",
                    payload
                );
                continue;
            }
        }

        if let Some(ann) = KelAnnouncement::from_pubsub_message(&payload, &local_peer_prefix) {
            debug!("Broadcasting: prefix={}, said={}", ann.prefix, ann.said);
            if command_tx.send(GossipCommand::Announce(ann)).await.is_err() {
                error!("Failed to send announce command - channel closed");
                return Err(SyncError::ChannelClosed);
            }
        }
    }

    warn!("Redis subscriber stream ended");
    Ok(())
}

/// Maximum fetches per peer per minute
const MAX_FETCHES_PER_PEER_PER_MINUTE: u32 = 8192;

/// Redis hash key for anti-entropy stale prefix tracking.
/// Maps kel_prefix → source_node_prefix.
const STALE_PREFIX_KEY: &str = "kels:anti_entropy:stale";

/// Redis key prefix for per-prefix sets of remote effective SAIDs we've already
/// tried and failed to sync.
///
/// Replaces the flat `kels:anti_entropy:divergent` set. Instead of permanently
/// skipping all divergent prefixes (which also blocks recovery), we track *which
/// remote states* we've already attempted. This way:
/// - Same remote effective SAID → skip (already tried, merge will fail again)
/// - New remote effective SAID (e.g., after recovery) → retry → succeeds → clear
/// - Different 3rd-branch combo from another peer → try → fail → add to seen set
///
/// Each key `kels:anti_entropy:seen_saids:<prefix>` is a Redis SET of SAID strings.
/// The set size per prefix is bounded by the number of KELS nodes in the network —
/// each node holds at most one divergent pair (KEL freezes on first divergence),
/// so each node contributes at most one unique effective SAID.
const SEEN_SAIDS_PREFIX: &str = "kels:anti_entropy:seen_saids:";

/// Redis sorted set tracking which prefixes have seen-SAIDs entries, scored by
/// timestamp. Used to bound the number of tracked prefixes via FIFO eviction.
const SEEN_SAIDS_ORDER_KEY: &str = "kels:anti_entropy:seen_saids_order";

/// Maximum number of prefixes tracked in the seen-SAIDs mechanism.
/// When exceeded, the oldest prefix (by timestamp) is evicted.
const MAX_SEEN_SAID_PREFIXES: i64 = 10_000;

/// Handles gossip events and coordinates with KELS
pub struct SyncHandler {
    kels_client: KelsClient,
    /// Tracks the latest known SAID for each prefix
    local_saids: HashMap<String, String>,
    /// Shared allowlist for peer URL lookups
    allowlist: SharedAllowlist,
    /// Tracks recently stored events to prevent Redis feedback loop
    recently_stored: RecentlyStoredFromGossip,
    /// Per-peer fetch rate limiting: maps peer_prefix -> (count, window_start)
    peer_fetch_counts: HashMap<String, (u32, Instant)>,
    /// Redis connection for recording stale prefixes
    redis: OptionalRedis,
}

impl SyncHandler {
    pub fn new(
        kels_url: &str,
        allowlist: SharedAllowlist,
        recently_stored: RecentlyStoredFromGossip,
        redis: OptionalRedis,
    ) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            local_saids: HashMap::new(),
            allowlist,
            recently_stored,
            peer_fetch_counts: HashMap::new(),
            redis,
        }
    }

    /// Record a prefix as stale for anti-entropy repair.
    async fn record_stale(&self, prefix: &str, source_node_prefix: &str) {
        if let Some(ref redis) = self.redis {
            record_stale_prefix(redis.as_ref(), prefix, source_node_prefix).await;
        }
    }

    /// Get all peer KELS URLs from the allowlist
    async fn get_peer_kels_urls(&self) -> Vec<(String, String)> {
        let guard = self.allowlist.read().await;
        guard
            .values()
            .map(|peer| (peer.peer_prefix.clone(), peer.kels_url.clone()))
            .collect()
    }

    /// Process a gossip event
    pub async fn handle_event(
        &mut self,
        event: GossipEvent,
        _command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        match event {
            GossipEvent::AnnouncementReceived { announcement } => {
                self.handle_announcement(announcement).await?;
            }
            GossipEvent::PeerConnected(peer_prefix) => {
                debug!("Peer connected: {}", peer_prefix);
            }
            GossipEvent::PeerDisconnected(peer_prefix) => {
                debug!("Peer disconnected: {}", peer_prefix);
            }
        }
        Ok(())
    }

    /// Handle an announcement from a peer.
    ///
    /// Tries the origin peer first (the node that stored the event), then
    /// falls back to other peers in the allowlist.
    async fn handle_announcement(
        &mut self,
        announcement: KelAnnouncement,
    ) -> Result<(), SyncError> {
        let prefix = &announcement.prefix;
        let remote_effective_said = &announcement.said;

        // Get our local effective SAID for this prefix
        let local_effective_said = self.get_local_effective_said(prefix).await?;

        // If effective SAIDs match, we're in sync
        if let Some(ref local) = local_effective_said
            && local == remote_effective_said
        {
            debug!("Already in sync for prefix {}", prefix);
            return Ok(());
        }

        // Application-level deduplication: if we already have this SAID, skip.
        if self.kels_client.event_exists(remote_effective_said).await? {
            debug!(
                "Already have announced SAID {} for prefix {}",
                remote_effective_said, prefix
            );
            return Ok(());
        }

        info!(
            "SAID mismatch for {}: local_effective={:?}, remote={}, origin={}. Fetching from peers.",
            prefix, local_effective_said, remote_effective_said, announcement.origin,
        );

        // Build peer list with origin first, then remaining peers
        let all_peers = self.get_peer_kels_urls().await;
        let mut peers = Vec::with_capacity(all_peers.len());

        // Origin peer goes first — they definitely have the event
        if let Some(origin_peer) = all_peers.iter().find(|(pp, _)| pp == &announcement.origin) {
            peers.push(origin_peer.clone());
        }
        for peer in &all_peers {
            if peer.0 != announcement.origin {
                peers.push(peer.clone());
            }
        }

        let mut fetched_events = None;
        let max_pages = kels::max_verification_pages();

        for (peer_prefix, kels_url) in &peers {
            // Per-peer rate limiting
            {
                let now = Instant::now();
                let entry = self
                    .peer_fetch_counts
                    .entry(peer_prefix.clone())
                    .or_insert((0, now));
                if now.duration_since(entry.1) >= Duration::from_secs(60) {
                    entry.0 = 1;
                    entry.1 = now;
                } else {
                    entry.0 += 1;
                    if entry.0 > MAX_FETCHES_PER_PEER_PER_MINUTE {
                        debug!(
                            "Rate limiting peer {}: {} fetches/min exceeded",
                            peer_prefix, MAX_FETCHES_PER_PEER_PER_MINUTE
                        );
                        continue;
                    }
                }
            }

            let remote_client = KelsClient::new(kels_url);

            // Fetch events via HTTP — delta when possible, full otherwise
            let events = if let Some(ref effective_said) = local_effective_said {
                // Delta fetch: only events after our local state
                match remote_client
                    .fetch_all_key_events(
                        prefix,
                        Some(effective_said),
                        MAX_EVENTS_PER_KEL_RESPONSE,
                        max_pages,
                    )
                    .await
                {
                    Ok(events) => events,
                    Err(KelsError::EventNotFound(_)) => {
                        // Since SAID was removed by recovery/contest on remote.
                        // Fetch events and audit records separately.
                        info!(
                            "Since SAID not found on remote (likely recovery). Fetching with audit for {}",
                            prefix
                        );
                        let events_result = remote_client
                            .fetch_all_key_events(
                                prefix,
                                None,
                                MAX_EVENTS_PER_KEL_RESPONSE,
                                max_pages,
                            )
                            .await;
                        let audit_result = remote_client.fetch_kel_audit(prefix).await;

                        match (events_result, audit_result) {
                            (Ok(clean_chain), Ok(audit_records)) => {
                                let archived_events = audit_records
                                    .last()
                                    .and_then(|record| match record.as_signed_key_events() {
                                        Ok(events) if !events.is_empty() => {
                                            info!(
                                                "Got {} archived adversary events for {}",
                                                events.len(),
                                                prefix
                                            );
                                            Some(events)
                                        }
                                        Ok(_) => None,
                                        Err(e) => {
                                            warn!("Failed to deserialize audit events: {}", e);
                                            None
                                        }
                                    })
                                    .unwrap_or_default();

                                if archived_events.is_empty() {
                                    // No audit data — fall through to normal submission
                                    clean_chain
                                } else {
                                    // Recovery with archived events: multi-step submission
                                    let tip_said = clean_chain.last().map(|e| e.event.said.clone());

                                    // Mark recently stored BEFORE submission
                                    if let Some(ref said) = tip_said {
                                        let key = format!("{}:{}", prefix, said);
                                        self.recently_stored
                                            .write()
                                            .await
                                            .insert(key, Instant::now());
                                    }

                                    // Step 1: Submit archived adversary events
                                    let _ = self.submit_events_to_kels(&archived_events).await;

                                    // Step 2+3: Split clean chain before the event preceding the
                                    // first recovery-revealing event. This bundles the owner's
                                    // event at the divergence serial with rec, so nodes that have
                                    // only adversary events at that serial can insert the owner
                                    // event as part of recovery.
                                    let applied = if let Some(idx) = clean_chain
                                        .iter()
                                        .position(|e| e.event.reveals_recovery_key())
                                        && idx > 1
                                    {
                                        let _ = self
                                            .submit_events_to_kels(&clean_chain[..idx - 1])
                                            .await;
                                        let recovery_applied = self
                                            .submit_events_to_kels(&clean_chain[idx - 1..])
                                            .await?;
                                        if !recovery_applied {
                                            self.submit_events_to_kels(&clean_chain).await?
                                        } else {
                                            recovery_applied
                                        }
                                    } else {
                                        self.submit_events_to_kels(&clean_chain).await?
                                    };

                                    if applied {
                                        self.refresh_local_effective_said(prefix).await;
                                    }
                                    return Ok(());
                                }
                            }
                            (Err(KelsError::EventNotFound(_)), _)
                            | (_, Err(KelsError::EventNotFound(_))) => {
                                warn!("KEL not found on remote for {}", prefix);
                                continue;
                            }
                            (Err(e), _) | (_, Err(e)) => {
                                warn!("Failed to fetch KEL with audit from {}: {}", kels_url, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Delta fetch failed from {} for {}: {}. Falling back to full fetch.",
                            kels_url, prefix, e
                        );
                        match remote_client
                            .fetch_all_key_events(
                                prefix,
                                None,
                                MAX_EVENTS_PER_KEL_RESPONSE,
                                max_pages,
                            )
                            .await
                        {
                            Ok(events) => events,
                            Err(KelsError::EventNotFound(_)) => {
                                warn!("KEL not found on remote for {}", prefix);
                                continue;
                            }
                            Err(e) => {
                                warn!("Failed to fetch KEL from {}: {}", kels_url, e);
                                continue;
                            }
                        }
                    }
                }
            } else {
                // No local state — fetch full KEL
                match remote_client
                    .fetch_all_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE, max_pages)
                    .await
                {
                    Ok(events) => events,
                    Err(KelsError::EventNotFound(_)) => {
                        warn!("KEL not found on remote for {}", prefix);
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to fetch KEL from {}: {}", kels_url, e);
                        continue;
                    }
                }
            };

            if events.is_empty() {
                continue;
            }

            info!(
                "Fetched {} events for prefix {} from {}",
                events.len(),
                prefix,
                kels_url
            );

            fetched_events = Some((events, kels_url.clone()));
            break;
        }

        let Some((events, kels_url)) = fetched_events else {
            // No peer had the events — record as stale for anti-entropy repair
            self.record_stale(prefix, &announcement.origin).await;
            return Ok(());
        };

        // Mark as recently stored BEFORE submitting to KELS to prevent Redis feedback loop.
        let said = events.last().map(|e| e.event.said.clone());
        if let Some(ref said) = said {
            let key = format!("{}:{}", prefix, said);
            self.recently_stored
                .write()
                .await
                .insert(key, Instant::now());
        }

        // Partition events for divergence-aware submission: primary chain first,
        // deferred fork event second, recovery events last.
        let has_recovery = events.iter().any(|e| e.event.is_recover());
        let (primary, deferred, recovery) = kels::partition_for_submission(events);

        // Submit primary chain in chunks
        for chunk in primary.chunks(MAX_EVENTS_PER_SUBMISSION) {
            self.submit_events_to_kels(chunk).await?;
        }

        // Submit deferred fork events (causes divergence/freeze)
        if !deferred.is_empty() {
            let _ = self.submit_events_to_kels(&deferred).await;
        }

        // Submit recovery events if present (resolves divergence)
        let initially_applied = if !recovery.is_empty() {
            self.submit_events_to_kels(&recovery).await?
        } else {
            true
        };

        // If recovery events were rejected, retry with the full remote KEL
        let applied = if !initially_applied && has_recovery {
            info!(
                "Recovery not applied for {} — retrying with full KEL from {}",
                prefix, kels_url
            );
            let remote_client = KelsClient::new(&kels_url);
            match remote_client
                .fetch_all_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE, max_pages)
                .await
            {
                Ok(events) => {
                    // Serving/forwarding: submit to local KELS which verifies on ingest
                    self.submit_events_to_kels(&events).await.unwrap_or(false)
                }
                Err(e) => {
                    warn!("Failed to fetch full KEL for retry: {}", e);
                    self.record_stale(prefix, &announcement.origin).await;
                    false
                }
            }
        } else {
            initially_applied
        };

        if applied {
            self.refresh_local_effective_said(prefix).await;
        }

        Ok(())
    }

    /// Get the effective tail SAID for a prefix from local KELS.
    ///
    /// Returns the deterministic effective SAID (composite hash for divergent KELs,
    /// real event SAID for non-divergent). Cached to avoid repeated DB round-trips.
    async fn get_local_effective_said(
        &mut self,
        prefix: &str,
    ) -> Result<Option<String>, SyncError> {
        // Check our cache first
        if let Some(said) = self.local_saids.get(prefix) {
            return Ok(Some(said.clone()));
        }

        // Resolving: fetch from KELS and compute effective tail SAID
        let effective = self
            .fetch_local_effective_said(prefix)
            .await?
            .map(|(said, _)| said);
        if let Some(ref said) = effective {
            self.local_saids.insert(prefix.to_string(), said.clone());
        }
        Ok(effective)
    }

    /// Re-fetch effective tail SAID from local KELS and update cache.
    async fn refresh_local_effective_said(&mut self, prefix: &str) {
        if let Ok(Some((effective, _))) = self.fetch_local_effective_said(prefix).await {
            self.local_saids.insert(prefix.to_string(), effective);
        }
    }

    /// Resolving: fetch effective tail SAID and divergence flag from local KELS service.
    /// A wrong answer just triggers an unnecessary sync (which itself verifies).
    async fn fetch_local_effective_said(
        &self,
        prefix: &str,
    ) -> Result<Option<(String, bool)>, SyncError> {
        self.kels_client
            .fetch_effective_said(prefix)
            .await
            .map_err(SyncError::Kels)
    }

    // partition_events, partition_for_seeding, and submit_events_seeding replaced
    // by kels::partition_for_submission in libkels.

    /// Submit events to local KELS using the client library.
    /// Returns true if events were applied (new events stored).
    async fn submit_events_to_kels(&self, events: &[SignedKeyEvent]) -> Result<bool, SyncError> {
        match self.kels_client.submit_events(events).await {
            Ok(result) => {
                if result.applied {
                    info!("Events applied by local KELS");
                    Ok(true)
                } else {
                    warn!(
                        "Events not applied by local KELS: diverged_at={:?}",
                        result.diverged_at
                    );
                    Ok(false)
                }
            }
            Err(KelsError::ContestedKel(msg)) => {
                warn!("KEL is contested: {}", msg);
                Ok(false)
            }
            Err(e) => Err(SyncError::Kels(e)),
        }
    }
}

/// Run the sync event handler.
///
/// If `peer_connected_tx` is provided, it will be signaled on the first
/// `PeerConnected` event. This allows the bootstrap flow to wait for
/// connectivity without consuming the event stream directly.
pub async fn run_sync_handler(
    kels_url: String,
    mut event_rx: mpsc::Receiver<GossipEvent>,
    command_tx: mpsc::Sender<GossipCommand>,
    allowlist: SharedAllowlist,
    recently_stored: RecentlyStoredFromGossip,
    redis: OptionalRedis,
    mut peer_connected_tx: Option<oneshot::Sender<()>>,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(&kels_url, allowlist, recently_stored, redis);

    while let Some(event) = event_rx.recv().await {
        // Signal first PeerConnected to the bootstrap flow
        if matches!(&event, GossipEvent::PeerConnected(_))
            && let Some(tx) = peer_connected_tx.take()
        {
            let _ = tx.send(());
        }

        if let Err(e) = handler.handle_event(event, &command_tx).await {
            error!("Error handling gossip event: {}", e);
        }
    }

    warn!("Event receiver closed");
    Ok(())
}

/// Record a stale prefix for anti-entropy repair.
///
/// Adds an entry to the Redis hash mapping `kel_prefix → source_node_prefix`.
/// The source node is the peer that was expected to have the KEL.
pub async fn record_stale_prefix(
    redis: &redis::aio::ConnectionManager,
    kel_prefix: &str,
    source_node_prefix: &str,
) {
    let mut conn = redis.clone();
    if let Err(e) = redis::cmd("HSET")
        .arg(STALE_PREFIX_KEY)
        .arg(kel_prefix)
        .arg(source_node_prefix)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!(
            "Failed to record stale prefix {} from {}: {}",
            kel_prefix, source_node_prefix, e
        );
    } else {
        debug!(
            "Recorded stale prefix {} (source: {})",
            kel_prefix, source_node_prefix
        );
    }
}

/// Record a remote effective SAID that we've tried and failed to sync for a prefix.
///
/// Adds the SAID to the per-prefix seen set and updates the eviction order.
/// If the number of tracked prefixes exceeds [`MAX_SEEN_SAID_PREFIXES`], the
/// oldest prefix is evicted.
async fn record_seen_said(
    redis: &redis::aio::ConnectionManager,
    kel_prefix: &str,
    remote_said: &str,
) {
    let mut conn = redis.clone();
    let key = format!("{}{}", SEEN_SAIDS_PREFIX, kel_prefix);

    if let Err(e) = redis::cmd("SADD")
        .arg(&key)
        .arg(remote_said)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!(
            "Failed to record seen SAID {} for prefix {}: {}",
            remote_said, kel_prefix, e
        );
        return;
    }

    // Update eviction order (ZADD with current timestamp as score)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    if let Err(e) = redis::cmd("ZADD")
        .arg(SEEN_SAIDS_ORDER_KEY)
        .arg(now)
        .arg(kel_prefix)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!(
            "Failed to update seen-SAIDs order for {}: {}",
            kel_prefix, e
        );
        return;
    }

    // Evict oldest if over limit
    let count: i64 = redis::cmd("ZCARD")
        .arg(SEEN_SAIDS_ORDER_KEY)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);

    if count > MAX_SEEN_SAID_PREFIXES {
        let evicted: Vec<String> = redis::cmd("ZPOPMIN")
            .arg(SEEN_SAIDS_ORDER_KEY)
            .arg(1)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();

        // ZPOPMIN returns [member, score], so first element is the prefix
        if let Some(evicted_prefix) = evicted.first() {
            let evicted_key = format!("{}{}", SEEN_SAIDS_PREFIX, evicted_prefix);
            let _ = redis::cmd("DEL")
                .arg(&evicted_key)
                .query_async::<()>(&mut conn)
                .await;
            debug!(
                "Evicted oldest seen-SAIDs prefix {} to stay under limit",
                evicted_prefix
            );
        }
    }

    info!(
        "Recorded seen SAID {} for prefix {} (will skip same remote state)",
        remote_said, kel_prefix
    );
}

/// Check if we've already tried (and failed) to sync a specific remote effective SAID.
async fn has_seen_said(
    redis: &redis::aio::ConnectionManager,
    kel_prefix: &str,
    remote_said: &str,
) -> bool {
    let mut conn = redis.clone();
    let key = format!("{}{}", SEEN_SAIDS_PREFIX, kel_prefix);
    redis::cmd("SISMEMBER")
        .arg(&key)
        .arg(remote_said)
        .query_async::<bool>(&mut conn)
        .await
        .unwrap_or(false)
}

/// Clear all seen SAIDs for a prefix (e.g., after recovery resolves divergence).
async fn clear_seen_saids(redis: &redis::aio::ConnectionManager, kel_prefix: &str) {
    let mut conn = redis.clone();
    let key = format!("{}{}", SEEN_SAIDS_PREFIX, kel_prefix);
    if let Err(e) = redis::cmd("DEL")
        .arg(&key)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!("Failed to clear seen SAIDs for {}: {}", kel_prefix, e);
    }
    let _ = redis::cmd("ZREM")
        .arg(SEEN_SAIDS_ORDER_KEY)
        .arg(kel_prefix)
        .query_async::<()>(&mut conn)
        .await;
    debug!("Cleared seen SAIDs for prefix {}", kel_prefix);
}

/// Fetch events from `source`, using delta fetch with full-fetch fallback.
/// Returns `None` on failure (caller should handle).
async fn fetch_events_delta(
    source: &KelsClient,
    prefix: &str,
    since: Option<&str>,
) -> Option<Vec<SignedKeyEvent>> {
    if let Some(since_effective_said) = since
        && let Ok(page) = source
            .fetch_key_events(
                prefix,
                Some(since_effective_said),
                MAX_EVENTS_PER_KEL_RESPONSE,
            )
            .await
    {
        return Some(page.events);
    }
    match source
        .fetch_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE)
        .await
    {
        Ok(page) => Some(page.events),
        Err(_) => None,
    }
}

/// Result of submitting fetched events to a KELS node.
enum RepairResult {
    /// Events applied successfully.
    Repaired(usize),
    /// Submission revealed divergence — prefix should be tracked as divergent.
    Diverged,
    /// KEL is contested — no further action possible.
    Contested,
    /// Submission or fetch failed — prefix should be re-queued as stale.
    Failed,
    /// No events to submit (already in sync).
    NoOp,
}

/// Fetch events from `source` (delta with fallback) and submit to `dest`.
async fn sync_prefix(
    source: &KelsClient,
    dest: &KelsClient,
    prefix: &str,
    since: Option<&str>,
) -> RepairResult {
    let events = match fetch_events_delta(source, prefix, since).await {
        Some(events) if !events.is_empty() => events,
        Some(_) => return RepairResult::NoOp,
        None => return RepairResult::Failed,
    };

    let count = events.len();
    match dest.submit_events(&events).await {
        Ok(result) if result.applied => RepairResult::Repaired(count),
        Ok(result) if result.diverged_at.is_some() => RepairResult::Diverged,
        Ok(_) => RepairResult::NoOp,
        Err(KelsError::ContestedKel(_)) => RepairResult::Contested,
        Err(_) => RepairResult::Failed,
    }
}

/// Drain the stale prefix hash from Redis, returning entries and deleting the key atomically.
async fn drain_stale_prefixes(
    redis: &redis::aio::ConnectionManager,
) -> Option<HashMap<String, String>> {
    let mut conn = redis.clone();
    let flat: Vec<String> = redis::cmd("HGETALL")
        .arg(STALE_PREFIX_KEY)
        .query_async(&mut conn)
        .await
        .ok()?;

    let map: HashMap<String, String> = flat
        .chunks(2)
        .filter_map(|pair| {
            if pair.len() == 2 {
                Some((pair[0].clone(), pair[1].clone()))
            } else {
                None
            }
        })
        .collect();

    if !map.is_empty() {
        let _ = redis::cmd("DEL")
            .arg(STALE_PREFIX_KEY)
            .query_async::<()>(&mut conn)
            .await;
    }

    Some(map)
}

/// Periodically runs anti-entropy repair to detect and fix silent divergence.
///
/// Two phases per cycle:
/// - **Phase 1 (targeted):** Process known-stale prefixes from the Redis hash.
/// - **Phase 2 (random sampling):** Compare a random page of prefixes with a random peer.
///
/// If Phase 1 finds stale entries, Phase 2 is skipped for that cycle.
pub async fn run_anti_entropy_loop(
    redis: Arc<redis::aio::ConnectionManager>,
    allowlist: SharedAllowlist,
    local_kels_url: String,
    signer: Arc<dyn RegistrySigner>,
    interval: Duration,
) {
    let local_client = KelsClient::new(&local_kels_url);

    loop {
        tokio::time::sleep(interval).await;

        let peers: Vec<(String, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| (p.peer_prefix.clone(), p.kels_url.clone()))
                .collect()
        };

        if peers.is_empty() {
            continue;
        }

        // Phase 1: Process known-stale prefixes
        let stale_entries = match drain_stale_prefixes(redis.as_ref()).await {
            Some(map) => map,
            None => {
                warn!("Anti-entropy: failed to read stale prefixes");
                continue;
            }
        };

        if !stale_entries.is_empty() {
            info!(
                "Anti-entropy: processing {} stale prefixes",
                stale_entries.len()
            );

            // Group stale prefixes by peer URL with local since SAIDs
            // Tuple: (kel_prefix, local_said, source_node_prefix)
            let mut peer_groups: HashMap<String, Vec<(String, Option<String>, String)>> =
                HashMap::new();
            for (kel_prefix, source_node_prefix) in &stale_entries {
                let kels_url = peers
                    .iter()
                    .find(|(pp, _)| pp == source_node_prefix)
                    .or_else(|| peers.first())
                    .map(|(_, url)| url.clone());
                let Some(kels_url) = kels_url else {
                    continue;
                };
                // Resolving: get local effective SAID for delta comparison
                let local_said = local_client
                    .fetch_effective_said(kel_prefix)
                    .await
                    .ok()
                    .flatten()
                    .map(|(said, _)| said);
                peer_groups.entry(kels_url).or_default().push((
                    kel_prefix.clone(),
                    local_said,
                    source_node_prefix.clone(),
                ));
            }

            // Batch fetch from each peer and process results
            for (kels_url, prefix_group) in &peer_groups {
                let remote_client = KelsClient::new(kels_url);
                let request: HashMap<String, Option<String>> = prefix_group
                    .iter()
                    .map(|(p, s, _)| (p.clone(), s.clone()))
                    .collect();

                let events_map = match remote_client.fetch_kels(&request).await {
                    Ok(map) => map,
                    Err(e) => {
                        warn!("Anti-entropy: batch fetch failed from {}: {}", kels_url, e);
                        for (prefix, _, source) in prefix_group {
                            warn!("Anti-entropy: re-queuing stale prefix {}", prefix);
                            record_stale_prefix(redis.as_ref(), prefix, source).await;
                        }
                        continue;
                    }
                };

                for (kel_prefix, _since, source_node_prefix) in prefix_group {
                    let result = match events_map.get(kel_prefix) {
                        Some(page) if !page.events.is_empty() => {
                            let count = page.events.len();
                            match local_client.submit_events(&page.events).await {
                                Ok(r) if r.applied => RepairResult::Repaired(count),
                                Ok(r) if r.diverged_at.is_some() => RepairResult::Diverged,
                                Ok(_) => RepairResult::NoOp,
                                Err(KelsError::ContestedKel(_)) => RepairResult::Contested,
                                Err(_) => RepairResult::Failed,
                            }
                        }
                        _ => RepairResult::NoOp,
                    };

                    match result {
                        RepairResult::Repaired(n) => {
                            info!("Anti-entropy: repaired {} ({} events)", kel_prefix, n);
                            clear_seen_saids(redis.as_ref(), kel_prefix).await;
                        }
                        RepairResult::Diverged => {
                            // No action — Phase 2 will handle via seen SAIDs when
                            // it next samples this prefix.
                        }
                        RepairResult::Contested => {
                            warn!("Anti-entropy: KEL contested for {}", kel_prefix);
                        }
                        RepairResult::Failed => {
                            warn!("Anti-entropy: re-queuing stale prefix {}", kel_prefix);
                            record_stale_prefix(redis.as_ref(), kel_prefix, source_node_prefix)
                                .await;
                        }
                        RepairResult::NoOp => {}
                    }
                }
            }
        }

        // Phase 2: Random sampling
        let (peer_prefix, peer_kels_url) = {
            let mut rng = rand::thread_rng();
            match peers.choose(&mut rng) {
                Some((pp, url)) => (pp.clone(), url.clone()),
                None => continue,
            }
        };

        let remote_client = KelsClient::new(&peer_kels_url);

        let random_cursor = kels::generate_nonce();
        let local_page = local_client
            .fetch_prefixes(signer.as_ref(), Some(&random_cursor), 100)
            .await;
        let remote_page = remote_client
            .fetch_prefixes(signer.as_ref(), Some(&random_cursor), 100)
            .await;

        let (Ok(local_page), Ok(remote_page)) = (local_page, remote_page) else {
            debug!("Anti-entropy: failed to fetch prefix pages for comparison");
            continue;
        };

        let local_map: HashMap<&str, &str> = local_page
            .prefixes
            .iter()
            .map(|s| (s.prefix.as_str(), s.said.as_str()))
            .collect();
        let remote_map: HashMap<&str, &str> = remote_page
            .prefixes
            .iter()
            .map(|s| (s.prefix.as_str(), s.said.as_str()))
            .collect();

        if local_map == remote_map {
            debug!("Anti-entropy: random sample matched");
            continue;
        }

        info!("Anti-entropy: random sample mismatch detected, reconciling");

        // Collect remote prefixes that need syncing (missing or different locally)
        let mut to_fetch = Vec::new();
        for state in &remote_page.prefixes {
            if local_map.get(state.prefix.as_str()) == Some(&state.said.as_str()) {
                continue;
            }
            if has_seen_said(redis.as_ref(), &state.prefix, &state.said).await {
                continue;
            }
            // Resolving: fetch local effective SAID and divergence flag for delta comparison
            let (local_said, local_divergent) = match local_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten()
            {
                Some((said, divergent)) => (Some(said), Some(divergent)),
                None => (None, None),
            };
            to_fetch.push((state, local_said, local_divergent));
        }

        // Batch fetch from remote and process results
        if !to_fetch.is_empty() {
            let request: HashMap<String, Option<String>> = to_fetch
                .iter()
                .map(|(state, local_said, _)| (state.prefix.clone(), local_said.clone()))
                .collect();

            let events_map = remote_client.fetch_kels(&request).await.unwrap_or_default();

            for (state, _local_said, local_divergent) in &to_fetch {
                let result = match events_map.get(&state.prefix) {
                    Some(page) if !page.events.is_empty() => {
                        let count = page.events.len();
                        match local_client.submit_events(&page.events).await {
                            Ok(r) if r.applied => RepairResult::Repaired(count),
                            Ok(r) if r.diverged_at.is_some() => RepairResult::Diverged,
                            Ok(_) => RepairResult::NoOp,
                            Err(KelsError::ContestedKel(_)) => RepairResult::Contested,
                            Err(_) => RepairResult::Failed,
                        }
                    }
                    _ => RepairResult::Failed,
                };

                match result {
                    RepairResult::Repaired(n) => {
                        info!(
                            "Anti-entropy: repaired {} from remote ({n} events)",
                            state.prefix
                        );
                        clear_seen_saids(redis.as_ref(), &state.prefix).await;
                    }
                    RepairResult::Diverged => {
                        record_seen_said(redis.as_ref(), &state.prefix, &state.said).await;
                    }
                    RepairResult::Failed => {
                        // Resolving: check if local KEL is already divergent (three-way).
                        // Only suppress retries when we know the local KEL is divergent,
                        // indicating a three-way divergence scenario.
                        if local_divergent == &Some(true) {
                            // Local KEL is divergent and merge failed — likely three-way
                            // divergence (nodes hold different adversary branch pairs). Record
                            // the remote's SAID as seen to stop retrying. This is a resolving
                            // heuristic: a wrong guess either causes an unnecessary retry or
                            // skips one sync cycle — neither is a security issue.
                            record_seen_said(redis.as_ref(), &state.prefix, &state.said).await;
                        } else {
                            record_stale_prefix(redis.as_ref(), &state.prefix, &peer_prefix).await;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Push to remote where remote is missing or different
        for state in &local_page.prefixes {
            if remote_map.get(state.prefix.as_str()) == Some(&state.said.as_str()) {
                continue;
            }
            if let Some(&remote_said) = remote_map.get(state.prefix.as_str())
                && has_seen_said(redis.as_ref(), &state.prefix, remote_said).await
            {
                continue;
            }

            // Resolving: get remote effective SAID for delta push
            let since = remote_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten()
                .map(|(said, _)| said);

            match sync_prefix(
                &local_client,
                &remote_client,
                &state.prefix,
                since.as_deref(),
            )
            .await
            {
                RepairResult::Repaired(n) => {
                    info!(
                        "Anti-entropy: pushed {} to remote ({n} events)",
                        state.prefix
                    );
                }
                RepairResult::Diverged => {
                    if let Some(&remote_said) = remote_map.get(state.prefix.as_str()) {
                        record_seen_said(redis.as_ref(), &state.prefix, remote_said).await;
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_handler() -> SyncHandler {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let recently_stored = Arc::new(RwLock::new(HashMap::new()));
        SyncHandler::new("http://localhost:8080", allowlist, recently_stored, None)
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_max_fetches_per_peer_per_minute_constant() {
        assert_eq!(MAX_FETCHES_PER_PEER_PER_MINUTE, 8192);
    }

    #[test]
    fn test_pubsub_channel_constant() {
        assert_eq!(PUBSUB_CHANNEL, "kel_updates");
    }

    #[test]
    fn test_sync_error_display() {
        let redis_error = SyncError::Redis(redis::RedisError::from((
            redis::ErrorKind::IoError,
            "connection refused",
        )));
        assert!(redis_error.to_string().contains("Redis error"));

        let kels_error = SyncError::Kels(KelsError::ServerError(
            "test".to_string(),
            kels::ErrorCode::InternalError,
        ));
        assert!(kels_error.to_string().contains("KELS client error"));

        let channel_error = SyncError::ChannelClosed;
        assert_eq!(channel_error.to_string(), "Channel closed");
    }

    #[test]
    fn test_sync_error_from_redis_error() {
        let redis_error =
            redis::RedisError::from((redis::ErrorKind::IoError, "connection refused"));
        let sync_error: SyncError = redis_error.into();
        assert!(matches!(sync_error, SyncError::Redis(_)));
    }

    #[test]
    fn test_sync_error_from_kels_error() {
        let kels_error = KelsError::ServerError("test".to_string(), kels::ErrorCode::InternalError);
        let sync_error: SyncError = kels_error.into();
        assert!(matches!(sync_error, SyncError::Kels(_)));
    }

    #[test]
    fn test_sync_handler_new() {
        let handler = create_test_handler();
        assert!(handler.local_saids.is_empty());
    }

    #[tokio::test]
    async fn test_sync_handler_peer_connected_event() {
        let mut handler = create_test_handler();
        let (command_tx, _command_rx) = mpsc::channel::<GossipCommand>(10);

        let peer_prefix = "test-peer-prefix".to_string();
        let event = GossipEvent::PeerConnected(peer_prefix);

        // Should not error
        let result = handler.handle_event(event, &command_tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_sync_handler_closes_on_receiver_close() {
        let (command_tx, _command_rx) = mpsc::channel::<GossipCommand>(10);
        let (event_tx, event_rx) = mpsc::channel::<GossipEvent>(10);
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let recently_stored = Arc::new(RwLock::new(HashMap::new()));

        // Drop the sender to close the channel
        drop(event_tx);

        // run_sync_handler should complete when receiver closes
        let result = run_sync_handler(
            "http://localhost:8080".to_string(),
            event_rx,
            command_tx,
            allowlist,
            recently_stored,
            None,
            None,
        )
        .await;
        assert!(result.is_ok());
    }
}
