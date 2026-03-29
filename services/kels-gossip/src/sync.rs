//! Synchronization logic between Redis pub/sub and gossip network.
//!
//! Handles:
//! - Subscribing to Redis for local KEL updates
//! - Broadcasting announcements to gossip network
//! - Processing incoming announcements via `forward_key_events` (streaming, divergence-aware)
//! - Delta-based sync (fetch only events after local state) with full-fetch fallback

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc, oneshot};
use tracing::{debug, error, info, warn};

use futures::{StreamExt, future::join_all};
use kels::{KelsClient, KelsError, PeerSigner};
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

/// Redis pub/sub channel for SAD object updates
const SAD_PUBSUB_CHANNEL: &str = "sad_updates";

/// Redis pub/sub channel for SAD chain updates
const SAD_CHAIN_PUBSUB_CHANNEL: &str = "sad_chain_updates";

/// Runs the Redis subscriber for SAD store updates (both objects and chains).
/// Broadcasts announcements to the gossip network on the SAD topic.
pub async fn run_sad_redis_subscriber(
    redis_url: &str,
    local_peer_prefix: String,
    command_tx: mpsc::Sender<GossipCommand>,
    recently_stored: RecentlyStoredFromGossip,
) -> Result<(), SyncError> {
    let client = redis::Client::open(redis_url)?;
    let mut pubsub = client.get_async_pubsub().await?;

    pubsub.subscribe(SAD_PUBSUB_CHANNEL).await?;
    pubsub.subscribe(SAD_CHAIN_PUBSUB_CHANNEL).await?;
    info!(
        "Subscribed to Redis channels: {}, {}",
        SAD_PUBSUB_CHANNEL, SAD_CHAIN_PUBSUB_CHANNEL
    );

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = match msg.get_channel_name().parse() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get SAD Redis message payload: {}", e);
                continue;
            }
        };

        // Feedback loop prevention
        {
            let mut guard = recently_stored.write().await;
            guard.retain(|_, instant| instant.elapsed() < RECENTLY_STORED_TTL);
            let cache_key = format!("sad:{}", payload);
            if guard.contains_key(&cache_key) {
                debug!("Skipping SAD Redis message (recently stored from gossip)");
                continue;
            }
        }

        let gossip_message = if channel == SAD_PUBSUB_CHANNEL {
            // Object update: payload is just the SAID
            kels::SadGossipMessage::Object {
                said: payload,
                origin: local_peer_prefix.clone(),
            }
        } else if channel == SAD_CHAIN_PUBSUB_CHANNEL {
            // Chain update: payload is "{chain_prefix}:{said}"
            if let Some(ann) = KelAnnouncement::from_pubsub_message(&payload, &local_peer_prefix) {
                kels::SadGossipMessage::Chain {
                    chain_prefix: ann.prefix,
                    said: ann.said,
                    origin: local_peer_prefix.clone(),
                }
            } else {
                continue;
            }
        } else {
            continue;
        };

        if command_tx
            .send(GossipCommand::AnnounceSad(gossip_message))
            .await
            .is_err()
        {
            error!("Failed to send SAD announce command - channel closed");
            return Err(SyncError::ChannelClosed);
        }
    }

    warn!("SAD Redis subscriber stream ended");
    Ok(())
}

fn max_fetches_per_peer_per_minute() -> u32 {
    kels::env_usize("GOSSIP_MAX_FETCHES_PER_PEER_PER_MINUTE", 8192) as u32
}

/// Redis hash key for anti-entropy stale prefix tracking.
/// Maps kel_prefix → source_node_prefix.
const STALE_PREFIX_KEY: &str = "kels:anti_entropy:stale";

/// Handles gossip events and coordinates with KELS
pub struct SyncHandler {
    kels_client: KelsClient,
    sadstore_client: kels::SadStoreClient,
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
        sadstore_url: &str,
        allowlist: SharedAllowlist,
        recently_stored: RecentlyStoredFromGossip,
        redis: OptionalRedis,
    ) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            sadstore_client: kels::SadStoreClient::new(sadstore_url),
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
            .map(|peer| {
                (
                    peer.peer_prefix.clone(),
                    format!("http://kels.{}", peer.base_domain),
                )
            })
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
            GossipEvent::SadAnnouncementReceived { message } => {
                self.handle_sad_announcement(message).await;
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

    /// Handle a SAD gossip announcement.
    ///
    /// For chain announcements: compare tip SAIDs and fetch chain if different.
    /// For object announcements: check existence and fetch if missing.
    async fn handle_sad_announcement(&self, message: kels::SadGossipMessage) {
        match message {
            kels::SadGossipMessage::Object { said, origin } => {
                self.handle_sad_object_announcement(&said, &origin).await;
            }
            kels::SadGossipMessage::Chain {
                chain_prefix,
                said,
                origin,
            } => {
                self.handle_sad_chain_announcement(&chain_prefix, &said, &origin)
                    .await;
            }
        }
    }

    /// Handle a SAD object announcement — fetch the object if we don't have it.
    async fn handle_sad_object_announcement(&self, said: &str, origin: &str) {
        // Look up origin peer's SADStore URL
        let Some(sadstore_url) = self.get_peer_sadstore_url(origin).await else {
            debug!("No SADStore URL for origin peer {}", origin);
            return;
        };

        let local_client = self.sadstore_client.clone();
        let remote_client = kels::SadStoreClient::new(&sadstore_url);

        // Check if we already have it locally (HEAD check, no data transfer)
        match local_client.sad_object_exists(said).await {
            Ok(true) => {
                debug!("SAD object {} already exists locally", said);
                return;
            }
            Ok(false) => {} // need to fetch
            Err(e) => {
                warn!("Failed to check local SAD object {}: {}", said, e);
                return;
            }
        }

        // Fetch from remote and store locally
        match remote_client.get_sad_object(said).await {
            Ok(object) => {
                if let Err(e) = local_client.put_sad_object(&object).await {
                    warn!("Failed to store SAD object {} locally: {}", said, e);
                }
            }
            Err(e) => {
                warn!("Failed to fetch SAD object {} from {}: {}", said, origin, e);
            }
        }
    }

    /// Handle a SAD chain announcement — fetch the chain if our tip differs.
    async fn handle_sad_chain_announcement(
        &self,
        chain_prefix: &str,
        remote_said: &str,
        origin: &str,
    ) {
        let Some(sadstore_url) = self.get_peer_sadstore_url(origin).await else {
            debug!("No SADStore URL for origin peer {}", origin);
            return;
        };

        let local_client = self.sadstore_client.clone();

        // Compare effective SAIDs
        let local_said = match local_client.fetch_sad_effective_said(chain_prefix).await {
            Ok(said) => said,
            Err(e) => {
                warn!(
                    "Failed to get local effective SAID for {}: {}",
                    chain_prefix, e
                );
                None
            }
        };

        if local_said.as_deref() == Some(remote_said) {
            debug!("SAD chain {} already in sync", chain_prefix);
            return;
        }

        // Fetch the full chain from the remote peer
        let remote_client = kels::SadStoreClient::new(&sadstore_url);
        match remote_client.fetch_sad_chain(chain_prefix, None).await {
            Ok(page) => {
                // Fetch content objects for all records first
                for stored in &page.records {
                    if let Some(ref content_said) = stored.record.content_said
                        && let Ok(object) = remote_client.get_sad_object(content_said).await
                    {
                        let _ = local_client.put_sad_object(&object).await;
                    }
                }

                // Submit all chain records in one batch (single KEL verification)
                if let Err(e) = local_client.submit_sad_records_batch(&page.records).await {
                    warn!(
                        "Failed to batch-submit SAD records for chain {}: {}",
                        chain_prefix, e
                    );
                    return;
                }
                debug!(
                    "Replicated {} SAD records for chain {}",
                    page.records.len(),
                    chain_prefix
                );
            }
            Err(e) => {
                warn!(
                    "Failed to fetch SAD chain {} from {}: {}",
                    chain_prefix, origin, e
                );
            }
        }
    }

    /// Derive a peer's SADStore URL from their base domain.
    async fn get_peer_sadstore_url(&self, peer_prefix: &str) -> Option<String> {
        let guard = self.allowlist.read().await;
        let peer = guard.get(peer_prefix)?;
        Some(format!("http://kels-sadstore.{}", peer.base_domain))
    }

    /// Handle an announcement from a peer.
    ///
    /// Uses `forward_key_events` to stream events page-at-a-time from a remote
    /// peer to local KELS. Delta fetch when possible, full fetch on fallback.
    /// Tries the origin peer first, then falls back to other peers.
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

        let max_pages = kels::max_pages();
        let local_sink = self.kels_client.as_kel_sink();

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
                    if entry.0 > max_fetches_per_peer_per_minute() {
                        debug!(
                            "Rate limiting peer {}: {} fetches/min exceeded",
                            peer_prefix,
                            max_fetches_per_peer_per_minute()
                        );
                        continue;
                    }
                }
            }

            let remote_source = KelsClient::new(kels_url).as_kel_source();

            // Mark as recently stored BEFORE forwarding to prevent Redis feedback loop.
            let key = format!("{}:{}", prefix, remote_effective_said);
            self.recently_stored
                .write()
                .await
                .insert(key, Instant::now());

            // Forward events: delta with fallback to full fetch.
            // transfer_key_events handles divergence-aware ordering (streaming).
            // When the remote SAID is not a real event (composite/contested hash),
            // the remote KEL is divergent and delta fetch from the local tip can't
            // reach events on other branches. Use full fetch instead.
            let remote_is_real_event = self
                .kels_client
                .event_exists(remote_effective_said)
                .await
                .unwrap_or(false);
            let since = if remote_is_real_event {
                local_effective_said.as_deref()
            } else {
                None
            };
            let result =
                forward_with_fallback(prefix, &remote_source, &local_sink, since, max_pages).await;

            match result {
                Ok(()) => {
                    self.refresh_local_effective_said(prefix).await;
                    let new_said = self.local_saids.get(prefix).cloned();
                    if new_said != local_effective_said {
                        info!("Forwarded events for prefix {} from {}", prefix, kels_url);
                        return Ok(());
                    }
                    // Forward succeeded but no new events — this peer has
                    // the same state as us. Record as stale so AE retries
                    // systematically from all peers later.
                    debug!(
                        "Forward from {} succeeded but no state change for {}",
                        kels_url, prefix
                    );
                    self.record_stale(prefix, &announcement.origin).await;
                    return Ok(());
                }
                Err(KelsError::EventNotFound(_)) => {
                    warn!("KEL not found on remote {} for {}", kels_url, prefix);
                    continue;
                }
                Err(KelsError::ContestedKel(_)) => {
                    debug!("KEL {} is already contested locally, skipping sync", prefix);
                    return Ok(());
                }
                Err(KelsError::ContestRequired) => {
                    debug!(
                        "KEL {} requires contest, cannot accept forwarded events from {}",
                        prefix, kels_url
                    );
                    continue;
                }
                Err(e) => {
                    warn!("Forward from {} failed for {}: {}", kels_url, prefix, e);
                    continue;
                }
            }
        }

        // No peer had the events — record as stale for anti-entropy repair
        self.record_stale(prefix, &announcement.origin).await;
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
}

/// Run the sync event handler.
///
/// If `peer_connected_tx` is provided, it will be signaled on the first
/// `PeerConnected` event. This allows the bootstrap flow to wait for
/// connectivity without consuming the event stream directly.
#[allow(clippy::too_many_arguments)]
pub async fn run_sync_handler(
    kels_url: String,
    sadstore_url: String,
    mut event_rx: mpsc::Receiver<GossipEvent>,
    command_tx: mpsc::Sender<GossipCommand>,
    allowlist: SharedAllowlist,
    recently_stored: RecentlyStoredFromGossip,
    redis: OptionalRedis,
    mut peer_connected_tx: Option<oneshot::Sender<()>>,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(&kels_url, &sadstore_url, allowlist, recently_stored, redis);

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

/// Forward events from a remote source to a local sink with delta-with-fallback.
///
/// Tries delta fetch first (using `since`), falls back to full fetch on
/// `EventNotFound` (remote may have recovered, removing the since SAID).
async fn forward_with_fallback(
    prefix: &str,
    source: &kels::HttpKelSource,
    sink: &kels::HttpKelSink,
    since: Option<&str>,
    max_pages: usize,
) -> Result<(), KelsError> {
    if let Some(since_said) = since {
        match kels::forward_key_events(
            prefix,
            source,
            sink,
            kels::page_size(),
            max_pages,
            Some(since_said),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(KelsError::EventNotFound(_)) => {
                info!(
                    "Since SAID not found on remote for {} (likely recovery). Falling back to full fetch.",
                    prefix
                );
            }
            Err(e) => return Err(e),
        }
    }

    // Full fetch (no since cursor)
    kels::forward_key_events(prefix, source, sink, kels::page_size(), max_pages, None).await
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

/// Result of submitting fetched events to a KELS node.
pub(crate) enum RepairResult {
    /// Events applied successfully (includes divergence — events were still stored).
    Repaired,
    /// KEL is contested — no further action possible.
    Contested,
    /// Submission or fetch failed — prefix should be re-queued as stale.
    Failed,
    /// No events to submit (already in sync).
    NoOp,
}

/// Forward events from `source` to `dest` using delta-with-fallback streaming.
pub(crate) async fn sync_prefix(
    source: &KelsClient,
    dest: &KelsClient,
    prefix: &str,
    since: Option<&str>,
) -> RepairResult {
    let remote_source = source.as_kel_source();
    let local_sink = dest.as_kel_sink();

    match forward_with_fallback(
        prefix,
        &remote_source,
        &local_sink,
        since,
        kels::max_pages(),
    )
    .await
    {
        Ok(()) => RepairResult::Repaired,
        Err(KelsError::EventNotFound(_)) => RepairResult::NoOp,
        Err(KelsError::ContestedKel(_)) => RepairResult::Contested,
        Err(_) => RepairResult::Failed,
    }
}

/// Drain a stale hash from Redis, returning entries and deleting the key atomically.
async fn drain_stale_hash(
    redis: &redis::aio::ConnectionManager,
    key: &str,
) -> Option<HashMap<String, String>> {
    let mut conn = redis.clone();
    let flat: Vec<String> = redis::cmd("HGETALL")
        .arg(key)
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
            .arg(key)
            .query_async::<()>(&mut conn)
            .await;
    }

    Some(map)
}

/// Drain the stale prefix hash from Redis.
async fn drain_stale_prefixes(
    redis: &redis::aio::ConnectionManager,
) -> Option<HashMap<String, String>> {
    drain_stale_hash(redis, STALE_PREFIX_KEY).await
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
    signer: Arc<dyn PeerSigner>,
    interval: Duration,
) {
    let local_client = KelsClient::new(&local_kels_url);

    loop {
        tokio::time::sleep(interval).await;

        let peers: Vec<(String, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| {
                    (
                        p.peer_prefix.clone(),
                        format!("http://kels.{}", p.base_domain),
                    )
                })
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

            // For each stale prefix, query effective SAIDs from peers to find
            // who has a different (newer) state, then sync only from those peers.
            // Parallelized across prefixes.
            let mut tasks = Vec::new();
            for (kel_prefix, source_node_prefix) in &stale_entries {
                // Build ordered peer list: source peer first, then others
                let mut ordered_peers: Vec<(String, String)> = Vec::new();
                if let Some(source) = peers.iter().find(|(pp, _)| pp == source_node_prefix) {
                    ordered_peers.push(source.clone());
                }
                for peer in &peers {
                    if peer.0 != *source_node_prefix {
                        ordered_peers.push(peer.clone());
                    }
                }
                if ordered_peers.is_empty() {
                    continue;
                }

                let local = local_client.clone();
                let prefix = kel_prefix.clone();
                let source = source_node_prefix.clone();
                tasks.push(async move {
                    let local_said = local
                        .fetch_effective_said(&prefix)
                        .await
                        .ok()
                        .flatten()
                        .map(|(s, _)| s);

                    // Query each peer's effective SAID and sync from peers
                    // that have a different state than local.
                    let mut any_peer_differs = false;
                    for (_, kels_url) in &ordered_peers {
                        let remote = KelsClient::new(kels_url);
                        let remote_effective =
                            remote.fetch_effective_said(&prefix).await.ok().flatten();
                        let remote_said = remote_effective.as_ref().map(|(s, _)| s.as_str());
                        let remote_is_divergent =
                            remote_effective.as_ref().map(|(_, d)| *d).unwrap_or(false);

                        if remote_said == local_said.as_deref() {
                            continue;
                        }
                        any_peer_differs = true;

                        // When the remote KEL is divergent (or contested), delta
                        // fetch from the local tip can't reach events on branches
                        // at lower serials. Full fetch is required.
                        let since_for_sync = if remote_is_divergent {
                            None
                        } else {
                            local_said.as_deref()
                        };
                        let result = sync_prefix(&remote, &local, &prefix, since_for_sync).await;
                        if matches!(result, RepairResult::Contested) {
                            return (prefix, source, RepairResult::Contested);
                        }

                        // Check if local state actually changed
                        let new_said = local
                            .fetch_effective_said(&prefix)
                            .await
                            .ok()
                            .flatten()
                            .map(|(s, _)| s);
                        if new_said != local_said {
                            return (prefix, source, RepairResult::Repaired);
                        }
                    }

                    if any_peer_differs {
                        // Peers had different state but sync didn't help — re-queue
                        (prefix, source, RepairResult::Failed)
                    } else {
                        // All peers agree on same state — nothing to repair
                        (prefix, source, RepairResult::NoOp)
                    }
                });
            }

            for (kel_prefix, source_node_prefix, result) in join_all(tasks).await {
                match result {
                    RepairResult::Repaired => {
                        info!("Anti-entropy: repaired {}", kel_prefix);
                    }
                    RepairResult::Contested => {
                        warn!("Anti-entropy: KEL contested for {}", kel_prefix);
                    }
                    RepairResult::Failed => {
                        warn!("Anti-entropy: re-queuing stale prefix {}", kel_prefix);
                        record_stale_prefix(redis.as_ref(), &kel_prefix, &source_node_prefix).await;
                    }
                    RepairResult::NoOp => {
                        debug!("Anti-entropy: all peers agree on state for {}", kel_prefix);
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
            // Resolving: fetch local effective SAID for delta comparison
            let local_said = local_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten()
                .map(|(said, _)| said);
            to_fetch.push((state, local_said));
        }

        // Sync each mismatched prefix concurrently via forward_key_events
        if !to_fetch.is_empty() {
            let tasks: Vec<_> = to_fetch
                .iter()
                .map(|(state, local_said)| {
                    let remote = remote_client.clone();
                    let local = local_client.clone();
                    let prefix = state.prefix.clone();
                    let since = local_said.clone();
                    async move {
                        let result = sync_prefix(&remote, &local, &prefix, since.as_deref()).await;
                        (prefix, result)
                    }
                })
                .collect();

            for (prefix, result) in join_all(tasks).await {
                match result {
                    RepairResult::Repaired => {
                        info!("Anti-entropy: repaired {} from remote", prefix);
                    }
                    RepairResult::Failed => {
                        record_stale_prefix(redis.as_ref(), &prefix, &peer_prefix).await;
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
            // Resolving: get remote effective SAID for delta push
            let since = remote_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten()
                .map(|(said, _)| said);

            if let RepairResult::Repaired = sync_prefix(
                &local_client,
                &remote_client,
                &state.prefix,
                since.as_deref(),
            )
            .await
            {
                info!("Anti-entropy: pushed {} to remote", state.prefix);
            }
        }
    }
}

// ==================== SAD Anti-Entropy ====================

/// Redis hash key for SAD chain anti-entropy stale prefix tracking.
const SAD_STALE_PREFIX_KEY: &str = "kels:anti_entropy:sad_chain_stale";

/// Record a SAD chain prefix as stale for anti-entropy repair.
pub async fn record_sad_stale_prefix(
    redis: &redis::aio::ConnectionManager,
    chain_prefix: &str,
    source_node_prefix: &str,
) {
    let mut conn = redis.clone();
    if let Err(e) = redis::cmd("HSET")
        .arg(SAD_STALE_PREFIX_KEY)
        .arg(chain_prefix)
        .arg(source_node_prefix)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!(
            "Failed to record SAD stale prefix {} from {}: {}",
            chain_prefix, source_node_prefix, e
        );
    }
}

/// Periodically runs anti-entropy repair for SAD chain data.
///
/// Two phases per cycle:
/// - **Phase 1 (targeted):** Process known-stale chain prefixes from Redis hash.
/// - **Phase 2 (random sampling):** Compare chain effective SAIDs with a random peer.
pub async fn run_sad_anti_entropy_loop(
    redis: Arc<redis::aio::ConnectionManager>,
    allowlist: SharedAllowlist,
    sadstore_url: String,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        let peers: Vec<(String, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| {
                    (
                        p.peer_prefix.clone(),
                        format!("http://kels-sadstore.{}", p.base_domain),
                    )
                })
                .collect()
        };

        if peers.is_empty() {
            continue;
        }

        let local_client = kels::SadStoreClient::new(&sadstore_url);

        // Phase 1: Process known-stale chain prefixes
        let stale_entries = match drain_stale_hash(redis.as_ref(), SAD_STALE_PREFIX_KEY).await {
            Some(map) => map,
            None => {
                warn!("SAD anti-entropy: failed to read stale prefixes");
                continue;
            }
        };

        if !stale_entries.is_empty() {
            info!(
                "SAD anti-entropy: processing {} stale chain prefixes",
                stale_entries.len()
            );

            let mut tasks = Vec::new();
            for (chain_prefix, source_node_prefix) in &stale_entries {
                let mut ordered_peers: Vec<(String, String)> = Vec::new();
                if let Some(source) = peers.iter().find(|(pp, _)| pp == source_node_prefix) {
                    ordered_peers.push(source.clone());
                }
                for peer in &peers {
                    if peer.0 != *source_node_prefix {
                        ordered_peers.push(peer.clone());
                    }
                }
                if ordered_peers.is_empty() {
                    continue;
                }

                let local = local_client.clone();
                let prefix = chain_prefix.clone();
                let source = source_node_prefix.clone();
                tasks.push(async move {
                    let local_said = local.fetch_sad_effective_said(&prefix).await.ok().flatten();

                    for (_, sadstore_url) in &ordered_peers {
                        let remote = kels::SadStoreClient::new(sadstore_url);
                        let remote_said = remote
                            .fetch_sad_effective_said(&prefix)
                            .await
                            .ok()
                            .flatten();

                        if remote_said == local_said {
                            continue;
                        }

                        // Fetch the full chain from remote and submit locally
                        if let Ok(page) = remote.fetch_sad_chain(&prefix, None).await {
                            // Fetch content objects first
                            for stored in &page.records {
                                if let Some(ref content_said) = stored.record.content_said
                                    && let Ok(object) = remote.get_sad_object(content_said).await
                                {
                                    let _ = local.put_sad_object(&object).await;
                                }
                            }
                            // Batch submit (single KEL verification)
                            if local.submit_sad_records_batch(&page.records).await.is_ok() {
                                return (prefix, source, true);
                            }
                        }
                    }
                    (prefix, source, false)
                });
            }

            for (chain_prefix, source_node_prefix, success) in join_all(tasks).await {
                if success {
                    info!("SAD anti-entropy: repaired chain {}", chain_prefix);
                } else {
                    warn!("SAD anti-entropy: re-queuing stale chain {}", chain_prefix);
                    record_sad_stale_prefix(redis.as_ref(), &chain_prefix, &source_node_prefix)
                        .await;
                }
            }
        }

        // Phase 2: Random sampling — compare chain effective SAIDs with a random peer
        let (_, peer_sadstore_url) = {
            let mut rng = rand::thread_rng();
            match peers.choose(&mut rng) {
                Some(p) => p.clone(),
                None => continue,
            }
        };

        let remote_client = kels::SadStoreClient::new(&peer_sadstore_url);

        // Fetch a chain from the remote to see if we're missing anything.
        // SAD chains don't have a prefix listing endpoint yet, so we rely on
        // stale prefix tracking from gossip failures for now.
        // Full random sampling requires a list_prefixes endpoint on the SADStore
        // service, which can be added in a follow-up.
        debug!("SAD anti-entropy: random sampling phase (stale-only for now)");
        let _ = remote_client;
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
        SyncHandler::new(
            "http://localhost:8080",
            "http://localhost:8081",
            allowlist,
            recently_stored,
            None,
        )
    }

    // ==================== Constants Tests ====================

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
            "http://localhost:8082".to_string(),
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
