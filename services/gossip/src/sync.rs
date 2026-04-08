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

use cesr::Matter;
use futures::{StreamExt, future::join_all};
use kels_core::{KelsClient, KelsError, PeerSigner};
use rand::seq::SliceRandom;
use thiserror::Error;

use crate::{
    allowlist::SharedAllowlist,
    types::{GossipCommand, GossipEvent, KelAnnouncement, SadAnnouncement},
};

/// Tracks prefix:said pairs recently stored via gossip to prevent feedback loops.
/// When gossip stores events, KELS publishes to Redis, which would re-trigger announcement.
pub type RecentlyStoredFromGossip = Arc<RwLock<HashMap<String, Instant>>>;

/// Shared Redis connection manager.
pub type RedisConnection = Arc<redis::aio::ConnectionManager>;

/// Optional Redis connection — None in tests where Redis is unavailable.
pub type OptionalRedis = Option<RedisConnection>;

pub const RECENTLY_STORED_TTL: Duration = Duration::from_secs(60);

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
    local_kel_prefix: cesr::Digest,
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

        // Check if this was recently stored via gossip (feedback loop prevention).
        // The KELS service publishes {prefix}:{effective_said}, which matches the
        // cache key inserted by handle_announcement before forwarding.
        {
            let mut guard = recently_stored.write().await;
            guard.retain(|_, instant| instant.elapsed() < RECENTLY_STORED_TTL);
            if guard.contains_key(&payload) {
                debug!(
                    "Skipping Redis message {} (recently stored from gossip)",
                    payload
                );
                continue;
            }
        }

        if let Some(ann) = KelAnnouncement::from_pubsub_message(&payload, &local_kel_prefix) {
            debug!("Broadcasting: prefix={}, said={}", ann.prefix, ann.said);
            if command_tx.send(GossipCommand::Kel(ann)).await.is_err() {
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
    local_kel_prefix: cesr::Digest,
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

        debug!(channel = %channel, payload = %payload, "SAD Redis message received");

        // Feedback loop prevention — key format must match what the gossip
        // handlers insert before storing locally.
        {
            let mut guard = recently_stored.write().await;
            guard.retain(|_, instant| instant.elapsed() < RECENTLY_STORED_TTL);
            let cache_key = if channel == SAD_PUBSUB_CHANNEL {
                format!("sad-object:{}", payload)
            } else {
                // Chain updates: strip ":repair" suffix before checking, since
                // the handler inserts without it. The SADStore publishes the
                // effective SAID, which matches the handler's cache key.
                let core = payload.strip_suffix(":repair").unwrap_or(&payload);
                format!("sad-record:{}", core)
            };
            if guard.contains_key(&cache_key) {
                debug!(cache_key = %cache_key, "Skipping SAD Redis message (recently stored from gossip)");
                continue;
            }
        }

        let gossip_message = if channel == SAD_PUBSUB_CHANNEL {
            // Object update: payload is just the SAID
            let said_digest = match cesr::Digest::from_qb64(&payload) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Invalid SAID CESR in SAD Redis message: {}", e);
                    continue;
                }
            };
            SadAnnouncement::Object {
                said: said_digest,
                origin: local_kel_prefix.clone(),
            }
        } else if channel == SAD_CHAIN_PUBSUB_CHANNEL {
            // Chain update: payload is "{chain_prefix}:{effective_said}" or with ":repair"
            let repair = payload.ends_with(":repair");
            let core = if repair {
                &payload[..payload.len() - ":repair".len()]
            } else {
                &payload
            };
            if let Some(ann) = KelAnnouncement::from_pubsub_message(core, &local_kel_prefix) {
                SadAnnouncement::Pointer {
                    chain_prefix: ann.prefix.clone(),
                    said: ann.said.clone(),
                    origin: local_kel_prefix.clone(),
                    repair,
                }
            } else {
                warn!(channel = %channel, payload = %payload, "Failed to parse SAD chain update");
                continue;
            }
        } else {
            warn!(channel = %channel, "Unexpected SAD Redis channel");
            continue;
        };

        debug!("Broadcasting SAD announcement via gossip");
        if command_tx
            .send(GossipCommand::Sad(gossip_message))
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

/// Redis pub/sub channel for mail updates
const MAIL_PUBSUB_CHANNEL: &str = "mail_updates";

/// Runs the Redis subscriber for mail updates.
/// Broadcasts mail announcements to the gossip network on the mail topic.
pub async fn run_mail_redis_subscriber(
    redis_url: &str,
    command_tx: mpsc::Sender<GossipCommand>,
    recently_stored: RecentlyStoredFromGossip,
) -> Result<(), SyncError> {
    let client = redis::Client::open(redis_url)?;
    let mut pubsub = client.get_async_pubsub().await?;

    pubsub.subscribe(MAIL_PUBSUB_CHANNEL).await?;
    info!("Subscribed to Redis channel: {}", MAIL_PUBSUB_CHANNEL);

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get mail Redis message payload: {}", e);
                continue;
            }
        };

        let announcement: kels_exchange::MailAnnouncement = match serde_json::from_str(&payload) {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to parse mail announcement from Redis: {}", e);
                continue;
            }
        };

        // Feedback loop prevention — use SAID as cache key, matching handle_mail_announcement
        let said = match &announcement {
            kels_exchange::MailAnnouncement::Message(m) => &m.said,
            kels_exchange::MailAnnouncement::Removal { said } => said,
        };
        {
            let mut guard = recently_stored.write().await;
            guard.retain(|_, instant| instant.elapsed() < RECENTLY_STORED_TTL);
            let cache_key = format!("mail:{}", said);
            if guard.contains_key(&cache_key) {
                debug!(cache_key = %cache_key, "Skipping mail Redis message (recently stored from gossip)");
                continue;
            }
        }

        debug!("Broadcasting mail announcement via gossip");
        if command_tx
            .send(GossipCommand::Mail(announcement))
            .await
            .is_err()
        {
            error!("Failed to send mail announce command - channel closed");
            return Err(SyncError::ChannelClosed);
        }
    }

    warn!("Mail Redis subscriber stream ended");
    Ok(())
}

fn max_fetches_per_peer_per_minute() -> u32 {
    kels_core::env_usize("GOSSIP_MAX_FETCHES_PER_PEER_PER_MINUTE", 1024) as u32
}

/// Redis hash key for anti-entropy stale prefix tracking.
/// Maps kel_prefix → source_node_prefix.
const STALE_PREFIX_KEY: &str = "kels:anti_entropy:stale";

/// Handles gossip events and coordinates with KELS
pub struct SyncHandler {
    kels_client: KelsClient,
    sadstore_client: kels_core::SadStoreClient,
    mail_client: kels_exchange::MailClient,
    signer: Arc<dyn kels_core::PeerSigner>,
    /// Tracks the latest known SAID for each prefix
    local_saids: HashMap<cesr::Digest, cesr::Digest>,
    /// Shared allowlist for peer URL lookups
    allowlist: SharedAllowlist,
    /// Tracks recently stored events to prevent Redis feedback loop
    recently_stored: RecentlyStoredFromGossip,
    /// Per-peer fetch rate limiting: maps peer_kel_prefix -> (count, window_start)
    peer_fetch_counts: HashMap<cesr::Digest, (u32, Instant)>,
    /// Redis connection for recording stale prefixes
    redis: OptionalRedis,
}

impl SyncHandler {
    pub fn new(
        kels_url: &str,
        sadstore_url: &str,
        mail_url: &str,
        allowlist: SharedAllowlist,
        recently_stored: RecentlyStoredFromGossip,
        redis: OptionalRedis,
        signer: Arc<dyn kels_core::PeerSigner>,
    ) -> Result<Self, kels_core::KelsError> {
        let mail_client = kels_exchange::MailClient::new(mail_url)
            .map_err(|e| kels_core::KelsError::HttpError(e.to_string()))?;
        Ok(Self {
            kels_client: KelsClient::new(kels_url)?,
            sadstore_client: kels_core::SadStoreClient::new(sadstore_url)?,
            mail_client,
            signer,
            local_saids: HashMap::new(),
            allowlist,
            recently_stored,
            peer_fetch_counts: HashMap::new(),
            redis,
        })
    }

    /// Record a prefix as stale for anti-entropy repair.
    async fn record_stale(&self, prefix: &cesr::Digest, source_node_prefix: &cesr::Digest) {
        if let Some(ref redis) = self.redis {
            record_stale_prefix(redis.as_ref(), prefix, source_node_prefix).await;
        }
    }

    /// Get all peer KELS URLs from the allowlist
    async fn get_peer_kels_urls(&self) -> Vec<(cesr::Digest, String)> {
        let guard = self.allowlist.read().await;
        guard
            .values()
            .map(|peer| {
                (
                    peer.kel_prefix.clone(),
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
            GossipEvent::KelAnnouncementReceived { announcement } => {
                self.handle_announcement(announcement).await?;
            }
            GossipEvent::SadAnnouncementReceived {
                announcement: message,
            } => {
                self.handle_sad_announcement(message).await;
            }
            GossipEvent::MailAnnouncementReceived { announcement } => {
                self.handle_mail_announcement(announcement).await;
            }
            GossipEvent::PeerConnected(peer_kel_prefix) => {
                debug!("Peer connected: {}", peer_kel_prefix);
            }
            GossipEvent::PeerDisconnected(peer_kel_prefix) => {
                debug!("Peer disconnected: {}", peer_kel_prefix);
            }
        }
        Ok(())
    }

    /// Handle a SAD gossip announcement.
    ///
    /// For chain announcements: compare tip SAIDs and fetch chain if different.
    /// For object announcements: check existence and fetch if missing.
    async fn handle_sad_announcement(&self, message: SadAnnouncement) {
        match message {
            SadAnnouncement::Object { said, origin } => {
                self.handle_sad_object_announcement(&said, &origin).await;
            }
            SadAnnouncement::Pointer {
                chain_prefix,
                said,
                origin,
                repair,
            } => {
                self.handle_sad_chain_announcement(&chain_prefix, &said, &origin, repair)
                    .await;
            }
        }
    }

    /// Handle a SAD object announcement — fetch the object if we don't have it.
    async fn handle_sad_object_announcement(&self, said: &cesr::Digest, origin: &cesr::Digest) {
        // Look up origin peer's SADStore URL
        let Some(sadstore_url) = self.get_peer_sadstore_url(origin).await else {
            debug!("No SADStore URL for origin peer {}", origin);
            return;
        };

        let local_client = self.sadstore_client.clone();
        let remote_client = match kels_core::SadStoreClient::new(&sadstore_url) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to build HTTP client for SAD object sync: {}", e);
                return;
            }
        };

        // Check if we already have it locally (HEAD check, no data transfer)
        let said_str: &str = said.as_ref();
        match local_client.sad_object_exists(said_str).await {
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

        // Mark as recently stored BEFORE storing to prevent Redis feedback loop.
        // The POST will publish to Redis `sad_updates`, which the subscriber checks
        // against this cache key.
        {
            let cache_key = format!("sad-object:{}", said);
            self.recently_stored
                .write()
                .await
                .insert(cache_key, Instant::now());
        }

        // Fetch from remote and store locally
        match remote_client.get_sad_object(said_str).await {
            Ok(object) => {
                if let Err(e) = local_client.post_sad_object(&object).await {
                    warn!("Failed to store SAD object {} locally: {}", said, e);
                }
            }
            Err(e) => {
                warn!("Failed to fetch SAD object {} from {}: {}", said, origin, e);
            }
        }
    }

    /// Handle a SAD chain announcement — fetch the chain if our tip differs.
    ///
    /// When `repair` is true, the origin node repaired a divergent chain. We use
    /// `?repair=true` to replace our local divergent state. The full chain is
    /// fetched (no delta) since repair truncates and replaces from the divergence point.
    async fn handle_sad_chain_announcement(
        &self,
        chain_prefix: &cesr::Digest,
        remote_said: &cesr::Digest,
        origin: &cesr::Digest,
        repair: bool,
    ) {
        let Some(sadstore_url) = self.get_peer_sadstore_url(origin).await else {
            debug!("No SADStore URL for origin peer {}", origin);
            return;
        };

        let local_client = self.sadstore_client.clone();

        // Compare effective SAIDs
        let local_said = match local_client
            .fetch_sad_pointer_effective_said(chain_prefix)
            .await
        {
            Ok(Some((said, _))) => Some(said),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "Failed to get local effective SAID for {}: {}",
                    chain_prefix, e
                );
                None
            }
        };

        debug!(
            chain_prefix = %chain_prefix,
            remote_said = %remote_said,
            local_said = ?local_said,
            repair = repair,
            origin = %origin,
            "SAD chain announcement received"
        );

        if local_said.as_deref() == Some(remote_said.as_ref()) {
            debug!("SAD chain {} already in sync", chain_prefix);
            return;
        }

        // Mark as recently stored BEFORE forwarding to prevent Redis feedback loop.
        // The SADStore publishes {prefix}:{effective_said} (or with :repair suffix)
        // to sad_chain_updates. The subscriber strips :repair before checking.
        let cache_key = format!("sad-record:{}:{}", chain_prefix, remote_said);
        self.recently_stored
            .write()
            .await
            .insert(cache_key.clone(), Instant::now());

        let remote_client = match kels_core::SadStoreClient::new(&sadstore_url) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to build HTTP client for SAD record sync: {}", e);
                return;
            }
        };

        // For repair: fetch full chain and submit with ?repair=true.
        // The SADStore deduplicates leading records that already exist locally,
        // so sending the full chain is safe — only the divergent tail is replaced.
        // For normal: delta fetch from local tip — but if the remote's effective
        // SAID is not a real pointer (e.g., synthetic divergent hash), delta fetch
        // from our local tip may miss branches. Use full fetch in that case.
        let sink = match if repair {
            local_client.as_sad_repair_sink()
        } else {
            local_client.as_sad_sink()
        } {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to build HTTP SAD sink: {}", e);
                return;
            }
        };
        let remote_is_real_pointer = local_client
            .sad_pointer_exists(remote_said.as_ref())
            .await
            .unwrap_or(false);
        let since_digest = if repair || !remote_is_real_pointer {
            None
        } else {
            local_said
                .as_deref()
                .and_then(|s| match cesr::Digest::from_qb64(s) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        warn!("Failed to parse SAID for delta sync: {}: {}", s, e);
                        None
                    }
                })
        };

        let source = match remote_client.as_sad_source() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to build HTTP SAD source: {}", e);
                return;
            }
        };

        debug!(
            chain_prefix = %chain_prefix,
            since = ?since_digest,
            repair = repair,
            "Fetching SAD chain from peer"
        );

        match kels_core::forward_sad_pointer(
            chain_prefix,
            &source,
            &sink,
            kels_core::page_size(),
            kels_core::max_pages(),
            since_digest.as_ref(),
        )
        .await
        {
            Ok(()) => {
                debug!(
                    chain_prefix = %chain_prefix,
                    "SAD chain replicated successfully"
                );
            }
            Err(e) => {
                self.recently_stored.write().await.remove(&cache_key);
                warn!(
                    "Failed to replicate SAD chain {} from {}: {}",
                    chain_prefix, origin, e
                );
            }
        }
    }

    /// Handle a mail gossip announcement — replicate metadata or process removal.
    async fn handle_mail_announcement(&self, announcement: kels_exchange::MailAnnouncement) {
        let said = match &announcement {
            kels_exchange::MailAnnouncement::Message(m) => &m.said,
            kels_exchange::MailAnnouncement::Removal { said } => said,
        };

        // Feedback loop prevention
        let cache_key = format!("mail:{}", said);
        {
            let guard = self.recently_stored.read().await;
            if guard.contains_key(&cache_key) {
                debug!("Skipping mail announcement (recently stored from gossip)");
                return;
            }
        }
        self.recently_stored
            .write()
            .await
            .insert(cache_key, Instant::now());

        if let Err(e) = self
            .mail_client
            .handle_announcement(&announcement, self.signer.as_ref())
            .await
        {
            warn!("Mail gossip handler failed: {}", e);
        }
    }

    /// Derive a peer's SADStore URL from their base domain.
    async fn get_peer_sadstore_url(&self, peer_kel_prefix: &cesr::Digest) -> Option<String> {
        let guard = self.allowlist.read().await;
        let peer = guard.get(peer_kel_prefix)?;
        Some(format!("http://sadstore.{}", peer.base_domain))
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
        // Get our local effective SAID for this prefix
        let local_effective_said = self.get_local_effective_said(&announcement.prefix).await?;

        // If effective SAIDs match, we're in sync
        if let Some(ref local) = local_effective_said
            && local == &announcement.said
        {
            debug!("Already in sync for prefix {}", announcement.prefix);
            return Ok(());
        }

        // Application-level deduplication: if we already have this SAID, skip.
        let remote_said_str: &str = announcement.said.as_ref();
        if self.kels_client.event_exists(remote_said_str).await? {
            debug!(
                "Already have announced SAID {} for prefix {}",
                announcement.said, announcement.prefix
            );
            return Ok(());
        }

        info!(
            "SAID mismatch for {}: local_effective={:?}, remote={}, origin={}. Fetching from peers.",
            announcement.prefix, local_effective_said, announcement.said, announcement.origin,
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

        let max_pages = kels_core::max_pages();
        let local_sink = self.kels_client.as_kel_sink()?;

        for (peer_kel_prefix, kels_url) in &peers {
            // Per-peer rate limiting
            {
                let now = Instant::now();
                let entry = self
                    .peer_fetch_counts
                    .entry(peer_kel_prefix.clone())
                    .or_insert((0, now));
                if now.duration_since(entry.1) >= Duration::from_secs(60) {
                    entry.0 = 1;
                    entry.1 = now;
                } else {
                    entry.0 += 1;
                    if entry.0 > max_fetches_per_peer_per_minute() {
                        debug!(
                            "Rate limiting peer {}: {} fetches/min exceeded",
                            peer_kel_prefix,
                            max_fetches_per_peer_per_minute()
                        );
                        continue;
                    }
                }
            }

            let remote_source = KelsClient::new(kels_url)?.as_kel_source()?;

            // Mark as recently stored BEFORE forwarding to prevent Redis feedback loop.
            // The KELS service publishes {prefix}:{effective_said} to kel_updates,
            // which matches this key for both divergent and non-divergent KELs.
            let key = format!("{}:{}", announcement.prefix, announcement.said);
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
                .event_exists(remote_said_str)
                .await
                .unwrap_or(false);
            let since = if remote_is_real_event {
                local_effective_said.as_ref()
            } else {
                None
            };
            let result = forward_with_fallback(
                &announcement.prefix,
                &remote_source,
                &local_sink,
                since,
                max_pages,
            )
            .await;

            match result {
                Ok(()) => {
                    self.refresh_local_effective_said(&announcement.prefix)
                        .await;
                    let new_said = self.local_saids.get(&announcement.prefix).cloned();
                    if new_said != local_effective_said {
                        info!(
                            "Forwarded events for prefix {} from {}",
                            announcement.prefix, kels_url
                        );
                        return Ok(());
                    }
                    // Forward succeeded but no new events — this peer has
                    // the same state as us. Record as stale so AE retries
                    // systematically from all peers later.
                    debug!(
                        "Forward from {} succeeded but no state change for {}",
                        kels_url, announcement.prefix
                    );
                    self.record_stale(&announcement.prefix, &announcement.origin)
                        .await;
                    return Ok(());
                }
                Err(KelsError::NotFound(_)) => {
                    warn!(
                        "KEL not found on remote {} for {}",
                        kels_url, announcement.prefix
                    );
                    continue;
                }
                Err(KelsError::ContestedKel(_)) => {
                    debug!(
                        "KEL {} is already contested locally, skipping sync",
                        announcement.prefix
                    );
                    return Ok(());
                }
                Err(KelsError::ContestRequired) => {
                    debug!(
                        "KEL {} requires contest, cannot accept forwarded events from {}",
                        announcement.prefix, kels_url
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        "Forward from {} failed for {}: {}",
                        kels_url, announcement.prefix, e
                    );
                    continue;
                }
            }
        }

        // No peer had the events — record as stale for anti-entropy repair
        self.record_stale(&announcement.prefix, &announcement.origin)
            .await;
        Ok(())
    }

    /// Get the effective tail SAID for a prefix from local KELS.
    ///
    /// Returns the deterministic effective SAID (composite hash for divergent KELs,
    /// real event SAID for non-divergent). Cached to avoid repeated DB round-trips.
    async fn get_local_effective_said(
        &mut self,
        prefix: &cesr::Digest,
    ) -> Result<Option<cesr::Digest>, SyncError> {
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
            self.local_saids.insert(prefix.clone(), said.clone());
        }
        Ok(effective)
    }

    /// Re-fetch effective tail SAID from local KELS and update cache.
    async fn refresh_local_effective_said(&mut self, prefix: &cesr::Digest) {
        if let Ok(Some((effective, _))) = self.fetch_local_effective_said(prefix).await {
            self.local_saids.insert(prefix.clone(), effective);
        }
    }

    /// Resolving: fetch effective tail SAID and divergence flag from local KELS service.
    /// A wrong answer just triggers an unnecessary sync (which itself verifies).
    async fn fetch_local_effective_said(
        &self,
        prefix: &cesr::Digest,
    ) -> Result<Option<(cesr::Digest, bool)>, SyncError> {
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
    mail_url: String,
    mut event_rx: mpsc::Receiver<GossipEvent>,
    command_tx: mpsc::Sender<GossipCommand>,
    allowlist: SharedAllowlist,
    recently_stored: RecentlyStoredFromGossip,
    redis: OptionalRedis,
    signer: Arc<dyn kels_core::PeerSigner>,
    mut peer_connected_tx: Option<oneshot::Sender<()>>,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(
        &kels_url,
        &sadstore_url,
        &mail_url,
        allowlist,
        recently_stored,
        redis,
        signer,
    )?;
    let mut reap_interval = tokio::time::interval(Duration::from_secs(300));
    reap_interval.tick().await; // consume initial tick

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                let Some(event) = event else {
                    break;
                };

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
            _ = reap_interval.tick() => {
                let now = Instant::now();
                handler.peer_fetch_counts.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
                // Clear cached effective SAIDs — they'll be re-fetched on next
                // access. Prevents unbounded growth from accumulated prefixes.
                handler.local_saids.clear();
            }
        }
    }

    warn!("Event receiver closed");
    Ok(())
}

/// Forward events from a remote source to a local sink with delta-with-fallback.
///
/// Tries delta fetch first (using `since`), falls back to full fetch on
/// `NotFound` (remote may have recovered, removing the since SAID).
async fn forward_with_fallback(
    prefix: &cesr::Digest,
    source: &kels_core::HttpKelSource,
    sink: &kels_core::HttpKelSink,
    since: Option<&cesr::Digest>,
    max_pages: usize,
) -> Result<(), KelsError> {
    if let Some(since_digest) = since {
        match kels_core::forward_key_events(
            prefix,
            source,
            sink,
            kels_core::page_size(),
            max_pages,
            Some(since_digest),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(KelsError::NotFound(_)) => {
                info!(
                    "Since SAID not found on remote for {} (likely recovery). Falling back to full fetch.",
                    prefix
                );
            }
            Err(e) => return Err(e),
        }
    }

    // Full fetch (no since cursor)
    kels_core::forward_key_events(
        prefix,
        source,
        sink,
        kels_core::page_size(),
        max_pages,
        None,
    )
    .await
}

/// Maximum retry count before giving up on a stale prefix. Phase 2 random
/// sampling will rediscover it if the inconsistency persists.
const MAX_STALE_RETRIES: u32 = 10;

/// Base backoff interval for stale prefix retries (seconds).
const STALE_BACKOFF_BASE_SECS: u64 = 30;

/// Parsed stale prefix entry from Redis.
struct StaleEntry {
    source: cesr::Digest,
    retries: u32,
}

/// Encode a stale entry value for Redis: `{source}:{retries}:{not_before_epoch}`.
fn encode_stale_value(source: &cesr::Digest, retries: u32) -> String {
    let backoff_secs = STALE_BACKOFF_BASE_SECS * 2u64.saturating_pow(retries);
    let not_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + backoff_secs;
    format!("{}:{}:{}", source, retries, not_before)
}

/// Decode a stale entry value: `{source}:{retries}:{not_before_epoch}`.
fn decode_stale_value(value: &str) -> (String, u32, u64) {
    let parts: Vec<&str> = value.rsplitn(3, ':').collect();
    if parts.len() == 3 {
        let not_before = parts[0].parse::<u64>().unwrap_or(0);
        let retries = parts[1].parse::<u32>().unwrap_or(0);
        (parts[2].to_string(), retries, not_before)
    } else {
        // Malformed entry — treat as first attempt due immediately
        warn!("Malformed stale entry value: {}", value);
        (value.to_string(), 0, 0)
    }
}

/// Record a stale prefix for anti-entropy repair (first occurrence).
pub async fn record_stale_prefix(
    redis: &redis::aio::ConnectionManager,
    kel_prefix: &cesr::Digest,
    source_node_prefix: &cesr::Digest,
) {
    record_stale_entry(redis, STALE_PREFIX_KEY, kel_prefix, source_node_prefix, 0).await;
}

/// Re-queue a stale prefix with incremented retry count and exponential backoff.
async fn requeue_stale_entry(
    redis: &redis::aio::ConnectionManager,
    key: &str,
    prefix: &cesr::Digest,
    source: &cesr::Digest,
    retries: u32,
) {
    let next_retries = retries + 1;
    if next_retries > MAX_STALE_RETRIES {
        warn!(
            "Anti-entropy: giving up on stale prefix {} after {} retries",
            prefix, retries
        );
        return;
    }
    record_stale_entry(redis, key, prefix, source, next_retries).await;
}

/// Write a stale entry to a Redis hash with backoff encoding.
async fn record_stale_entry(
    redis: &redis::aio::ConnectionManager,
    hash_key: &str,
    prefix: &cesr::Digest,
    source: &cesr::Digest,
    retries: u32,
) {
    let mut conn = redis.clone();
    let value = encode_stale_value(source, retries);
    let prefix_str: &str = prefix.as_ref();
    if let Err(e) = redis::cmd("HSET")
        .arg(hash_key)
        .arg(prefix_str)
        .arg(&value)
        .query_async::<()>(&mut conn)
        .await
    {
        warn!(
            "Failed to record stale prefix {} from {}: {}",
            prefix, source, e
        );
    } else {
        debug!(
            "Recorded stale prefix {} (source: {}, retries: {})",
            prefix, source, retries
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
    prefix: &cesr::Digest,
    since: Option<&cesr::Digest>,
) -> RepairResult {
    let remote_source = match source.as_kel_source() {
        Ok(s) => s,
        Err(e) => {
            warn!(prefix = %prefix, error = %e, "Failed to build HTTP KEL source");
            return RepairResult::Failed;
        }
    };
    let local_sink = match dest.as_kel_sink() {
        Ok(s) => s,
        Err(e) => {
            warn!(prefix = %prefix, error = %e, "Failed to build HTTP KEL sink");
            return RepairResult::Failed;
        }
    };

    match forward_with_fallback(
        prefix,
        &remote_source,
        &local_sink,
        since,
        kels_core::max_pages(),
    )
    .await
    {
        Ok(()) => RepairResult::Repaired,
        Err(KelsError::NotFound(_)) => RepairResult::NoOp,
        Err(KelsError::ContestedKel(_)) => RepairResult::Contested,
        Err(_) => RepairResult::Failed,
    }
}

/// Drain due stale entries from a Redis hash.
///
/// Reads all entries, returns those whose `not_before` has passed, and re-queues
/// entries that aren't due yet (still backing off).
async fn drain_due_stale_entries(
    redis: &redis::aio::ConnectionManager,
    key: &str,
) -> Option<HashMap<cesr::Digest, StaleEntry>> {
    let mut conn = redis.clone();
    let flat: Vec<String> = redis::cmd("HGETALL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .ok()?;

    let raw: Vec<(String, String)> = flat
        .chunks(2)
        .filter_map(|pair| {
            if pair.len() == 2 {
                Some((pair[0].clone(), pair[1].clone()))
            } else {
                None
            }
        })
        .collect();

    if raw.is_empty() {
        return Some(HashMap::new());
    }

    // Delete the whole hash — we'll re-queue entries that aren't due yet
    let _ = redis::cmd("DEL")
        .arg(key)
        .query_async::<()>(&mut conn)
        .await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut due = HashMap::new();
    for (prefix_str, value) in raw {
        let (source_str, retries, not_before) = decode_stale_value(&value);
        if now >= not_before {
            let prefix = match cesr::Digest::from_qb64(&prefix_str) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Invalid CESR prefix in stale entry: {}: {}", prefix_str, e);
                    continue;
                }
            };
            let source = match cesr::Digest::from_qb64(&source_str) {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "Invalid CESR source in stale entry for {}: {}",
                        prefix_str, e
                    );
                    continue;
                }
            };
            due.insert(prefix, StaleEntry { source, retries });
        } else {
            // Not due yet — re-queue with same retries/not_before
            let _ = redis::cmd("HSET")
                .arg(key)
                .arg(&prefix_str)
                .arg(&value)
                .query_async::<()>(&mut conn)
                .await;
        }
    }

    Some(due)
}

/// Drain due stale KEL prefixes from Redis.
async fn drain_stale_prefixes(
    redis: &redis::aio::ConnectionManager,
) -> Option<HashMap<cesr::Digest, StaleEntry>> {
    drain_due_stale_entries(redis, STALE_PREFIX_KEY).await
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
    let local_client = match KelsClient::new(&local_kels_url) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build HTTP client for anti-entropy loop: {}", e);
            return;
        }
    };

    loop {
        tokio::time::sleep(interval).await;

        let peers: Vec<(cesr::Digest, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| {
                    (
                        p.kel_prefix.clone(),
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
            for (kel_prefix, entry) in &stale_entries {
                // Build ordered peer list: source peer first, then others
                let mut ordered_peers: Vec<(cesr::Digest, String)> = Vec::new();
                if let Some(source) = peers.iter().find(|(pp, _)| *pp == entry.source) {
                    ordered_peers.push(source.clone());
                }
                for peer in &peers {
                    if peer.0 != entry.source {
                        ordered_peers.push(peer.clone());
                    }
                }
                if ordered_peers.is_empty() {
                    continue;
                }

                let local = local_client.clone();
                let prefix = kel_prefix.clone();
                let source = entry.source.clone();
                let retries = entry.retries;
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
                        let remote = match KelsClient::new(kels_url) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(
                                    "Anti-entropy: failed to build client for {}: {}",
                                    kels_url, e
                                );
                                continue;
                            }
                        };
                        let remote_effective =
                            remote.fetch_effective_said(&prefix).await.ok().flatten();
                        let remote_said = remote_effective.as_ref().map(|(s, _)| s);
                        let remote_is_divergent =
                            remote_effective.as_ref().map(|(_, d)| *d).unwrap_or(false);

                        if remote_said == local_said.as_ref() {
                            continue;
                        }
                        any_peer_differs = true;

                        // When the remote KEL is divergent (or contested), delta
                        // fetch from the local tip can't reach events on branches
                        // at lower serials. Full fetch is required.
                        let since_for_sync = if remote_is_divergent {
                            None
                        } else {
                            local_said.as_ref()
                        };
                        let result = sync_prefix(&remote, &local, &prefix, since_for_sync).await;
                        if matches!(result, RepairResult::Contested) {
                            return (prefix, source, retries, RepairResult::Contested);
                        }

                        // Check if local state actually changed
                        let new_said = local
                            .fetch_effective_said(&prefix)
                            .await
                            .ok()
                            .flatten()
                            .map(|(s, _)| s);
                        if new_said != local_said {
                            return (prefix, source, retries, RepairResult::Repaired);
                        }
                    }

                    if any_peer_differs {
                        (prefix, source, retries, RepairResult::Failed)
                    } else {
                        (prefix, source, retries, RepairResult::NoOp)
                    }
                });
            }

            for (kel_prefix, source_node_prefix, retries, result) in join_all(tasks).await {
                match result {
                    RepairResult::Repaired => {
                        info!("Anti-entropy: repaired {}", kel_prefix);
                    }
                    RepairResult::Contested => {
                        warn!("Anti-entropy: KEL contested for {}", kel_prefix);
                    }
                    RepairResult::Failed => {
                        warn!(
                            "Anti-entropy: re-queuing stale prefix {} (retry {})",
                            kel_prefix,
                            retries + 1
                        );
                        requeue_stale_entry(
                            redis.as_ref(),
                            STALE_PREFIX_KEY,
                            &kel_prefix,
                            &source_node_prefix,
                            retries,
                        )
                        .await;
                    }
                    RepairResult::NoOp => {
                        debug!("Anti-entropy: all peers agree on state for {}", kel_prefix);
                    }
                }
            }
        }

        // Phase 2: Random sampling
        let (peer_kel_prefix, peer_kels_url) = {
            let mut rng = rand::thread_rng();
            match peers.choose(&mut rng) {
                Some((pp, url)) => (pp.clone(), url.clone()),
                None => continue,
            }
        };

        let remote_client = match KelsClient::new(&peer_kels_url) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Anti-entropy: failed to build client for {}: {}",
                    peer_kels_url, e
                );
                continue;
            }
        };

        let random_cursor = kels_core::generate_nonce();
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
            .map(|s| (s.prefix.as_ref(), s.said.as_ref()))
            .collect();
        let remote_map: HashMap<&str, &str> = remote_page
            .prefixes
            .iter()
            .map(|s| (s.prefix.as_ref(), s.said.as_ref()))
            .collect();

        if local_map == remote_map {
            debug!("Anti-entropy: random sample matched");
            continue;
        }

        info!("Anti-entropy: random sample mismatch detected, reconciling");

        // Collect remote prefixes that need syncing (missing or different locally)
        let mut to_fetch = Vec::new();
        for state in &remote_page.prefixes {
            if local_map.get(state.prefix.as_ref()) == Some(&state.said.as_ref()) {
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
                        let result = sync_prefix(&remote, &local, &prefix, since.as_ref()).await;
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
                        record_stale_prefix(redis.as_ref(), &prefix, &peer_kel_prefix).await;
                    }
                    _ => {}
                }
            }
        }

        // Push to remote where remote is missing or different
        for state in &local_page.prefixes {
            if remote_map.get(state.prefix.as_ref()) == Some(&state.said.as_ref()) {
                continue;
            }
            // Resolving: get remote effective SAID for delta push
            let since = remote_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten()
                .map(|(said, _)| said);

            if let RepairResult::Repaired =
                sync_prefix(&local_client, &remote_client, &state.prefix, since.as_ref()).await
            {
                info!("Anti-entropy: pushed {} to remote", state.prefix);
            }
        }
    }
}

// ==================== SAD Anti-Entropy ====================

/// Redis hash key for SAD chain anti-entropy stale prefix tracking.
const SAD_STALE_PREFIX_KEY: &str = "kels:anti_entropy:sad_chain_stale";

/// Record a SAD chain prefix as stale for anti-entropy repair (first occurrence).
pub async fn record_sad_stale_prefix(
    redis: &redis::aio::ConnectionManager,
    chain_prefix: &cesr::Digest,
    source_node_prefix: &cesr::Digest,
) {
    record_stale_entry(
        redis,
        SAD_STALE_PREFIX_KEY,
        chain_prefix,
        source_node_prefix,
        0,
    )
    .await;
}

/// Periodically runs anti-entropy repair for SAD chain data.
///
/// Two phases per cycle:
/// - **Phase 1 (targeted):** Process known-stale chain prefixes from Redis hash.
/// - **Phase 2 (random sampling):** Compare chain effective SAIDs with a random peer.
pub async fn run_sad_anti_entropy_loop(
    redis: Arc<redis::aio::ConnectionManager>,
    allowlist: SharedAllowlist,
    signer: Arc<dyn kels_core::PeerSigner>,
    sadstore_url: String,
    interval: Duration,
) {
    let local_client = match kels_core::SadStoreClient::new(&sadstore_url) {
        Ok(c) => c,
        Err(e) => {
            error!("SAD anti-entropy: failed to build local client: {}", e);
            return;
        }
    };

    loop {
        tokio::time::sleep(interval).await;

        let peers: Vec<(cesr::Digest, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| {
                    (
                        p.kel_prefix.clone(),
                        format!("http://sadstore.{}", p.base_domain),
                    )
                })
                .collect()
        };

        if peers.is_empty() {
            continue;
        }

        // Phase 1: Process known-stale chain prefixes
        let stale_entries =
            match drain_due_stale_entries(redis.as_ref(), SAD_STALE_PREFIX_KEY).await {
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
            for (chain_prefix, entry) in &stale_entries {
                let mut ordered_peers: Vec<(cesr::Digest, String)> = Vec::new();
                if let Some(source) = peers.iter().find(|(pp, _)| *pp == entry.source) {
                    ordered_peers.push(source.clone());
                }
                for peer in &peers {
                    if peer.0 != entry.source {
                        ordered_peers.push(peer.clone());
                    }
                }
                if ordered_peers.is_empty() {
                    continue;
                }

                let local = local_client.clone();
                let prefix = chain_prefix.clone();
                let source = entry.source.clone();
                let retries = entry.retries;
                tasks.push(async move {
                    let (local_said, local_divergent) =
                        match local.fetch_sad_pointer_effective_said(&prefix).await {
                            Ok(Some((said, div))) => (Some(said), div),
                            _ => (None, false),
                        };

                    for (_, sadstore_url) in &ordered_peers {
                        let remote = match kels_core::SadStoreClient::new(sadstore_url) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let (remote_said, remote_divergent) =
                            match remote.fetch_sad_pointer_effective_said(&prefix).await {
                                Ok(Some((said, div))) => (Some(said), div),
                                _ => (None, false),
                            };

                        if remote_said == local_said {
                            continue;
                        }

                        // Determine sync direction: check if the remote's SAID
                        // exists in our local chain. If yes, we're ahead → push.
                        // If no, remote is ahead → pull.
                        let remote_said_ref = match &remote_said {
                            Some(s) => s.as_ref(),
                            None => continue,
                        };
                        let we_have_remote = local
                            .sad_pointer_exists(remote_said_ref)
                            .await
                            .unwrap_or(false);

                        if we_have_remote {
                            // We're ahead — push to remote
                            let use_repair = remote_divergent && !local_divergent;
                            let Ok(local_source) = local.as_sad_source() else {
                                continue;
                            };
                            let sink_result = if use_repair {
                                remote.as_sad_repair_sink()
                            } else {
                                remote.as_sad_sink()
                            };
                            let Ok(remote_sink) = sink_result else {
                                continue;
                            };
                            // Full fetch when repairing or when local is divergent
                            // (delta from remote's SAID may miss branches that sort
                            // before the cursor in a divergent chain).
                            let since_digest = if use_repair || local_divergent {
                                None
                            } else {
                                remote_said.as_deref().and_then(|s| {
                                    match cesr::Digest::from_qb64(s) {
                                        Ok(d) => Some(d),
                                        Err(e) => {
                                            warn!(
                                                "Failed to parse SAID for delta sync: {}: {}",
                                                s, e
                                            );
                                            None
                                        }
                                    }
                                })
                            };
                            if kels_core::forward_sad_pointer(
                                &prefix,
                                &local_source,
                                &remote_sink,
                                kels_core::page_size(),
                                kels_core::max_pages(),
                                since_digest.as_ref(),
                            )
                            .await
                            .is_ok()
                            {
                                return (prefix, source, retries, true);
                            }
                        } else {
                            // Remote is ahead — pull from remote
                            let use_repair = local_divergent && !remote_divergent;
                            let Ok(remote_source) = remote.as_sad_source() else {
                                continue;
                            };
                            let sink_result = if use_repair {
                                local.as_sad_repair_sink()
                            } else {
                                local.as_sad_sink()
                            };
                            let Ok(local_sink) = sink_result else {
                                continue;
                            };
                            let since_digest = if use_repair {
                                None
                            } else {
                                local_said.as_deref().and_then(|s| {
                                    match cesr::Digest::from_qb64(s) {
                                        Ok(d) => Some(d),
                                        Err(e) => {
                                            warn!(
                                                "Failed to parse SAID for delta sync: {}: {}",
                                                s, e
                                            );
                                            None
                                        }
                                    }
                                })
                            };
                            if kels_core::forward_sad_pointer(
                                &prefix,
                                &remote_source,
                                &local_sink,
                                kels_core::page_size(),
                                kels_core::max_pages(),
                                since_digest.as_ref(),
                            )
                            .await
                            .is_ok()
                            {
                                return (prefix, source, retries, true);
                            }
                        }
                    }
                    (prefix, source, retries, false)
                });
            }

            for (chain_prefix, source_node_prefix, retries, success) in join_all(tasks).await {
                if success {
                    info!("SAD anti-entropy: repaired chain {}", chain_prefix);
                } else {
                    warn!(
                        "SAD anti-entropy: re-queuing stale chain {} (retry {})",
                        chain_prefix,
                        retries + 1
                    );
                    requeue_stale_entry(
                        redis.as_ref(),
                        SAD_STALE_PREFIX_KEY,
                        &chain_prefix,
                        &source_node_prefix,
                        retries,
                    )
                    .await;
                }
            }
        }

        // Phase 2: Random sampling — compare chain effective SAIDs with a random peer
        let (peer_kel_prefix, peer_sadstore_url) = {
            let mut rng = rand::thread_rng();
            match peers.choose(&mut rng) {
                Some(p) => p.clone(),
                None => continue,
            }
        };

        let remote_client = match kels_core::SadStoreClient::new(&peer_sadstore_url) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "SAD anti-entropy: failed to build remote client for {}: {}",
                    peer_sadstore_url, e
                );
                continue;
            }
        };

        let random_cursor = kels_core::generate_nonce();
        let local_page = local_client
            .fetch_sad_pointer_prefixes(signer.as_ref(), Some(&random_cursor), 100)
            .await;
        let remote_page = remote_client
            .fetch_sad_pointer_prefixes(signer.as_ref(), Some(&random_cursor), 100)
            .await;

        let (Ok(local_page), Ok(remote_page)) = (local_page, remote_page) else {
            debug!("SAD anti-entropy: failed to fetch prefix pages for comparison");
            continue;
        };

        let local_map: HashMap<&str, &str> = local_page
            .prefixes
            .iter()
            .map(|s| (s.prefix.as_ref(), s.said.as_ref()))
            .collect();
        let remote_map: HashMap<&str, &str> = remote_page
            .prefixes
            .iter()
            .map(|s| (s.prefix.as_ref(), s.said.as_ref()))
            .collect();

        if local_map == remote_map {
            debug!("SAD anti-entropy: random sample matched");
            continue;
        }

        info!("SAD anti-entropy: random sample mismatch detected, reconciling");

        // Reconcile: for each prefix that differs, determine direction and sync
        let all_prefixes: std::collections::HashSet<&str> = remote_page
            .prefixes
            .iter()
            .chain(local_page.prefixes.iter())
            .map(|s| s.prefix.as_ref())
            .collect();

        type SadSyncFuture = std::pin::Pin<
            Box<
                dyn Future<
                        Output = (
                            cesr::Digest,
                            cesr::Digest,
                            &'static str,
                            Result<(), kels_core::KelsError>,
                        ),
                    > + Send,
            >,
        >;
        let mut sync_tasks: Vec<SadSyncFuture> = Vec::new();
        for prefix in all_prefixes {
            let local_said_str = local_map.get(prefix).copied();
            let remote_said_str = remote_map.get(prefix).copied();

            if local_said_str == remote_said_str {
                continue;
            }

            let prefix_digest = match cesr::Digest::from_qb64(prefix) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Determine direction: check if remote's SAID exists locally
            let we_have_remote = if let Some(said) = remote_said_str {
                local_client.sad_pointer_exists(said).await.unwrap_or(false)
            } else {
                // Remote doesn't have it at all — we're ahead
                true
            };

            let (local_said, local_divergent) = match local_client
                .fetch_sad_pointer_effective_said(&prefix_digest)
                .await
            {
                Ok(Some((said, div))) => (Some(said), div),
                _ => (None, false),
            };
            let (remote_said, remote_divergent) = match remote_client
                .fetch_sad_pointer_effective_said(&prefix_digest)
                .await
            {
                Ok(Some((said, div))) => (Some(said), div),
                _ => (None, false),
            };

            if we_have_remote {
                // We're ahead — push to remote
                let use_repair = remote_divergent && !local_divergent;
                let Ok(local_source) = local_client.as_sad_source() else {
                    continue;
                };
                let sink_result = if use_repair {
                    remote_client.as_sad_repair_sink()
                } else {
                    remote_client.as_sad_sink()
                };
                let Ok(remote_sink) = sink_result else {
                    continue;
                };
                let since = if use_repair {
                    None
                } else {
                    remote_said
                        .as_deref()
                        .and_then(|s| match cesr::Digest::from_qb64(s) {
                            Ok(d) => Some(d),
                            Err(e) => {
                                warn!("Failed to parse SAID for delta sync: {}: {}", s, e);
                                None
                            }
                        })
                };
                let prefix_d = prefix_digest.clone();
                let peer = peer_kel_prefix.clone();
                sync_tasks.push(Box::pin(async move {
                    let result = kels_core::forward_sad_pointer(
                        &prefix_d,
                        &local_source,
                        &remote_sink,
                        kels_core::page_size(),
                        kels_core::max_pages(),
                        since.as_ref(),
                    )
                    .await;
                    (prefix_d, peer, "pushed", result)
                }));
            } else {
                // Remote is ahead — pull from remote
                let use_repair = local_divergent && !remote_divergent;
                let Ok(remote_source) = remote_client.as_sad_source() else {
                    continue;
                };
                let sink_result = if use_repair {
                    local_client.as_sad_repair_sink()
                } else {
                    local_client.as_sad_sink()
                };
                let Ok(local_sink) = sink_result else {
                    continue;
                };
                let since = if use_repair {
                    None
                } else {
                    local_said
                        .as_deref()
                        .and_then(|s| match cesr::Digest::from_qb64(s) {
                            Ok(d) => Some(d),
                            Err(e) => {
                                warn!("Failed to parse SAID for delta sync: {}: {}", s, e);
                                None
                            }
                        })
                };
                let prefix_d = prefix_digest.clone();
                let peer = peer_kel_prefix.clone();
                sync_tasks.push(Box::pin(async move {
                    let result = kels_core::forward_sad_pointer(
                        &prefix_d,
                        &remote_source,
                        &local_sink,
                        kels_core::page_size(),
                        kels_core::max_pages(),
                        since.as_ref(),
                    )
                    .await;
                    (prefix_d, peer, "pulled", result)
                }));
            }
        }

        for (prefix, peer, direction, result) in join_all(sync_tasks).await {
            match result {
                Ok(()) => {
                    info!("SAD anti-entropy: {} {} from/to remote", direction, prefix);
                }
                Err(_) if direction == "pulled" => {
                    // Only record stale when we failed to pull (we're behind).
                    // Failed pushes don't need retrying — gossip will deliver.
                    record_sad_stale_prefix(redis.as_ref(), &prefix, &peer).await;
                }
                Err(_) => {
                    debug!(
                        "SAD anti-entropy: push failed for {}, gossip will deliver",
                        prefix
                    );
                }
            }
        }

        // Phase 3: Object comparison — compare SAD object sets with the same random peer
        let obj_cursor = kels_core::generate_nonce();
        let local_objects = local_client
            .fetch_sad_objects(signer.as_ref(), Some(&obj_cursor), 100)
            .await;
        let remote_objects = remote_client
            .fetch_sad_objects(signer.as_ref(), Some(&obj_cursor), 100)
            .await;

        let (Ok(local_objects), Ok(remote_objects)) = (local_objects, remote_objects) else {
            debug!("SAD anti-entropy: failed to fetch object pages for comparison");
            continue;
        };

        let local_obj_set: std::collections::HashSet<&str> =
            local_objects.saids.iter().map(|s| s.as_ref()).collect();
        let remote_obj_set: std::collections::HashSet<&str> =
            remote_objects.saids.iter().map(|s| s.as_ref()).collect();

        if local_obj_set == remote_obj_set {
            debug!("SAD anti-entropy: object sample matched");
            continue;
        }

        // Pull: objects on remote but not local
        let mut obj_pulled = 0u64;
        for said in remote_obj_set.difference(&local_obj_set) {
            if let Ok(object) = remote_client.get_sad_object(said).await
                && local_client.post_sad_object(&object).await.is_ok()
            {
                obj_pulled += 1;
            }
        }

        // Push: objects on local but not remote
        let mut obj_pushed = 0u64;
        for said in local_obj_set.difference(&remote_obj_set) {
            if let Ok(object) = local_client.get_sad_object(said).await
                && remote_client.post_sad_object(&object).await.is_ok()
            {
                obj_pushed += 1;
            }
        }

        if obj_pulled > 0 || obj_pushed > 0 {
            info!(
                "SAD anti-entropy: objects — pulled {}, pushed {}",
                obj_pulled, obj_pushed
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    struct TestSigner;

    #[async_trait::async_trait]
    impl kels_core::PeerSigner for TestSigner {
        async fn sign(&self, _data: &[u8]) -> Result<kels_core::SignResult, kels_core::KelsError> {
            Ok(kels_core::SignResult {
                signature: cesr::Signature::from_raw(cesr::SignatureCode::MlDsa65, vec![0u8; 3309])
                    .unwrap(),
                peer_kel_prefix: test_digest("test-prefix"),
            })
        }
    }

    fn create_test_handler() -> SyncHandler {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let recently_stored = Arc::new(RwLock::new(HashMap::new()));
        let signer: Arc<dyn kels_core::PeerSigner> = Arc::new(TestSigner);
        SyncHandler::new(
            "http://localhost:8080",
            "http://localhost:8081",
            "http://localhost:8083",
            allowlist,
            recently_stored,
            None,
            signer,
        )
        .unwrap()
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_pubsub_channel_constant() {
        assert_eq!(PUBSUB_CHANNEL, "kel_updates");
    }

    #[test]
    fn test_sync_error_display() {
        let redis_error = SyncError::Redis(redis::RedisError::from((
            redis::ErrorKind::Io,
            "connection refused",
        )));
        assert!(redis_error.to_string().contains("Redis error"));

        let kels_error = SyncError::Kels(KelsError::ServerError(
            "test".to_string(),
            kels_core::ErrorCode::InternalError,
        ));
        assert!(kels_error.to_string().contains("KELS client error"));

        let channel_error = SyncError::ChannelClosed;
        assert_eq!(channel_error.to_string(), "Channel closed");
    }

    #[test]
    fn test_sync_error_from_redis_error() {
        let redis_error = redis::RedisError::from((redis::ErrorKind::Io, "connection refused"));
        let sync_error: SyncError = redis_error.into();
        assert!(matches!(sync_error, SyncError::Redis(_)));
    }

    #[test]
    fn test_sync_error_from_kels_error() {
        let kels_error =
            KelsError::ServerError("test".to_string(), kels_core::ErrorCode::InternalError);
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

        let peer_kel_prefix = test_digest("test-peer-prefix");
        let event = GossipEvent::PeerConnected(peer_kel_prefix);

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
        let signer: Arc<dyn kels_core::PeerSigner> = Arc::new(TestSigner);
        let result = run_sync_handler(
            "http://localhost:8080".to_string(),
            "http://localhost:8082".to_string(),
            "http://localhost:8083".to_string(),
            event_rx,
            command_tx,
            allowlist,
            recently_stored,
            None,
            signer,
            None,
        )
        .await;
        assert!(result.is_ok());
    }
}
