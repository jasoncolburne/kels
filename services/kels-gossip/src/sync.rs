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

    /// Partition events into two branches based on content analysis.
    /// Returns (adversary_branch, recovery_branch) where the recovery branch contains
    /// events that reveal recovery keys (rec/cnt/ror/dec). The adversary branch should
    /// be submitted first to establish divergence context, then the recovery branch.
    fn partition_events(events: Vec<SignedKeyEvent>) -> (Vec<SignedKeyEvent>, Vec<SignedKeyEvent>) {
        if events.len() <= 1 {
            return (events, vec![]);
        }

        let saids: std::collections::HashSet<String> =
            events.iter().map(|e| e.event.said.clone()).collect();

        // An event is a "root" if its previous is not in this batch
        let roots: Vec<_> = events
            .iter()
            .filter(|e| {
                e.event
                    .previous
                    .as_ref()
                    .map(|p| !saids.contains(p))
                    .unwrap_or(true)
            })
            .collect();

        // If 0 or 1 roots, everything is one chain — no partitioning needed
        if roots.len() <= 1 {
            return (events, vec![]);
        }

        // Multiple roots: build chains from each root
        let children: HashMap<String, Vec<&SignedKeyEvent>> = {
            let mut map: HashMap<String, Vec<&SignedKeyEvent>> = HashMap::new();
            for e in &events {
                if let Some(prev) = &e.event.previous {
                    map.entry(prev.clone()).or_default().push(e);
                }
            }
            map
        };

        // Walk each chain and check if it contains recovery-revealing events.
        // Prefer contest roots as "recovery" (submitted second) since contest
        // requires divergence to already be established by the first batch.
        let mut recovery_root_said: Option<String> = None;
        let mut contest_root_said: Option<String> = None;
        for root in &roots {
            let mut has_recovery = root.event.reveals_recovery_key();
            let mut stack: Vec<&str> = vec![root.event.said.as_str()];
            while let Some(current) = stack.pop() {
                if let Some(kids) = children.get(current) {
                    for next in kids {
                        if next.event.reveals_recovery_key() {
                            has_recovery = true;
                        }
                        stack.push(&next.event.said);
                    }
                }
            }
            if has_recovery {
                if root.event.is_contest() && contest_root_said.is_none() {
                    contest_root_said = Some(root.event.said.clone());
                } else if recovery_root_said.is_none() {
                    recovery_root_said = Some(root.event.said.clone());
                }
            }
        }
        let recovery_root_said = contest_root_said.or(recovery_root_said);

        // If no recovery branch found, fall back to returning everything as one batch
        let Some(recovery_root) = recovery_root_said else {
            return (events, vec![]);
        };

        // Collect the recovery chain's SAIDs (DFS to follow all sub-branches)
        let mut recovery_saids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        recovery_saids.insert(recovery_root.clone());
        let mut stack: Vec<&str> = vec![recovery_root.as_str()];
        while let Some(current) = stack.pop() {
            if let Some(kids) = children.get(current) {
                for next in kids {
                    recovery_saids.insert(next.event.said.clone());
                    stack.push(&next.event.said);
                }
            }
        }

        // Adversary events first, recovery events second
        let (recovery, adversary): (Vec<_>, Vec<_>) = events
            .into_iter()
            .partition(|e| recovery_saids.contains(&e.event.said));

        (adversary, recovery)
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
                    .fetch_key_events(prefix, Some(effective_said), MAX_EVENTS_PER_KEL_RESPONSE)
                    .await
                {
                    Ok(page) => page.events,
                    Err(KelsError::KeyNotFound(_)) => {
                        // Since SAID was removed by recovery/contest on remote.
                        // Fetch events and audit records separately.
                        info!(
                            "Since SAID not found on remote (likely recovery). Fetching with audit for {}",
                            prefix
                        );
                        let events_result = remote_client
                            .fetch_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE)
                            .await;
                        let audit_result = remote_client.fetch_kel_audit(prefix).await;

                        match (events_result, audit_result) {
                            (Ok(page), Ok(audit_records)) => {
                                let clean_chain = page.events;
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

                                    // Step 2+3: Split clean chain at first recovery-revealing event.
                                    let applied = if let Some(idx) = clean_chain
                                        .iter()
                                        .position(|e| e.event.reveals_recovery_key())
                                        && idx > 0
                                    {
                                        let _ =
                                            self.submit_events_to_kels(&clean_chain[..idx]).await;
                                        let recovery_applied =
                                            self.submit_events_to_kels(&clean_chain[idx..]).await?;
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
                            (Err(KelsError::KeyNotFound(_)), _)
                            | (_, Err(KelsError::KeyNotFound(_))) => {
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
                            .fetch_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE)
                            .await
                        {
                            Ok(page) => page.events,
                            Err(KelsError::KeyNotFound(_)) => {
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
                    .fetch_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE)
                    .await
                {
                    Ok(page) => page.events,
                    Err(KelsError::KeyNotFound(_)) => {
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

        // For large event sets (e.g. full KEL fetch), use divergence-aware chunked seeding
        let has_recovery = events.iter().any(|e| e.event.is_recover());
        let applied = if events.len() > MAX_EVENTS_PER_SUBMISSION {
            self.submit_events_seeding(events, MAX_EVENTS_PER_SUBMISSION)
                .await?
        } else {
            // Partition events by content: adversary branch first, recovery branch second.
            let (adversary_events, recovery_events) = Self::partition_events(events);

            let initially_applied = if recovery_events.is_empty() {
                self.submit_events_to_kels(&adversary_events).await?
            } else if adversary_events.is_empty() {
                self.submit_events_to_kels(&recovery_events).await?
            } else {
                let _ = self.submit_events_to_kels(&adversary_events).await;
                self.submit_events_to_kels(&recovery_events).await?
            };

            // If recovery events were rejected, retry with the full remote KEL
            if !initially_applied && has_recovery {
                info!(
                    "Recovery not applied for {} — retrying with full KEL from {}",
                    prefix, kels_url
                );
                let remote_client = KelsClient::new(&kels_url);
                match remote_client
                    .fetch_key_events(prefix, None, MAX_EVENTS_PER_KEL_RESPONSE)
                    .await
                {
                    Ok(page) => {
                        // Serving/forwarding: submit to local KELS which verifies on ingest
                        self.submit_events_to_kels(&page.events)
                            .await
                            .unwrap_or(false)
                    }
                    Err(e) => {
                        warn!("Failed to fetch full KEL for retry: {}", e);
                        self.record_stale(prefix, &announcement.origin).await;
                        false
                    }
                }
            } else {
                initially_applied
            }
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
        let effective = self.fetch_local_effective_said(prefix).await?;
        if let Some(ref said) = effective {
            self.local_saids.insert(prefix.to_string(), said.clone());
        }
        Ok(effective)
    }

    /// Re-fetch effective tail SAID from local KELS and update cache.
    async fn refresh_local_effective_said(&mut self, prefix: &str) {
        if let Ok(Some(effective)) = self.fetch_local_effective_said(prefix).await {
            self.local_saids.insert(prefix.to_string(), effective);
        }
    }

    /// Resolving: fetch effective tail SAID from local KELS service.
    /// A wrong answer just triggers an unnecessary sync (which itself verifies).
    async fn fetch_local_effective_said(&self, prefix: &str) -> Result<Option<String>, SyncError> {
        self.kels_client
            .fetch_effective_said(prefix)
            .await
            .map_err(SyncError::Kels)
    }

    /// Partition events for chunked seeding of a potentially divergent KEL.
    ///
    /// Detects fork points (multiple events sharing the same `previous`) and
    /// separates events into:
    /// - primary_chain: one complete branch, submitted first to keep the KEL linear
    /// - deferred_events: the other branch(es) at each fork point, submitted last
    /// - recovery_events: rec/cnt events and their continuations, submitted after deferred
    ///
    /// We pick the longer branch as primary (more data stays accessible during seeding).
    /// No identity attribution — either branch could belong to either party.
    fn partition_for_seeding(
        events: Vec<SignedKeyEvent>,
    ) -> (
        Vec<SignedKeyEvent>,
        Vec<SignedKeyEvent>,
        Vec<SignedKeyEvent>,
    ) {
        if events.is_empty() {
            return (vec![], vec![], vec![]);
        }

        // Build previous → children map
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        let said_to_event: HashMap<String, &SignedKeyEvent> =
            events.iter().map(|e| (e.event.said.clone(), e)).collect();

        for e in &events {
            if let Some(prev) = &e.event.previous {
                children
                    .entry(prev.clone())
                    .or_default()
                    .push(e.event.said.clone());
            }
        }

        // Find fork points: previous values with >1 child
        let fork_points: Vec<String> = children
            .iter()
            .filter(|(_, kids)| kids.len() > 1)
            .map(|(prev, _)| prev.clone())
            .collect();

        // No forks → everything is primary
        if fork_points.is_empty() {
            return (events, vec![], vec![]);
        }

        // For each fork point, walk branches to determine length and detect recovery
        let mut deferred_saids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut recovery_saids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for fork_prev in &fork_points {
            let kids = match children.get(fork_prev) {
                Some(k) => k,
                None => continue,
            };

            // Walk each branch from this fork point
            let mut branches: Vec<(Vec<String>, bool)> = Vec::new(); // (saids, has_recovery)
            for kid_said in kids {
                let mut chain = vec![kid_said.clone()];
                let mut has_recovery = said_to_event
                    .get(kid_said)
                    .map(|e| e.event.reveals_recovery_key())
                    .unwrap_or(false);

                let mut dfs_stack: Vec<String> = vec![kid_said.clone()];
                while let Some(current) = dfs_stack.pop() {
                    if let Some(next_kids) = children.get(&current) {
                        for next in next_kids {
                            chain.push(next.clone());
                            if let Some(e) = said_to_event.get(next)
                                && e.event.reveals_recovery_key()
                            {
                                has_recovery = true;
                            }
                            dfs_stack.push(next.clone());
                        }
                    }
                }
                branches.push((chain, has_recovery));
            }

            // Sort by length descending — longest branch becomes primary
            branches.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

            // First (longest) branch is primary; rest are deferred or recovery
            for (i, (chain, has_recovery)) in branches.into_iter().enumerate() {
                if i == 0 {
                    // Primary branch — check if it has recovery events
                    if has_recovery {
                        // Extract recovery events from the primary chain
                        for (idx, said) in chain.iter().enumerate() {
                            if let Some(e) = said_to_event.get(said)
                                && e.event.reveals_recovery_key()
                            {
                                // This and all subsequent events go to recovery
                                for recovery_said in &chain[idx..] {
                                    recovery_saids.insert(recovery_said.clone());
                                }
                                break;
                            }
                        }
                    }
                    continue;
                }

                // Non-primary branches
                if has_recovery {
                    for said in chain {
                        recovery_saids.insert(said);
                    }
                } else {
                    for said in chain {
                        deferred_saids.insert(said);
                    }
                }
            }
        }

        // Partition events into three buckets maintaining original order
        let mut primary = Vec::new();
        let mut deferred = Vec::new();
        let mut recovery = Vec::new();

        for event in events {
            if recovery_saids.contains(&event.event.said) {
                recovery.push(event);
            } else if deferred_saids.contains(&event.event.said) {
                deferred.push(event);
            } else {
                primary.push(event);
            }
        }

        (primary, deferred, recovery)
    }

    /// Submit events for seeding using divergence-aware chunking.
    ///
    /// Partitions events to ensure the primary chain is submitted linearly first,
    /// then deferred fork events, then recovery events.
    async fn submit_events_seeding(
        &self,
        events: Vec<SignedKeyEvent>,
        max_events: usize,
    ) -> Result<bool, SyncError> {
        let (primary_chain, deferred, recovery) = Self::partition_for_seeding(events);

        // 1. Submit primary chain in chunks (KEL stays linear)
        for chunk in primary_chain.chunks(max_events) {
            self.submit_events_to_kels(chunk).await?;
        }

        // 2. Submit deferred fork events (causes divergence/freeze)
        if !deferred.is_empty() {
            let _ = self.submit_events_to_kels(&deferred).await;
        }

        // 3. Submit recovery events if present (resolves divergence)
        if !recovery.is_empty() {
            return self.submit_events_to_kels(&recovery).await;
        }

        Ok(true)
    }

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
            let mut peer_groups: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
            for (kel_prefix, source_node_prefix) in &stale_entries {
                let kels_url = peers
                    .iter()
                    .find(|(pp, _)| pp == source_node_prefix)
                    .or_else(|| peers.first())
                    .map(|(_, url)| url.clone());
                let Some(kels_url) = kels_url else {
                    continue;
                };
                // Resolving: compute effective tail SAID for sync comparison
                // Resolving: get local effective SAID for delta comparison
                let local_said = local_client
                    .fetch_effective_said(kel_prefix)
                    .await
                    .ok()
                    .flatten();
                peer_groups
                    .entry(kels_url)
                    .or_default()
                    .push((kel_prefix.clone(), local_said));
            }

            // Batch fetch from each peer and process results
            for (kels_url, prefix_group) in &peer_groups {
                let remote_client = KelsClient::new(kels_url);
                let request: HashMap<String, Option<String>> = prefix_group
                    .iter()
                    .map(|(p, s)| (p.clone(), s.clone()))
                    .collect();

                let events_map = match remote_client.fetch_kels(&request).await {
                    Ok(map) => map,
                    Err(e) => {
                        warn!("Anti-entropy: batch fetch failed from {}: {}", kels_url, e);
                        for (prefix, _) in prefix_group {
                            warn!("Anti-entropy: failed to repair stale prefix {}", prefix);
                        }
                        continue;
                    }
                };

                for (kel_prefix, _since) in prefix_group {
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
                            // Don't re-add — Phase 2 will rediscover if still needed.
                            // Re-adding causes a hot retry loop when the source peer
                            // is unreachable.
                            warn!("Anti-entropy: failed to repair stale prefix {}", kel_prefix);
                        }
                        RepairResult::NoOp => {}
                    }
                }
            }
            continue; // skip Phase 2 when we had stale entries
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
            // Resolving: fetch local effective SAID for delta comparison
            let local_said = local_client
                .fetch_effective_said(&state.prefix)
                .await
                .ok()
                .flatten();
            to_fetch.push((state, local_said));
        }

        // Batch fetch from remote and process results
        if !to_fetch.is_empty() {
            let request: HashMap<String, Option<String>> = to_fetch
                .iter()
                .map(|(state, local_said)| (state.prefix.clone(), local_said.clone()))
                .collect();

            let events_map = remote_client.fetch_kels(&request).await.unwrap_or_default();

            for (state, _local_said) in &to_fetch {
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
                        // Use the local effective SAID we already fetched — if it exists
                        // and differs from the remote, record seen to stop retrying.
                        if _local_said.is_some() {
                            // We had local state but merge still failed — likely three-way divergence
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
                .flatten();

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

    use kels::{EventKind, KeyEvent};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

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

    /// Create a minimal SignedKeyEvent for testing partition logic.
    /// Uses the `said` as a simple identifier and `previous` for chain linking.
    fn make_event(said: &str, previous: Option<&str>, kind: EventKind) -> SignedKeyEvent {
        SignedKeyEvent {
            event: KeyEvent {
                said: said.to_string(),
                prefix: "test-prefix".to_string(),
                previous: previous.map(|s| s.to_string()),
                serial: 0,
                public_key: None,
                rotation_hash: None,
                recovery_key: if kind.reveals_recovery_key() {
                    Some("recovery-key".to_string())
                } else {
                    None
                },
                recovery_hash: None,
                kind,
                anchor: None,
                delegating_prefix: None,
            },
            signatures: vec![],
        }
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

    // --- partition_events tests ---

    #[test]
    fn test_partition_events_empty() {
        let (adversary, recovery) = SyncHandler::partition_events(vec![]);
        assert!(adversary.is_empty());
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_events_single_event() {
        let events = vec![make_event("icp1", None, EventKind::Icp)];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 1);
        assert_eq!(adversary[0].event.said, "icp1");
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_events_linear_chain_no_recovery() {
        // A simple chain: icp → rot → ixn — no partitioning needed
        let events = vec![
            make_event("icp1", None, EventKind::Icp),
            make_event("rot1", Some("icp1"), EventKind::Rot),
            make_event("ixn1", Some("rot1"), EventKind::Ixn),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 3);
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_events_linear_chain_with_recovery() {
        // A single chain with recovery: icp → ixn → rec → rot
        // Single root — cannot partition, returns everything as adversary
        let events = vec![
            make_event("icp1", None, EventKind::Icp),
            make_event("ixn1", Some("icp1"), EventKind::Ixn),
            make_event("rec1", Some("ixn1"), EventKind::Rec),
            make_event("rot1", Some("rec1"), EventKind::Rot),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 4);
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_events_two_branches_recovery_detected() {
        // Two branches from a shared ancestor (not in batch):
        // Branch 1 (adversary): adv1 → adv2 (previous "shared" not in batch)
        // Branch 2 (recovery):  rec1 → rot1 (previous "shared" not in batch)
        let events = vec![
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("adv2", Some("adv1"), EventKind::Ixn),
            make_event("rec1", Some("shared"), EventKind::Rec),
            make_event("rot1", Some("rec1"), EventKind::Rot),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        // Recovery branch has rec1 and rot1
        assert_eq!(recovery.len(), 2);
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(recovery_saids.contains(&"rec1"));
        assert!(recovery_saids.contains(&"rot1"));
        // Adversary branch has adv1 and adv2
        assert_eq!(adversary.len(), 2);
        let adversary_saids: Vec<_> = adversary.iter().map(|e| e.event.said.as_str()).collect();
        assert!(adversary_saids.contains(&"adv1"));
        assert!(adversary_saids.contains(&"adv2"));
    }

    #[test]
    fn test_partition_events_two_branches_contest_detected() {
        // Contest event (cnt) also reveals recovery key
        let events = vec![
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("cnt1", Some("shared"), EventKind::Cnt),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 1);
        assert_eq!(adversary[0].event.said, "adv1");
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].event.said, "cnt1");
    }

    #[test]
    fn test_partition_events_two_branches_no_recovery_in_either() {
        // Two branches but neither has recovery events — returns all as adversary
        let events = vec![
            make_event("ixn1", Some("shared"), EventKind::Ixn),
            make_event("ixn2", Some("shared"), EventKind::Ixn),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 2);
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_events_recovery_branch_with_pre_recovery_events() {
        // Recovery branch: ixn1 → rec1 → rot1 (ixn before recovery)
        // Adversary branch: adv1 → adv2 → adv3
        // Both branch from "shared" (not in batch)
        let events = vec![
            make_event("ixn1", Some("shared"), EventKind::Ixn),
            make_event("rec1", Some("ixn1"), EventKind::Rec),
            make_event("rot1", Some("rec1"), EventKind::Rot),
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("adv2", Some("adv1"), EventKind::Ixn),
            make_event("adv3", Some("adv2"), EventKind::Ixn),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        // Recovery chain includes ixn1, rec1, rot1 (the whole chain from the recovery root)
        assert_eq!(recovery.len(), 3);
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(recovery_saids.contains(&"ixn1"));
        assert!(recovery_saids.contains(&"rec1"));
        assert!(recovery_saids.contains(&"rot1"));
        // Adversary chain
        assert_eq!(adversary.len(), 3);
        let adversary_saids: Vec<_> = adversary.iter().map(|e| e.event.said.as_str()).collect();
        assert!(adversary_saids.contains(&"adv1"));
        assert!(adversary_saids.contains(&"adv2"));
        assert!(adversary_saids.contains(&"adv3"));
    }

    #[test]
    fn test_partition_events_decommission_detected_as_recovery() {
        // Decommission (dec) also reveals recovery key
        let events = vec![
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("dec1", Some("shared"), EventKind::Dec),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 1);
        assert_eq!(adversary[0].event.said, "adv1");
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].event.said, "dec1");
    }

    #[test]
    fn test_partition_events_single_root_shared_by_both_branches() {
        // Both branches descend from icp (which IS in the batch) → single root
        // partition_events cannot split these — returns all as adversary
        let events = vec![
            make_event("icp1", None, EventKind::Icp),
            make_event("ixn1", Some("icp1"), EventKind::Ixn),
            make_event("rec1", Some("ixn1"), EventKind::Rec),
            make_event("adv1", Some("icp1"), EventKind::Ixn),
            make_event("adv2", Some("adv1"), EventKind::Ixn),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        // Single root (icp1) — cannot partition
        assert_eq!(adversary.len(), 5);
        assert!(recovery.is_empty());
    }

    // --- partition_for_seeding tests ---

    #[test]
    fn test_partition_for_seeding_empty() {
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(vec![]);
        assert!(primary.is_empty());
        assert!(deferred.is_empty());
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_for_seeding_linear_kel_no_divergence() {
        // Linear chain: icp → ixn1 → ixn2 → ixn3
        let events = vec![
            make_event("icp", None, EventKind::Icp),
            make_event("ixn1", Some("icp"), EventKind::Ixn),
            make_event("ixn2", Some("ixn1"), EventKind::Ixn),
            make_event("ixn3", Some("ixn2"), EventKind::Ixn),
        ];
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);
        assert_eq!(primary.len(), 4);
        assert!(deferred.is_empty());
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_for_seeding_divergent_kel_two_chunks() {
        // Primary chain: icp → ixn1 → ixn2 → ixn3 → ixn4 → ixn5 → ixn6 → ixn7 → ixn8
        // Fork event:                          fork_ixn3 (previous = ixn2, same gen as ixn3)
        let events = vec![
            make_event("icp", None, EventKind::Icp),
            make_event("ixn1", Some("icp"), EventKind::Ixn),
            make_event("ixn2", Some("ixn1"), EventKind::Ixn),
            make_event("ixn3", Some("ixn2"), EventKind::Ixn),
            make_event("ixn4", Some("ixn3"), EventKind::Ixn),
            make_event("ixn5", Some("ixn4"), EventKind::Ixn),
            make_event("ixn6", Some("ixn5"), EventKind::Ixn),
            make_event("ixn7", Some("ixn6"), EventKind::Ixn),
            make_event("ixn8", Some("ixn7"), EventKind::Ixn),
            make_event("fork_ixn3", Some("ixn2"), EventKind::Ixn),
        ];
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);

        // Primary should have 9 events (the longer branch)
        assert_eq!(primary.len(), 9);
        let primary_saids: Vec<_> = primary.iter().map(|e| e.event.said.as_str()).collect();
        assert!(primary_saids.contains(&"icp"));
        assert!(primary_saids.contains(&"ixn3"));
        assert!(primary_saids.contains(&"ixn8"));

        // Deferred should have 1 event (the fork)
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].event.said, "fork_ixn3");

        // No recovery
        assert!(recovery.is_empty());
    }

    #[test]
    fn test_partition_for_seeding_divergent_with_recovery() {
        // Primary chain (10 events):
        //   icp → ixn1 → ixn2 → ixn3 → ixn4 → ixn5 → ixn6 → ixn7 → ixn8 → ixn9
        // Fork event: fork_ixn3 (previous = ixn2)
        // Recovery: rec10 (previous = ixn9) → ixn11 → ixn12
        let events = vec![
            make_event("icp", None, EventKind::Icp),
            make_event("ixn1", Some("icp"), EventKind::Ixn),
            make_event("ixn2", Some("ixn1"), EventKind::Ixn),
            make_event("ixn3", Some("ixn2"), EventKind::Ixn),
            make_event("ixn4", Some("ixn3"), EventKind::Ixn),
            make_event("ixn5", Some("ixn4"), EventKind::Ixn),
            make_event("ixn6", Some("ixn5"), EventKind::Ixn),
            make_event("ixn7", Some("ixn6"), EventKind::Ixn),
            make_event("ixn8", Some("ixn7"), EventKind::Ixn),
            make_event("ixn9", Some("ixn8"), EventKind::Ixn),
            make_event("fork_ixn3", Some("ixn2"), EventKind::Ixn),
            make_event("rec10", Some("ixn9"), EventKind::Rec),
            make_event("ixn11", Some("rec10"), EventKind::Ixn),
            make_event("ixn12", Some("ixn11"), EventKind::Ixn),
        ];
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);

        let primary_saids: Vec<_> = primary.iter().map(|e| e.event.said.as_str()).collect();
        assert_eq!(primary.len(), 10);
        assert!(primary_saids.contains(&"icp"));
        assert!(primary_saids.contains(&"ixn9"));
        assert!(!primary_saids.contains(&"rec10"));

        // Deferred: fork event
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].event.said, "fork_ixn3");

        // Recovery: rec10 → ixn11 → ixn12
        assert_eq!(recovery.len(), 3);
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(recovery_saids.contains(&"rec10"));
        assert!(recovery_saids.contains(&"ixn11"));
        assert!(recovery_saids.contains(&"ixn12"));
    }

    #[test]
    fn test_partition_for_seeding_deferred_branch_is_longer() {
        let events = vec![
            make_event("b1", Some("shared"), EventKind::Ixn),
            make_event("a1", Some("shared"), EventKind::Ixn),
            make_event("a2", Some("a1"), EventKind::Ixn),
            make_event("a3", Some("a2"), EventKind::Ixn),
        ];
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);

        // The longer branch (a1→a2→a3) should be primary
        assert_eq!(primary.len(), 3);
        let primary_saids: Vec<_> = primary.iter().map(|e| e.event.said.as_str()).collect();
        assert!(primary_saids.contains(&"a1"));
        assert!(primary_saids.contains(&"a2"));
        assert!(primary_saids.contains(&"a3"));

        // The shorter branch (b1) should be deferred
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].event.said, "b1");

        assert!(recovery.is_empty());
    }

    // --- DFS traversal tests ---

    #[test]
    fn test_partition_events_detects_recovery_on_non_first_sub_branch() {
        let events = vec![
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("adv2", Some("adv1"), EventKind::Ixn),
            make_event("rec_root", Some("shared"), EventKind::Ixn),
            make_event("fork_a", Some("rec_root"), EventKind::Ixn),
            make_event("fork_b", Some("fork_a"), EventKind::Ixn),
            make_event("fork_c", Some("fork_a"), EventKind::Rec),
        ];
        let (_adversary, recovery) = SyncHandler::partition_events(events);
        assert!(
            !recovery.is_empty(),
            "recovery on non-first sub-branch must be detected"
        );
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(recovery_saids.contains(&"rec_root"));
        assert!(recovery_saids.contains(&"fork_c"));
    }

    #[test]
    fn test_partition_events_collects_all_sub_branches_of_recovery_root() {
        let events = vec![
            make_event("adv1", Some("shared"), EventKind::Ixn),
            make_event("rec1", Some("shared"), EventKind::Rec),
            make_event("sub_a", Some("rec1"), EventKind::Ixn),
            make_event("sub_b", Some("rec1"), EventKind::Ixn),
        ];
        let (adversary, recovery) = SyncHandler::partition_events(events);
        assert_eq!(adversary.len(), 1);
        assert_eq!(adversary[0].event.said, "adv1");
        assert_eq!(recovery.len(), 3);
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(recovery_saids.contains(&"rec1"));
        assert!(recovery_saids.contains(&"sub_a"));
        assert!(recovery_saids.contains(&"sub_b"));
    }

    #[test]
    fn test_partition_for_seeding_counts_all_sub_branch_descendants() {
        let events = vec![
            make_event("a1", Some("shared"), EventKind::Ixn),
            make_event("a2", Some("a1"), EventKind::Ixn),
            make_event("a3", Some("a1"), EventKind::Ixn),
            make_event("a4", Some("a1"), EventKind::Ixn),
            make_event("b1", Some("shared"), EventKind::Ixn),
            make_event("b2", Some("b1"), EventKind::Ixn),
            make_event("b3", Some("b2"), EventKind::Ixn),
        ];
        let (primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);
        let primary_saids: Vec<_> = primary.iter().map(|e| e.event.said.as_str()).collect();
        assert!(
            primary_saids.contains(&"a1"),
            "branch with more total descendants should be primary"
        );
        let deferred_saids: Vec<_> = deferred.iter().map(|e| e.event.said.as_str()).collect();
        assert!(deferred_saids.contains(&"b1"));
        assert!(deferred_saids.contains(&"b2"));
        assert!(deferred_saids.contains(&"b3"));
        assert!(recovery.is_empty());
    }

    // ==================== Anti-Entropy Tests ====================

    #[test]
    fn test_stale_prefix_key_constant() {
        assert_eq!(STALE_PREFIX_KEY, "kels:anti_entropy:stale");
    }

    // Mock signer for testing fetch_prefixes
    struct MockSigner;

    #[async_trait::async_trait]
    impl kels::RegistrySigner for MockSigner {
        async fn sign(&self, _data: &[u8]) -> Result<kels::SignResult, KelsError> {
            Ok(kels::SignResult {
                signature: "0BAAAA_mock_signature".to_string(),
                peer_prefix: "EMockPeerPrefix_____________________________".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_fetch_prefixes_success() {
        let mock_server = MockServer::start().await;

        let response_body = kels::PrefixListResponse {
            prefixes: vec![
                kels::PrefixState {
                    prefix: "Eprefix_a___________________________________".to_string(),
                    said: "Esaid_a_____________________________________".to_string(),
                },
                kels::PrefixState {
                    prefix: "Eprefix_b___________________________________".to_string(),
                    said: "Esaid_b_____________________________________".to_string(),
                },
            ],
            next_cursor: None,
        };

        Mock::given(method("POST"))
            .and(path("/api/kels/prefixes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = KelsClient::new(&mock_server.uri());
        let signer = MockSigner;

        let result = client
            .fetch_prefixes(
                &signer,
                Some("Ecursor_____________________________________"),
                100,
            )
            .await;

        assert!(result.is_ok());
        let page = result.unwrap();
        assert_eq!(page.prefixes.len(), 2);
        assert_eq!(
            page.prefixes[0].prefix,
            "Eprefix_a___________________________________"
        );
        assert_eq!(
            page.prefixes[1].prefix,
            "Eprefix_b___________________________________"
        );
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn test_fetch_prefixes_with_pagination() {
        let mock_server = MockServer::start().await;

        let response_body = kels::PrefixListResponse {
            prefixes: vec![kels::PrefixState {
                prefix: "Eprefix_c___________________________________".to_string(),
                said: "Esaid_c_____________________________________".to_string(),
            }],
            next_cursor: Some("Enext_cursor________________________________".to_string()),
        };

        Mock::given(method("POST"))
            .and(path("/api/kels/prefixes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = KelsClient::new(&mock_server.uri());
        let signer = MockSigner;

        let result = client.fetch_prefixes(&signer, None, 1).await;

        assert!(result.is_ok());
        let page = result.unwrap();
        assert_eq!(page.prefixes.len(), 1);
        assert_eq!(
            page.next_cursor,
            Some("Enext_cursor________________________________".to_string())
        );
    }

    #[tokio::test]
    async fn test_fetch_prefixes_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/kels/prefixes"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(kels::ErrorResponse {
                    error: "Internal Server Error".to_string(),
                    code: kels::ErrorCode::InternalError,
                }),
            )
            .mount(&mock_server)
            .await;

        let client = KelsClient::new(&mock_server.uri());
        let signer = MockSigner;

        let result = client.fetch_prefixes(&signer, None, 100).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_prefixes_empty_response() {
        let mock_server = MockServer::start().await;

        let response_body = kels::PrefixListResponse {
            prefixes: vec![],
            next_cursor: None,
        };

        Mock::given(method("POST"))
            .and(path("/api/kels/prefixes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = KelsClient::new(&mock_server.uri());
        let signer = MockSigner;

        let result = client.fetch_prefixes(&signer, None, 100).await;

        assert!(result.is_ok());
        let page = result.unwrap();
        assert!(page.prefixes.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn test_partition_for_seeding_recovery_on_non_first_sub_branch() {
        let events = vec![
            make_event("a1", Some("shared"), EventKind::Ixn),
            make_event("a2", Some("a1"), EventKind::Ixn),
            make_event("a3", Some("a2"), EventKind::Ixn),
            make_event("a4", Some("a2"), EventKind::Rec),
            make_event("b1", Some("shared"), EventKind::Ixn),
        ];
        let (_primary, deferred, recovery) = SyncHandler::partition_for_seeding(events);
        let recovery_saids: Vec<_> = recovery.iter().map(|e| e.event.said.as_str()).collect();
        assert!(
            recovery_saids.contains(&"a4"),
            "recovery on non-first sub-branch must be detected"
        );
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].event.said, "b1");
    }
}
