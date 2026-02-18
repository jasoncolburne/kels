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
use kels::{KelsClient, KelsError, MAX_EVENTS_PER_SUBMISSION, SignedKeyEvent};
use thiserror::Error;

use crate::{
    allowlist::SharedAllowlist,
    gossip_layer::{GossipCommand, GossipEvent},
    protocol::KelAnnouncement,
};

/// Tracks prefix:said pairs recently stored via gossip to prevent feedback loops.
/// When gossip stores events, KELS publishes to Redis, which would re-trigger announcement.
pub type RecentlyStoredFromGossip = Arc<RwLock<HashMap<String, Instant>>>;

/// Shared Redis connection for the retry queue (failed gossip fetches).
pub type RetryQueue = Arc<redis::aio::ConnectionManager>;

/// Optional retry queue — None in tests where Redis is unavailable.
pub type OptionalRetryQueue = Option<RetryQueue>;

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

/// Redis key for the retry queue set
const RETRY_QUEUE_KEY: &str = "kels:resync:retry";

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
    /// Redis-backed retry queue for failed gossip fetches
    retry_queue: OptionalRetryQueue,
}

impl SyncHandler {
    pub fn new(
        kels_url: &str,
        allowlist: SharedAllowlist,
        recently_stored: RecentlyStoredFromGossip,
        retry_queue: OptionalRetryQueue,
    ) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            local_saids: HashMap::new(),
            allowlist,
            recently_stored,
            peer_fetch_counts: HashMap::new(),
            retry_queue,
        }
    }

    /// Queue a failed fetch for later retry via the periodic resync loop.
    async fn queue_retry(&self, prefix: &str, said: &str) {
        let Some(ref retry_queue) = self.retry_queue else {
            return;
        };
        let entry = format!("{}:{}", prefix, said);
        let mut conn = retry_queue.as_ref().clone();
        if let Err(e) = redis::cmd("SADD")
            .arg(RETRY_QUEUE_KEY)
            .arg(&entry)
            .query_async::<()>(&mut conn)
            .await
        {
            warn!("Failed to queue retry for {}: {}", entry, e);
        } else {
            debug!("Queued retry for {}", entry);
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
        let remote_said = &announcement.said;

        // Get our local SAID for this prefix
        let local_said = self.get_local_said(prefix).await?;

        // If SAIDs match, we're in sync
        if let Some(ref local) = local_said
            && local == remote_said
        {
            debug!("Already in sync for prefix {}", prefix);
            return Ok(());
        }

        // Application-level deduplication: if we already have this SAID, skip.
        if self.kels_client.event_exists(remote_said).await? {
            debug!(
                "Already have announced SAID {} for prefix {}",
                remote_said, prefix
            );
            return Ok(());
        }

        info!(
            "SAID mismatch for {}: local={:?}, remote={}, origin={}. Fetching from peers.",
            prefix, local_said, remote_said, announcement.origin,
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
            let events = if let Some(ref local_said) = local_said {
                // Delta fetch: only events after our local state
                match remote_client.fetch_kel_since(prefix, local_said).await {
                    Ok(events) => events,
                    Err(KelsError::KeyNotFound(_)) => {
                        // Since SAID was removed by recovery/contest on remote.
                        // Fetch with audit to get archived adversary events.
                        info!(
                            "Since SAID not found on remote (likely recovery). Fetching with audit for {}",
                            prefix
                        );
                        match remote_client.fetch_kel_with_audit(prefix).await {
                            Ok(response) => {
                                let clean_chain = response.events;
                                let archived_events = response
                                    .audit_records
                                    .as_ref()
                                    .and_then(|records| records.last())
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

                                    if applied && let Some(said) = tip_said {
                                        self.local_saids.insert(prefix.to_string(), said);
                                    }
                                    return Ok(());
                                }
                            }
                            Err(KelsError::KeyNotFound(_)) => {
                                warn!("KEL not found on remote for {}", prefix);
                                continue;
                            }
                            Err(e) => {
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
                        match remote_client.get_kel(prefix).await {
                            Ok(kel) => kel.events().to_vec(),
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
                match remote_client.get_kel(prefix).await {
                    Ok(kel) => kel.events().to_vec(),
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
            // No peer had the events — queue for retry
            self.queue_retry(prefix, remote_said).await;
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
                match remote_client.get_kel(prefix).await {
                    Ok(full_kel) => self
                        .submit_events_to_kels(full_kel.events())
                        .await
                        .unwrap_or(false),
                    Err(e) => {
                        warn!("Failed to fetch full KEL for retry: {}", e);
                        self.queue_retry(prefix, remote_said).await;
                        false
                    }
                }
            } else {
                initially_applied
            }
        };

        if applied && let Some(said) = said {
            self.local_saids.insert(prefix.to_string(), said);
        }

        Ok(())
    }

    /// Get the latest SAID for a prefix from local KELS
    async fn get_local_said(&mut self, prefix: &str) -> Result<Option<String>, SyncError> {
        // Check our cache first
        if let Some(said) = self.local_saids.get(prefix) {
            return Ok(Some(said.clone()));
        }

        // Fetch from KELS
        let events = self.fetch_local_kel(prefix).await?;
        if let Some(last_event) = events.last() {
            let said = last_event.event.said.clone();
            self.local_saids.insert(prefix.to_string(), said.clone());
            Ok(Some(said))
        } else {
            Ok(None)
        }
    }

    /// Fetch a KEL from local KELS using the client library
    async fn fetch_local_kel(&self, prefix: &str) -> Result<Vec<SignedKeyEvent>, SyncError> {
        match self.kels_client.get_kel(prefix).await {
            Ok(kel) => Ok(kel.events().to_vec()),
            Err(KelsError::KeyNotFound(_)) => Ok(vec![]),
            Err(e) => Err(SyncError::Kels(e)),
        }
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
    retry_queue: OptionalRetryQueue,
    mut peer_connected_tx: Option<oneshot::Sender<()>>,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(&kels_url, allowlist, recently_stored, retry_queue);

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

/// Periodically retries failed gossip fetches from the Redis retry queue.
///
/// Each cycle: reads all pending `prefix:said` entries, clears the queue,
/// then tries each entry against shuffled peers. Entries that fail again
/// (non-404) are re-added for the next cycle. Entries where all peers
/// return 404 are dropped (SAID was likely superseded).
pub async fn run_resync_loop(
    retry_queue: RetryQueue,
    allowlist: SharedAllowlist,
    local_kels_url: String,
    interval: Duration,
) {
    use rand::seq::SliceRandom;

    let local_client = KelsClient::new(&local_kels_url);

    loop {
        tokio::time::sleep(interval).await;

        // Read all pending entries
        let entries: Vec<String> = {
            let mut conn = retry_queue.as_ref().clone();
            match redis::cmd("SMEMBERS")
                .arg(RETRY_QUEUE_KEY)
                .query_async::<Vec<String>>(&mut conn)
                .await
            {
                Ok(entries) if entries.is_empty() => continue,
                Ok(entries) => {
                    // Clear the set — entries re-added on failure
                    let _ = redis::cmd("DEL")
                        .arg(RETRY_QUEUE_KEY)
                        .query_async::<()>(&mut conn)
                        .await;
                    entries
                }
                Err(e) => {
                    warn!("Failed to read retry queue: {}", e);
                    continue;
                }
            }
        };

        info!("Resync loop: processing {} pending entries", entries.len());

        // Collect all peers with their kels_url
        let peers: Vec<(String, String)> = {
            let guard = allowlist.read().await;
            guard
                .values()
                .map(|p| (p.peer_prefix.clone(), p.kels_url.clone()))
                .collect()
        };

        if peers.is_empty() {
            warn!("Resync loop: no peers available, re-queuing all entries");
            let mut conn = retry_queue.as_ref().clone();
            for entry in &entries {
                let _ = redis::cmd("SADD")
                    .arg(RETRY_QUEUE_KEY)
                    .arg(entry)
                    .query_async::<()>(&mut conn)
                    .await;
            }
            continue;
        }

        // Shuffle peers for load distribution
        let mut shuffled_peers = peers.clone();
        {
            let mut rng = rand::thread_rng();
            shuffled_peers.shuffle(&mut rng);
        }

        for entry in &entries {
            // Parse prefix:said
            let Some((prefix, said)) = entry.split_once(':') else {
                warn!("Resync loop: invalid entry format: {}", entry);
                continue;
            };

            let mut all_not_found = true;
            let mut resolved = false;

            for (_peer_prefix, kels_url) in &shuffled_peers {
                let peer_client = KelsClient::new(kels_url);

                // Cheap pre-check: does the peer have this event?
                match peer_client.event_exists(said).await {
                    Ok(true) => {}
                    Ok(false) => {
                        // Peer doesn't have it — try next
                        continue;
                    }
                    Err(_) => {
                        // Peer is down — try next
                        all_not_found = false;
                        continue;
                    }
                }

                all_not_found = false;

                // Peer has the event — fetch the KEL
                // Check if we have local state for this prefix
                let local_events = match local_client.get_kel(prefix).await {
                    Ok(kel) => Some(kel),
                    Err(KelsError::KeyNotFound(_)) => None,
                    Err(e) => {
                        warn!("Resync loop: failed to get local KEL for {}: {}", prefix, e);
                        break;
                    }
                };

                let events = if let Some(ref kel) = local_events
                    && let Some(last) = kel.events().last()
                {
                    // Delta fetch
                    match peer_client.fetch_kel_since(prefix, &last.event.said).await {
                        Ok(events) => events,
                        Err(KelsError::KeyNotFound(_)) => {
                            // Since SAID not found — try full fetch
                            match peer_client.get_kel(prefix).await {
                                Ok(kel) => kel.events().to_vec(),
                                Err(_) => continue,
                            }
                        }
                        Err(_) => continue,
                    }
                } else {
                    // No local state — full fetch
                    match peer_client.get_kel(prefix).await {
                        Ok(kel) => kel.events().to_vec(),
                        Err(KelsError::KeyNotFound(_)) => continue,
                        Err(_) => continue,
                    }
                };

                if events.is_empty() {
                    // Delta was empty — local already has all events for this prefix
                    resolved = true;
                    break;
                }

                // Submit to local KELS
                match local_client.submit_events(&events).await {
                    Ok(result) => {
                        if result.applied {
                            info!(
                                "Resync loop: applied {} events for prefix {}",
                                events.len(),
                                prefix
                            );
                        } else {
                            debug!(
                                "Resync loop: events not applied for prefix {} (possibly already synced)",
                                prefix
                            );
                        }
                        resolved = true;
                        break;
                    }
                    Err(KelsError::ContestedKel(msg)) => {
                        warn!("Resync loop: KEL contested for {}: {}", prefix, msg);
                        resolved = true;
                        break;
                    }
                    Err(e) => {
                        warn!("Resync loop: submit failed for {}: {}", prefix, e);
                        continue;
                    }
                }
            }

            // If all peers returned 404, drop the entry (SAID superseded)
            if all_not_found {
                debug!(
                    "Resync loop: all peers returned 404 for {}, dropping entry",
                    entry
                );
                continue;
            }

            // If not resolved, re-add to retry queue for next cycle
            if !resolved {
                let mut conn = retry_queue.as_ref().clone();
                let _ = redis::cmd("SADD")
                    .arg(RETRY_QUEUE_KEY)
                    .arg(entry)
                    .query_async::<()>(&mut conn)
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kels::{EventKind, KeyEvent};
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
