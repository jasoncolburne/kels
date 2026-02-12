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
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use futures::StreamExt;
use kels::{KelsClient, KelsError, PeerScope, SignedKeyEvent};
use libp2p::PeerId;
use thiserror::Error;

use crate::{
    allowlist::SharedAllowlist,
    gossip::{GossipCommand, GossipEvent},
    protocol::{AnnouncementScope, KelAnnouncement},
};

/// Tracks prefix:said pairs recently stored via gossip to prevent feedback loops.
/// When gossip stores events, KELS publishes to Redis, which would re-trigger announcement.
pub type RecentlyStoredFromGossip = Arc<RwLock<HashMap<String, Instant>>>;

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
///
/// Initial broadcast routing based on this node's scope:
/// - Regional: broadcast regional→core (core nodes will bridge)
/// - Core: broadcast core→all
pub async fn run_redis_subscriber(
    redis_url: &str,
    command_tx: mpsc::Sender<GossipCommand>,
    local_scope: PeerScope,
    recently_stored: RecentlyStoredFromGossip,
    local_peer_id: PeerId,
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

        let sender = local_peer_id.to_string();

        match local_scope {
            PeerScope::Regional => {
                // Regional node: broadcast regional→core
                if let Some(ann) = KelAnnouncement::from_pubsub_message(
                    &payload,
                    AnnouncementScope::Regional,
                    AnnouncementScope::Core,
                    sender,
                ) {
                    debug!(
                        "Broadcasting: prefix={}, said={}, regional→core",
                        ann.prefix, ann.said
                    );
                    if command_tx.send(GossipCommand::Announce(ann)).await.is_err() {
                        error!("Failed to send announce command - channel closed");
                        return Err(SyncError::ChannelClosed);
                    }
                }
            }
            PeerScope::Core => {
                // Core node: broadcast core→all
                if let Some(ann) = KelAnnouncement::from_pubsub_message(
                    &payload,
                    AnnouncementScope::Core,
                    AnnouncementScope::All,
                    sender,
                ) {
                    debug!(
                        "Broadcasting: prefix={}, said={}, core→all",
                        ann.prefix, ann.said
                    );
                    if command_tx.send(GossipCommand::Announce(ann)).await.is_err() {
                        error!("Failed to send announce command - channel closed");
                        return Err(SyncError::ChannelClosed);
                    }
                }
            }
        }
    }

    warn!("Redis subscriber stream ended");
    Ok(())
}

/// Handles gossip events and coordinates with KELS
pub struct SyncHandler {
    kels_client: KelsClient,
    /// Tracks the latest known SAID for each prefix
    local_saids: HashMap<String, String>,
    /// Shared allowlist for peer URL lookups
    allowlist: SharedAllowlist,
    /// This node's peer ID
    local_peer_id: PeerId,
    /// This node's scope (determined at startup)
    local_scope: PeerScope,
    /// Tracks recently stored events to prevent Redis feedback loop
    recently_stored: RecentlyStoredFromGossip,
}

impl SyncHandler {
    pub fn new(
        kels_url: &str,
        allowlist: SharedAllowlist,
        local_peer_id: PeerId,
        local_scope: PeerScope,
        recently_stored: RecentlyStoredFromGossip,
    ) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            local_saids: HashMap::new(),
            allowlist,
            local_peer_id,
            local_scope,
            recently_stored,
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

        // Walk each chain and check if it contains recovery-revealing events
        let mut recovery_root_said: Option<String> = None;
        for root in &roots {
            let mut current = root.event.said.as_str();
            let mut has_recovery = root.event.reveals_recovery_key();
            while let Some(next) = children.get(current).and_then(|v| v.first()) {
                if next.event.reveals_recovery_key() {
                    has_recovery = true;
                }
                current = &next.event.said;
            }
            if has_recovery {
                recovery_root_said = Some(root.event.said.clone());
                break;
            }
        }

        // If no recovery branch found, fall back to returning everything as one batch
        let Some(recovery_root) = recovery_root_said else {
            return (events, vec![]);
        };

        // Collect the recovery chain's SAIDs
        let mut recovery_saids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        recovery_saids.insert(recovery_root.clone());
        let mut current = recovery_root.as_str();
        while let Some(next) = children.get(current).and_then(|v| v.first()) {
            recovery_saids.insert(next.event.said.clone());
            current = &next.event.said;
        }

        // Adversary events first, recovery events second
        let (recovery, adversary): (Vec<_>, Vec<_>) = events
            .into_iter()
            .partition(|e| recovery_saids.contains(&e.event.said));

        (adversary, recovery)
    }

    /// Get the local node's scope as an announcement scope
    fn get_local_scope(&self) -> AnnouncementScope {
        match self.local_scope {
            PeerScope::Core => AnnouncementScope::Core,
            PeerScope::Regional => AnnouncementScope::Regional,
        }
    }

    /// Get a peer's KELS URL from the allowlist
    async fn get_peer_kels_url(&self, peer_id: &str) -> Option<String> {
        let guard = self.allowlist.read().await;
        for peer in guard.values() {
            if peer.peer_id == peer_id {
                return Some(peer.kels_url.clone());
            }
        }
        None
    }

    /// Process a gossip event
    pub async fn handle_event(
        &mut self,
        event: GossipEvent,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        match event {
            GossipEvent::AnnouncementReceived { announcement } => {
                self.handle_announcement(announcement, command_tx).await?;
            }
            GossipEvent::PeerConnected(peer_id) => {
                debug!("Peer connected: {}", peer_id);
            }
            GossipEvent::PeerDisconnected(peer_id) => {
                debug!("Peer disconnected: {}", peer_id);
            }
        }
        Ok(())
    }

    /// Handle an announcement from a peer
    async fn handle_announcement(
        &mut self,
        announcement: KelAnnouncement,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        let prefix = &announcement.prefix;
        let remote_said = &announcement.said;

        // Filter by destination - only process messages meant for our scope
        let local_scope = self.get_local_scope();
        if announcement.destination != AnnouncementScope::All
            && announcement.destination != local_scope
        {
            debug!(
                "Ignoring announcement for {}: destination={} but local_scope={}",
                prefix, announcement.destination, local_scope
            );
            return Ok(());
        }

        // Get our local SAID for this prefix
        let local_said = self.get_local_said(prefix).await?;

        // If SAIDs match, we're in sync
        if let Some(ref local) = local_said
            && local == remote_said
        {
            debug!("Already in sync for prefix {}", prefix);
            return Ok(());
        }

        // Check if we already have the announced SAID (we may be ahead of the announcer)
        if self.kels_client.event_exists(remote_said).await? {
            debug!(
                "Already have announced SAID {} for prefix {}",
                remote_said, prefix
            );
            return Ok(());
        }

        info!(
            "SAID mismatch for {}: local={:?}, remote={}. Fetching from sender {} ({}->{})",
            prefix,
            local_said,
            remote_said,
            announcement.sender,
            announcement.origin,
            announcement.destination
        );

        // Look up the sender's KELS URL from the allowlist
        let kels_url = match self.get_peer_kels_url(&announcement.sender).await {
            Some(url) => url,
            None => {
                // this is expected for regional peer messages that are seen by core peers not
                // associated with their registry
                debug!(
                    "Sender {} not in allowlist, cannot fetch KEL for {}",
                    announcement.sender, prefix
                );
                return Ok(());
            }
        };

        // Fetch events via HTTP — delta when possible, full otherwise
        let remote_client = KelsClient::new(&kels_url);
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
                                // 1. Submit archived adversary events (establishes adversary branch)
                                // 2. Submit clean chain pre-recovery events (creates fork)
                                // 3. Submit recovery + post-recovery events (merge Path 1 resolves)
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
                                // Pre-recovery events create divergence, then recovery resolves it.
                                // If recovery fails (frozen KEL rejected pre-rec events),
                                // retry with the full chain — merge look-ahead handles it.
                                let applied = if let Some(idx) = clean_chain
                                    .iter()
                                    .position(|e| e.event.reveals_recovery_key())
                                    && idx > 0
                                {
                                    let _ = self.submit_events_to_kels(&clean_chain[..idx]).await;
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

                                self.handle_rebroadcast(
                                    prefix,
                                    tip_said,
                                    applied,
                                    &announcement,
                                    command_tx,
                                )
                                .await;
                                return Ok(());
                            }
                        }
                        Err(KelsError::KeyNotFound(_)) => {
                            warn!("KEL not found on remote for {}", prefix);
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("Failed to fetch KEL with audit from {}: {}", kels_url, e);
                            return Ok(());
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
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("Failed to fetch KEL from {}: {}", kels_url, e);
                            return Ok(());
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
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to fetch KEL from {}: {}", kels_url, e);
                    return Ok(());
                }
            }
        };

        if events.is_empty() {
            warn!("Received empty KEL for {}", prefix);
            return Ok(());
        }

        info!(
            "Fetched {} events for prefix {} from {}",
            events.len(),
            prefix,
            kels_url
        );

        // Partition events by content: adversary branch first, recovery branch second.
        // The adversary branch establishes divergence context; the recovery branch resolves it.
        let has_recovery = events.iter().any(|e| e.event.is_recover());
        let (adversary_events, recovery_events) = Self::partition_events(events);

        // Mark as recently stored BEFORE submitting to KELS to prevent Redis feedback loop.
        // KELS publishes to Redis immediately when storing, so we must mark first.
        let all_events: Vec<_> = adversary_events
            .iter()
            .chain(recovery_events.iter())
            .collect();
        let said = all_events.last().map(|e| e.event.said.clone());
        if let Some(ref said) = said {
            let key = format!("{}:{}", prefix, said);
            self.recently_stored
                .write()
                .await
                .insert(key, Instant::now());
        }

        // Submit adversary events first (establishes divergence), then recovery events
        let initially_applied = if recovery_events.is_empty() {
            // No recovery branch — submit everything as one batch
            self.submit_events_to_kels(&adversary_events).await?
        } else if adversary_events.is_empty() {
            // No adversary branch — submit recovery events directly
            self.submit_events_to_kels(&recovery_events).await?
        } else {
            // Both branches: adversary first to establish divergence, then recovery
            let _ = self.submit_events_to_kels(&adversary_events).await;
            self.submit_events_to_kels(&recovery_events).await?
        };

        // If recovery events were rejected (e.g., frozen KEL missing owner's
        // predecessor events), retry with the full remote KEL so merge's
        // look-ahead can process [owner_events..., rec] as one batch.
        let applied = if !initially_applied && has_recovery {
            info!(
                "Recovery not applied for {} — retrying with full KEL from {}",
                prefix, kels_url
            );
            match remote_client.get_kel(prefix).await {
                Ok(full_kel) => self
                    .submit_events_to_kels(full_kel.events())
                    .await
                    .unwrap_or(false),
                Err(e) => {
                    warn!("Failed to fetch full KEL for retry: {}", e);
                    false
                }
            }
        } else {
            initially_applied
        };

        self.handle_rebroadcast(prefix, said, applied, &announcement, command_tx)
            .await;

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

    /// Handle post-submission steps: update SAID cache and rebroadcast if applied.
    async fn handle_rebroadcast(
        &mut self,
        prefix: &str,
        tip_said: Option<String>,
        applied: bool,
        announcement: &KelAnnouncement,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) {
        if applied {
            if let Some(said) = tip_said {
                self.local_saids.insert(prefix.to_string(), said);

                let sender = self.local_peer_id.to_string();

                let rebroadcast = match (announcement.origin, announcement.destination) {
                    (AnnouncementScope::Regional, AnnouncementScope::Core) => {
                        Some(announcement.rebroadcast(
                            AnnouncementScope::Core,
                            AnnouncementScope::All,
                            sender,
                        ))
                    }
                    _ => None,
                };

                if let Some(ann) = rebroadcast {
                    info!(
                        "Re-broadcasting: prefix={}, {}->{}",
                        ann.prefix, ann.origin, ann.destination
                    );
                    if command_tx.send(GossipCommand::Announce(ann)).await.is_err() {
                        warn!("Failed to re-broadcast announcement - channel closed");
                    }
                } else {
                    debug!(
                        "No rebroadcast needed for prefix={} ({}->{})",
                        prefix, announcement.origin, announcement.destination
                    );
                }
            }
        } else {
            debug!(
                "Events not applied, skipping re-broadcast for prefix={}",
                prefix
            );
        }
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

/// Run the sync event handler
pub async fn run_sync_handler(
    kels_url: String,
    mut event_rx: mpsc::Receiver<GossipEvent>,
    command_tx: mpsc::Sender<GossipCommand>,
    allowlist: SharedAllowlist,
    local_peer_id: PeerId,
    local_scope: PeerScope,
    recently_stored: RecentlyStoredFromGossip,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(
        &kels_url,
        allowlist,
        local_peer_id,
        local_scope,
        recently_stored,
    );

    while let Some(event) = event_rx.recv().await {
        if let Err(e) = handler.handle_event(event, &command_tx).await {
            error!("Error handling gossip event: {}", e);
        }
    }

    warn!("Event receiver closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kels::{EventKind, KeyEvent};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_handler(local_peer_id: PeerId) -> SyncHandler {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let recently_stored = Arc::new(RwLock::new(HashMap::new()));
        SyncHandler::new(
            "http://localhost:8080",
            allowlist,
            local_peer_id,
            PeerScope::Regional,
            recently_stored,
        )
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
        let local_peer_id = PeerId::random();
        let handler = create_test_handler(local_peer_id);
        assert!(handler.local_saids.is_empty());
    }

    #[tokio::test]
    async fn test_sync_handler_peer_connected_event() {
        let local_peer_id = PeerId::random();
        let mut handler = create_test_handler(local_peer_id);
        let (command_tx, _command_rx) = mpsc::channel::<GossipCommand>(10);

        let peer_id = PeerId::random();
        let event = GossipEvent::PeerConnected(peer_id);

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
        let local_peer_id = PeerId::random();

        // Drop the sender to close the channel
        drop(event_tx);

        // run_sync_handler should complete when receiver closes
        let result = run_sync_handler(
            "http://localhost:8080".to_string(),
            event_rx,
            command_tx,
            allowlist,
            local_peer_id,
            PeerScope::Regional,
            recently_stored,
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

    // --- handle_rebroadcast tests ---

    #[tokio::test]
    async fn test_handle_rebroadcast_regional_to_core_rebroadcasts_core_to_all() {
        let local_peer_id = PeerId::random();
        let mut handler = create_test_handler(local_peer_id);
        let (command_tx, mut command_rx) = mpsc::channel::<GossipCommand>(10);

        let announcement = KelAnnouncement::from_pubsub_message(
            "test-prefix:test-said",
            AnnouncementScope::Regional,
            AnnouncementScope::Core,
            "sender-peer".to_string(),
        )
        .unwrap();

        handler
            .handle_rebroadcast(
                "test-prefix",
                Some("test-said".to_string()),
                true,
                &announcement,
                &command_tx,
            )
            .await;

        // Should rebroadcast core→all
        let cmd = command_rx.try_recv().unwrap();
        let GossipCommand::Announce(ann) = cmd;
        assert_eq!(ann.origin, AnnouncementScope::Core);
        assert_eq!(ann.destination, AnnouncementScope::All);

        // SAID cache should be updated
        assert_eq!(
            handler.local_saids.get("test-prefix"),
            Some(&"test-said".to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_rebroadcast_core_to_all_no_rebroadcast() {
        let local_peer_id = PeerId::random();
        let mut handler = create_test_handler(local_peer_id);
        let (command_tx, mut command_rx) = mpsc::channel::<GossipCommand>(10);

        let announcement = KelAnnouncement::from_pubsub_message(
            "test-prefix:test-said",
            AnnouncementScope::Core,
            AnnouncementScope::All,
            "sender-peer".to_string(),
        )
        .unwrap();

        handler
            .handle_rebroadcast(
                "test-prefix",
                Some("test-said".to_string()),
                true,
                &announcement,
                &command_tx,
            )
            .await;

        // No rebroadcast for core→all (final hop)
        assert!(command_rx.try_recv().is_err());
        // But SAID cache should still be updated
        assert_eq!(
            handler.local_saids.get("test-prefix"),
            Some(&"test-said".to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_rebroadcast_not_applied_no_rebroadcast() {
        let local_peer_id = PeerId::random();
        let mut handler = create_test_handler(local_peer_id);
        let (command_tx, mut command_rx) = mpsc::channel::<GossipCommand>(10);

        let announcement = KelAnnouncement::from_pubsub_message(
            "test-prefix:test-said",
            AnnouncementScope::Regional,
            AnnouncementScope::Core,
            "sender-peer".to_string(),
        )
        .unwrap();

        handler
            .handle_rebroadcast(
                "test-prefix",
                Some("test-said".to_string()),
                false, // not applied
                &announcement,
                &command_tx,
            )
            .await;

        // Not applied: no rebroadcast and no SAID cache update
        assert!(command_rx.try_recv().is_err());
        assert!(!handler.local_saids.contains_key("test-prefix"));
    }

    #[tokio::test]
    async fn test_handle_rebroadcast_no_tip_said() {
        let local_peer_id = PeerId::random();
        let mut handler = create_test_handler(local_peer_id);
        let (command_tx, mut command_rx) = mpsc::channel::<GossipCommand>(10);

        let announcement = KelAnnouncement::from_pubsub_message(
            "test-prefix:test-said",
            AnnouncementScope::Regional,
            AnnouncementScope::Core,
            "sender-peer".to_string(),
        )
        .unwrap();

        handler
            .handle_rebroadcast("test-prefix", None, true, &announcement, &command_tx)
            .await;

        // No tip SAID: no rebroadcast, no cache update
        assert!(command_rx.try_recv().is_err());
        assert!(!handler.local_saids.contains_key("test-prefix"));
    }
}
