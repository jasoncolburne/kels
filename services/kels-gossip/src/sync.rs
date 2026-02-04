//! Synchronization logic between Redis pub/sub and gossip network.
//!
//! Handles:
//! - Subscribing to Redis for local KEL updates
//! - Broadcasting announcements to gossip network
//! - Processing incoming announcements and fetching missing KELs via HTTP
//! - Submitting fetched events to local KELS

use crate::allowlist::SharedAllowlist;
use crate::gossip::{GossipCommand, GossipEvent};
use crate::protocol::{AnnouncementScope, KelAnnouncement};
use futures::StreamExt;
use kels::{KelsClient, KelsError, PeerScope, SignedKeyEvent};
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

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
/// - Core: broadcast BOTH core→core AND core→regional
pub async fn run_redis_subscriber(
    redis_url: &str,
    command_tx: mpsc::Sender<GossipCommand>,
    allowlist: SharedAllowlist,
    local_peer_id: PeerId,
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

        let local_scope = crate::allowlist::get_local_scope(&local_peer_id, &allowlist).await;

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
                // Core node: broadcast both core→core AND core→regional
                if let Some(ann) = KelAnnouncement::from_pubsub_message(
                    &payload,
                    AnnouncementScope::Core,
                    AnnouncementScope::Core,
                    sender.clone(),
                ) {
                    debug!(
                        "Broadcasting: prefix={}, said={}, core→core",
                        ann.prefix, ann.said
                    );
                    if command_tx
                        .send(GossipCommand::Announce(ann.clone()))
                        .await
                        .is_err()
                    {
                        error!("Failed to send announce command - channel closed");
                        return Err(SyncError::ChannelClosed);
                    }

                    let regional_ann = ann.rebroadcast(
                        AnnouncementScope::Core,
                        AnnouncementScope::Regional,
                        sender,
                    );
                    debug!(
                        "Broadcasting: prefix={}, said={}, core→regional",
                        regional_ann.prefix, regional_ann.said
                    );
                    if command_tx
                        .send(GossipCommand::Announce(regional_ann))
                        .await
                        .is_err()
                    {
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
    /// Shared allowlist for determining local scope and peer URLs
    allowlist: SharedAllowlist,
    /// This node's peer ID
    local_peer_id: PeerId,
    /// Tracks recently stored events to prevent Redis feedback loop
    recently_stored: RecentlyStoredFromGossip,
}

impl SyncHandler {
    pub fn new(
        kels_url: &str,
        allowlist: SharedAllowlist,
        local_peer_id: PeerId,
        recently_stored: RecentlyStoredFromGossip,
    ) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            local_saids: HashMap::new(),
            allowlist,
            local_peer_id,
            recently_stored,
        }
    }

    /// Get the local node's scope from the allowlist
    async fn get_local_scope(&self) -> AnnouncementScope {
        match crate::allowlist::get_local_scope(&self.local_peer_id, &self.allowlist).await {
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
        let local_scope = self.get_local_scope().await;
        if announcement.destination != local_scope {
            debug!(
                "Ignoring announcement for {}: destination={} but local_scope={}",
                prefix, announcement.destination, local_scope
            );
            return Ok(());
        }

        // Get our local SAID for this prefix
        let local_said = self.get_local_said(prefix).await?;

        // If SAIDs match, we're in sync
        if let Some(ref local) = local_said {
            if local == remote_said {
                debug!("Already in sync for prefix {}", prefix);
                return Ok(());
            }
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
                warn!(
                    "Sender {} not in allowlist, cannot fetch KEL for {}",
                    announcement.sender, prefix
                );
                return Ok(());
            }
        };

        // Fetch the KEL via HTTP
        let remote_client = KelsClient::new(&kels_url);
        let events = match remote_client.get_kel(prefix).await {
            Ok(kel) => kel.events().to_vec(),
            Err(KelsError::KeyNotFound(_)) => {
                warn!("KEL not found on remote for {}", prefix);
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to fetch KEL from {}: {}", kels_url, e);
                return Ok(());
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

        // Submit the events to local KELS and check if they were accepted
        let accepted = self.submit_events_to_kels(&events).await?;

        // Update our local SAID cache and re-broadcast only if we stored new events
        if accepted {
            if let Some(last_event) = events.last() {
                let said = last_event.event.said.clone();
                self.local_saids.insert(prefix.clone(), said.clone());

                // Mark as recently stored to prevent Redis feedback loop
                let key = format!("{}:{}", prefix, said);
                self.recently_stored
                    .write()
                    .await
                    .insert(key, Instant::now());

                // Determine rebroadcast based on original announcement's routing
                let sender = self.local_peer_id.to_string();

                // Rebroadcast rules:
                // regional→core => rebroadcast core→core
                // core→core => rebroadcast core→regional
                // core→regional => don't rebroadcast
                // regional→regional => don't rebroadcast
                let rebroadcast = match (announcement.origin, announcement.destination) {
                    (AnnouncementScope::Regional, AnnouncementScope::Core) => {
                        Some(announcement.rebroadcast(
                            AnnouncementScope::Core,
                            AnnouncementScope::Core,
                            sender,
                        ))
                    }
                    (AnnouncementScope::Core, AnnouncementScope::Core) => {
                        Some(announcement.rebroadcast(
                            AnnouncementScope::Core,
                            AnnouncementScope::Regional,
                            sender,
                        ))
                    }
                    _ => None, // core→regional or regional→regional: no rebroadcast
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
                "Events not accepted, skipping re-broadcast for prefix={}",
                prefix
            );
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

    /// Submit events to local KELS using the client library.
    /// Returns true if events were accepted (new events stored).
    async fn submit_events_to_kels(&self, events: &[SignedKeyEvent]) -> Result<bool, SyncError> {
        match self.kels_client.submit_events(events).await {
            Ok(result) => {
                if result.accepted {
                    info!("Events accepted by local KELS");
                    Ok(true)
                } else {
                    warn!(
                        "Events not accepted by local KELS: diverged_at={:?}",
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
    recently_stored: RecentlyStoredFromGossip,
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(&kels_url, allowlist, local_peer_id, recently_stored);

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
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_handler(local_peer_id: PeerId) -> SyncHandler {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let recently_stored = Arc::new(RwLock::new(HashMap::new()));
        SyncHandler::new(
            "http://localhost:8080",
            allowlist,
            local_peer_id,
            recently_stored,
        )
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
            recently_stored,
        )
        .await;
        assert!(result.is_ok());
    }
}
