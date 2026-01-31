//! Synchronization logic between Redis pub/sub and gossip network.
//!
//! Handles:
//! - Subscribing to Redis for local KEL updates
//! - Broadcasting announcements to gossip network
//! - Processing incoming announcements and fetching missing KELs
//! - Submitting fetched events to local KELS

use crate::gossip::{GossipCommand, GossipEvent};
use crate::protocol::{KelAnnouncement, KelResponse};
use futures::StreamExt;
use kels::{KelsClient, KelsError, SignedKeyEvent};
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
/// The `propagation_delay_ms` parameter adds an artificial delay before broadcasting
/// announcements. This is only for testing adversarial scenarios and should be 0
/// in production.
pub async fn run_redis_subscriber(
    redis_url: &str,
    command_tx: mpsc::Sender<GossipCommand>,
    propagation_delay_ms: u64,
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

        // Parse the message and create an announcement
        if let Some(announcement) = KelAnnouncement::from_pubsub_message(&payload) {
            // Apply test propagation delay if configured
            if propagation_delay_ms > 0 {
                debug!(
                    "Delaying announcement by {}ms (test mode)",
                    propagation_delay_ms
                );
                tokio::time::sleep(std::time::Duration::from_millis(propagation_delay_ms)).await;
            }

            debug!(
                "Broadcasting announcement: prefix={}, said={}",
                announcement.prefix, announcement.said
            );
            if command_tx
                .send(GossipCommand::Announce(announcement))
                .await
                .is_err()
            {
                error!("Failed to send announce command - channel closed");
                return Err(SyncError::ChannelClosed);
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
    /// Tracks pending requests to avoid duplicate fetches
    pending_fetches: HashMap<String, PeerId>,
}

impl SyncHandler {
    pub fn new(kels_url: &str) -> Self {
        Self {
            kels_client: KelsClient::new(kels_url),
            local_saids: HashMap::new(),
            pending_fetches: HashMap::new(),
        }
    }

    /// Process a gossip event
    pub async fn handle_event(
        &mut self,
        event: GossipEvent,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        match event {
            GossipEvent::AnnouncementReceived {
                peer_id,
                announcement,
            } => {
                self.handle_announcement(peer_id, announcement, command_tx)
                    .await?;
            }
            GossipEvent::KelRequestReceived {
                peer_id,
                channel,
                request,
            } => {
                self.handle_kel_request(peer_id, channel, request.prefix, command_tx)
                    .await?;
            }
            GossipEvent::KelResponseReceived { peer_id, response } => {
                self.handle_kel_response(peer_id, response).await?;
            }
            GossipEvent::PeerConnected(peer_id) => {
                debug!("Peer connected: {}", peer_id);
            }
            GossipEvent::PeerDisconnected(peer_id) => {
                debug!("Peer disconnected: {}", peer_id);
                // Clean up any pending fetches from this peer
                self.pending_fetches.retain(|_, pid| *pid != peer_id);
            }
        }
        Ok(())
    }

    /// Handle an announcement from a peer
    async fn handle_announcement(
        &mut self,
        peer_id: PeerId,
        announcement: KelAnnouncement,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        let prefix = &announcement.prefix;
        let remote_said = &announcement.said;

        // Get our local SAID for this prefix
        let local_said = self.get_local_said(prefix).await?;

        // If SAIDs match, we're in sync
        if let Some(ref local) = local_said {
            if local == remote_said {
                debug!("Already in sync for prefix {}", prefix);
                return Ok(());
            }
        }

        // Check if we already have a pending fetch for this prefix
        if self.pending_fetches.contains_key(prefix) {
            debug!("Already fetching prefix {} from another peer", prefix);
            return Ok(());
        }

        info!(
            "SAID mismatch for {}: local={:?}, remote={}. Fetching from {}",
            prefix, local_said, remote_said, peer_id
        );

        // Request the KEL from the announcing peer
        self.pending_fetches.insert(prefix.clone(), peer_id);
        command_tx
            .send(GossipCommand::RequestKel {
                peer_id,
                prefix: prefix.clone(),
            })
            .await
            .map_err(|_| SyncError::ChannelClosed)?;

        Ok(())
    }

    /// Handle a KEL request from a peer
    async fn handle_kel_request(
        &mut self,
        peer_id: PeerId,
        channel: ResponseChannel<KelResponse>,
        prefix: String,
        command_tx: &mpsc::Sender<GossipCommand>,
    ) -> Result<(), SyncError> {
        info!(
            "Received KEL request from {} for prefix {}",
            peer_id, prefix
        );

        // Fetch the KEL from local KELS
        let events = self.fetch_local_kel(&prefix).await?;

        info!(
            "Sending {} events for prefix {} to {}",
            events.len(),
            prefix,
            peer_id
        );

        let response = KelResponse {
            prefix: prefix.clone(),
            events,
        };

        command_tx
            .send(GossipCommand::RespondKel { channel, response })
            .await
            .map_err(|_| SyncError::ChannelClosed)?;

        Ok(())
    }

    /// Handle a KEL response from a peer
    async fn handle_kel_response(
        &mut self,
        _peer_id: PeerId,
        response: KelResponse,
    ) -> Result<(), SyncError> {
        let prefix = &response.prefix;

        // Clear pending fetch
        self.pending_fetches.remove(prefix);

        if response.events.is_empty() {
            warn!("Received empty KEL response for {}", prefix);
            return Ok(());
        }

        info!(
            "Received {} events for prefix {} from peer",
            response.events.len(),
            prefix
        );

        // Submit the events to local KELS
        self.submit_events_to_kels(&response.events).await?;

        // Update our local SAID cache
        if let Some(last_event) = response.events.last() {
            self.local_saids
                .insert(prefix.clone(), last_event.event.said.clone());
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

    /// Submit events to local KELS using the client library
    async fn submit_events_to_kels(&self, events: &[SignedKeyEvent]) -> Result<(), SyncError> {
        match self.kels_client.submit_events(events).await {
            Ok(result) => {
                if result.accepted {
                    info!("Events accepted by local KELS");
                } else {
                    warn!(
                        "Events not accepted by local KELS: diverged_at={:?}",
                        result.diverged_at
                    );
                }
                Ok(())
            }
            Err(KelsError::ContestedKel(msg)) => {
                warn!("KEL is contested: {}", msg);
                Ok(())
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
) -> Result<(), SyncError> {
    let mut handler = SyncHandler::new(&kels_url);

    while let Some(event) = event_rx.recv().await {
        if let Err(e) = handler.handle_event(event, &command_tx).await {
            error!("Error handling gossip event: {}", e);
        }
    }

    warn!("Event receiver closed");
    Ok(())
}
