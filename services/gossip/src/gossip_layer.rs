//! Gossip networking layer for KELS.
//!
//! Wraps the custom gossip protocol (HyParView + PlumTree) to broadcast KEL
//! update announcements and SAD store announcements between peers.

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use kels_gossip_core::Gossip;
use kels_gossip_core::net::actor::Event;
use kels_gossip_core::proto::TopicId;
use thiserror::Error;

use kels_exchange::MailAnnouncement;

use crate::types::{GossipCommand, GossipEvent, IelAnnouncement, KelAnnouncement, SadAnnouncement};

/// Default gossip topic name for KEL announcements
pub const DEFAULT_TOPIC: &str = "kels/gossip/v1/topics/events";

/// Gossip topic name for SAD store announcements
pub const SAD_TOPIC: &str = "kels/gossip/v1/topics/sad";

/// Gossip topic name for IEL announcements
pub const IEL_TOPIC: &str = "kels/gossip/v1/topics/iel";

/// Gossip topic name for mail announcements
pub const MAIL_TOPIC: &str = "kels/gossip/v1/topics/mail";

#[derive(Error, Debug)]
pub enum GossipError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Gossip protocol error: {0}")]
    Protocol(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Channel closed")]
    ChannelClosed,
}

/// Derive a TopicId from a topic name string (Blake3 hash → first 32 bytes).
pub fn topic_id_from_name(name: &str) -> TopicId {
    let hash = blake3::hash(name.as_bytes());
    let bytes: [u8; 32] = *hash.as_bytes();
    TopicId::from_bytes(bytes)
}

/// Run the gossip event loop.
///
/// Subscribes to gossip events, processes commands from the sync layer,
/// and forwards events to the sync handler.
#[allow(clippy::too_many_arguments)]
pub async fn run_gossip(
    gossip_handle: Gossip,
    kel_topic: TopicId,
    sad_topic: TopicId,
    iel_topic: TopicId,
    mail_topic: TopicId,
    mut command_rx: mpsc::Receiver<GossipCommand>,
    event_tx: mpsc::Sender<GossipEvent>,
    local_node_prefix: cesr::Digest256,
) -> Result<(), GossipError> {
    let mut event_rx = gossip_handle.subscribe();

    loop {
        tokio::select! {
            // Handle incoming commands from sync layer
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    GossipCommand::Kel(announcement) => {
                        let data = serde_json::to_vec(&announcement)?;
                        if let Err(e) = gossip_handle.broadcast(kel_topic, Bytes::from(data), kels_gossip_core::proto::Scope::Swarm).await {
                            warn!("Failed to broadcast KEL announcement: {}", e);
                        } else {
                            debug!("Broadcast KEL announcement for prefix: {}", announcement.prefix);
                        }
                    }
                    GossipCommand::Sad(message) => {
                        let data = serde_json::to_vec(&message)?;
                        if let Err(e) = gossip_handle.broadcast(sad_topic, Bytes::from(data), kels_gossip_core::proto::Scope::Swarm).await {
                            warn!("Failed to broadcast SAD announcement: {}", e);
                        } else {
                            debug!("Broadcast SAD announcement");
                        }
                    }
                    GossipCommand::Iel(announcement) => {
                        let data = serde_json::to_vec(&announcement)?;
                        if let Err(e) = gossip_handle.broadcast(iel_topic, Bytes::from(data), kels_gossip_core::proto::Scope::Swarm).await {
                            warn!("Failed to broadcast IEL announcement: {}", e);
                        } else {
                            debug!("Broadcast IEL announcement for prefix: {}", announcement.prefix);
                        }
                    }
                    GossipCommand::Mail(announcement) => {
                        let data = serde_json::to_vec(&announcement)?;
                        if let Err(e) = gossip_handle.broadcast(mail_topic, Bytes::from(data), kels_gossip_core::proto::Scope::Swarm).await {
                            warn!("Failed to broadcast mail announcement: {}", e);
                        } else {
                            debug!("Broadcast mail announcement");
                        }
                    }
                }
            }

            // Handle gossip protocol events
            event = event_rx.recv() => {
                match event {
                    Ok(Event::Received(msg)) => {
                        if msg.delivered_from == local_node_prefix {
                            debug!("Received announcement from self, ignoring");
                            continue;
                        }

                        // Route by topic
                        if msg.topic == kel_topic {
                            match serde_json::from_slice::<KelAnnouncement>(&msg.content) {
                                Ok(announcement) => {
                                    debug!(
                                        "Received KEL announcement via {}: prefix={}, said={}",
                                        msg.delivered_from, announcement.prefix, announcement.said
                                    );
                                    event_tx
                                        .send(GossipEvent::KelAnnouncementReceived { announcement })
                                        .await
                                        .map_err(|_| GossipError::ChannelClosed)?;
                                }
                                Err(e) => {
                                    warn!("Failed to parse KEL announcement: {}", e);
                                }
                            }
                        } else if msg.topic == sad_topic {
                            match serde_json::from_slice::<SadAnnouncement>(&msg.content) {
                                Ok(announcement) => {
                                    debug!("Received SAD announcement");
                                    event_tx
                                        .send(GossipEvent::SadAnnouncementReceived { announcement })
                                        .await
                                        .map_err(|_| GossipError::ChannelClosed)?;
                                }
                                Err(e) => {
                                    warn!("Failed to parse SAD announcement: {}", e);
                                }
                            }
                        } else if msg.topic == iel_topic {
                            match serde_json::from_slice::<IelAnnouncement>(&msg.content) {
                                Ok(announcement) => {
                                    debug!(
                                        "Received IEL announcement via {}: prefix={}, said={}",
                                        msg.delivered_from,
                                        announcement.prefix,
                                        announcement.said
                                    );
                                    event_tx
                                        .send(GossipEvent::IelAnnouncementReceived { announcement })
                                        .await
                                        .map_err(|_| GossipError::ChannelClosed)?;
                                }
                                Err(e) => {
                                    warn!("Failed to parse IEL announcement: {}", e);
                                }
                            }
                        } else if msg.topic == mail_topic {
                            match serde_json::from_slice::<MailAnnouncement>(&msg.content) {
                                Ok(announcement) => {
                                    debug!("Received mail announcement");
                                    event_tx
                                        .send(GossipEvent::MailAnnouncementReceived { announcement })
                                        .await
                                        .map_err(|_| GossipError::ChannelClosed)?;
                                }
                                Err(e) => {
                                    warn!("Failed to parse mail announcement: {}", e);
                                }
                            }
                        } else {
                            debug!("Received message for unknown topic");
                        }
                    }
                    Ok(Event::NeighborUp(prefix)) => {
                        debug!("Connected to peer: {}", prefix);
                        let _ = event_tx.send(GossipEvent::PeerConnected(prefix)).await;
                    }
                    Ok(Event::NeighborDown(prefix)) => {
                        debug!("Disconnected from peer: {}", prefix);
                        let _ = event_tx.send(GossipEvent::PeerDisconnected(prefix)).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Gossip event subscriber lagged by {} messages", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        error!("Gossip event channel closed");
                        return Err(GossipError::ChannelClosed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_topic_constant() {
        assert_eq!(DEFAULT_TOPIC, "kels/gossip/v1/topics/events");
    }

    #[test]
    fn test_sad_topic_constant() {
        assert_eq!(SAD_TOPIC, "kels/gossip/v1/topics/sad");
    }

    #[test]
    fn test_gossip_error_display() {
        let transport_err = GossipError::Transport("connection failed".to_string());
        assert!(transport_err.to_string().contains("Transport error"));
        assert!(transport_err.to_string().contains("connection failed"));

        let protocol_err = GossipError::Protocol("subscription failed".to_string());
        assert!(protocol_err.to_string().contains("Gossip protocol error"));

        let channel_err = GossipError::ChannelClosed;
        assert_eq!(channel_err.to_string(), "Channel closed");
    }

    #[test]
    fn test_gossip_error_from_serde_json() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let json_err = json_result.expect_err("Expected JSON parse error");
        let gossip_err: GossipError = json_err.into();
        assert!(matches!(gossip_err, GossipError::Serialization(_)));
    }

    #[test]
    fn test_topic_id_from_name_deterministic() {
        let id1 = topic_id_from_name("kels/events/v1");
        let id2 = topic_id_from_name("kels/events/v1");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_topic_id_from_name_different_names() {
        let id1 = topic_id_from_name("kels/events/v1");
        let id2 = topic_id_from_name("kels/events/v2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_all_topics_differ() {
        let kel = topic_id_from_name(DEFAULT_TOPIC);
        let sad = topic_id_from_name(SAD_TOPIC);
        let mail = topic_id_from_name(MAIL_TOPIC);
        assert_ne!(kel, sad);
        assert_ne!(kel, mail);
        assert_ne!(sad, mail);
    }
}
