//! libp2p networking layer for KELS gossip.
//!
//! Sets up gossipsub for announcements and request-response for KEL fetching.

use crate::allowlist::{AllowlistBehaviour, SharedAllowlist};
use crate::protocol::{KelAnnouncement, KelRequest, KelResponse, PROTOCOL_NAME};
use futures::prelude::*;
use kels::KelsRegistryClient;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify, noise,
    request_response::{self, Codec, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Default gossipsub topic for KEL announcements
pub const DEFAULT_TOPIC: &str = "kels/events/v1";

#[derive(Error, Debug)]
pub enum GossipError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Gossipsub error: {0}")]
    Gossipsub(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Channel closed")]
    ChannelClosed,
}

/// Events emitted by the gossip layer to the sync layer
#[derive(Debug)]
pub enum GossipEvent {
    /// Received an announcement from a peer
    AnnouncementReceived {
        peer_id: PeerId,
        announcement: KelAnnouncement,
    },
    /// Received a KEL request from a peer
    KelRequestReceived {
        peer_id: PeerId,
        channel: ResponseChannel<KelResponse>,
        request: KelRequest,
    },
    /// Received a KEL response from a peer
    KelResponseReceived {
        peer_id: PeerId,
        response: KelResponse,
    },
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
}

/// Commands sent from sync layer to gossip layer
#[derive(Debug)]
pub enum GossipCommand {
    /// Broadcast an announcement to the network
    Announce(KelAnnouncement),
    /// Request a KEL from a specific peer
    RequestKel { peer_id: PeerId, prefix: String },
    /// Respond to a KEL request
    RespondKel {
        channel: ResponseChannel<KelResponse>,
        response: KelResponse,
    },
}

/// JSON codec for request-response protocol
#[derive(Debug, Clone, Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Protocol = &'static str;
    type Request = KelRequest;
    type Response = KelResponse;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Self::Request>> + Send + 'async_trait>,
    >
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?;
            serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Self::Response>> + Send + 'async_trait>,
    >
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?;
            serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let bytes = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            io.write_all(&bytes).await?;
            io.close().await?;
            Ok(())
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        res: Self::Response,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let bytes = serde_json::to_vec(&res)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            io.write_all(&bytes).await?;
            io.close().await?;
            Ok(())
        })
    }
}

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct KelsBehaviour {
    gossipsub: gossipsub::Behaviour,
    request_response: request_response::Behaviour<JsonCodec>,
    identify: identify::Behaviour,
    allowlist: AllowlistBehaviour,
}

/// Build and run the libp2p swarm
#[allow(clippy::too_many_arguments)]
pub async fn run_swarm(
    keypair: libp2p_identity::Keypair,
    listen_addr: Multiaddr,
    peer_addrs: Vec<Multiaddr>,
    topic_name: &str,
    allowlist: SharedAllowlist,
    registry_client: KelsRegistryClient,
    registry_prefix: String,
    mut command_rx: mpsc::Receiver<GossipCommand>,
    event_tx: mpsc::Sender<GossipEvent>,
) -> Result<(), GossipError> {
    let (mut swarm, mut refresh_rx) = build_swarm(keypair, topic_name, allowlist.clone())?;

    // Listen on the specified address
    swarm
        .listen_on(listen_addr.clone())
        .map_err(|e| GossipError::Transport(e.to_string()))?;
    info!("Listening on {}", listen_addr);

    // Connect to peers from registry
    for addr in peer_addrs {
        info!("Dialing peer: {}", addr);
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!("Failed to dial {}: {}", addr, e);
        }
    }

    let topic = IdentTopic::new(topic_name);

    loop {
        tokio::select! {
            // Handle incoming commands
            Some(cmd) = command_rx.recv() => {
                handle_command(&mut swarm, &topic, cmd)?;
            }

            // Handle swarm events
            event = swarm.select_next_some() => {
                if let Err(e) = handle_swarm_event(&mut swarm, event, &event_tx).await {
                    error!("Error handling swarm event: {}", e);
                }
            }

            // Handle allowlist refresh requests (triggered by unknown peer connections)
            Some(()) = refresh_rx.recv() => {
                debug!("Refreshing allowlist due to unknown peer connection");
                if let Err(e) = crate::allowlist::refresh_allowlist(
                    &registry_client,
                    &registry_prefix,
                    &allowlist,
                ).await {
                    warn!("Failed to refresh allowlist: {}", e);
                }
                // Verify pending peers after refresh
                swarm.behaviour_mut().allowlist.verify_pending_peers().await;
            }
        }
    }
}

fn build_swarm(
    keypair: libp2p_identity::Keypair,
    topic_name: &str,
    allowlist: SharedAllowlist,
) -> Result<(Swarm<KelsBehaviour>, mpsc::Receiver<()>), GossipError> {
    // Create allowlist behaviour and get refresh receiver before SwarmBuilder
    let (allowlist_behaviour, refresh_rx) = AllowlistBehaviour::new(allowlist);

    // Message ID function for deduplication
    let message_id_fn = |message: &gossipsub::Message| {
        let mut hasher = DefaultHasher::new();
        message.data.hash(&mut hasher);
        MessageId::from(hasher.finish().to_string())
    };

    // Gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|e| GossipError::Gossipsub(e.to_string()))?;

    // Convert libp2p_identity::Keypair to libp2p::identity::Keypair
    // The forked libp2p-identity is compatible with libp2p's identity
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| GossipError::Transport(e.to_string()))?
        .with_dns()
        .map_err(|e| GossipError::Transport(e.to_string()))?
        .with_behaviour(|key| {
            let gossipsub = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| GossipError::Gossipsub(e.to_string()))?;

            let request_response = request_response::Behaviour::new(
                [(PROTOCOL_NAME, ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let identify = identify::Behaviour::new(identify::Config::new(
                "/kels-gossip/1.0.0".to_string(),
                key.public(),
            ));

            Ok(KelsBehaviour {
                gossipsub,
                request_response,
                identify,
                allowlist: allowlist_behaviour,
            })
        })
        .map_err(|e| GossipError::Transport(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to the topic
    let topic = IdentTopic::new(topic_name);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|e| GossipError::Gossipsub(e.to_string()))?;

    info!("Local peer ID: {}", swarm.local_peer_id());

    Ok((swarm, refresh_rx))
}

fn handle_command(
    swarm: &mut Swarm<KelsBehaviour>,
    topic: &IdentTopic,
    cmd: GossipCommand,
) -> Result<(), GossipError> {
    match cmd {
        GossipCommand::Announce(announcement) => {
            let data = serde_json::to_vec(&announcement)?;
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                warn!("Failed to publish announcement: {}", e);
            } else {
                debug!("Published announcement for prefix: {}", announcement.prefix);
            }
        }
        GossipCommand::RequestKel { peer_id, prefix } => {
            let request = KelRequest {
                prefix: prefix.clone(),
            };
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
            debug!("Sent KEL request to {} for prefix: {}", peer_id, prefix);
        }
        GossipCommand::RespondKel { channel, response } => {
            if let Err(e) = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, response)
            {
                warn!("Failed to send KEL response: {:?}", e);
            }
        }
    }
    Ok(())
}

async fn handle_swarm_event(
    swarm: &mut Swarm<KelsBehaviour>,
    event: SwarmEvent<KelsBehaviourEvent>,
    event_tx: &mpsc::Sender<GossipEvent>,
) -> Result<(), GossipError> {
    match event {
        SwarmEvent::Behaviour(KelsBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => match serde_json::from_slice::<KelAnnouncement>(&message.data) {
            Ok(announcement) => {
                // Use message.source (original publisher) not propagation_source (forwarder)
                // This ensures we fetch the KEL from the peer that actually has it
                let source_peer = message.source.unwrap_or(propagation_source);
                debug!(
                    "Received announcement from {} (via {}): prefix={}, said={}",
                    source_peer, propagation_source, announcement.prefix, announcement.said
                );
                event_tx
                    .send(GossipEvent::AnnouncementReceived {
                        peer_id: source_peer,
                        announcement,
                    })
                    .await
                    .map_err(|_| GossipError::ChannelClosed)?;
            }
            Err(e) => {
                warn!("Failed to parse announcement: {}", e);
            }
        },

        SwarmEvent::Behaviour(KelsBehaviourEvent::RequestResponse(
            request_response::Event::Message { peer, message },
        )) => match message {
            request_response::Message::Request {
                channel, request, ..
            } => {
                debug!(
                    "Received KEL request from {}: prefix={}",
                    peer, request.prefix
                );
                event_tx
                    .send(GossipEvent::KelRequestReceived {
                        peer_id: peer,
                        channel,
                        request,
                    })
                    .await
                    .map_err(|_| GossipError::ChannelClosed)?;
            }
            request_response::Message::Response { response, .. } => {
                debug!(
                    "Received KEL response from {}: prefix={}, events={}",
                    peer,
                    response.prefix,
                    response.events.len()
                );
                event_tx
                    .send(GossipEvent::KelResponseReceived {
                        peer_id: peer,
                        response,
                    })
                    .await
                    .map_err(|_| GossipError::ChannelClosed)?;
            }
        },

        SwarmEvent::Behaviour(KelsBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            debug!("Identified peer {}: {:?}", peer_id, info.protocols);
            // Add peer's listen addresses
            for addr in info.listen_addrs {
                swarm.add_external_address(addr);
            }
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("Connected to peer: {}", peer_id);
            let _ = event_tx.send(GossipEvent::PeerConnected(peer_id)).await;
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("Disconnected from peer: {}", peer_id);
            let _ = event_tx.send(GossipEvent::PeerDisconnected(peer_id)).await;
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on: {}", address);
        }

        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_topic_constant() {
        assert_eq!(DEFAULT_TOPIC, "kels/events/v1");
    }

    #[test]
    fn test_gossip_error_display() {
        let transport_err = GossipError::Transport("connection failed".to_string());
        assert!(transport_err.to_string().contains("Transport error"));
        assert!(transport_err.to_string().contains("connection failed"));

        let gossipsub_err = GossipError::Gossipsub("subscription failed".to_string());
        assert!(gossipsub_err.to_string().contains("Gossipsub error"));

        let channel_err = GossipError::ChannelClosed;
        assert_eq!(channel_err.to_string(), "Channel closed");

        let io_err = GossipError::Io(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        assert!(io_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_gossip_error_from_serde_json() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let json_err = json_result.expect_err("Expected JSON parse error");
        let gossip_err: GossipError = json_err.into();
        assert!(matches!(gossip_err, GossipError::Serialization(_)));
    }

    #[test]
    fn test_gossip_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let gossip_err: GossipError = io_err.into();
        assert!(matches!(gossip_err, GossipError::Io(_)));
    }

    #[test]
    fn test_gossip_event_debug() {
        let peer_id = PeerId::random();

        let connected = GossipEvent::PeerConnected(peer_id);
        let debug_str = format!("{:?}", connected);
        assert!(debug_str.contains("PeerConnected"));

        let disconnected = GossipEvent::PeerDisconnected(peer_id);
        let debug_str = format!("{:?}", disconnected);
        assert!(debug_str.contains("PeerDisconnected"));

        let announcement = KelAnnouncement {
            prefix: "test_prefix".to_string(),
            said: "test_said".to_string(),
        };
        let received = GossipEvent::AnnouncementReceived {
            peer_id,
            announcement,
        };
        let debug_str = format!("{:?}", received);
        assert!(debug_str.contains("AnnouncementReceived"));
        assert!(debug_str.contains("test_prefix"));

        let response = KelResponse {
            prefix: "resp_prefix".to_string(),
            events: vec![],
        };
        let resp_received = GossipEvent::KelResponseReceived { peer_id, response };
        let debug_str = format!("{:?}", resp_received);
        assert!(debug_str.contains("KelResponseReceived"));
    }

    #[test]
    fn test_gossip_command_debug() {
        let announcement = KelAnnouncement {
            prefix: "cmd_prefix".to_string(),
            said: "cmd_said".to_string(),
        };
        let announce = GossipCommand::Announce(announcement);
        let debug_str = format!("{:?}", announce);
        assert!(debug_str.contains("Announce"));
        assert!(debug_str.contains("cmd_prefix"));

        let peer_id = PeerId::random();
        let request = GossipCommand::RequestKel {
            peer_id,
            prefix: "request_prefix".to_string(),
        };
        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("RequestKel"));
        assert!(debug_str.contains("request_prefix"));
    }

    #[test]
    fn test_json_codec_debug() {
        let codec = JsonCodec;
        let debug_str = format!("{:?}", codec);
        assert!(debug_str.contains("JsonCodec"));
    }

    #[test]
    fn test_json_codec_clone() {
        let codec = JsonCodec;
        let cloned = codec.clone();
        // Both should format the same way
        assert_eq!(format!("{:?}", codec), format!("{:?}", cloned));
    }

    #[test]
    fn test_kel_request_serialization() {
        let request = KelRequest {
            prefix: "test_prefix_123".to_string(),
        };

        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed: KelRequest = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed.prefix, "test_prefix_123");
    }

    #[test]
    fn test_kel_response_serialization() {
        let response = KelResponse {
            prefix: "resp_prefix_456".to_string(),
            events: vec![],
        };

        let bytes = serde_json::to_vec(&response).unwrap();
        let parsed: KelResponse = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed.prefix, "resp_prefix_456");
        assert!(parsed.events.is_empty());
    }

    #[test]
    fn test_kel_request_invalid_json() {
        let invalid_bytes = b"not valid json";
        let result: Result<KelRequest, _> = serde_json::from_slice(invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_kel_response_invalid_json() {
        let invalid_bytes = b"not valid json";
        let result: Result<KelResponse, _> = serde_json::from_slice(invalid_bytes);
        assert!(result.is_err());
    }
}
