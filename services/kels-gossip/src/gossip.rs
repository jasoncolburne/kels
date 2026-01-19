//! libp2p networking layer for KELS gossip.
//!
//! Sets up gossipsub for announcements and request-response for KEL fetching.

use crate::protocol::{KelAnnouncement, KelRequest, KelResponse, PROTOCOL_NAME};
use futures::prelude::*;
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
}

/// Build and run the libp2p swarm
pub async fn run_swarm(
    listen_addr: Multiaddr,
    bootstrap_peers: Vec<Multiaddr>,
    topic_name: &str,
    mut command_rx: mpsc::Receiver<GossipCommand>,
    event_tx: mpsc::Sender<GossipEvent>,
) -> Result<(), GossipError> {
    let mut swarm = build_swarm(topic_name)?;

    // Listen on the specified address
    swarm
        .listen_on(listen_addr.clone())
        .map_err(|e| GossipError::Transport(e.to_string()))?;
    info!("Listening on {}", listen_addr);

    // Connect to bootstrap peers
    for addr in bootstrap_peers {
        info!("Dialing bootstrap peer: {}", addr);
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
        }
    }
}

fn build_swarm(topic_name: &str) -> Result<Swarm<KelsBehaviour>, GossipError> {
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

    let swarm = SwarmBuilder::with_new_identity()
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
            })
        })
        .map_err(|e| GossipError::Transport(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to the topic
    let topic = IdentTopic::new(topic_name);
    let mut swarm = swarm;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|e| GossipError::Gossipsub(e.to_string()))?;

    info!("Local peer ID: {}", swarm.local_peer_id());

    Ok(swarm)
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
                debug!(
                    "Received announcement from {}: prefix={}, said={}",
                    propagation_source, announcement.prefix, announcement.said
                );
                event_tx
                    .send(GossipEvent::AnnouncementReceived {
                        peer_id: propagation_source,
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
