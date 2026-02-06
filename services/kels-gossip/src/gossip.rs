//! libp2p networking layer for KELS gossip.
//!
//! Sets up gossipsub for KEL update announcements.

use crate::allowlist::{AllowlistBehaviour, SharedAllowlist};
use crate::protocol::KelAnnouncement;
use futures::prelude::*;
use kels::MultiRegistryClient;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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
    #[error("Channel closed")]
    ChannelClosed,
}

/// Events emitted by the gossip layer to the sync layer
#[derive(Debug)]
pub enum GossipEvent {
    /// Received an announcement from a peer
    AnnouncementReceived { announcement: KelAnnouncement },
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
}

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct KelsBehaviour {
    gossipsub: gossipsub::Behaviour,
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
    registry_client: MultiRegistryClient,
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

            let identify = identify::Behaviour::new(identify::Config::new(
                "/kels-gossip/1.0.0".to_string(),
                key.public(),
            ));

            Ok(KelsBehaviour {
                gossipsub,
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
            Ok(announcement) if announcement.sender != swarm.local_peer_id().to_base58() => {
                debug!(
                    "Received announcement via {}: prefix={}, said={}, sender={}",
                    propagation_source, announcement.prefix, announcement.said, announcement.sender
                );
                event_tx
                    .send(GossipEvent::AnnouncementReceived { announcement })
                    .await
                    .map_err(|_| GossipError::ChannelClosed)?;
            }
            Ok(_) => {
                debug!("Received announcement from self");
            }
            Err(e) => {
                warn!("Failed to parse announcement: {}", e);
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
    }

    #[test]
    fn test_gossip_error_from_serde_json() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let json_err = json_result.expect_err("Expected JSON parse error");
        let gossip_err: GossipError = json_err.into();
        assert!(matches!(gossip_err, GossipError::Serialization(_)));
    }
}
