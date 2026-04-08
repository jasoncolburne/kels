//! KELS gossip protocol library
//!
//! This crate implements a gossip protocol for the KELS (Key Event Log System) network,
//! providing decentralized message broadcasting across federated peers.
//!
//! The protocol is composed of two layers, inspired by the
//! [iroh-gossip](https://github.com/n0-computer/iroh-gossip) implementation:
//!
//! - **HyParView** ([paper](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf)):
//!   A membership protocol that maintains partial views of the network. Each peer keeps a small
//!   set of active connections and a larger set of passive (known but unconnected) peers.
//!
//! - **PlumTree** ([paper](https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf)):
//!   An epidemic broadcast tree protocol that builds on the membership layer. It maintains eager
//!   and lazy peer sets, self-optimizing the broadcast tree by latency.
//!
//! The protocol logic is implemented as an IO-free state machine, adapted from iroh-gossip's
//! proto module with KELS-specific modifications (KELS prefix identity, CESR encoding, etc.).
//!
//! # Architecture
//!
//! ```text
//! Application (gossip messages)
//!         |
//!    PlumTree (broadcast)
//!         |
//!    HyParView (membership)
//!         |
//!    Network layer (TCP + AES-GCM-256)
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use kels_gossip_core::{Gossip, GossipConfig};
//! use kels_gossip_core::proto::{TopicId, Scope};
//! use kels_gossip_core::addr::PeerAddr;
//! use bytes::Bytes;
//!
//! # async fn example() -> Result<(), kels_gossip_core::net::Error> {
//! // Create and start a gossip instance (requires Signer + PeerVerifier impls).
//! // let gossip = Gossip::new(config, signer, verifier, listen_addr).await?;
//! //
//! // Join a topic with bootstrap peers.
//! // gossip.join(topic_id, bootstrap_peers).await?;
//! //
//! // Broadcast a message.
//! // gossip.broadcast(topic_id, data, Scope::Swarm).await?;
//! //
//! // Receive events.
//! // let mut events = gossip.subscribe();
//! // while let Ok(event) = events.recv().await { /* handle */ }
//! # Ok(())
//! # }
//! ```

pub mod addr;
pub mod net;
pub mod proto;

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use addr::PeerAddr;
use net::actor::{Command, Event};
use net::{Error, PeerVerifier, Signer};
use proto::{PeerData, Scope, TopicId};

// Re-export key types for convenience.
pub use net::actor::{Event as GossipEvent, GossipMessage};

/// Configuration for the gossip instance.
#[derive(Debug, Clone, Default)]
pub struct GossipConfig {
    /// Protocol configuration (membership + broadcast layer settings).
    pub protocol: proto::Config,
    /// Data advertised to peers (typically our `host:port` as UTF-8 bytes).
    pub advertise_data: PeerData,
}

/// Handle to a running gossip instance.
///
/// The `Gossip` handle communicates with a background actor that manages
/// the protocol state machine, peer connections, and timers.
///
/// Cloning the handle creates another reference to the same actor.
#[derive(Clone)]
pub struct Gossip {
    cmd_tx: mpsc::Sender<Command>,
    event_tx: broadcast::Sender<Event>,
}

impl Gossip {
    /// Create and start a new gossip instance.
    ///
    /// Binds a TCP listener on `listen_addr` and spawns the background actor.
    /// The returned handle can be cloned and shared across tasks.
    pub async fn new<S: Signer, V: PeerVerifier>(
        config: GossipConfig,
        signer: S,
        verifier: V,
        listen_addr: SocketAddr,
    ) -> Result<(Self, GossipHandle), Error> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (event_tx, _) = broadcast::channel(1024);

        let mut actor = net::actor::GossipActor::new(
            config.protocol,
            config.advertise_data,
            signer,
            verifier,
            cmd_rx,
            event_tx.clone(),
        );
        actor.listen(listen_addr).await?;

        let actor_handle = tokio::spawn(actor.run());

        let gossip = Self { cmd_tx, event_tx };
        let handle = GossipHandle {
            _actor: actor_handle,
        };

        Ok((gossip, handle))
    }

    /// Join a topic with the given bootstrap peers.
    ///
    /// Dials any bootstrap peers we're not already connected to, then joins the topic
    /// on the protocol layer.
    pub async fn join(&self, topic: TopicId, bootstrap: Vec<PeerAddr>) -> Result<(), Error> {
        self.cmd_tx
            .send(Command::Join { topic, bootstrap })
            .await
            .map_err(|_| Error::Shutdown)
    }

    /// Broadcast data on a topic.
    pub async fn broadcast(&self, topic: TopicId, data: Bytes, scope: Scope) -> Result<(), Error> {
        self.cmd_tx
            .send(Command::Broadcast { topic, data, scope })
            .await
            .map_err(|_| Error::Shutdown)
    }

    /// Leave a topic.
    pub async fn leave(&self, topic: TopicId) -> Result<(), Error> {
        self.cmd_tx
            .send(Command::Leave { topic })
            .await
            .map_err(|_| Error::Shutdown)
    }

    /// Subscribe to gossip events.
    ///
    /// Returns a broadcast receiver that yields [`Event`]s from all topics.
    /// Multiple subscribers can be created by calling this multiple times.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.event_tx.subscribe()
    }

    /// Request the actor to shut down.
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.cmd_tx
            .send(Command::Shutdown)
            .await
            .map_err(|_| Error::Shutdown)
    }
}

/// Handle to the background gossip actor task.
///
/// Dropping this handle does NOT stop the actor — use [`Gossip::shutdown`] for that.
/// This handle is useful for awaiting the actor's completion.
pub struct GossipHandle {
    _actor: JoinHandle<()>,
}

impl GossipHandle {
    /// Wait for the actor to complete.
    pub async fn finished(self) {
        let _ = self._actor.await;
    }
}
