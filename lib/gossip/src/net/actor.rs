//! Gossip actor — event loop bridging the IO-free protocol state machine to the network.
//!
//! The actor owns the [`proto::State`] and manages:
//! - Peer TCP connections (dial, accept, read, write)
//! - On-demand dialing when the protocol needs to reach unconnected peers
//! - Protocol timers (via tokio tasks)
//! - Application commands (join, broadcast, leave)
//! - Event dispatch to subscribers

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures::AsyncReadExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::addr::PeerAddr;
use crate::identity::NodePrefix;
use crate::proto::{self, PeerData, Scope, TopicId};

use super::{Error, PeerVerifier, Signer, codec, transport};

/// Application-facing event from the gossip protocol.
#[derive(Debug, Clone)]
pub enum Event {
    /// A peer joined our active view for a topic.
    NeighborUp(NodePrefix),
    /// A peer left our active view for a topic.
    NeighborDown(NodePrefix),
    /// A gossip message was received.
    Received(GossipMessage),
}

/// A received gossip message.
#[derive(Debug, Clone)]
pub struct GossipMessage {
    /// The topic this message belongs to.
    pub topic: TopicId,
    /// The message content.
    pub content: Bytes,
    /// The peer that delivered this message.
    pub delivered_from: NodePrefix,
}

/// Commands sent from the application to the gossip actor.
pub(crate) enum Command {
    /// Join a topic with bootstrap peers.
    Join {
        topic: TopicId,
        bootstrap: Vec<PeerAddr>,
    },
    /// Broadcast data on a topic.
    Broadcast {
        topic: TopicId,
        data: Bytes,
        scope: Scope,
    },
    /// Leave a topic.
    Leave { topic: TopicId },
    /// Shut down the actor.
    Shutdown,
}

/// Internal message from a peer reader task.
enum PeerMessage {
    /// A protocol message was received from a peer.
    Received {
        peer_prefix: NodePrefix,
        message: proto::Message<NodePrefix>,
    },
    /// A peer disconnected (reader task exited).
    Disconnected {
        peer_prefix: NodePrefix,
        /// Connection generation at time of spawn, used to ignore stale disconnects
        /// from replaced connections.
        generation: u64,
    },
}

/// Result of an on-demand dial attempt.
#[allow(clippy::large_enum_variant)]
enum DialResult {
    /// Dial succeeded — connection established.
    Success(transport::PeerConnection),
    /// Dial failed.
    Failure {
        peer_prefix: NodePrefix,
        error: Error,
    },
}

/// State for an active peer connection.
struct ActivePeer {
    /// Channel to send outbound protocol messages.
    msg_tx: mpsc::Sender<proto::Message<NodePrefix>>,
    /// Reader task handle.
    _reader: JoinHandle<()>,
    /// Writer task handle.
    _writer: JoinHandle<()>,
    /// Connection generation, used to ignore stale disconnect messages from replaced connections.
    generation: u64,
}

/// The gossip actor.
///
/// Owns the protocol state machine and manages all IO: peer connections,
/// timers, and application command/event channels.
///
/// When the protocol needs to send a message to a peer we don't have a
/// connection to, the actor looks up the peer's advertised address (from
/// PeerData), queues the message, and dials on demand — matching the
/// pattern from iroh-gossip.
pub(crate) struct GossipActor<S, V> {
    state: proto::State<NodePrefix, StdRng>,
    signer: Arc<S>,
    verifier: Arc<V>,
    listener: Option<TcpListener>,
    /// Active peer connections.
    peers: HashMap<NodePrefix, ActivePeer>,
    /// Messages queued for peers being dialed.
    pending_dials: HashMap<NodePrefix, Vec<proto::Message<NodePrefix>>>,
    /// Known peer addresses from PeerData events (advertised host:port).
    peer_addrs: HashMap<NodePrefix, String>,
    cmd_rx: mpsc::Receiver<Command>,
    event_tx: broadcast::Sender<Event>,
    peer_msg_tx: mpsc::Sender<PeerMessage>,
    peer_msg_rx: mpsc::Receiver<PeerMessage>,
    timer_tx: mpsc::Sender<proto::Timer<NodePrefix>>,
    timer_rx: mpsc::Receiver<proto::Timer<NodePrefix>>,
    dial_tx: mpsc::Sender<DialResult>,
    dial_rx: mpsc::Receiver<DialResult>,
    /// Monotonically increasing counter for connection generations.
    /// Used to ignore stale disconnect messages from replaced connections.
    connection_generation: u64,
}

impl<S: Signer, V: PeerVerifier> GossipActor<S, V> {
    /// Create a new gossip actor.
    pub fn new(
        config: proto::Config,
        advertise_data: PeerData,
        signer: S,
        verifier: V,
        cmd_rx: mpsc::Receiver<Command>,
        event_tx: broadcast::Sender<Event>,
    ) -> Self {
        let our_id = signer.node_prefix();
        let rng = StdRng::from_os_rng();
        let state = proto::State::new(our_id, advertise_data, config, rng);

        let (peer_msg_tx, peer_msg_rx) = mpsc::channel(256);
        let (timer_tx, timer_rx) = mpsc::channel(256);
        let (dial_tx, dial_rx) = mpsc::channel(64);

        Self {
            state,
            signer: Arc::new(signer),
            verifier: Arc::new(verifier),
            listener: None,
            peers: HashMap::new(),
            pending_dials: HashMap::new(),
            peer_addrs: HashMap::new(),
            cmd_rx,
            event_tx,
            peer_msg_tx,
            peer_msg_rx,
            timer_tx,
            timer_rx,
            dial_tx,
            dial_rx,
            connection_generation: 0,
        }
    }

    /// Bind a TCP listener for incoming peer connections.
    pub async fn listen(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let listener = TcpListener::bind(addr).await?;
        debug!(%addr, "listening for gossip connections");
        self.listener = Some(listener);
        Ok(())
    }

    /// Run the actor event loop until shutdown.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Accept incoming connections.
                result = accept_if_listening(&self.listener) => {
                    if let Some((tcp, peer_addr)) = result {
                        self.handle_incoming(tcp, peer_addr).await;
                    }
                }

                // Process application commands.
                Some(cmd) = self.cmd_rx.recv() => {
                    if self.handle_command(cmd).await {
                        break;
                    }
                }

                // Process messages from peer reader tasks.
                Some(msg) = self.peer_msg_rx.recv() => {
                    self.handle_peer_message(msg);
                }

                // Process expired timers.
                Some(timer) = self.timer_rx.recv() => {
                    self.handle_timer(timer);
                }

                // Process dial results from on-demand dialing.
                Some(result) = self.dial_rx.recv() => {
                    self.handle_dial_result(result);
                }
            }
        }
        debug!("gossip actor shutting down");
    }

    /// Handle an incoming TCP connection.
    async fn handle_incoming(&mut self, tcp: tokio::net::TcpStream, peer_addr: SocketAddr) {
        match transport::accept(tcp, peer_addr, &*self.signer, &*self.verifier).await {
            Ok(conn) => {
                let peer_prefix = conn.peer_prefix;

                if self.peers.contains_key(&peer_prefix) {
                    if self
                        .peers
                        .get(&peer_prefix)
                        .is_some_and(|p| p._reader.is_finished())
                    {
                        // Existing connection is dead (reader task exited — peer restarted
                        // or network partition resolved). Replace with the new connection.
                        debug!(%peer_prefix, %peer_addr, "existing connection dead, replacing with incoming");
                        self.peers.remove(&peer_prefix);
                    } else {
                        // Existing connection appears alive. Drop this incoming to avoid
                        // duplicate-connection races (both sides dialing simultaneously).
                        debug!(%peer_prefix, %peer_addr, "incoming connection but already connected, dropping");
                        return;
                    }
                }

                // If we have a pending dial for this peer (they connected to us first),
                // cancel the pending dial and drain queued messages via this connection.
                let queued = self.pending_dials.remove(&peer_prefix);
                self.setup_peer(conn);
                if let Some(messages) = queued {
                    self.drain_queued_messages(peer_prefix, messages);
                }
                debug!(%peer_prefix, %peer_addr, "incoming peer connected");
            }
            Err(e) => warn!(%peer_addr, error = %e, "incoming handshake failed"),
        }
    }

    /// Handle a command from the application. Returns `true` if the actor should shut down.
    async fn handle_command(&mut self, cmd: Command) -> bool {
        match cmd {
            Command::Join { topic, bootstrap } => {
                self.handle_join(topic, bootstrap);
            }
            Command::Broadcast { topic, data, scope } => {
                let now = Instant::now();
                let in_event =
                    proto::InEvent::Command(topic, proto::topic::Command::Broadcast(data, scope));
                let events: Vec<_> = self.state.handle(in_event, now).collect();
                self.process_out_events(events);
            }
            Command::Leave { topic } => {
                let now = Instant::now();
                let in_event = proto::InEvent::Command(topic, proto::topic::Command::Quit);
                let events: Vec<_> = self.state.handle(in_event, now).collect();
                self.process_out_events(events);
            }
            Command::Shutdown => return true,
        }
        false
    }

    /// Handle the join flow: store bootstrap addresses and join the topic.
    ///
    /// Dials are NOT performed here — they happen on-demand when the protocol
    /// tries to send Join messages to bootstrap peers via `process_out_events`.
    /// This keeps the actor event loop non-blocking so it can accept incoming
    /// connections while outbound dials proceed concurrently.
    fn handle_join(&mut self, topic: TopicId, bootstrap: Vec<PeerAddr>) {
        let mut bootstrap_peers = Vec::new();

        for addr in bootstrap {
            // Store the address for future on-demand dialing.
            self.peer_addrs
                .insert(addr.prefix, format!("{}:{}", addr.host, addr.port));
            bootstrap_peers.push(addr.prefix);
        }

        let now = Instant::now();
        let in_event = proto::InEvent::Command(topic, proto::topic::Command::Join(bootstrap_peers));
        let events: Vec<_> = self.state.handle(in_event, now).collect();
        self.process_out_events(events);
    }

    /// Handle a message from a peer reader task.
    fn handle_peer_message(&mut self, msg: PeerMessage) {
        let now = Instant::now();
        match msg {
            PeerMessage::Received {
                peer_prefix,
                message,
            } => {
                let in_event = proto::InEvent::RecvMessage(peer_prefix, message);
                let events: Vec<_> = self.state.handle(in_event, now).collect();
                self.process_out_events(events);
            }
            PeerMessage::Disconnected {
                peer_prefix,
                generation,
            } => {
                // Only inform the protocol if this peer is still tracked AND the
                // generation matches. Stale disconnects from replaced connections
                // (e.g., after a peer restart) are safely ignored.
                let is_current = self
                    .peers
                    .get(&peer_prefix)
                    .is_some_and(|p| p.generation == generation);
                if is_current {
                    self.peers.remove(&peer_prefix);
                    let in_event = proto::InEvent::PeerDisconnected(peer_prefix);
                    let events: Vec<_> = self.state.handle(in_event, now).collect();
                    self.process_out_events(events);
                }
                debug!(%peer_prefix, %generation, %is_current, "peer disconnected");
            }
        }
    }

    /// Handle an expired timer.
    fn handle_timer(&mut self, timer: proto::Timer<NodePrefix>) {
        let now = Instant::now();
        let in_event = proto::InEvent::TimerExpired(timer);
        let events: Vec<_> = self.state.handle(in_event, now).collect();
        self.process_out_events(events);
    }

    /// Handle a completed dial attempt.
    fn handle_dial_result(&mut self, result: DialResult) {
        match result {
            DialResult::Success(conn) => {
                let peer_prefix = conn.peer_prefix;
                let queued = self.pending_dials.remove(&peer_prefix).unwrap_or_default();

                if self.peers.contains_key(&peer_prefix) {
                    if self
                        .peers
                        .get(&peer_prefix)
                        .is_some_and(|p| p._reader.is_finished())
                    {
                        // Existing connection is dead. Replace with new dialed connection.
                        debug!(%peer_prefix, "existing connection dead, replacing with dialed");
                        self.peers.remove(&peer_prefix);
                    } else {
                        // Already connected via accept while we were dialing.
                        // Use the existing connection; drain queued messages through it.
                        debug!(%peer_prefix, "dial succeeded but already connected, using existing");
                        self.drain_queued_messages(peer_prefix, queued);
                        return;
                    }
                }

                self.setup_peer(conn);
                debug!(%peer_prefix, queued = queued.len(), "on-demand dial succeeded");
                self.drain_queued_messages(peer_prefix, queued);
            }
            DialResult::Failure { peer_prefix, error } => {
                let queued_count = self
                    .pending_dials
                    .remove(&peer_prefix)
                    .map(|q| q.len())
                    .unwrap_or(0);
                warn!(
                    %peer_prefix,
                    queued_count,
                    error = %error,
                    "on-demand dial failed, dropping queued messages"
                );

                if self.peers.contains_key(&peer_prefix) {
                    // Already connected via accept — don't tell the protocol
                    // the peer is gone (the accepted connection is still alive).
                    debug!(%peer_prefix, "dial failed but already connected via accept, ignoring");
                    return;
                }

                // Inform the protocol that this peer is unreachable.
                let now = Instant::now();
                let in_event = proto::InEvent::PeerDisconnected(peer_prefix);
                let events: Vec<_> = self.state.handle(in_event, now).collect();
                self.process_out_events(events);
            }
        }
    }

    /// Drain queued messages to a newly connected peer.
    fn drain_queued_messages(
        &self,
        peer_prefix: NodePrefix,
        messages: Vec<proto::Message<NodePrefix>>,
    ) {
        if let Some(peer_state) = self.peers.get(&peer_prefix) {
            for msg in messages {
                if peer_state.msg_tx.try_send(msg).is_err() {
                    warn!(%peer_prefix, "failed to drain queued message (channel full or closed)");
                    break;
                }
            }
        }
    }

    /// Process output events from the protocol state machine.
    fn process_out_events(&mut self, events: Vec<proto::OutEvent<NodePrefix>>) {
        for event in events {
            match event {
                proto::OutEvent::SendMessage(peer, msg) => {
                    if let Some(peer_state) = self.peers.get(&peer) {
                        // Peer is connected — send directly.
                        if peer_state.msg_tx.try_send(msg).is_err() {
                            // Channel full or closed — connection is stalled/dead.
                            // Disconnect so HyParView can replace this peer.
                            warn!(%peer, "peer channel full or closed, disconnecting");
                            self.peers.remove(&peer);
                            let now = Instant::now();
                            let in_event = proto::InEvent::PeerDisconnected(peer);
                            let events: Vec<_> = self.state.handle(in_event, now).collect();
                            self.process_out_events(events);
                        }
                    } else if let Some(queue) = self.pending_dials.get_mut(&peer) {
                        // Already dialing this peer — queue the message.
                        queue.push(msg);
                    } else if let Some(addr) = self.peer_addrs.get(&peer).cloned() {
                        // Not connected, not dialing, but we know the address — start dialing.
                        debug!(%peer, %addr, "on-demand dial: queuing message and dialing peer");
                        self.pending_dials.insert(peer, vec![msg]);
                        let signer = self.signer.clone();
                        let verifier = self.verifier.clone();
                        let dial_tx = self.dial_tx.clone();
                        tokio::spawn(async move {
                            let result = match resolve_and_dial(&addr, &*signer, &*verifier).await {
                                Ok(conn) => DialResult::Success(conn),
                                Err(error) => DialResult::Failure {
                                    peer_prefix: peer,
                                    error,
                                },
                            };
                            let _ = dial_tx.send(result).await;
                        });
                    } else {
                        debug!(%peer, "cannot send message: no connection and no known address");
                    }
                }
                proto::OutEvent::ScheduleTimer(duration, timer) => {
                    let tx = self.timer_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(duration).await;
                        let _ = tx.send(timer).await;
                    });
                }
                proto::OutEvent::DisconnectPeer(peer) => {
                    self.peers.remove(&peer);
                    self.pending_dials.remove(&peer);
                    debug!(%peer, "disconnected peer by protocol request");
                }
                proto::OutEvent::EmitEvent(topic, topic_event) => {
                    let event = match topic_event {
                        proto::topic::Event::NeighborUp(peer) => Event::NeighborUp(peer),
                        proto::topic::Event::NeighborDown(peer) => Event::NeighborDown(peer),
                        proto::topic::Event::Received(gossip_event) => {
                            Event::Received(GossipMessage {
                                topic,
                                content: gossip_event.content,
                                delivered_from: gossip_event.delivered_from,
                            })
                        }
                    };
                    // Ignore send errors — no subscribers is fine.
                    let _ = self.event_tx.send(event);
                }
                proto::OutEvent::PeerData(peer, data) => {
                    // Store the peer's advertised address for future on-demand dialing.
                    if let Ok(addr_str) = std::str::from_utf8(data.as_bytes())
                        && !addr_str.is_empty()
                    {
                        self.peer_addrs.insert(peer, addr_str.to_string());
                        debug!(%peer, addr = %addr_str, "stored peer address from PeerData");
                    }
                }
            }
        }
    }

    /// Set up reader/writer tasks for a newly connected peer.
    fn setup_peer(&mut self, conn: transport::PeerConnection) {
        let peer_prefix = conn.peer_prefix;
        let (read_half, write_half) = conn.stream.split();

        self.connection_generation += 1;
        let generation = self.connection_generation;

        let (msg_tx, mut msg_rx) = mpsc::channel::<proto::Message<NodePrefix>>(64);
        let peer_msg_tx = self.peer_msg_tx.clone();

        // Reader task: reads protocol messages and forwards to the actor.
        let reader = tokio::spawn(async move {
            let mut reader = read_half;
            loop {
                match codec::read_message::<_, proto::Message<NodePrefix>>(&mut reader).await {
                    Ok(msg) => {
                        if peer_msg_tx
                            .send(PeerMessage::Received {
                                peer_prefix,
                                message: msg,
                            })
                            .await
                            .is_err()
                        {
                            break; // Actor shut down.
                        }
                    }
                    Err(_) => {
                        let _ = peer_msg_tx
                            .send(PeerMessage::Disconnected {
                                peer_prefix,
                                generation,
                            })
                            .await;
                        break;
                    }
                }
            }
        });

        // Writer task: receives protocol messages from the actor and sends to the peer.
        let writer = tokio::spawn(async move {
            let mut writer = write_half;
            while let Some(msg) = msg_rx.recv().await {
                if codec::write_message(&mut writer, &msg).await.is_err() {
                    break;
                }
            }
        });

        self.peers.insert(
            peer_prefix,
            ActivePeer {
                msg_tx,
                _reader: reader,
                _writer: writer,
                generation,
            },
        );
    }
}

/// Resolve a `host:port` address string and dial the peer.
async fn resolve_and_dial<S: Signer, V: PeerVerifier>(
    addr: &str,
    signer: &S,
    verifier: &V,
) -> Result<transport::PeerConnection, Error> {
    let socket_addr: SocketAddr = tokio::net::lookup_host(addr).await?.next().ok_or_else(|| {
        Error::Io(std::io::Error::other(
            "DNS resolution returned no addresses",
        ))
    })?;
    transport::dial(socket_addr, signer, verifier).await
}

/// Helper to accept from a listener if one is bound, otherwise pend forever.
async fn accept_if_listening(
    listener: &Option<TcpListener>,
) -> Option<(tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(l) => l.accept().await.ok(),
        None => std::future::pending().await,
    }
}
