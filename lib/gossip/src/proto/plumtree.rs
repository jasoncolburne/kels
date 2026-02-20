//! Implementation of the PlumTree epidemic broadcast tree protocol
//!
//! Adapted from [iroh-gossip](https://github.com/n0-computer/iroh-gossip) (MIT/Apache-2.0),
//! which is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luis Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski.
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};

use bytes::Bytes;
use derive_more::{Add, From, Sub};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{
    IO, PeerPrefixEntity,
    util::{TimeBoundCache, idbytes_impls},
};

/// A message identifier, which is the message content's blake3 hash.
#[derive(Serialize, Deserialize, Clone, Hash, Copy, PartialEq, Eq, MaxSize)]
pub struct MessageId([u8; 32]);
idbytes_impls!(MessageId, "MessageId");

impl MessageId {
    /// Create a `[MessageId]` by hashing the message content.
    ///
    /// This hashes the input with [`blake3::hash`].
    pub fn from_content(message: &[u8]) -> Self {
        Self::from(blake3::hash(message))
    }
}

/// Events PlumTree is informed of from the peer sampling service and IO layer.
#[derive(Debug)]
pub enum InEvent<PI> {
    /// A [`Message`] was received from the peer.
    RecvMessage(PI, Message),
    /// Broadcast the contained payload to the given scope.
    Broadcast(Bytes, Scope),
    /// A timer has expired.
    TimerExpired(Timer),
    /// New member `PI` has joined the topic.
    NeighborUp(PI),
    /// Peer `PI` has disconnected from the topic.
    NeighborDown(PI),
}

/// Events PlumTree emits.
#[derive(Debug, PartialEq, Eq)]
pub enum OutEvent<PI> {
    /// Ask the IO layer to send a [`Message`] to peer `PI`.
    SendMessage(PI, Message),
    /// Schedule a [`Timer`].
    ScheduleTimer(Duration, Timer),
    /// Emit an [`Event`] to the application.
    EmitEvent(Event<PI>),
}

/// Kinds of timers PlumTree needs to schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Timer {
    /// Request the content for [`MessageId`] by sending [`Message::Graft`].
    SendGraft(MessageId),
    /// Dispatch the [`Message::IHave`] in our lazy push queue.
    DispatchLazyPush,
    /// Evict the message cache
    EvictCache,
}

/// Event emitted by the [`State`] to the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<PI> {
    /// A new gossip message was received.
    Received(GossipEvent<PI>),
}

#[derive(Clone, derive_more::Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GossipEvent<PI> {
    /// The content of the gossip message.
    #[debug("<{}b>", content.len())]
    pub content: Bytes,
    /// The peer that we received the gossip message from. Note that this is not the peer that
    /// originally broadcasted the message, but the peer before us in the gossiping path.
    pub delivered_from: PI,
    /// The broadcast scope of the message.
    pub scope: DeliveryScope,
}

impl<PI> GossipEvent<PI> {
    fn from_message(message: &Gossip, from: PI) -> Self {
        Self {
            content: message.content.clone(),
            scope: message.scope,
            delivered_from: from,
        }
    }
}

/// Number of delivery hops a message has taken.
#[derive(
    From,
    Add,
    Sub,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Debug,
    Hash,
    MaxSize,
)]
pub struct Round(u16);

impl Round {
    pub fn next(&self) -> Round {
        Round(self.0 + 1)
    }
}

/// Messages that we can send and receive from peers within the topic.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message {
    /// When receiving Gossip, emit as event and forward full message to eager peer and (after a
    /// delay) message IDs to lazy peers.
    Gossip(Gossip),
    /// When receiving Prune, move the peer from the eager to the lazy set.
    Prune,
    /// When receiving Graft, move the peer to the eager set and send the full content for the
    /// included message ID.
    Graft(Graft),
    /// When receiving IHave, do nothing initially, and request the messages for the included
    /// message IDs after some time if they aren't pushed eagerly to us.
    IHave(Vec<IHave>),
}

/// Payload messages transmitted by the protocol.
#[derive(Serialize, Deserialize, Clone, derive_more::Debug, PartialEq, Eq)]
pub struct Gossip {
    /// Id of the message.
    id: MessageId,
    /// Message contents.
    #[debug("<{}b>", content.len())]
    content: Bytes,
    /// Scope to broadcast to.
    scope: DeliveryScope,
}

impl Gossip {
    fn round(&self) -> Option<Round> {
        match self.scope {
            DeliveryScope::Swarm(round) => Some(round),
            DeliveryScope::Neighbors => None,
        }
    }
}

/// The scope to deliver the message to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Copy)]
pub enum DeliveryScope {
    /// This message was received from the swarm, with a distance (in hops) travelled from the
    /// original broadcaster.
    Swarm(Round),
    /// This message was received from a direct neighbor that broadcasted the message to neighbors
    /// only.
    Neighbors,
}

impl DeliveryScope {
    /// Whether this message was directly received from its publisher.
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Neighbors | Self::Swarm(Round(0)))
    }
}

/// The broadcast scope of a gossip message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Copy)]
pub enum Scope {
    /// The message is broadcast to all peers in the swarm.
    Swarm,
    /// The message is broadcast only to the immediate neighbors of a peer.
    Neighbors,
}

impl Gossip {
    /// Get a clone of this `Gossip` message and increase the delivery round by 1.
    pub fn next_round(&self) -> Option<Gossip> {
        match self.scope {
            DeliveryScope::Neighbors => None,
            DeliveryScope::Swarm(round) => Some(Gossip {
                id: self.id,
                content: self.content.clone(),
                scope: DeliveryScope::Swarm(round.next()),
            }),
        }
    }

    /// Validate that the message id is the blake3 hash of the message content.
    pub fn validate(&self) -> bool {
        let expected = MessageId::from_content(&self.content);
        expected == self.id
    }
}

/// Control message to inform peers we have a message without transmitting the whole payload.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, MaxSize)]
pub struct IHave {
    /// Id of the message.
    pub(crate) id: MessageId,
    /// Delivery round of the message.
    pub(crate) round: Round,
}

/// Control message to signal a peer that they have been moved to the eager set, and to ask the
/// peer to do the same with this node.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Graft {
    /// Message id that triggers the graft, if any.
    id: Option<MessageId>,
    /// Delivery round of the [`Message::IHave`] that triggered this Graft message.
    round: Round,
}

/// Configuration for the gossip broadcast layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Timeout before requesting a message payload via Graft after receiving an IHave.
    pub graft_timeout_1: Duration,
    /// Timeout for retrying a Graft request if the first one didn't get a reply.
    pub graft_timeout_2: Duration,
    /// Timeout after which IHave messages are dispatched to lazy peers.
    pub dispatch_timeout: Duration,
    /// The optimization threshold: lazy peers must be this many hops closer to the origin
    /// than our eager peers to trigger a tree optimization (Graft lazy, Prune eager).
    pub optimization_threshold: Round,
    /// Duration for which to keep gossip messages in the internal message cache.
    pub message_cache_retention: Duration,
    /// Duration for which to keep the `MessageId`s for received messages.
    pub message_id_retention: Duration,
    /// How often the internal caches will be checked for expired items.
    pub cache_evict_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            graft_timeout_1: Duration::from_millis(80),
            graft_timeout_2: Duration::from_millis(40),
            dispatch_timeout: Duration::from_millis(5),
            optimization_threshold: Round(7),
            message_cache_retention: Duration::from_secs(30),
            message_id_retention: Duration::from_secs(90),
            cache_evict_interval: Duration::from_secs(1),
        }
    }
}

/// Stats about this topic's plumtree.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Number of payload messages received so far.
    pub payload_messages_received: u64,
    /// Number of control messages received so far.
    pub control_messages_received: u64,
    /// Max round seen so far.
    pub max_last_delivery_hop: u16,
}

/// State of the plumtree.
#[derive(Debug)]
pub struct State<PI> {
    /// Our address.
    me: PI,
    /// Configuration for this plumtree.
    config: Config,

    /// Set of peers used for payload exchange.
    pub(crate) eager_push_peers: BTreeSet<PI>,
    /// Set of peers used for control message exchange.
    pub(crate) lazy_push_peers: BTreeSet<PI>,

    lazy_push_queue: BTreeMap<PI, Vec<IHave>>,

    /// Messages for which a [`MessageId`] has been seen via a [`Message::IHave`] but we have not
    /// yet received the full payload.
    missing_messages: HashMap<MessageId, VecDeque<(PI, Round)>>,
    /// Messages for which the full payload has been seen.
    received_messages: TimeBoundCache<MessageId, ()>,
    /// Payloads of received messages.
    cache: TimeBoundCache<MessageId, Gossip>,

    /// Message ids for which a [`Timer::SendGraft`] has been scheduled.
    graft_timer_scheduled: HashSet<MessageId>,
    /// Whether a [`Timer::DispatchLazyPush`] has been scheduled.
    dispatch_timer_scheduled: bool,

    /// Set to false after the first message is received. Used for initial timer scheduling.
    init: bool,

    /// [`Stats`] of this plumtree.
    pub(crate) stats: Stats,

    max_message_size: usize,
}

impl<PI: PeerPrefixEntity> State<PI> {
    /// Initialize the [`State`] of a plumtree.
    pub fn new(me: PI, config: Config, max_message_size: usize) -> Self {
        Self {
            me,
            eager_push_peers: Default::default(),
            lazy_push_peers: Default::default(),
            lazy_push_queue: Default::default(),
            config,
            missing_messages: Default::default(),
            received_messages: Default::default(),
            graft_timer_scheduled: Default::default(),
            dispatch_timer_scheduled: false,
            cache: Default::default(),
            init: false,
            stats: Default::default(),
            max_message_size,
        }
    }

    /// Handle an [`InEvent`].
    pub fn handle(&mut self, event: InEvent<PI>, now: Instant, io: &mut impl IO<PI>) {
        if !self.init {
            self.init = true;
            self.on_evict_cache_timer(now, io)
        }
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, now, io),
            InEvent::Broadcast(data, scope) => self.broadcast(data, scope, now, io),
            InEvent::NeighborUp(peer) => self.on_neighbor_up(peer),
            InEvent::NeighborDown(peer) => self.on_neighbor_down(peer),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DispatchLazyPush => self.on_dispatch_timer(io),
                Timer::SendGraft(id) => {
                    self.on_send_graft_timer(id, io);
                }
                Timer::EvictCache => self.on_evict_cache_timer(now, io),
            },
        }
    }

    /// Get access to the [`Stats`] of the plumtree.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Handle receiving a [`Message`].
    fn handle_message(&mut self, sender: PI, message: Message, now: Instant, io: &mut impl IO<PI>) {
        if matches!(message, Message::Gossip(_)) {
            self.stats.payload_messages_received += 1;
        } else {
            self.stats.control_messages_received += 1;
        }
        match message {
            Message::Gossip(details) => self.on_gossip(sender, details, now, io),
            Message::Prune => self.on_prune(sender),
            Message::IHave(details) => self.on_ihave(sender, details, io),
            Message::Graft(details) => self.on_graft(sender, details, io),
        }
    }

    /// Dispatches messages from lazy queue over to lazy peers.
    fn on_dispatch_timer(&mut self, io: &mut impl IO<PI>) {
        let chunk_size = self.max_message_size
            // Space for discriminator
            - 1
            // Space for length prefix
            - 2;
        let chunk_len = chunk_size / IHave::POSTCARD_MAX_SIZE;
        while let Some((peer, list)) = self.lazy_push_queue.pop_first() {
            for chunk in list.chunks(chunk_len) {
                io.push(OutEvent::SendMessage(peer, Message::IHave(chunk.to_vec())));
            }
        }

        self.dispatch_timer_scheduled = false;
    }

    /// Send a gossip message.
    fn broadcast(&mut self, content: Bytes, scope: Scope, now: Instant, io: &mut impl IO<PI>) {
        let id = MessageId::from_content(&content);
        let scope = match scope {
            Scope::Neighbors => DeliveryScope::Neighbors,
            Scope::Swarm => DeliveryScope::Swarm(Round(0)),
        };
        let message = Gossip { id, content, scope };
        let me = self.me;
        if let DeliveryScope::Swarm(_) = scope {
            self.received_messages
                .insert(id, (), now + self.config.message_id_retention);
            self.cache.insert(
                id,
                message.clone(),
                now + self.config.message_cache_retention,
            );
            self.lazy_push(message.clone(), &me, io);
        }

        self.eager_push(message.clone(), &me, io);
    }

    /// Handle receiving a [`Message::Gossip`].
    fn on_gossip(&mut self, sender: PI, message: Gossip, now: Instant, io: &mut impl IO<PI>) {
        // Validate that the message id is the blake3 hash of the message content.
        if !message.validate() {
            warn!(
                peer = ?sender,
                "Received a message with spoofed message id ({})", message.id
            );
            return;
        }

        // if we already received this message: move peer to lazy set
        // and notify peer about this.
        if self.received_messages.contains_key(&message.id) {
            self.add_lazy(sender);
            io.push(OutEvent::SendMessage(sender, Message::Prune));
        // otherwise store the message, emit to application and forward to peers
        } else {
            if let DeliveryScope::Swarm(prev_round) = message.scope {
                // insert the message in the list of received messages
                self.received_messages.insert(
                    message.id,
                    (),
                    now + self.config.message_id_retention,
                );
                // increase the round for forwarding the message, and add to cache
                let Some(message) = message.next_round() else {
                    return;
                };

                self.cache.insert(
                    message.id,
                    message.clone(),
                    now + self.config.message_cache_retention,
                );
                // push the message to our peers
                self.eager_push(message.clone(), &sender, io);
                self.lazy_push(message.clone(), &sender, io);
                // cleanup places where we track missing messages
                self.graft_timer_scheduled.remove(&message.id);
                let previous_ihaves = self.missing_messages.remove(&message.id);
                // do the optimization step from the paper
                if let Some(previous_ihaves) = previous_ihaves {
                    self.optimize_tree(&sender, &message, previous_ihaves, io);
                }
                self.stats.max_last_delivery_hop =
                    self.stats.max_last_delivery_hop.max(prev_round.0);
            }

            // emit event to application
            io.push(OutEvent::EmitEvent(Event::Received(
                GossipEvent::from_message(&message, sender),
            )));
        }
    }

    /// Optimize the tree by pruning the `sender` of a [`Message::Gossip`] if we previously
    /// received a [`Message::IHave`] for the same message with a much lower number of delivery
    /// hops from the original broadcaster of the message.
    fn optimize_tree(
        &mut self,
        gossip_sender: &PI,
        message: &Gossip,
        previous_ihaves: VecDeque<(PI, Round)>,
        io: &mut impl IO<PI>,
    ) {
        let Some(round) = message.round() else {
            return;
        };
        let best_ihave = previous_ihaves
            .iter()
            .min_by(|(_a_peer, a_round), (_b_peer, b_round)| a_round.cmp(b_round))
            .copied();

        if let Some((ihave_peer, ihave_round)) = best_ihave
            && (ihave_round < round)
            && (round - ihave_round) >= self.config.optimization_threshold
        {
            // Graft the sender of the IHave, but only if it's not already eager.
            if !self.eager_push_peers.contains(&ihave_peer) {
                let message = Message::Graft(Graft {
                    id: None,
                    round: ihave_round,
                });
                self.add_eager(ihave_peer);
                io.push(OutEvent::SendMessage(ihave_peer, message));
            }
            // Prune the sender of the Gossip.
            self.add_lazy(*gossip_sender);
            io.push(OutEvent::SendMessage(*gossip_sender, Message::Prune));
        }
    }

    /// Handle receiving a [`Message::Prune`].
    fn on_prune(&mut self, sender: PI) {
        self.add_lazy(sender);
    }

    /// Handle receiving a [`Message::IHave`].
    fn on_ihave(&mut self, sender: PI, ihaves: Vec<IHave>, io: &mut impl IO<PI>) {
        for ihave in ihaves {
            if !self.received_messages.contains_key(&ihave.id) {
                self.missing_messages
                    .entry(ihave.id)
                    .or_default()
                    .push_back((sender, ihave.round));

                if !self.graft_timer_scheduled.contains(&ihave.id) {
                    self.graft_timer_scheduled.insert(ihave.id);
                    io.push(OutEvent::ScheduleTimer(
                        self.config.graft_timeout_1,
                        Timer::SendGraft(ihave.id),
                    ));
                }
            }
        }
    }

    /// A scheduled [`Timer::SendGraft`] has reached its deadline.
    fn on_send_graft_timer(&mut self, id: MessageId, io: &mut impl IO<PI>) {
        self.graft_timer_scheduled.remove(&id);
        if self.received_messages.contains_key(&id) {
            return;
        }
        let entry = self
            .missing_messages
            .get_mut(&id)
            .and_then(|entries| entries.pop_front());
        if let Some((peer, round)) = entry {
            self.add_eager(peer);
            let message = Message::Graft(Graft {
                id: Some(id),
                round,
            });
            io.push(OutEvent::SendMessage(peer, message));
            io.push(OutEvent::ScheduleTimer(
                self.config.graft_timeout_2,
                Timer::SendGraft(id),
            ));
        }
    }

    /// Handle receiving a [`Message::Graft`].
    fn on_graft(&mut self, sender: PI, details: Graft, io: &mut impl IO<PI>) {
        self.add_eager(sender);
        if let Some(id) = details.id {
            if let Some(message) = self.cache.get(&id) {
                io.push(OutEvent::SendMessage(
                    sender,
                    Message::Gossip(message.clone()),
                ));
            } else {
                debug!(?id, peer=?sender, "on_graft failed to graft: message not in cache");
            }
        }
    }

    /// Handle a [`InEvent::NeighborUp`] when a peer joins the topic.
    fn on_neighbor_up(&mut self, peer: PI) {
        self.add_eager(peer);
    }

    /// Handle a [`InEvent::NeighborDown`] when a peer leaves the topic.
    fn on_neighbor_down(&mut self, peer: PI) {
        self.missing_messages.retain(|_message_id, ihaves| {
            ihaves.retain(|(ihave_peer, _round)| *ihave_peer != peer);
            !ihaves.is_empty()
        });
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.remove(&peer);
    }

    fn on_evict_cache_timer(&mut self, now: Instant, io: &mut impl IO<PI>) {
        self.cache.expire_until(now);
        self.received_messages.expire_until(now);
        io.push(OutEvent::ScheduleTimer(
            self.config.cache_evict_interval,
            Timer::EvictCache,
        ));
    }

    /// Moves peer into eager set.
    fn add_eager(&mut self, peer: PI) {
        self.lazy_push_peers.remove(&peer);
        self.eager_push_peers.insert(peer);
    }

    /// Moves peer into lazy set.
    fn add_lazy(&mut self, peer: PI) {
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.insert(peer);
    }

    /// Immediately sends message to eager peers.
    fn eager_push(&mut self, gossip: Gossip, sender: &PI, io: &mut impl IO<PI>) {
        for peer in self
            .eager_push_peers
            .iter()
            .filter(|peer| **peer != self.me && *peer != sender)
        {
            io.push(OutEvent::SendMessage(
                *peer,
                Message::Gossip(gossip.clone()),
            ));
        }
    }

    /// Queue lazy message announcements into the queue that will be sent out as batched
    /// [`Message::IHave`] messages once the [`Timer::DispatchLazyPush`] timer is triggered.
    fn lazy_push(&mut self, gossip: Gossip, sender: &PI, io: &mut impl IO<PI>) {
        let Some(round) = gossip.round() else {
            return;
        };
        for peer in self.lazy_push_peers.iter().filter(|x| *x != sender) {
            self.lazy_push_queue.entry(*peer).or_default().push(IHave {
                id: gossip.id,
                round,
            });
        }
        if !self.dispatch_timer_scheduled {
            io.push(OutEvent::ScheduleTimer(
                self.config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            self.dispatch_timer_scheduled = true;
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use super::*;
    #[test]
    fn optimize_tree() {
        let mut io = VecDeque::new();
        let config: Config = Default::default();
        let mut state = State::new(1, config.clone(), 1024);
        let now = Instant::now();

        // we receive an IHave message from peer 2
        let content: Bytes = b"hi".to_vec().into();
        let id = MessageId::from_content(&content);
        let event = InEvent::RecvMessage(
            2u32,
            Message::IHave(vec![IHave {
                id,
                round: Round(2),
            }]),
        );
        state.handle(event, now, &mut io);
        io.clear();
        // we then receive a `Gossip` message with the same `MessageId` from peer 3
        // the message has `round: 6`, which is less hops than peer 2 but not enough
        // to trigger optimization (default threshold: 7)
        let event = InEvent::RecvMessage(
            3,
            Message::Gossip(Gossip {
                id,
                content: content.clone(),
                scope: DeliveryScope::Swarm(Round(6)),
            }),
        );
        state.handle(event, now, &mut io);
        let expected = {
            let mut io = VecDeque::new();
            io.push(OutEvent::ScheduleTimer(
                config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            io.push(OutEvent::EmitEvent(Event::Received(GossipEvent {
                content,
                delivered_from: 3,
                scope: DeliveryScope::Swarm(Round(6)),
            })));
            io
        };
        assert_eq!(io, expected);
        io.clear();

        // now peer 3 is 9 hops away — this triggers the optimization:
        // peer 2 promoted to eager, peer 3 demoted to lazy
        let content: Bytes = b"hi2".to_vec().into();
        let id = MessageId::from_content(&content);
        let event = InEvent::RecvMessage(
            2u32,
            Message::IHave(vec![IHave {
                id,
                round: Round(2),
            }]),
        );
        state.handle(event, now, &mut io);
        io.clear();

        let event = InEvent::RecvMessage(
            3,
            Message::Gossip(Gossip {
                id,
                content: content.clone(),
                scope: DeliveryScope::Swarm(Round(9)),
            }),
        );
        state.handle(event, now, &mut io);
        let expected = {
            let mut io = VecDeque::new();
            io.push(OutEvent::SendMessage(
                2,
                Message::Graft(Graft {
                    id: None,
                    round: Round(2),
                }),
            ));
            io.push(OutEvent::SendMessage(3, Message::Prune));
            io.push(OutEvent::EmitEvent(Event::Received(GossipEvent {
                content,
                delivered_from: 3,
                scope: DeliveryScope::Swarm(Round(9)),
            })));
            io
        };
        assert_eq!(io, expected);
    }

    #[test]
    fn spoofed_messages_are_ignored() {
        let config: Config = Default::default();
        let mut state = State::new(1, config.clone(), 1024);
        let now = Instant::now();

        // correct message
        let content: Bytes = b"hello1".to_vec().into();
        let message = Message::Gossip(Gossip {
            content: content.clone(),
            id: MessageId::from_content(&content),
            scope: DeliveryScope::Swarm(Round(1)),
        });
        let mut io = VecDeque::new();
        state.handle(InEvent::RecvMessage(2, message), now, &mut io);
        let expected = {
            let mut io = VecDeque::new();
            io.push(OutEvent::ScheduleTimer(
                config.cache_evict_interval,
                Timer::EvictCache,
            ));
            io.push(OutEvent::ScheduleTimer(
                config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            io.push(OutEvent::EmitEvent(Event::Received(GossipEvent {
                content,
                delivered_from: 2,
                scope: DeliveryScope::Swarm(Round(1)),
            })));
            io
        };
        assert_eq!(io, expected);

        // spoofed id — should be ignored
        let content: Bytes = b"hello2".to_vec().into();
        let message = Message::Gossip(Gossip {
            content,
            id: MessageId::from_content(b"foo"),
            scope: DeliveryScope::Swarm(Round(1)),
        });
        let mut io = VecDeque::new();
        state.handle(InEvent::RecvMessage(2, message), now, &mut io);
        let expected = VecDeque::new();
        assert_eq!(io, expected);
    }

    #[test]
    fn cache_is_evicted() {
        let config: Config = Default::default();
        let mut state = State::new(1, config.clone(), 1024);
        let now = Instant::now();
        let content: Bytes = b"hello1".to_vec().into();
        let message = Message::Gossip(Gossip {
            content: content.clone(),
            id: MessageId::from_content(&content),
            scope: DeliveryScope::Swarm(Round(1)),
        });
        let mut io = VecDeque::new();
        state.handle(InEvent::RecvMessage(2, message), now, &mut io);
        assert_eq!(state.cache.len(), 1);

        let now = now + Duration::from_secs(1);
        state.handle(InEvent::TimerExpired(Timer::EvictCache), now, &mut io);
        assert_eq!(state.cache.len(), 1);

        let now = now + config.message_cache_retention;
        state.handle(InEvent::TimerExpired(Timer::EvictCache), now, &mut io);
        assert_eq!(state.cache.len(), 0);
    }
}
