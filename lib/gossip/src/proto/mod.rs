//! IO-free gossip protocol state machine
//!
//! This module implements the gossip protocol as an IO-free state machine, adapted from
//! [iroh-gossip](https://github.com/n0-computer/iroh-gossip) by the n0 team. The original
//! implementation is licensed under MIT/Apache-2.0.
//!
//! The protocol is made up from two parts:
//!
//! - A **membership protocol** based on [HyParView](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf),
//!   which maintains partial views of peers in the network. Each peer keeps a small active view
//!   (default 5 peers) and a larger passive view (default 30 peers) for resilience.
//!
//! - A **gossip broadcast protocol** based on [PlumTree](https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf),
//!   which builds an epidemic broadcast tree on top of the membership layer. It maintains eager
//!   and lazy peer sets, self-optimizing the tree by latency.
//!
//! All protocol messages are namespaced by a [`TopicId`], a 32-byte identifier. Topics are
//! separate swarms and broadcast scopes. The entry point is [`State`], which contains the
//! protocol state for a node.

use std::{fmt, hash::Hash};

use bytes::Bytes;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(crate) mod hyparview;
pub(crate) mod plumtree;
pub mod state;
pub mod topic;
pub mod util;

pub use hyparview::Config as HyparviewConfig;
pub use plumtree::{Config as PlumtreeConfig, DeliveryScope, Scope};
pub use state::{InEvent, Message, OutEvent, State, Timer, TopicId};
pub use topic::{Command, Config, Event, IO};

/// The default maximum size in bytes for a gossip message.
/// This is a sane but arbitrary default and can be changed in the [`Config`].
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4096;

/// The minimum allowed value for [`Config::max_message_size`].
pub const MIN_MAX_MESSAGE_SIZE: usize = 512;

/// The identifier for a peer.
///
/// The protocol implementation is generic over this trait. When implementing the protocol,
/// a concrete type must be chosen (e.g., [`crate::identity::NodePrefix`]) that will be used
/// throughout to identify and index individual peers.
///
/// Note that the concrete type will be used in protocol messages. Therefore, implementations of
/// the protocol are only compatible if the same concrete type is supplied for this trait.
pub trait PeerPrefixEntity:
    Hash + Eq + Ord + Copy + fmt::Debug + Serialize + DeserializeOwned
{
}
impl<T> PeerPrefixEntity for T where
    T: Hash + Eq + Ord + Copy + fmt::Debug + Serialize + DeserializeOwned
{
}

/// Opaque binary data that is transmitted on messages that introduce new peers.
///
/// Implementations may use these bytes to supply addresses or other information needed to connect
/// to a peer that is not included in the peer's [`PeerPrefixentity`].
#[derive(derive_more::Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[debug("PeerData({}b)", self.0.len())]
pub struct PeerData(Bytes);

impl PeerData {
    /// Create a new [`PeerData`] from a byte buffer.
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self(data.into())
    }

    /// Get a reference to the contained [`bytes::Bytes`].
    pub fn inner(&self) -> &bytes::Bytes {
        &self.0
    }

    /// Get the peer data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// PeerInfo contains a peer's identifier and the opaque peer data as provided by the implementer.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct PeerInfo<PI> {
    pub id: PI,
    pub data: Option<PeerData>,
}

impl<PI> From<(PI, Option<PeerData>)> for PeerInfo<PI> {
    fn from((id, data): (PI, Option<PeerData>)) -> Self {
        Self { id, data }
    }
}
