//! KELS Registry - Node Registration and Discovery Service
//!
//! Provides registration and discovery for KELS gossip nodes.
//! When new nodes come online, they query the registry to find peers,
//! bootstrap sync missing KELs, then register as ready for queries.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod handlers;
pub mod identity_client;
pub mod peer_handlers;
pub mod peer_store;
pub mod registry_kel_handlers;
pub mod repository;
pub mod server;
pub mod signature;
pub mod store;

pub use kels::{Peer, PeerHistory};
pub use peer_store::PeerRepository;
pub use server::run;
pub use store::{NodeRegistration, NodeStatus, RegistryStore};
