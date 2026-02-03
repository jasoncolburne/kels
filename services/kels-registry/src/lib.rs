//! KELS Registry - Node Registration and Discovery Service
//!
//! Provides registration and discovery for KELS gossip nodes.
//! When new nodes come online, they query the registry to find peers,
//! bootstrap sync missing KELs, then register as ready for queries.
//!
//! # Federation Support
//!
//! The registry supports federation across multiple independent registries.
//! - **Core peers**: Replicated across all registries via Raft consensus
//! - **Regional peers**: Local to each registry
//! - **Automatic failover**: Leader election handles node failures

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod federation;
pub mod handlers;
pub mod identity_client;
pub mod peer_store;
pub mod raft_store;
pub mod repository;
pub mod server;
pub mod signature;
pub mod store;

pub use federation::{
    FederationConfig, FederationError, FederationMember, FederationNetwork, FederationNode,
    FederationStatus,
};
pub use kels::{Peer, PeerHistory, PeerScope};
pub use peer_store::PeerRepository;
pub use server::run;
pub use store::{NodeRegistration, NodeStatus, RegistryStore};
