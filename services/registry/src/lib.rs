//! KELS Registry - Node Registration and Discovery Service
//!
//! Provides registration and discovery for KELS gossip nodes.
//! When new nodes come online, they query the registry to find peers,
//! bootstrap sync missing KELs, then register as ready for queries.
//!
//! # Federation Support
//!
//! The registry supports federation across multiple independent registries.
//! - **Peers**: Replicated across all registries via Raft consensus
//! - **Automatic failover**: Leader election handles node failures

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod federation;
pub mod handlers;
pub mod raft_store;
pub mod repository;
pub mod server;

pub use federation::{
    FederationConfig, FederationError, FederationMember, FederationNetwork, FederationNode,
    FederationStatus,
};
pub use server::run;
