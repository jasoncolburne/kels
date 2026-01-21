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
pub mod server;
pub mod store;

pub use server::run;
pub use store::{NodeRegistration, NodeStatus, RegistryStore};
