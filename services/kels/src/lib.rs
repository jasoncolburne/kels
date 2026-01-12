//! KELS - Key Event Log Service
//!
//! Provides storage and retrieval of KERI-inspired Key Event Logs (KELs).
//! Key events (icp, rot, ixn) are stored with their cryptographic signatures
//! and can be retrieved by prefix or individual SAID.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod handlers;
pub mod repository;
pub mod server;

pub use kels::KelsError;
pub use repository::{AuditRecordRepository, KelsRepository, KeyEventRepository};
pub use server::run;
