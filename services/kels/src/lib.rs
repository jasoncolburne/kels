//! KELS - Key Event Log Service

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
