//! KELS - Key Event Log Service

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

mod handlers;
pub mod repository;
mod server;

pub use repository::{KelsRepository, KeyEventRepository, RecoveryRecordRepository};
pub use server::run;
