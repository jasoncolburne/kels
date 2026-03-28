//! KELS SADStore - Replicated Self-Addressed Data Store

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

mod handlers;
pub mod repository;
mod server;

pub use repository::SadStoreRepository;
pub use server::run;
