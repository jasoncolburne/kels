//! KELS SADStore - Replicated Self-Addressed Data Store

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod compaction;
pub(crate) mod expansion;
mod handlers;
pub mod object_store;
pub mod repository;
mod server;

pub use object_store::ObjectStore;
pub use repository::SadStoreRepository;
pub use server::run;
