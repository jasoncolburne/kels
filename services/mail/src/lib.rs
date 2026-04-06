//! KELS Mail - General-purpose ESSR messaging service

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod blob_store;
mod handlers;
pub mod repository;
mod server;

pub use blob_store::BlobStore;
pub use repository::MailRepository;
pub use server::run;
