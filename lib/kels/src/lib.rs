//! KELS (Key Event Log Storage) client library
//!
//! This library provides types, client, and key management for KELS operations.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod builder;
#[cfg(feature = "redis")]
pub mod cache;
pub mod client;
pub mod crypto;
pub mod error;
pub mod file_store;
#[cfg(feature = "secure-enclave")]
pub mod hardware;
pub mod kel;
pub mod repository;
pub mod repository_store;
pub mod store;
pub mod types;

pub use builder::KeyEventBuilder;
#[cfg(feature = "redis")]
pub use cache::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel};
#[cfg(feature = "redis")]
pub use client::RedisKelCache;
pub use client::{KelCache, KelCacheConfig, KelsClient};
#[cfg(feature = "native")]
pub use crypto::ExternalKeyProvider;
pub use crypto::{KeyProvider, SoftwareKeyProvider};
pub use error::KelsError;
pub use file_store::FileKelStore;
#[cfg(feature = "secure-enclave")]
pub use hardware::HardwareKeyProvider;
pub use kel::Kel;
pub use kel::compute_rotation_hash;
pub use repository::SignedEventRepository;
pub use repository_store::RepositoryKelStore;
pub use store::KelStore;
pub use types::{
    BatchKelPrefixRequest, BatchKelsRequest, BatchSubmitResponse, CachedKel, ContestedPrefix,
    ErrorResponse, EventKind, EventSignature, KelMergeResult, KelResponse, KelsAuditRecord,
    KeyEvent, KeyEventSignature, RecoveryOutcome, SignedKeyEvent,
};
