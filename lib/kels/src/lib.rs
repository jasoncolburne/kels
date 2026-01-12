//! KELS (Key Event Log Storage) client library
//!
//! This library provides types, client, and key management for KELS operations.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

#[cfg(feature = "redis")]
pub mod cache;
pub mod client;
pub mod crypto;
pub mod error;
#[cfg(feature = "secure-enclave")]
pub mod hardware;
pub mod kel;
pub mod types;

#[cfg(feature = "redis")]
pub use cache::{LocalCache, SerializedKel, ServerKelCache, parse_pubsub_message, pubsub_channel};
#[cfg(feature = "redis")]
pub use client::RedisKelCache;
pub use client::{KelCache, KelCacheConfig, KelsClient};
#[cfg(feature = "native")]
pub use crypto::ExternalKeyProvider;
pub use crypto::{KeyProvider, SoftwareKeyProvider};
pub use error::KelsError;
#[cfg(feature = "secure-enclave")]
pub use hardware::HardwareKeyProvider;
pub use kel::compute_rotation_hash;
pub use kel::{
    FileKelStore, Kel, KelStore, KeyEventBuilder, RepositoryKelStore, SignedEventRepository,
};
pub use types::{
    BatchKelPrefixRequest, BatchKelsRequest, BatchSubmitResponse, CachedKel, ContestedPrefix,
    ErrorResponse, EventKind, EventSignature, KelMergeResult, KelsAuditEvent, KelsAuditKind,
    KelsAuditRecord, KeyEvent, KeyEventSignature, RecoveryOutcome, SignedKeyEvent,
};
