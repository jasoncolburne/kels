//! KELS (Key Event Log Storage) client library
//!
//! This library provides types, client, and key management for KELS operations.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

#[cfg(feature = "redis")]
pub mod cache;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "secure-enclave")]
pub mod hardware;

pub mod builder;
pub mod client;
pub mod crypto;
pub mod error;
pub mod repository;
pub mod store;
pub mod types;

#[cfg(feature = "redis")]
pub use cache::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel};
#[cfg(feature = "redis")]
pub use client::RedisKelCache;

#[cfg(feature = "server")]
pub use server::shutdown_signal;

#[cfg(feature = "secure-enclave")]
pub use crypto::HardwareProviderConfig;
#[cfg(feature = "secure-enclave")]
pub use hardware::HardwareKeyProvider;

pub use builder::KeyEventBuilder;
pub use client::{
    KelCache, KelCacheConfig, KelsClient, KelsRegistryClient, MultiRegistryClient, RegistrySigner,
    SignResult,
};
pub use crypto::{KeyProvider, ProviderConfig, SoftwareKeyProvider, SoftwareProviderConfig};
pub use error::KelsError;
pub use repository::SignedEventRepository;
pub use store::{FileKelStore, KelStore, RepositoryKelStore};
pub use types::{
    BatchKelsRequest, BatchSubmitResponse, CachedKel, DeregisterRequest, ErrorCode, ErrorResponse,
    EventKind, EventSignature, KelMergeResult, KelResponse, KelsAuditRecord, KeyEvent,
    KeyEventSignature, NodeInfo, NodeRegistration, NodeStatus, NodeType, Peer, PeerHistory,
    PeerScope, PeersResponse, PrefixListResponse, PrefixState, RaftLogAuditRecord, RaftLogEntry,
    RaftState, RaftVote, RegisterNodeRequest, SignedKeyEvent, SignedRequest, StatusUpdateRequest,
};
pub use types::{Kel, compute_rotation_hash};
