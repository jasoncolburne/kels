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
pub mod registry_client;
pub mod repository;
pub mod repository_store;
#[cfg(feature = "server")]
pub mod server;
pub mod store;
pub mod types;

pub use builder::KeyEventBuilder;
#[cfg(feature = "redis")]
pub use cache::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel};
#[cfg(feature = "redis")]
pub use client::RedisKelCache;
pub use client::{KelCache, KelCacheConfig, KelsClient};
#[cfg(feature = "secure-enclave")]
pub use crypto::HardwareProviderConfig;
pub use crypto::{KeyProvider, ProviderConfig, SoftwareKeyProvider, SoftwareProviderConfig};
pub use error::KelsError;
pub use file_store::FileKelStore;
#[cfg(feature = "secure-enclave")]
pub use hardware::HardwareKeyProvider;
pub use kel::Kel;
pub use kel::compute_rotation_hash;
pub use registry_client::{KelsRegistryClient, MultiRegistryClient, RegistrySigner, SignResult};
pub use repository::SignedEventRepository;
pub use repository_store::RepositoryKelStore;
#[cfg(feature = "server")]
pub use server::shutdown_signal;
pub use store::KelStore;
pub use types::{
    BatchKelsRequest, BatchSubmitResponse, CachedKel, DeregisterRequest, ErrorCode, ErrorResponse,
    EventKind, EventSignature, KelMergeResult, KelResponse, KelsAuditRecord, KeyEvent,
    KeyEventSignature, NodeInfo, NodeRegistration, NodeStatus, NodeType, Peer, PeerHistory,
    PeerScope, PeersResponse, PrefixListResponse, PrefixState, RaftLogAuditRecord, RaftLogEntry,
    RaftState, RaftVote, RegisterNodeRequest, SignedKeyEvent, SignedRequest, StatusUpdateRequest,
};
