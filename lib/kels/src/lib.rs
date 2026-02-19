//! KELS (Key Event Log Storage) client library
//!
//! This library provides types, client, and key management for KELS operations.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

/// Try an async operation and check the result. If the check fails, evaluate and
/// await the retry expression (which may use different parameters) and check again.
///
/// Returns `Ok(Some(value))` if the check passes, `Ok(None)` if it fails after retry,
/// or `Err(e)` if either operation errors.
#[macro_export]
macro_rules! retry_once {
    ($initial:expr, $check:expr, $retry:expr $(,)?) => {{
        let result = $initial.await;
        match result {
            Ok(val) if $check(&val) => Ok(Some(val)),
            Ok(_) => match $retry.await {
                Ok(val) if $check(&val) => Ok(Some(val)),
                Ok(_) => Ok(None),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }};
}

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
    IdentityClient, KelCache, KelCacheConfig, KelsClient, KelsRegistryClient, MultiRegistryClient,
    RegistrySigner, SignResult, sign_request, trusted_prefixes,
};
pub use crypto::{KeyProvider, ProviderConfig, SoftwareKeyProvider, SoftwareProviderConfig};
pub use error::KelsError;
pub use repository::SignedEventRepository;
pub use store::{FileKelStore, KelStore, RepositoryKelStore};
pub use types::{
    AdditionHistory, AdditionWithVotes, BatchKelsRequest, BatchSubmitResponse, CachedKel,
    CompletedProposalsResponse, DeregisterRequest, ErrorCode, ErrorResponse, EventKind,
    EventSignature, KelMergeResult, KelResponse, KelsAuditRecord, KeyEvent, KeyEventSignature,
    NodeInfo, NodeRegistration, NodeStatus, NodeType, Peer, PeerAdditionProposal, PeerHistory,
    PeerRemovalProposal, PeersResponse, PrefixListResponse, PrefixState, PrefixesRequest, Proposal,
    ProposalHistory, ProposalStatus, ProposalWithVotes, ProposalWithVotesMethods,
    REJECTION_THRESHOLD, RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote,
    RegisterNodeRequest, RemovalHistory, RemovalWithVotes, SignedKeyEvent, SignedRequest,
    StatusUpdateRequest, Vote, compute_effective_tail_said, generate_nonce, hash_tip_saids,
    validate_timestamp,
};
pub use types::{Kel, compute_rotation_hash};

/// Maximum number of events allowed in a single submit_events request.
/// Shared between the server handler and gossip client chunking logic.
pub const MAX_EVENTS_PER_SUBMISSION: usize = 500;
