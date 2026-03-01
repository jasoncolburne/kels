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
pub mod serving;
pub mod store;
pub mod types;

use std::env;

#[cfg(feature = "redis")]
pub use cache::{
    LocalCache, MAX_CACHED_KEL_EVENTS, ServerKelCache, parse_pubsub_message, pubsub_channel,
};
#[cfg(feature = "server")]
pub use server::shutdown_signal;

#[cfg(feature = "secure-enclave")]
pub use crypto::HardwareProviderConfig;
#[cfg(feature = "secure-enclave")]
pub use hardware::HardwareKeyProvider;

pub use builder::KeyEventBuilder;
pub use client::{
    IdentityClient, KelsClient, KelsRegistryClient, MultiRegistryClient, RegistrySigner,
    SignResult, sign_request, trusted_prefixes,
};
pub use crypto::{KeyProvider, ProviderConfig, SoftwareKeyProvider, SoftwareProviderConfig};
pub use error::KelsError;
pub use repository::SignedEventRepository;
pub use serving::{KelServer, KeyEventsQuery, serve_kel_page};
pub use store::{FileKelStore, KelStore, RepositoryKelStore};
pub use types::{
    AdditionHistory, AdditionWithVotes, AdminRequest, BatchKelsRequest, BatchSubmitResponse,
    CachedKel, CompletedProposalsResponse, DeregisterRequest, ErrorCode, ErrorResponse, EventKind,
    EventSignature, KelMergeResult, KelsAuditRecord, KeyEvent, KeyEventSignature, NodeInfo,
    NodeRegistration, NodeStatus, NodeType, Peer, PeerAdditionProposal, PeerHistory,
    PeerRemovalProposal, PeersResponse, PrefixListResponse, PrefixState, PrefixesRequest, Proposal,
    ProposalHistory, ProposalStatus, ProposalWithVotes, ProposalWithVotesMethods,
    REJECTION_THRESHOLD, RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote,
    RegisterNodeRequest, RemovalHistory, RemovalWithVotes, SignedKeyEvent, SignedKeyEventPage,
    SignedRequest, StatusUpdateRequest, Vote, generate_nonce, hash_tip_saids, validate_timestamp,
};
pub use types::{
    BranchTip, HttpKelSink, HttpKelSource, KelVerifier, PageLoader, PagedKelSink, PagedKelSource,
    StoreKelSource, StorePageLoader, Verification, benchmark_key_events, collect_key_events,
    completed_verification, compute_rotation_hash, forward_key_events, partition_for_submission,
    resolve_key_events, truncate_incomplete_generation, verify_key_events,
};

/// Maximum number of events allowed in a single submit_events request.
/// Shared between the server handler and gossip client chunking logic.
pub const MAX_EVENTS_PER_SUBMISSION: usize = 512;

/// Maximum number of prefixes allowed in a single batch fetch request.
/// Shared between the server handler and client chunking logic.
pub const MAX_BATCH_PREFIXES: usize = 64;

/// Maximum number of events fetched in a single KEL database query or HTTP page.
pub const MAX_EVENTS_PER_KEL_QUERY: usize = 512;

/// Default maximum number of pages to walk during `completed_verification()`.
/// Override with `KELS_MAX_VERIFICATION_PAGES` environment variable.
/// At 512 events per page, 512 pages = ~262K events before failing secure.
pub const DEFAULT_MAX_VERIFICATION_PAGES: usize = 512;

/// Read the max verification pages from env, falling back to the default.
pub fn max_verification_pages() -> usize {
    env::var("KELS_MAX_VERIFICATION_PAGES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_VERIFICATION_PAGES)
}

/// Maximum number of events returned in a single KEL response page.
/// KELs larger than this are not cached server-side.
pub const MAX_EVENTS_PER_KEL_RESPONSE: usize = MAX_EVENTS_PER_KEL_QUERY;
