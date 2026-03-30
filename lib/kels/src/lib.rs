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
pub mod merge;
pub mod repository;
pub mod serving;
pub mod store;
pub mod types;

use std::{env, sync::LazyLock};

#[cfg(feature = "redis")]
pub use cache::{LocalCache, ServerKelCache, parse_pubsub_message, pubsub_channel};
#[cfg(feature = "server")]
pub use server::shutdown_signal;

#[cfg(feature = "secure-enclave")]
pub use crypto::HardwareProviderConfig;
#[cfg(feature = "secure-enclave")]
pub use hardware::{
    HardwareKeyProvider, SecureEnclaveKeyHandle, se_delete_all_keys, se_is_available,
};

pub use builder::{KeyEventBuilder, should_rotate_with_recovery};
pub use cesr::VerificationKeyCode;
pub use client::{
    IdentityClient, IdentityInfo, IdentityStatus, KelsClient, KelsRegistryClient,
    ManageKelOperation, ManageKelRequest, ManageKelResponse, PeerSigner, RotateMode,
    SadStoreClient, SignResponse, SignResult, nodes_sorted_by_latency, sign_request,
    sync_member_kel, trusted_prefixes, verify_peer_anchoring, verify_peer_votes, with_failover,
};
pub use crypto::{
    FileKeyStateStore, KeyProvider, KeyStateStore, ProviderConfig, SoftwareKeyProvider,
    SoftwareProviderConfig,
};
pub use error::KelsError;
pub use merge::{MergeOutcome, MergeTransaction};
pub use repository::{SignedEventRepository, load_signed_history, load_signed_history_tail};
pub use serving::{KelServer, KeyEventsQuery, serve_kel_page};
pub use store::{FileKelStore, KelStore, KelStoreSink, RepositoryKelStore};
pub use types::{
    AdditionHistory, AdditionWithVotes, AdminRequest, BranchTip, CachedKel,
    CompletedProposalsResponse, EffectiveSaidResponse, ErrorCode, ErrorResponse, EventKind,
    EventSignature, FederationStatus, HttpKelSink, HttpKelSource, HttpSadSink, HttpSadSource,
    KelMergeResult, KelRecoveryEvent, KelVerification, KelVerifier, KeyEvent, KeyEventSignature,
    NodeInfo, NodeStatus, NodeType, PageLoader, PagedKelSink, PagedKelSource, PagedSadSink,
    PagedSadSource, Peer, PeerAdditionProposal, PeerHistory, PeerRemovalProposal, PeersResponse,
    PrefixListResponse, PrefixState, PrefixesRequest, Proposal, ProposalHistory, ProposalResponse,
    ProposalStatus, ProposalWithVotes, ProposalWithVotesMethods, REJECTION_THRESHOLD,
    RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote, RecoveryRecord, RecoveryRecordPage,
    RemovalHistory, RemovalWithVotes, SadChainRepair, SadChainRepairPage, SadChainRepairRecord,
    SadGossipMessage, SadObjectEntry, SadObjectListResponse, SadObjectsRequest, SadRecord,
    SadRecordPage, SadRecordSignature, SadRecordSubmission, SadRecordVerification, SignedKeyEvent,
    SignedKeyEventPage, SignedRequest, SignedSadRecord, StoreKelSource, StorePageLoader,
    SubmitEventsResponse, Vote, benchmark_key_events, completed_verification,
    compute_approval_threshold, compute_rotation_hash, compute_sad_prefix, forward_key_events,
    forward_sad_records, generate_nonce, hash_effective_said, truncate_incomplete_generation,
    validate_timestamp, verify_key_events, verify_key_events_with,
    verify_key_events_collecting_establishment_keys, verify_sad_records,
};

#[cfg(any(test, feature = "dev-tools"))]
pub use types::resolve_key_events;

/// Minimum page size. Defines the security bound for proactive recovery rotation:
/// between any two recovery-revealing events, at most `MINIMUM_PAGE_SIZE - 2`
/// non-revealing events are allowed. An adversary can only fork after the last
/// recovery-revealing event (forking before triggers ContestRequired), so the
/// worst-case recovery batch is `[62 events, rec, rot] = 64` and the worst-case
/// contest batch is `[62 events, cnt] = 63`. Both fit in one page submission.
///
/// At 64 events, a full page of ML-DSA-65 events stays under 256KB and
/// ML-DSA-87 events under 512KB.
pub const MINIMUM_PAGE_SIZE: usize = 64;

/// Maximum non-revealing events between recovery-revealing events.
/// `MINIMUM_PAGE_SIZE - 2` leaves room for rec+rot in the recovery batch.
pub const MAX_NON_REVEALING_EVENTS: usize = MINIMUM_PAGE_SIZE - 2;

/// Default page size for all KEL operations: submissions, queries, and responses.
/// Clamped to at least `MINIMUM_PAGE_SIZE` at parse time. Operators may increase
/// this for deployments that need larger batches, but the security bound is always
/// defined by `MINIMUM_PAGE_SIZE`.
/// Override with `KELS_PAGE_SIZE` environment variable.
pub const DEFAULT_PAGE_SIZE: usize = MINIMUM_PAGE_SIZE;

pub fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(s) => match s.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "{} is set but not a valid usize: {:?}, using default {}",
                    name, s, default
                );
                default
            }
        },
        Err(_) => default,
    }
}

static PAGE_SIZE: LazyLock<usize> =
    LazyLock::new(|| env_usize("KELS_PAGE_SIZE", DEFAULT_PAGE_SIZE).max(MINIMUM_PAGE_SIZE));

/// Read the page size, cached from env on first access.
pub fn page_size() -> usize {
    *PAGE_SIZE
}

/// Default maximum number of pages to walk during `completed_verification()`.
/// Override with `KELS_MAX_VERIFICATION_PAGES` environment variable.
/// At 64 events per page, 64 pages = 4096 max events before failing secure.
pub const DEFAULT_MAX_VERIFICATION_PAGES: usize = 64;

static MAX_VERIFICATION_PAGES: LazyLock<usize> = LazyLock::new(|| {
    env_usize(
        "KELS_MAX_VERIFICATION_PAGES",
        DEFAULT_MAX_VERIFICATION_PAGES,
    )
});

/// Read the max verification pages, cached from env on first access.
pub fn max_pages() -> usize {
    *MAX_VERIFICATION_PAGES
}

/// Sentinel limit for loading an entire KEL without pagination.
/// Only appropriate for client-side local stores (CLI, FFI) and tests —
/// never use on server-side code paths.
pub const LOAD_ALL: u64 = i64::MAX as u64;
