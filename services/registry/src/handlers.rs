//! KELS Registry REST API Handlers

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cesr::Matter;
use dashmap::DashMap;
use kels_core::{
    AdditionHistory, CompletedProposalsResponse, EffectiveSaidResponse, ErrorCode, ErrorResponse,
    IdentityClient, KeyEventsQuery, Peer, PeerAdditionProposal, PeerHistory, PeerRemovalProposal,
    PeersResponse, Proposal, ProposalHistory, ProposalResponse, ProposalStatus,
    ProposalWithVotesMethods, RemovalHistory, SignedKeyEvent, SignedKeyEventPage, Vote,
};
use serde::Deserialize;
use tracing::warn;
use verifiable_storage::SelfAddressed;

use crate::federation::{
    FederationNode, FederationResponse, FederationRpc, FederationRpcResponse, FederationStatus,
    SignedFederationRpc,
};

fn max_writes_per_ip_per_second() -> u32 {
    kels_core::env_usize("KELS_MAX_WRITES_PER_IP_PER_SECOND", 256) as u32
}

fn ip_rate_limit_burst() -> u32 {
    kels_core::env_usize("KELS_IP_RATE_LIMIT_BURST", 1024) as u32
}

fn max_member_events_per_prefix_per_day() -> u32 {
    kels_core::env_usize("KELS_MAX_MEMBER_EVENTS_PER_PREFIX_PER_DAY", 64) as u32
}

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn a background task that periodically removes expired entries from
/// rate limit maps. Prevents unbounded growth from attacker-generated keys.
pub fn spawn_rate_limit_reaper(state: Arc<FederationState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RATE_LIMIT_REAP_INTERVAL).await;
            let now = Instant::now();
            let day = Duration::from_secs(SECS_PER_DAY);
            state
                .member_kel_prefix_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
            state
                .member_kel_ip_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
        }
    });
}

/// Check whether adding `event_count` new events would exceed the daily limit.
/// Does NOT update the counter — call `accrue_prefix_rate_limit` after merge.
///
/// Duplicated in `kels/src/handlers.rs`. Keep in sync.
fn check_prefix_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    prefix: &str,
    event_count: u32,
    max_events: u32,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 + event_count > max_events {
        return Err(ApiError::rate_limited("Too many events for this prefix"));
    }

    Ok(())
}

/// Accrue the actual number of new events after merge completes.
///
/// Duplicated in `kels/src/handlers.rs`. Keep in sync.
fn accrue_prefix_rate_limit(limits: &DashMap<String, (u32, Instant)>, prefix: &str, count: u32) {
    if count == 0 {
        return;
    }
    let now = Instant::now();
    let mut entry = limits.entry(prefix.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 += count;
}

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::NotFound,
            }),
        )
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::BadRequest,
            }),
        )
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::Unauthorized,
            }),
        )
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::Unauthorized,
            }),
        )
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::InternalError,
            }),
        )
    }

    fn rate_limited(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: msg.into(),
                code: ErrorCode::RateLimited,
            }),
        )
    }
}

/// Per-IP write rate limiting using a token bucket.
/// Tokens refill at max_writes_per_ip_per_second(), up to ip_rate_limit_burst().
fn check_ip_rate_limit(
    limits: &DashMap<std::net::IpAddr, (u32, Instant)>,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(ip).or_insert((ip_rate_limit_burst(), now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * max_writes_per_ip_per_second() as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(ip_rate_limit_burst());
        entry.1 = now;
    }
    if entry.0 == 0 {
        return Err(ApiError::rate_limited("Too many requests"));
    }
    entry.0 -= 1;
    Ok(())
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// ==================== Federation Handlers ====================

/// State for federation endpoints.
pub struct FederationState {
    pub node: Arc<FederationNode>,
    pub identity_client: Arc<IdentityClient>,
    pub member_kel_repo: crate::raft_store::MemberKelRepository,
    /// Per-IP rate limiting for member KEL submit endpoint.
    pub member_kel_ip_rate_limits: DashMap<std::net::IpAddr, (u32, Instant)>,
    /// Per-prefix daily rate limiting for member KEL submit endpoint.
    pub member_kel_prefix_rate_limits: DashMap<String, (u32, Instant)>,
}

/// Push own KEL events to all federation members via forward_key_events.
///
/// Best-effort: logs warnings on failure. AE loop handles any gaps.
async fn push_own_kel_to_members(state: &FederationState) {
    let self_prefix = state.node.config().self_prefix;

    // Fetch own events from identity service (source of truth)
    let identity_source = match kels_core::HttpKelSource::new(
        state.identity_client.base_url(),
        "/api/v1/identity/kel",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to build HTTP source for identity KEL");
            return;
        }
    };
    let local_sink = kels_core::RepositoryKelStore::new(std::sync::Arc::new(
        crate::raft_store::MemberKelRepository::new(state.member_kel_repo.pool.clone()),
    ));

    // First, sync own KEL from identity to local MemberKelRepository
    if let Err(e) = kels_core::forward_key_events(
        &self_prefix,
        &identity_source,
        &local_sink,
        kels_core::page_size(),
        kels_core::max_pages(),
        None,
    )
    .await
    {
        warn!(error = %e, "Failed to sync own KEL from identity before pushing to members");
        return;
    }

    // Push to each member in parallel using forward_key_events.
    // Each member gets its own source+sink pair — the source reads from local
    // repo (cheap: just DB queries), the sink submits via HTTP.
    let config = state.node.config();
    let futures: Vec<_> = config
        .members
        .iter()
        .filter(|m| m.prefix != self_prefix)
        .map(|member| {
            let member_prefix = member.prefix;
            let pool = state.member_kel_repo.pool.clone();
            let member_url = member.url.clone();
            async move {
                let repo_store = kels_core::RepositoryKelStore::new(std::sync::Arc::new(
                    crate::raft_store::MemberKelRepository::new(pool),
                ));
                let repo_source = kels_core::StoreKelSource::new(&repo_store);
                let member_sink =
                    match kels_core::HttpKelSink::new(&member_url, "/api/v1/member-kels/events") {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(member = %member_prefix, error = %e, "Failed to build HTTP sink");
                            return;
                        }
                    };
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    kels_core::forward_key_events(
                        &self_prefix,
                        &repo_source,
                        &member_sink,
                        kels_core::page_size(),
                        kels_core::max_pages(),
                        None,
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(member = %member_prefix, error = %e, "Failed to push KEL to member");
                    }
                    Err(_) => {
                        warn!(member = %member_prefix, "Timed out pushing KEL to member");
                    }
                }
            }
        })
        .collect();

    futures::future::join_all(futures).await;
}

/// Handle incoming Raft RPC from federation members.
///
/// Verifies the sender is a known federation member and validates
/// the signature against their KEL before processing.
pub async fn federation_rpc(
    State(state): State<Arc<FederationState>>,
    Json(signed_rpc): Json<SignedFederationRpc>,
) -> Result<Json<FederationRpcResponse>, ApiError> {
    // Verify sender is a federation member
    if !state.node.config().is_member(&signed_rpc.sender_prefix) {
        return Err(ApiError::forbidden(format!(
            "Unknown federation member: {}",
            signed_rpc.sender_prefix
        )));
    }

    // Consuming: verify sender's KEL to extract trusted public key for RPC auth.
    // Try local MemberKelRepository first, fall back to HTTP during bootstrap.
    let store = kels_core::RepositoryKelStore::new(std::sync::Arc::new(
        crate::raft_store::MemberKelRepository::new(state.member_kel_repo.pool.clone()),
    ));
    let local_result = kels_core::completed_verification(
        &mut kels_core::StorePageLoader::new(&store),
        &signed_rpc.sender_prefix,
        kels_core::page_size(),
        kels_core::max_pages(),
        std::iter::empty::<cesr::Digest>(),
    )
    .await;

    let kel_verification = match local_result {
        Ok(v) if !v.is_empty() => v,
        _ => {
            // HTTP fetch during bootstrap (local DB may not have this member's KEL yet)
            let member = state
                .node
                .config()
                .member_by_prefix(&signed_rpc.sender_prefix)
                .ok_or_else(|| {
                    ApiError::unauthorized(format!("Unknown member: {}", signed_rpc.sender_prefix))
                })?;
            let source = kels_core::HttpKelSource::new(
                &member.url,
                &format!("/api/v1/member-kels/kel/{}", signed_rpc.sender_prefix),
            )
            .map_err(|e| ApiError::internal_error(format!("Failed to build HTTP client: {}", e)))?;
            kels_core::verify_key_events(
                &signed_rpc.sender_prefix,
                &source,
                kels_core::KelVerifier::new(&signed_rpc.sender_prefix),
                kels_core::page_size(),
                kels_core::max_pages(),
            )
            .await
            .map_err(|e| ApiError::unauthorized(format!("Sender KEL invalid: {}", e)))?
        }
    };

    if kel_verification.is_divergent() {
        return Err(ApiError::unauthorized("Sender KEL is divergent"));
    }

    let current_key = kel_verification.current_public_key().ok_or_else(|| {
        ApiError::unauthorized("Failed to get public key from KEL: no establishment event")
    })?;
    let public_key = current_key.clone();
    public_key
        .verify(signed_rpc.payload.as_bytes(), &signed_rpc.signature)
        .map_err(|_| ApiError::unauthorized("Signature verification failed"))?;

    // Parse the verified payload
    let rpc: FederationRpc = serde_json::from_str(&signed_rpc.payload)
        .map_err(|e| ApiError::bad_request(format!("Invalid RPC payload: {}", e)))?;

    let response = match rpc {
        FederationRpc::AppendEntries(req) => match state.node.raft().append_entries(req).await {
            Ok(resp) => FederationRpcResponse::AppendEntries(resp),
            Err(e) => FederationRpcResponse::Error {
                message: e.to_string(),
            },
        },
        FederationRpc::Vote(req) => match state.node.raft().vote(req).await {
            Ok(resp) => FederationRpcResponse::Vote(resp),
            Err(e) => FederationRpcResponse::Error {
                message: e.to_string(),
            },
        },
        FederationRpc::Snapshot(transfer) => {
            // Reconstruct the Snapshot from the transfer data
            use openraft::Snapshot;
            use std::io::Cursor;

            let snapshot = Snapshot {
                meta: transfer.meta,
                snapshot: Cursor::new(transfer.data),
            };

            match state
                .node
                .raft()
                .install_full_snapshot(transfer.vote, snapshot)
                .await
            {
                Ok(resp) => FederationRpcResponse::Snapshot(resp),
                Err(e) => FederationRpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    };

    Ok(Json(response))
}

/// Get federation status.
pub async fn federation_status(
    State(state): State<Arc<FederationState>>,
) -> Result<Json<FederationStatus>, ApiError> {
    let status = state.node.status().await;
    Ok(Json(status))
}

// ==================== Public Federation API ====================

/// Query parameters for the proposals endpoint.
#[derive(Debug, Deserialize)]
pub struct ProposalsQuery {
    #[serde(default)]
    pub audit: bool,
}

/// Public endpoint returning completed proposals with their votes.
///
/// Default mode returns only approved, non-withdrawn addition proposals for
/// currently active peers. Use `?audit=true` for the full unfiltered response.
pub async fn list_completed_proposals(
    State(state): State<Arc<FederationState>>,
    Query(query): Query<ProposalsQuery>,
) -> Result<Json<CompletedProposalsResponse>, ApiError> {
    if query.audit {
        return Ok(Json(CompletedProposalsResponse {
            additions: state.node.completed_addition_proposals_with_votes().await,
            removals: state.node.completed_removal_proposals_with_votes().await,
        }));
    }

    let additions = state
        .node
        .completed_addition_proposals_with_votes()
        .await
        .into_iter()
        .filter(|awv| {
            let Some(last) = awv.history.latest() else {
                return false;
            };
            awv.status(last.threshold) == ProposalStatus::Approved
        })
        .collect();

    let removals = state
        .node
        .completed_removal_proposals_with_votes()
        .await
        .into_iter()
        .filter(|rwv| {
            let Some(last) = rwv.history.latest() else {
                return false;
            };
            rwv.status(last.threshold) == ProposalStatus::Approved
        })
        .collect();

    Ok(Json(CompletedProposalsResponse {
        additions,
        removals,
    }))
}

// ==================== Admin API ====================

/// Verify a signed admin request against this node's own identity.
/// Request to add a peer.
#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub peer_kel_prefix: cesr::Digest,
    pub node_id: String,
    pub base_domain: String,
    pub gossip_addr: String,
}

/// Get a specific proposal with votes.
pub async fn get_proposal(
    State(state): State<Arc<FederationState>>,
    Path(proposal_prefix): Path<String>,
) -> Result<Json<kels_core::ProposalWithVotes>, ApiError> {
    let proposal_digest = cesr::Digest::from_qb64(&proposal_prefix)
        .map_err(|e| ApiError::bad_request(format!("Invalid proposal prefix: {}", e)))?;

    if let Some(addition) = state
        .node
        .get_addition_proposal_with_votes(&proposal_digest)
        .await
    {
        Ok(Json(kels_core::ProposalWithVotes::Addition(addition)))
    } else if let Some(removal) = state
        .node
        .get_removal_proposal_with_votes(&proposal_digest)
        .await
    {
        Ok(Json(kels_core::ProposalWithVotes::Removal(removal)))
    } else {
        Err(ApiError::not_found(format!(
            "Proposal not found: {}",
            proposal_prefix
        )))
    }
}

/// Submit an addition proposal (create or withdraw) via Raft consensus.
///
/// For new proposals (v0, no previous): creates an empty proposal requiring multi-party approval.
/// For withdrawals (v1, has previous, withdrawn_at set): withdraws a pending proposal.
///
/// Full verification before Raft submission:
/// 1. Proposer is a federation member
/// 2. Threshold matches current config (new proposals only)
/// 3. Build and verify the full proposal chain (AdditionHistory)
/// 4. Verify each record's SAID is anchored in proposer's KEL
pub async fn admin_submit_addition_proposal(
    State(state): State<Arc<FederationState>>,
    Json(proposal): Json<PeerAdditionProposal>,
) -> Result<Json<ProposalResponse>, ApiError> {
    // 1. Verify proposer is a federation member
    if !state.node.config().is_member(&proposal.proposer) {
        return Err(ApiError::forbidden(format!(
            "Proposer {} is not a federation member",
            proposal.proposer
        )));
    }

    // 2. Verify threshold matches current config (only enforced at submission time,
    //    not during Raft log replay where config may have changed)
    if proposal.previous.is_none() && proposal.threshold != state.node.approval_threshold() {
        return Err(ApiError::bad_request(format!(
            "Proposal threshold {} doesn't match current threshold {}",
            proposal.threshold,
            state.node.approval_threshold()
        )));
    }

    // 3. Build and verify the full proposal chain
    let records = if proposal.previous.is_some() {
        // Withdrawal (v1): fetch existing v0 and build full chain
        let existing = state
            .node
            .get_addition_proposal(&proposal.prefix)
            .await
            .ok_or_else(|| {
                ApiError::not_found(format!("Proposal not found: {}", proposal.prefix))
            })?;
        vec![existing, proposal.clone()]
    } else {
        // New proposal (v0): chain is just this record
        vec![proposal.clone()]
    };

    let history = AdditionHistory {
        prefix: proposal.prefix,
        records,
    };

    history
        .verify()
        .map_err(|e| ApiError::bad_request(format!("Proposal chain verification failed: {}", e)))?;

    // 4. Verify each record's SAID is anchored in proposer's KEL
    for record in &history.records {
        state
            .node
            .verify_anchoring(&record.said, &record.proposer)
            .await
            .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;
    }

    // 5. Submit to Raft
    let response = state
        .node
        .submit_addition_proposal(proposal)
        .await
        .map_err(|e| match e {
            crate::federation::FederationError::NotLeader {
                leader_prefix,
                leader_url,
            } => ApiError::bad_request(format!(
                "Not leader. Leader: {:?} at {:?}",
                leader_prefix, leader_url
            )),
            _ => ApiError::internal_error(format!("Failed to submit proposal: {}", e)),
        })?;

    match response {
        FederationResponse::ProposalCreated {
            proposal_prefix,
            votes_needed,
            current_votes,
        } => Ok(Json(ProposalResponse {
            proposal_prefix,
            status: "pending".to_string(),
            votes_needed,
            current_votes,
            message: format!("Proposal created. Need {} approvals.", votes_needed),
        })),
        FederationResponse::ProposalWithdrawn(id) => Ok(Json(ProposalResponse {
            proposal_prefix: id,
            status: "withdrawn".to_string(),
            votes_needed: 0,
            current_votes: 0,
            message: "Proposal withdrawn.".to_string(),
        })),
        FederationResponse::PeerAlreadyExists(peer_kel_prefix) => Err(ApiError::bad_request(
            format!("Peer already exists: {}", peer_kel_prefix),
        )),
        FederationResponse::ProposalAlreadyExists(proposal_prefix) => Err(ApiError::bad_request(
            format!("Proposal already exists: {}", proposal_prefix),
        )),
        FederationResponse::SaidMismatch(msg) => {
            Err(ApiError::bad_request(format!("SAID mismatch: {}", msg)))
        }
        FederationResponse::NotAuthorized(msg) => Err(ApiError::forbidden(msg)),
        FederationResponse::HasVotes(msg) => Err(ApiError::bad_request(msg)),
        FederationResponse::ProposalNotFound(id) => {
            Err(ApiError::not_found(format!("Proposal not found: {}", id)))
        }
        _ => Err(ApiError::internal_error(format!(
            "Unexpected response: {:?}",
            response
        ))),
    }
}

/// Submit a removal proposal (create or withdraw) via Raft consensus.
///
/// For new proposals (v0, no previous): creates a removal proposal requiring multi-party approval.
/// For withdrawals (v1, has previous, withdrawn_at set): withdraws a pending removal proposal.
pub async fn admin_submit_removal_proposal(
    State(state): State<Arc<FederationState>>,
    Json(proposal): Json<PeerRemovalProposal>,
) -> Result<Json<ProposalResponse>, ApiError> {
    // 1. Verify proposer is a federation member
    if !state.node.config().is_member(&proposal.proposer) {
        return Err(ApiError::forbidden(format!(
            "Proposer {} is not a federation member",
            proposal.proposer
        )));
    }

    // 2. Verify threshold matches current config (only enforced at submission time,
    //    not during Raft log replay where config may have changed)
    if proposal.previous.is_none() && proposal.threshold != state.node.approval_threshold() {
        return Err(ApiError::bad_request(format!(
            "Proposal threshold {} doesn't match current threshold {}",
            proposal.threshold,
            state.node.approval_threshold()
        )));
    }

    // 3. Build and verify the full proposal chain
    let records = if proposal.previous.is_some() {
        let existing = state
            .node
            .get_removal_proposal(&proposal.prefix)
            .await
            .ok_or_else(|| {
                ApiError::not_found(format!("Removal proposal not found: {}", proposal.prefix))
            })?;
        vec![existing, proposal.clone()]
    } else {
        vec![proposal.clone()]
    };

    let history = RemovalHistory {
        prefix: proposal.prefix,
        records,
    };

    history.verify().map_err(|e| {
        ApiError::bad_request(format!("Removal proposal chain verification failed: {}", e))
    })?;

    // 4. Verify each record's SAID is anchored in proposer's KEL
    for record in &history.records {
        state
            .node
            .verify_anchoring(&record.said, &record.proposer)
            .await
            .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;
    }

    // 5. Submit to Raft
    let response = state
        .node
        .submit_removal_proposal(proposal)
        .await
        .map_err(|e| match e {
            crate::federation::FederationError::NotLeader {
                leader_prefix,
                leader_url,
            } => ApiError::bad_request(format!(
                "Not leader. Leader: {:?} at {:?}",
                leader_prefix, leader_url
            )),
            _ => ApiError::internal_error(format!("Failed to submit removal proposal: {}", e)),
        })?;

    match response {
        FederationResponse::ProposalCreated {
            proposal_prefix,
            votes_needed,
            current_votes,
        } => Ok(Json(ProposalResponse {
            proposal_prefix,
            status: "pending".to_string(),
            votes_needed,
            current_votes,
            message: format!("Removal proposal created. Need {} approvals.", votes_needed),
        })),
        FederationResponse::ProposalWithdrawn(id) => Ok(Json(ProposalResponse {
            proposal_prefix: id,
            status: "withdrawn".to_string(),
            votes_needed: 0,
            current_votes: 0,
            message: "Removal proposal withdrawn.".to_string(),
        })),
        FederationResponse::PeerNotFound(peer_kel_prefix) => Err(ApiError::not_found(format!(
            "Peer not found: {}",
            peer_kel_prefix
        ))),
        FederationResponse::ProposalAlreadyExists(proposal_prefix) => Err(ApiError::bad_request(
            format!("Removal proposal already exists: {}", proposal_prefix),
        )),
        FederationResponse::SaidMismatch(msg) => {
            Err(ApiError::bad_request(format!("SAID mismatch: {}", msg)))
        }
        FederationResponse::NotAuthorized(msg) => Err(ApiError::forbidden(msg)),
        FederationResponse::HasVotes(msg) => Err(ApiError::bad_request(msg)),
        FederationResponse::ProposalNotFound(id) => Err(ApiError::not_found(format!(
            "Removal proposal not found: {}",
            id
        ))),
        _ => Err(ApiError::internal_error(format!(
            "Unexpected response: {:?}",
            response
        ))),
    }
}

/// Vote on a proposal.
///
/// Full verification before Raft submission:
/// 1. Vote SAID integrity
/// 2. Voter is a federation member
/// 3. Vote references correct proposal
/// 4. Proposal chain is valid and not withdrawn (ProposalHistory verification)
/// 5. Vote SAID is anchored in voter's KEL
pub async fn admin_vote_proposal(
    State(state): State<Arc<FederationState>>,
    Path(proposal_prefix): Path<String>,
    Json(vote): Json<Vote>,
) -> Result<Json<ProposalResponse>, ApiError> {
    let proposal_digest = cesr::Digest::from_qb64(&proposal_prefix)
        .map_err(|e| ApiError::bad_request(format!("Invalid proposal prefix: {}", e)))?;

    // 1. Verify vote SAID integrity
    vote.verify_said()
        .map_err(|e| ApiError::bad_request(format!("Vote verification failed: {}", e)))?;

    // 2. Verify voter is a federation member
    if !state.node.config().is_member(&vote.voter) {
        return Err(ApiError::forbidden(format!(
            "Voter {} is not a federation member",
            vote.voter
        )));
    }

    // 3. Verify vote references this proposal
    if vote.proposal != proposal_digest {
        return Err(ApiError::bad_request(format!(
            "Vote is for proposal {} but submitted to {}",
            vote.proposal, proposal_prefix
        )));
    }

    // 4. Verify the proposal chain is valid and not withdrawn
    //    Check both addition and removal proposals
    if let Some(addition) = state.node.get_addition_proposal(&proposal_digest).await {
        let history = AdditionHistory {
            prefix: addition.prefix,
            records: vec![addition],
        };
        history.verify().map_err(|e| {
            ApiError::internal_error(format!("Stored proposal failed verification: {}", e))
        })?;
        if history.is_withdrawn() {
            return Err(ApiError::bad_request(format!(
                "Proposal {} has been withdrawn",
                proposal_prefix
            )));
        }
    } else if let Some(removal) = state.node.get_removal_proposal(&proposal_digest).await {
        let history = RemovalHistory {
            prefix: removal.prefix,
            records: vec![removal],
        };
        history.verify().map_err(|e| {
            ApiError::internal_error(format!(
                "Stored removal proposal failed verification: {}",
                e
            ))
        })?;
        if history.is_withdrawn() {
            return Err(ApiError::bad_request(format!(
                "Removal proposal {} has been withdrawn",
                proposal_prefix
            )));
        }
    } else {
        return Err(ApiError::not_found(format!(
            "Proposal not found: {}",
            proposal_prefix
        )));
    }

    // 4b. Check proposal expiration (checked here, not in Raft state machine,
    //     to avoid non-determinism from wall clock skew between nodes)
    if let Some(addition) = state.node.get_addition_proposal(&proposal_digest).await
        && addition.is_expired()
    {
        return Err(ApiError::bad_request(format!(
            "Proposal {} has expired",
            proposal_prefix
        )));
    }
    if let Some(removal) = state.node.get_removal_proposal(&proposal_digest).await
        && removal.is_expired()
    {
        return Err(ApiError::bad_request(format!(
            "Proposal {} has expired",
            proposal_prefix
        )));
    }

    // 5. Verify vote SAID is anchored in voter's KEL
    state
        .node
        .verify_anchoring(&vote.said, &vote.voter)
        .await
        .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;

    let response = state
        .node
        .vote_peer(proposal_digest, vote)
        .await
        .map_err(|e| match e {
            crate::federation::FederationError::NotLeader {
                leader_prefix,
                leader_url,
            } => ApiError::bad_request(format!(
                "Not leader. Leader: {:?} at {:?}",
                leader_prefix, leader_url
            )),
            _ => ApiError::internal_error(format!("Failed to vote: {}", e)),
        })?;

    match response {
        FederationResponse::VoteRecorded {
            proposal_prefix,
            current_votes,
            votes_needed,
            approved,
            proposal,
        } => {
            if approved {
                if let Some(v0) = proposal {
                    let self_prefix = state.node.config().self_prefix;

                    // Idempotency: if peer is already active, skip create/anchor/submit.
                    // Note: get_peer() checks both active and inactive — we must only
                    // skip for active peers, otherwise re-adding a removed peer is a no-op.
                    let already_active = state
                        .node
                        .state_machine()
                        .inner()
                        .lock()
                        .await
                        .active_peers_by_kel_prefix
                        .contains_key(&v0.peer_kel_prefix);

                    if !already_active {
                        let peer = Peer::create(
                            v0.peer_kel_prefix,
                            v0.node_id.clone(),
                            self_prefix,
                            true,
                            v0.base_domain.clone(),
                            v0.gossip_addr.clone(),
                        )
                        .map_err(|e| {
                            ApiError::internal_error(format!("Failed to create peer: {}", e))
                        })?;

                        if peer.authorizing_kel != self_prefix {
                            return Err(ApiError::internal_error(
                                "Peer authorizing_kel does not match self prefix".to_string(),
                            ));
                        }

                        state
                            .identity_client
                            .anchor(&peer.said)
                            .await
                            .map_err(|e| {
                                ApiError::internal_error(format!(
                                    "Failed to anchor peer SAID: {}",
                                    e
                                ))
                            })?;

                        // Push own KEL to all members after anchoring
                        push_own_kel_to_members(&state).await;

                        state.node.add_peer(peer.clone()).await.map_err(|e| {
                            ApiError::internal_error(format!("Failed to add peer via Raft: {}", e))
                        })?;
                    }

                    return Ok(Json(ProposalResponse {
                        proposal_prefix,
                        status: "approved".to_string(),
                        votes_needed,
                        current_votes,
                        message: format!("Proposal approved! Peer {} added.", v0.peer_kel_prefix),
                    }));
                }

                return Err(ApiError::internal_error(
                    "Proposal approved but no proposal data returned".to_string(),
                ));
            }

            Ok(Json(ProposalResponse {
                proposal_prefix,
                status: "pending".to_string(),
                votes_needed,
                current_votes,
                message: format!(
                    "Vote recorded. {} of {} approvals.",
                    current_votes, votes_needed
                ),
            }))
        }
        FederationResponse::RemovalApproved {
            proposal_prefix,
            peer_kel_prefix,
            current_votes,
            votes_needed,
            proposal,
        } => {
            if let Some(_removal_proposal) = proposal {
                let self_prefix = state.node.config().self_prefix;

                // Idempotency: if peer is already inactive, skip deactivate/anchor/submit
                let current_peer = state
                    .node
                    .state_machine()
                    .inner()
                    .lock()
                    .await
                    .get_peer(&peer_kel_prefix)
                    .cloned();

                let already_inactive = current_peer.as_ref().is_some_and(|p| !p.active);

                if !already_inactive {
                    let active_peer = current_peer.ok_or_else(|| {
                        ApiError::internal_error(format!(
                            "Peer {} not found in Raft state for deactivation",
                            peer_kel_prefix
                        ))
                    })?;

                    // Set authorizing_kel before deactivate() so the SAID
                    // is derived over the correct content
                    let mut to_deactivate = active_peer.clone();
                    to_deactivate.authorizing_kel = self_prefix;
                    let deactivated = to_deactivate.deactivate().map_err(|e| {
                        ApiError::internal_error(format!("Failed to deactivate peer: {}", e))
                    })?;

                    state
                        .identity_client
                        .anchor(&deactivated.said)
                        .await
                        .map_err(|e| {
                            ApiError::internal_error(format!(
                                "Failed to anchor deactivated peer SAID: {}",
                                e
                            ))
                        })?;

                    // Push own KEL to all members after anchoring
                    push_own_kel_to_members(&state).await;

                    state.node.remove_peer(deactivated).await.map_err(|e| {
                        ApiError::internal_error(format!("Failed to remove peer via Raft: {}", e))
                    })?;
                }

                return Ok(Json(ProposalResponse {
                    proposal_prefix,
                    status: "removal_approved".to_string(),
                    votes_needed,
                    current_votes,
                    message: format!("Removal approved! Peer {} deactivated.", peer_kel_prefix),
                }));
            }

            Err(ApiError::internal_error(
                "Removal approved but no proposal data returned".to_string(),
            ))
        }
        FederationResponse::ProposalNotFound(id) => {
            Err(ApiError::not_found(format!("Proposal not found: {}", id)))
        }
        FederationResponse::AlreadyVoted(id) => Err(ApiError::bad_request(format!(
            "Already voted on proposal: {}",
            id
        ))),
        FederationResponse::ProposalExpired(id) => {
            Err(ApiError::bad_request(format!("Proposal expired: {}", id)))
        }
        FederationResponse::ProposalRejected(id) => Ok(Json(ProposalResponse {
            proposal_prefix: id,
            status: "rejected".to_string(),
            votes_needed: 0,
            current_votes: 0,
            message: "Proposal rejected — rejection threshold met.".to_string(),
        })),
        _ => Err(ApiError::internal_error(format!(
            "Unexpected response: {:?}",
            response
        ))),
    }
}

/// Query parameters for the peers endpoint.
#[derive(Debug, Deserialize)]
pub struct PeersQuery {
    #[serde(default)]
    pub all: bool,
}

/// List all peers from federation.
///
/// Peers come from the Raft state machine. By default returns only active peers.
/// Use `?all=true` to include deactivated peers.
pub async fn list_peers_federated(
    State(state): State<Arc<FederationState>>,
    Query(query): Query<PeersQuery>,
) -> Result<Json<PeersResponse>, ApiError> {
    let core_peers = if query.all {
        state.node.all_peers().await
    } else {
        state.node.peers().await
    };

    let histories: Vec<PeerHistory> = core_peers
        .into_iter()
        .filter(|p| query.all || p.active)
        .map(|peer| PeerHistory {
            prefix: peer.prefix,
            records: vec![peer],
        })
        .collect();

    Ok(Json(PeersResponse { peers: histories }))
}

/// Submit member key events (push model).
///
/// Accepts signed key events for a federation member's KEL. If the submitted prefix
/// matches this node's own prefix, fans out to all other federation members.
/// Events received for other members' prefixes are stored without further fan-out.
///
/// Follows the KELS submit handler pattern: signature pre-validation, save_with_merge,
/// per-prefix and per-IP rate limiting.
pub async fn submit_member_key_events(
    State(state): State<Arc<FederationState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(events): Json<Vec<SignedKeyEvent>>,
) -> Result<Json<kels_core::SubmitEventsResponse>, ApiError> {
    if events.is_empty() {
        return Ok(Json(kels_core::SubmitEventsResponse {
            diverged_at: None,
            applied: true,
        }));
    }

    // Extract prefix from first event, validate all events share the same prefix
    let prefix = events[0].event.prefix;
    for event in &events {
        if event.event.prefix != prefix {
            return Err(ApiError::bad_request(
                "All events must share the same prefix",
            ));
        }
    }

    // Check trusted prefix
    if !state.node.config().is_trusted_prefix(&prefix) {
        return Err(ApiError::forbidden(format!(
            "Not a trusted member prefix: {}",
            prefix
        )));
    }

    // Per-IP rate limiting
    check_ip_rate_limit(&state.member_kel_ip_rate_limits, addr.ip())?;

    // Per-prefix daily rate limiting (counts events, not submissions)
    check_prefix_rate_limit(
        &state.member_kel_prefix_rate_limits,
        prefix.as_ref(),
        events.len() as u32,
        max_member_events_per_prefix_per_day(),
    )?;

    // Signature pre-validation (fast rejection before expensive merge)
    for signed_event in &events {
        if signed_event.signatures.is_empty() {
            return Err(ApiError::bad_request("Event missing signature"));
        }
        // Signature CESR format is validated at deserialization (cesr::Signature).
        if signed_event.event.requires_dual_signature() && signed_event.signatures.len() < 2 {
            return Err(ApiError::bad_request(
                "Dual signatures required for recovery event",
            ));
        }
    }

    // Full merge: verification, divergence detection, recovery.
    let outcome = state
        .member_kel_repo
        .save_with_merge(prefix.as_ref(), &events)
        .await
        .map_err(|e| match e {
            kels_core::KelsError::VerificationFailed(msg) => ApiError::unauthorized(msg),
            kels_core::KelsError::InvalidKeyEvent(msg) => ApiError::bad_request(msg),
            kels_core::KelsError::InvalidSignature(msg) => ApiError::bad_request(msg),
            kels_core::KelsError::KelDecommissioned => {
                ApiError::unauthorized("KEL is decommissioned".to_string())
            }
            kels_core::KelsError::ContestedKel(msg) => ApiError::unauthorized(msg),
            _ => ApiError::internal_error(e.to_string()),
        })?;

    // Accrue only the actual new events (duplicates don't count)
    accrue_prefix_rate_limit(
        &state.member_kel_prefix_rate_limits,
        prefix.as_ref(),
        outcome.new_event_count as u32,
    );

    let applied = matches!(
        outcome.result,
        kels_core::KelMergeResult::Accepted
            | kels_core::KelMergeResult::Recovered
            | kels_core::KelMergeResult::Contested
            | kels_core::KelMergeResult::Diverged
    );

    // Fan out to members if this is our own prefix and events were applied
    let config = state.node.config();
    let propagate = prefix == config.self_prefix;
    if propagate && applied {
        let self_prefix = config.self_prefix;
        let futures: Vec<_> = config
            .members
            .iter()
            .filter(|m| m.prefix != self_prefix)
            .map(|member| {
                let events = events.clone();
                let url = member.url.clone();
                let member_prefix = member.prefix;
                async move {
                    let client = match kels_core::KelsClient::with_path_prefix(
                        &url,
                        "/api/v1/member-kels",
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(member = %member_prefix, error = %e, "Failed to build HTTP client");
                            return;
                        }
                    };
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        client.submit_events(&events),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => {
                            warn!(member = %member_prefix, error = %e, "Failed to fan out member KEL events");
                        }
                        Err(_) => {
                            warn!(member = %member_prefix, "Timed out fanning out member KEL events");
                        }
                    }
                }
            })
            .collect();

        futures::future::join_all(futures).await;
    }

    Ok(Json(kels_core::SubmitEventsResponse {
        diverged_at: outcome.diverged_at,
        applied,
    }))
}

/// Get the effective SAID for a member's KEL prefix.
///
/// **RESOLVING ONLY — NOT VERIFIED.** Used for sync comparison.
/// A wrong value triggers an unnecessary sync, not a security hole.
pub async fn get_member_effective_said(
    State(state): State<Arc<FederationState>>,
    Path(prefix): Path<String>,
) -> Result<Json<EffectiveSaidResponse>, ApiError> {
    match state
        .member_kel_repo
        .compute_prefix_effective_said(&prefix)
        .await
    {
        Ok(Some((said, divergent))) => Ok(Json(EffectiveSaidResponse { said, divergent })),
        Ok(None) => Err(ApiError::not_found(format!(
            "No KEL found for prefix: {}",
            prefix
        ))),
        Err(e) => Err(ApiError::internal_error(format!(
            "Failed to compute effective SAID: {}",
            e
        ))),
    }
}

/// Public endpoint to get a specific federation member's KEL with pagination.
pub async fn get_member_key_events(
    State(state): State<Arc<FederationState>>,
    Path(prefix): Path<String>,
    Query(query): Query<KeyEventsQuery>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let limit = query
        .limit
        .unwrap_or(kels_core::page_size())
        .min(kels_core::page_size()) as u64;

    let prefix_digest = cesr::Digest::from_qb64(&prefix)
        .map_err(|e| ApiError::bad_request(format!("Invalid prefix: {}", e)))?;
    let since_digest = query
        .since
        .as_deref()
        .map(cesr::Digest::from_qb64)
        .transpose()
        .map_err(|e| ApiError::bad_request(format!("Invalid since SAID: {}", e)))?;
    let page = kels_core::serve_kel_page(
        &state.member_kel_repo,
        &prefix_digest,
        since_digest.as_ref(),
        limit,
    )
    .await
    .map_err(|e| ApiError::internal_error(format!("Failed to serve member KEL: {}", e)))?;

    Ok(Json(page))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ApiError Tests ====================

    #[test]
    fn test_api_error_not_found() {
        let err = ApiError::not_found("test item");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1.error, "test item");
    }

    #[test]
    fn test_api_error_bad_request() {
        let err = ApiError::bad_request("invalid input");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.error, "invalid input");
    }

    #[test]
    fn test_api_error_unauthorized() {
        let err = ApiError::unauthorized("access denied");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1.error, "access denied");
    }

    #[test]
    fn test_api_error_forbidden() {
        let err = ApiError::forbidden("not allowed");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(err.1.error, "not allowed");
    }

    #[test]
    fn test_api_error_internal_error() {
        let err = ApiError::internal_error("server crash");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.1.error, "server crash");
    }

    #[test]
    fn test_api_error_rate_limited() {
        let err = ApiError::rate_limited("Too many requests");
        assert_eq!(err.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.1.code, ErrorCode::RateLimited);
        assert_eq!(err.1.error, "Too many requests");
    }

    // ==================== ErrorResponse Tests ====================

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "test error".to_string(),
            code: ErrorCode::BadRequest,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("test error"));
        assert!(json.contains("bad_request"));
    }

    // ==================== health Tests ====================

    #[tokio::test]
    async fn test_health() {
        let status = health().await;
        assert_eq!(status, StatusCode::OK);
    }
}
