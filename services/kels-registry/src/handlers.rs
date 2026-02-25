//! KELS Registry REST API Handlers

use std::{
    collections::{HashMap, HashSet},
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
use dashmap::DashMap;
use kels::{
    AdditionHistory, AdminRequest, CompletedProposalsResponse, DeregisterRequest, ErrorCode,
    ErrorResponse, NodeRegistration, Peer, PeerAdditionProposal, PeerHistory, PeerRemovalProposal,
    PeersResponse, Proposal, ProposalHistory, ProposalStatus, ProposalWithVotesMethods,
    RegisterNodeRequest, RemovalHistory, SignedKeyEventPage, SignedRequest, StatusUpdateRequest,
    Vote,
};
use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use kels::IdentityClient;

use crate::{
    federation::{
        FederationNode, FederationResponse, FederationRpc, FederationRpcResponse, FederationStatus,
        SignedFederationRpc,
    },
    store::{RegistryStore, StoreError},
};

/// Maximum write requests per IP per second (token bucket: refill rate).
const MAX_WRITES_PER_IP_PER_SECOND: u32 = 200;

/// Burst capacity for per-IP write rate limiting.
const IP_RATE_LIMIT_BURST: u32 = 1000;

pub struct AppState {
    pub store: RegistryStore,
    pub federation_node: Option<Arc<FederationNode>>,
    /// Per-IP write rate limiting: maps IP -> (tokens_remaining, last_refill)
    pub ip_rate_limits: DashMap<std::net::IpAddr, (u32, Instant)>,
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
/// Tokens refill at MAX_WRITES_PER_IP_PER_SECOND, up to IP_RATE_LIMIT_BURST.
fn check_ip_rate_limit(
    limits: &DashMap<std::net::IpAddr, (u32, Instant)>,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let now = Instant::now();
    let mut entry = limits.entry(ip).or_insert((IP_RATE_LIMIT_BURST, now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * MAX_WRITES_PER_IP_PER_SECOND as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(IP_RATE_LIMIT_BURST);
        entry.1 = now;
    }
    if entry.0 == 0 {
        return Err(ApiError::rate_limited("Too many requests"));
    }
    entry.0 -= 1;
    Ok(())
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound(id) => ApiError::not_found(format!("Node not found: {}", id)),
            StoreError::Redis(e) => ApiError::internal_error(format!("Storage error: {}", e)),
            StoreError::Serialization(e) => {
                ApiError::internal_error(format!("Serialization error: {}", e))
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

/// Verifies peer is in allowlist and verifies the backing proposal
/// was properly approved with sufficient anchored votes.
async fn verify_and_authorize<T: serde::Serialize>(
    state: &AppState,
    signed_request: &SignedRequest<T>,
) -> Result<Peer, ApiError> {
    let peer_prefix_str = &signed_request.peer_prefix;

    // Look up the peer from Raft state (source of truth)
    let federation_node = state
        .federation_node
        .as_ref()
        .ok_or_else(|| ApiError::internal_error("Federation not configured"))?;
    let peer = {
        let sm = federation_node.state_machine().inner().lock().await;
        sm.get_peer(peer_prefix_str).cloned()
    };

    let peer = match peer {
        Some(peer) if peer.active => peer,
        Some(_) => {
            return Err(ApiError::forbidden(format!(
                "Peer {} is not authorized (deactivated)",
                peer_prefix_str
            )));
        }
        None => {
            return Err(ApiError::forbidden(format!(
                "Peer {} is not in allowlist",
                peer_prefix_str
            )));
        }
    };

    // Verify signature against peer's current public key from their KEL
    // Consuming: verify peer's KEL (paginated) to extract trusted public key
    let kels_client = kels::KelsClient::new(&peer.kels_url);
    let mut verifier = kels::KelVerifier::new(&peer.peer_prefix);
    let mut since: Option<String> = None;
    loop {
        let page = kels_client
            .fetch_key_events(
                &peer.peer_prefix,
                since.as_deref(),
                kels::MAX_EVENTS_PER_KEL_QUERY,
            )
            .await
            .map_err(|_| {
                ApiError::forbidden("Could not fetch peer KEL for signature verification")
            })?;
        if page.events.is_empty() {
            break;
        }
        verifier
            .verify_page(&page.events)
            .map_err(|_| ApiError::forbidden("Peer KEL verification failed"))?;
        since = page.events.last().map(|e| e.event.said.clone());
        if !page.has_more {
            break;
        }
    }
    let ctx = verifier.into_merge_context();

    signed_request
        .verify_signature_with_ctx(&ctx)
        .map_err(|_| ApiError::unauthorized("Signature verification failed"))?;

    // Verify the backing proposal was properly approved
    if let Some(node) = state.federation_node.as_ref() {
        let threshold = node.approval_threshold();
        let prefixes = node.config().member_prefixes();
        let member_prefixes: std::collections::HashSet<&str> =
            prefixes.iter().map(|s| s.as_str()).collect();

        // Find an approved, non-withdrawn addition proposal for this peer
        let proposals = node.completed_addition_proposals_with_votes().await;
        let pwv = proposals
            .iter()
            .find(|pw| {
                pw.history
                    .inception()
                    .is_some_and(|p| p.peer_prefix == peer.peer_prefix)
                    && !pw.history.is_withdrawn()
                    && pw.status(threshold) == kels::ProposalStatus::Approved
            })
            .ok_or_else(|| {
                ApiError::forbidden(format!(
                    "No approved proposal found for peer {}",
                    peer.peer_prefix
                ))
            })?;

        // Structural verification: chain, votes, references, withdrawal invariant
        pwv.verify().map_err(|e| {
            ApiError::forbidden(format!(
                "Proposal verification failed for peer {}: {}",
                peer.peer_prefix, e
            ))
        })?;

        // Verify proposal anchoring: each record in proposer's KEL
        let proposer = pwv
            .proposer()
            .ok_or_else(|| ApiError::internal_error("Approved proposal has no proposer"))?;

        if !member_prefixes.contains(proposer) {
            return Err(ApiError::forbidden(format!(
                "Proposer {} is not a federation member",
                proposer
            )));
        }

        for record in &pwv.history.records {
            node.verify_anchoring(&record.said, &record.proposer)
                .await
                .map_err(|e| ApiError::forbidden(format!("Proposal anchoring failed: {}", e)))?;
        }

        // Verify vote anchoring: each approval vote in voter's KEL
        let mut verified_voters = std::collections::HashSet::new();
        for vote in &pwv.votes {
            if !vote.approve || !member_prefixes.contains(vote.voter.as_str()) {
                continue;
            }

            if node.verify_anchoring(&vote.said, &vote.voter).await.is_ok() {
                verified_voters.insert(vote.voter.clone());
            }
        }

        if verified_voters.len() < threshold {
            return Err(ApiError::forbidden(format!(
                "Insufficient verified votes for peer {} ({}/{})",
                peer.peer_prefix,
                verified_voters.len(),
                threshold
            )));
        }
    }

    Ok(peer)
}

#[derive(Debug, Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeRegistration>,
    pub next_cursor: Option<String>,
}

pub async fn health() -> StatusCode {
    StatusCode::OK
}

pub async fn register_node(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(signed_request): Json<SignedRequest<RegisterNodeRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;
    let peer = verify_and_authorize(&state, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot register node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }
    if request.kels_url.is_empty() {
        return Err(ApiError::bad_request("kels_url is required"));
    }
    if request.gossip_addr.is_empty() {
        return Err(ApiError::bad_request("gossip_addr is required"));
    }

    let registration = state.store.register(request).await?;
    Ok(Json(registration))
}

pub async fn deregister_node(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(signed_request): Json<SignedRequest<DeregisterRequest>>,
) -> Result<StatusCode, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;
    let peer = verify_and_authorize(&state, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot deregister node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }

    state.store.deregister(&request.node_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_status(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(signed_request): Json<SignedRequest<StatusUpdateRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
    check_ip_rate_limit(&state.ip_rate_limits, addr.ip())?;
    let peer = verify_and_authorize(&state, &signed_request).await?;
    let request = signed_request.payload;

    if request.node_id != peer.node_id {
        return Err(ApiError::forbidden(format!(
            "Cannot update status for node_id '{}' with peer authorized for '{}'",
            request.node_id, peer.node_id
        )));
    }

    let registration = state
        .store
        .update_status(&request.node_id, request.status)
        .await?;
    Ok(Json(registration))
}

// ==================== Peer Handlers ====================

// ==================== Registry KEL Handlers ====================

pub struct RegistryKelState {
    pub identity_client: Arc<IdentityClient>,
    pub prefix: String,
}

// ==================== Federation Handlers ====================

/// State for federation endpoints.
pub struct FederationState {
    pub node: Arc<FederationNode>,
    pub identity_client: Arc<IdentityClient>,
}

/// Eagerly sync own KEL to Raft if there are new events.
///
/// The admin CLI anchors SAIDs in the identity KEL, then submits requests
/// that need anchoring verification against Raft state. Without this sync,
/// the 30-second background loop may not have picked up the new anchor yet.
async fn ensure_own_kel_synced(state: &FederationState) {
    let fut = async {
        if let Ok(own_page) = state
            .identity_client
            .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
            .await
            && let Some(first) = own_page.events.first()
        {
            let prefix = &first.event.prefix;
            let raft_count = state
                .node
                .get_member_context(prefix)
                .await
                .and_then(|ctx| {
                    ctx.branch_tips()
                        .first()
                        .map(|bt| bt.tip.event.serial as usize + 1)
                })
                .unwrap_or(0);
            if own_page.events.len() > raft_count {
                let events = own_page.events[raft_count..].to_vec();
                let _ = state.node.submit_key_events(events).await;
            }
        }
    };

    if tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .is_err()
    {
        tracing::warn!("Timed out syncing own KEL to Raft (no quorum?)");
    }
}

/// Accept key events from any federation member and submit to Raft.
///
/// No signature auth needed — the events are self-verifying (signed key events)
/// and apply() checks the prefix is a trusted member. This endpoint allows
/// followers to forward their KEL events to the leader for Raft consensus.
pub async fn federation_submit_key_events(
    State(state): State<Arc<FederationState>>,
    Json(events): Json<Vec<kels::SignedKeyEvent>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if events.is_empty() {
        return Err(ApiError::bad_request("No events provided"));
    }

    // Verify prefix is a trusted member before forwarding to Raft
    let prefix = &events[0].event.prefix;
    if !state.node.config().is_member(prefix) {
        return Err(ApiError::forbidden(format!(
            "Not a trusted member: {}",
            prefix
        )));
    }

    match state.node.submit_key_events(events).await {
        Ok(FederationResponse::KeyEventsAccepted { prefix, new_count }) => {
            Ok(Json(serde_json::json!({
                "status": "accepted",
                "prefix": prefix,
                "new_count": new_count
            })))
        }
        Ok(FederationResponse::KeyEventsRejected(reason)) => {
            Err(ApiError::bad_request(format!("Rejected: {}", reason)))
        }
        Ok(_) => Err(ApiError::internal_error("Unexpected response")),
        Err(e) => Err(ApiError::internal_error(e.to_string())),
    }
}

/// Handle incoming Raft RPC from federation members.
///
/// Verifies the sender is a known federation member and validates
/// the signature against their KEL before processing.
pub async fn federation_rpc(
    State(state): State<Arc<FederationState>>,
    Json(signed_rpc): Json<SignedFederationRpc>,
) -> Result<Json<FederationRpcResponse>, ApiError> {
    use cesr::{Matter, PublicKey, Signature};

    // Verify sender is a federation member
    if !state.node.config().is_member(&signed_rpc.sender_prefix) {
        return Err(ApiError::forbidden(format!(
            "Unknown federation member: {}",
            signed_rpc.sender_prefix
        )));
    }

    // Consuming: get verified context for sender's KEL to extract trusted public key for RPC auth.
    // Try Raft state first (already-verified context), fall back to HTTP fetch during bootstrap
    // (chicken-and-egg: KELs are replicated via Raft, but Raft RPCs need KELs to auth)
    let ctx = match state
        .node
        .get_member_context(&signed_rpc.sender_prefix)
        .await
    {
        Some(ctx) => ctx,
        None => {
            // HTTP fetch during bootstrap
            let member = state
                .node
                .config()
                .member_by_prefix(&signed_rpc.sender_prefix)
                .ok_or_else(|| {
                    ApiError::unauthorized(format!("Unknown member: {}", signed_rpc.sender_prefix))
                })?;
            let url = format!("{}/api/registry-kel", member.url.trim_end_matches('/'));
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| ApiError::internal_error(e.to_string()))?;
            let resp = client.get(&url).send().await.map_err(|e| {
                ApiError::unauthorized(format!("Failed to fetch sender KEL: {}", e))
            })?;
            if !resp.status().is_success() {
                return Err(ApiError::unauthorized(format!(
                    "Failed to fetch sender KEL: {}",
                    resp.status()
                )));
            }
            let page: kels::SignedKeyEventPage = resp.json().await.map_err(|e| {
                ApiError::unauthorized(format!("Failed to parse sender KEL: {}", e))
            })?;
            let mut verifier = kels::KelVerifier::new(&signed_rpc.sender_prefix);
            verifier
                .verify_page(&page.events)
                .map_err(|e| ApiError::unauthorized(format!("Sender KEL invalid: {}", e)))?;
            verifier.into_merge_context()
        }
    };

    if ctx.is_divergent() {
        return Err(ApiError::unauthorized("Sender KEL is divergent"));
    }

    let current_key = ctx.current_public_key().ok_or_else(|| {
        ApiError::unauthorized("Failed to get public key from KEL: no establishment event")
    })?;
    let public_key = PublicKey::from_qb64(current_key)
        .map_err(|e| ApiError::unauthorized(format!("Invalid public key: {}", e)))?;
    let signature = Signature::from_qb64(&signed_rpc.signature)
        .map_err(|e| ApiError::unauthorized(format!("Invalid signature format: {}", e)))?;
    public_key
        .verify(signed_rpc.payload.as_bytes(), &signature)
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
            member_prefixes: state.node.member_prefixes(),
            approval_threshold: state.node.approval_threshold(),
        }));
    }

    let active_peer_prefixes: HashSet<String> = state
        .node
        .peers()
        .await
        .into_iter()
        .filter(|p| p.active)
        .map(|p| p.peer_prefix)
        .collect();

    let threshold = state.node.approval_threshold();

    let additions = state
        .node
        .completed_addition_proposals_with_votes()
        .await
        .into_iter()
        .filter(|awv| {
            awv.history
                .inception()
                .is_some_and(|p| active_peer_prefixes.contains(&p.peer_prefix))
                && !awv.history.is_withdrawn()
                && awv.status(threshold) == ProposalStatus::Approved
        })
        .collect();

    Ok(Json(CompletedProposalsResponse {
        additions,
        removals: vec![],
        member_prefixes: state.node.member_prefixes(),
        approval_threshold: threshold,
    }))
}

// ==================== Admin API ====================

/// Verify a signed admin request against this node's own identity.
///
/// Checks that the request was signed by this node's identity key by:
/// 1. Confirming the signer prefix matches our own
/// 2. Verifying the signature against our KEL's current public key
async fn verify_admin_request<T: Serialize>(
    signed_request: &SignedRequest<T>,
    identity_client: &IdentityClient,
) -> Result<(), ApiError> {
    let our_prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| ApiError::internal_error(format!("Identity error: {}", e)))?;

    if signed_request.peer_prefix != our_prefix {
        return Err(ApiError::forbidden("Not signed by this node's identity"));
    }

    // Consuming: verify identity KEL (paginated) for admin signature check
    let mut verifier = kels::KelVerifier::new(&our_prefix);
    let mut since: Option<String> = None;
    loop {
        let page = identity_client
            .get_key_events(since.as_deref(), kels::MAX_EVENTS_PER_KEL_QUERY)
            .await
            .map_err(|e| ApiError::internal_error(format!("Identity KEL error: {}", e)))?;
        if page.events.is_empty() {
            break;
        }
        verifier
            .verify_page(&page.events)
            .map_err(|e| ApiError::internal_error(format!("Identity KEL invalid: {}", e)))?;
        since = page.events.last().map(|e| e.event.said.clone());
        if !page.has_more {
            break;
        }
    }
    let ctx = verifier.into_merge_context();

    signed_request
        .verify_signature_with_ctx(&ctx)
        .map_err(|_| ApiError::unauthorized("Admin signature verification failed"))?;

    Ok(())
}

/// Request to add a peer.
#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub peer_prefix: String,
    pub node_id: String,
    pub kels_url: String,
    pub gossip_addr: String,
}

/// Response for proposal operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProposalResponse {
    pub proposal_id: String,
    pub status: String,
    pub votes_needed: usize,
    pub current_votes: usize,
    pub message: String,
}

/// Get a specific proposal with votes (admin, signed request required).
/// Returns either an addition or removal proposal.
///
/// This endpoint uses `SignedRequest<AdminRequest>` for authentication — the admin
/// CLI signs the request via the identity service (HSM-backed). If we add more admin
/// query endpoints, they should follow this same pattern.
pub async fn admin_get_proposal(
    State(state): State<Arc<FederationState>>,
    Path(proposal_id): Path<String>,
    Json(signed_request): Json<SignedRequest<AdminRequest>>,
) -> Result<Json<kels::ProposalWithVotes>, ApiError> {
    verify_admin_request(&signed_request, &state.identity_client).await?;

    if let Some(addition) = state
        .node
        .get_addition_proposal_with_votes(&proposal_id)
        .await
    {
        Ok(Json(kels::ProposalWithVotes::Addition(addition)))
    } else if let Some(removal) = state
        .node
        .get_removal_proposal_with_votes(&proposal_id)
        .await
    {
        Ok(Json(kels::ProposalWithVotes::Removal(removal)))
    } else {
        Err(ApiError::not_found(format!(
            "Proposal not found: {}",
            proposal_id
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
        prefix: proposal.prefix.clone(),
        records,
    };

    history
        .verify()
        .map_err(|e| ApiError::bad_request(format!("Proposal chain verification failed: {}", e)))?;

    // 4. Verify each record's SAID is anchored in proposer's KEL
    ensure_own_kel_synced(&state).await;
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
            proposal_id,
            votes_needed,
            current_votes,
        } => Ok(Json(ProposalResponse {
            proposal_id,
            status: "pending".to_string(),
            votes_needed,
            current_votes,
            message: format!("Proposal created. Need {} approvals.", votes_needed),
        })),
        FederationResponse::ProposalWithdrawn(id) => Ok(Json(ProposalResponse {
            proposal_id: id,
            status: "withdrawn".to_string(),
            votes_needed: 0,
            current_votes: 0,
            message: "Proposal withdrawn.".to_string(),
        })),
        FederationResponse::PeerAlreadyExists(peer_prefix) => Err(ApiError::bad_request(format!(
            "Peer already exists: {}",
            peer_prefix
        ))),
        FederationResponse::ProposalAlreadyExists(proposal_id) => Err(ApiError::bad_request(
            format!("Proposal already exists: {}", proposal_id),
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
        prefix: proposal.prefix.clone(),
        records,
    };

    history.verify().map_err(|e| {
        ApiError::bad_request(format!("Removal proposal chain verification failed: {}", e))
    })?;

    // 4. Verify each record's SAID is anchored in proposer's KEL
    ensure_own_kel_synced(&state).await;
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
            proposal_id,
            votes_needed,
            current_votes,
        } => Ok(Json(ProposalResponse {
            proposal_id,
            status: "pending".to_string(),
            votes_needed,
            current_votes,
            message: format!("Removal proposal created. Need {} approvals.", votes_needed),
        })),
        FederationResponse::ProposalWithdrawn(id) => Ok(Json(ProposalResponse {
            proposal_id: id,
            status: "withdrawn".to_string(),
            votes_needed: 0,
            current_votes: 0,
            message: "Removal proposal withdrawn.".to_string(),
        })),
        FederationResponse::PeerNotFound(peer_prefix) => Err(ApiError::not_found(format!(
            "Peer not found: {}",
            peer_prefix
        ))),
        FederationResponse::ProposalAlreadyExists(proposal_id) => Err(ApiError::bad_request(
            format!("Removal proposal already exists: {}", proposal_id),
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
    Path(proposal_id): Path<String>,
    Json(vote): Json<Vote>,
) -> Result<Json<ProposalResponse>, ApiError> {
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
    if vote.proposal != proposal_id {
        return Err(ApiError::bad_request(format!(
            "Vote is for proposal {} but submitted to {}",
            vote.proposal, proposal_id
        )));
    }

    // 4. Verify the proposal chain is valid and not withdrawn
    //    Check both addition and removal proposals
    if let Some(addition) = state.node.get_addition_proposal(&proposal_id).await {
        let history = AdditionHistory {
            prefix: addition.prefix.clone(),
            records: vec![addition],
        };
        history.verify().map_err(|e| {
            ApiError::internal_error(format!("Stored proposal failed verification: {}", e))
        })?;
        if history.is_withdrawn() {
            return Err(ApiError::bad_request(format!(
                "Proposal {} has been withdrawn",
                proposal_id
            )));
        }
    } else if let Some(removal) = state.node.get_removal_proposal(&proposal_id).await {
        let history = RemovalHistory {
            prefix: removal.prefix.clone(),
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
                proposal_id
            )));
        }
    } else {
        return Err(ApiError::not_found(format!(
            "Proposal not found: {}",
            proposal_id
        )));
    }

    // 4b. Check proposal expiration (checked here, not in Raft state machine,
    //     to avoid non-determinism from wall clock skew between nodes)
    if let Some(addition) = state.node.get_addition_proposal(&proposal_id).await
        && addition.is_expired()
    {
        return Err(ApiError::bad_request(format!(
            "Proposal {} has expired",
            proposal_id
        )));
    }
    if let Some(removal) = state.node.get_removal_proposal(&proposal_id).await
        && removal.is_expired()
    {
        return Err(ApiError::bad_request(format!(
            "Proposal {} has expired",
            proposal_id
        )));
    }

    // 5. Verify vote SAID is anchored in voter's KEL
    ensure_own_kel_synced(&state).await;
    state
        .node
        .verify_anchoring(&vote.said, &vote.voter)
        .await
        .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;

    let response = state
        .node
        .vote_peer(proposal_id.clone(), vote)
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
            proposal_id,
            current_votes,
            votes_needed,
            approved,
            proposal,
        } => {
            if approved {
                if let Some(v0) = proposal {
                    let self_prefix = state.node.config().self_prefix.clone();

                    // Idempotency: if peer already exists, skip create/anchor/submit
                    let already_exists = state
                        .node
                        .state_machine()
                        .inner()
                        .lock()
                        .await
                        .get_peer(&v0.peer_prefix)
                        .is_some();

                    if !already_exists {
                        let peer = Peer::create(
                            v0.peer_prefix.clone(),
                            v0.node_id.clone(),
                            self_prefix.clone(),
                            true,
                            v0.kels_url.clone(),
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

                        // Eagerly submit own KEL to Raft after anchoring
                        // (best-effort, background sync catches misses)
                        if let Ok(own_page) = state
                            .identity_client
                            .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
                            .await
                            && let Some(first) = own_page.events.first()
                        {
                            let prefix = &first.event.prefix;
                            let raft_count = state
                                .node
                                .get_member_context(prefix)
                                .await
                                .and_then(|ctx| {
                                    ctx.branch_tips()
                                        .first()
                                        .map(|bt| bt.tip.event.serial as usize + 1)
                                })
                                .unwrap_or(0);
                            if own_page.events.len() > raft_count {
                                let events = own_page.events[raft_count..].to_vec();
                                if let Err(e) = state.node.submit_key_events(events).await {
                                    tracing::warn!(
                                        error = %e,
                                        "Failed to eagerly submit own KEL to Raft after anchor"
                                    );
                                }
                            }
                        }

                        state.node.add_peer(peer.clone()).await.map_err(|e| {
                            ApiError::internal_error(format!("Failed to add peer via Raft: {}", e))
                        })?;
                    }

                    return Ok(Json(ProposalResponse {
                        proposal_id,
                        status: "approved".to_string(),
                        votes_needed,
                        current_votes,
                        message: format!("Proposal approved! Peer {} added.", v0.peer_prefix),
                    }));
                }

                return Err(ApiError::internal_error(
                    "Proposal approved but no proposal data returned".to_string(),
                ));
            }

            Ok(Json(ProposalResponse {
                proposal_id,
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
            proposal_id,
            peer_prefix,
            current_votes,
            votes_needed,
            proposal,
        } => {
            if let Some(_removal_proposal) = proposal {
                let self_prefix = state.node.config().self_prefix.clone();

                // Idempotency: if peer is already inactive, skip deactivate/anchor/submit
                let current_peer = state
                    .node
                    .state_machine()
                    .inner()
                    .lock()
                    .await
                    .get_peer(&peer_prefix)
                    .cloned();

                let already_inactive = current_peer.as_ref().is_some_and(|p| !p.active);

                if !already_inactive {
                    let active_peer = current_peer.ok_or_else(|| {
                        ApiError::internal_error(format!(
                            "Peer {} not found in Raft state for deactivation",
                            peer_prefix
                        ))
                    })?;

                    // Set authorizing_kel before deactivate() so the SAID
                    // is derived over the correct content
                    let mut to_deactivate = active_peer.clone();
                    to_deactivate.authorizing_kel = self_prefix.clone();
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

                    // Eagerly submit own KEL to Raft after anchoring
                    if let Ok(own_page) = state
                        .identity_client
                        .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
                        .await
                        && let Some(first) = own_page.events.first()
                    {
                        let prefix = &first.event.prefix;
                        let raft_count = state
                            .node
                            .get_member_context(prefix)
                            .await
                            .and_then(|ctx| {
                                ctx.branch_tips()
                                    .first()
                                    .map(|bt| bt.tip.event.serial as usize + 1)
                            })
                            .unwrap_or(0);
                        if own_page.events.len() > raft_count {
                            let events = own_page.events[raft_count..].to_vec();
                            if let Err(e) = state.node.submit_key_events(events).await {
                                tracing::warn!(
                                    error = %e,
                                    "Failed to eagerly submit own KEL to Raft after removal anchor"
                                );
                            }
                        }
                    }

                    state.node.remove_peer(deactivated).await.map_err(|e| {
                        ApiError::internal_error(format!("Failed to remove peer via Raft: {}", e))
                    })?;
                }

                return Ok(Json(ProposalResponse {
                    proposal_id,
                    status: "removal_approved".to_string(),
                    votes_needed,
                    current_votes,
                    message: format!("Removal approved! Peer {} deactivated.", peer_prefix),
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
            proposal_id: id,
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
            prefix: peer.prefix.clone(),
            records: vec![peer],
        })
        .collect();

    Ok(Json(PeersResponse { peers: histories }))
}

/// Public endpoint for clients to verify peer records are anchored in the registry's KEL.
pub async fn get_registry_kel(
    State(state): State<Arc<RegistryKelState>>,
) -> Result<Json<SignedKeyEventPage>, ApiError> {
    let page = state
        .identity_client
        .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(page))
}

/// Public endpoint to get all cached federation member KELs.
/// Used for high availability - clients can fetch all KELs from any registry.
pub async fn get_registry_kels(
    State(state): State<Arc<FederationState>>,
) -> Result<Json<HashMap<String, SignedKeyEventPage>>, ApiError> {
    let member_prefixes = state.node.member_prefixes();
    let member_contexts = state.node.get_all_member_contexts().await;
    let mut result: HashMap<String, SignedKeyEventPage> = HashMap::new();

    // Read each member's KEL from the MemberKelRepository (DB-backed)
    for prefix in &member_prefixes {
        if member_contexts.contains_key(prefix)
            && let Ok(page) = state
                .node
                .state_machine()
                .read_member_kel_page(prefix, kels::MAX_EVENTS_PER_KEL_QUERY as u64, 0)
                .await
        {
            result.insert(prefix.clone(), page);
        }
    }

    // Add our own fresh KEL (not cached, always current)
    let own_page = state
        .identity_client
        .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch own KEL: {}", e)))?;

    if let Some(first) = own_page.events.first() {
        result.insert(first.event.prefix.clone(), own_page);
    }

    Ok(Json(result))
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

    // ==================== ApiError From<StoreError> Tests ====================

    #[test]
    fn test_api_error_from_store_not_found() {
        let store_err = StoreError::NotFound("node-123".to_string());
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::NOT_FOUND);
        assert!(api_err.1.error.contains("Node not found: node-123"));
    }

    #[test]
    fn test_api_error_from_store_redis() {
        let redis_err = redis::RedisError::from((redis::ErrorKind::IoError, "connection failed"));
        let store_err = StoreError::Redis(redis_err);
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("Storage error"));
    }

    #[test]
    fn test_api_error_from_store_serialization() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let store_err = StoreError::Serialization(json_err);
        let api_err: ApiError = store_err.into();
        assert_eq!(api_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(api_err.1.error.contains("Serialization error"));
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

    // ==================== NodesResponse Tests ====================

    #[test]
    fn test_nodes_response_serialization() {
        let response = NodesResponse {
            nodes: vec![],
            next_cursor: Some("next".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("nodes"));
        assert!(json.contains("next_cursor"));
        assert!(json.contains("next"));
    }

    #[test]
    fn test_nodes_response_without_cursor() {
        let response = NodesResponse {
            nodes: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("nodes"));
        assert!(json.contains("null"));
    }

    // ==================== health Tests ====================

    #[tokio::test]
    async fn test_health() {
        let status = health().await;
        assert_eq!(status, StatusCode::OK);
    }
}
