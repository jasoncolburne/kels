//! KELS Registry REST API Handlers

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kels::{
    CompletedProposalsResponse, DeregisterRequest, ErrorCode, ErrorResponse, Kel, NodeRegistration,
    Peer, PeerHistory, PeerScope, PeersResponse, Proposal, ProposalHistory,
    ProposalWithVotesMethods, RegisterNodeRequest, SignedRequest, StatusUpdateRequest,
};
use serde::{Deserialize, Serialize};
use verifiable_storage::{ChainedRepository, SelfAddressed};
use verifiable_storage_postgres::{Order, Query as StorageQuery, QueryExecutor};

use crate::{
    federation::{
        AdditionHistory, FederationNode, FederationResponse, FederationRpc, FederationRpcResponse,
        FederationStatus, PeerAdditionProposal, PeerRemovalProposal, RemovalHistory,
        SignedFederationRpc, Vote,
    },
    identity_client::IdentityClient,
    repository::RegistryRepository,
    signature::{self, SignatureError},
    store::{RegistryStore, StoreError},
};

pub struct AppState {
    pub store: RegistryStore,
    pub repo: Arc<RegistryRepository>,
    pub federation_node: Option<Arc<FederationNode>>,
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
}

impl From<SignatureError> for ApiError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::PeerIdMismatch { .. } => {
                ApiError::unauthorized(format!("Invalid signature: {}", e))
            }
            SignatureError::VerificationFailed => {
                ApiError::unauthorized("Signature verification failed")
            }
            _ => ApiError::bad_request(format!("Invalid request: {}", e)),
        }
    }
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

/// Verifies signature, checks peer is in allowlist, and for core peers verifies
/// the backing proposal was properly approved with sufficient anchored votes.
async fn verify_and_authorize<T: serde::Serialize>(
    state: &AppState,
    signed_request: &SignedRequest<T>,
) -> Result<Peer, ApiError> {
    let payload_json = serde_json::to_vec(&signed_request.payload)
        .map_err(|e| ApiError::internal_error(format!("Failed to serialize payload: {}", e)))?;

    let peer_id = signature::verify_signature(
        &payload_json,
        &signed_request.peer_id,
        &signed_request.public_key,
        &signed_request.signature,
    )?;
    let peer_id_str = peer_id.to_string();

    let query = StorageQuery::<Peer>::new()
        .eq("peer_id", &peer_id_str)
        .order_by("version", Order::Desc)
        .limit(1);

    let peers: Vec<Peer> = state
        .repo
        .peers
        .pool
        .fetch(query)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to query allowlist: {}", e)))?;

    let peer = match peers.into_iter().next() {
        Some(peer) if peer.active => peer,
        Some(_) => {
            return Err(ApiError::forbidden(format!(
                "Peer {} is not authorized (deactivated)",
                peer_id_str
            )));
        }
        None => {
            return Err(ApiError::forbidden(format!(
                "Peer {} is not in allowlist",
                peer_id_str
            )));
        }
    };

    // For core peers, verify the backing proposal was properly approved
    if peer.scope == PeerScope::Core {
        let node = state.federation_node.as_ref().ok_or_else(|| {
            ApiError::internal_error("Core peer found but federation not configured")
        })?;

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
                    .is_some_and(|p| p.peer_id == peer.peer_id)
                    && !pw.history.is_withdrawn()
                    && pw.status(threshold) == kels::ProposalStatus::Approved
            })
            .ok_or_else(|| {
                ApiError::forbidden(format!(
                    "No approved proposal found for core peer {}",
                    peer.peer_id
                ))
            })?;

        // Structural verification: chain, votes, references, withdrawal invariant
        pwv.verify().map_err(|e| {
            ApiError::forbidden(format!(
                "Proposal verification failed for peer {}: {}",
                peer.peer_id, e
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
                "Insufficient verified votes for core peer {} ({}/{})",
                peer.peer_id,
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
    Json(signed_request): Json<SignedRequest<RegisterNodeRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
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
    if request.gossip_multiaddr.is_empty() {
        return Err(ApiError::bad_request("gossip_multiaddr is required"));
    }

    let registration = state.store.register(request).await?;
    Ok(Json(registration))
}

pub async fn deregister_node(
    State(state): State<Arc<AppState>>,
    Json(signed_request): Json<SignedRequest<DeregisterRequest>>,
) -> Result<StatusCode, ApiError> {
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
    Json(signed_request): Json<SignedRequest<StatusUpdateRequest>>,
) -> Result<Json<NodeRegistration>, ApiError> {
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
    pub repo: Arc<RegistryRepository>,
    pub identity_client: Arc<IdentityClient>,
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

    // Get sender's KEL (try cache first, refresh on verification failure)
    let verify_with_kel = |kel: &kels::Kel| -> Result<(), ApiError> {
        let current_key = kel
            .last_establishment_event()
            .and_then(|e| e.event.public_key.clone())
            .ok_or_else(|| {
                ApiError::unauthorized("Failed to get public key from KEL: no establishment event")
            })?;

        let public_key = PublicKey::from_qb64(&current_key)
            .map_err(|e| ApiError::unauthorized(format!("Invalid public key: {}", e)))?;

        let signature = Signature::from_qb64(&signed_rpc.signature)
            .map_err(|e| ApiError::unauthorized(format!("Invalid signature format: {}", e)))?;

        public_key
            .verify(signed_rpc.payload.as_bytes(), &signature)
            .map_err(|_| ApiError::unauthorized("Signature verification failed"))
    };

    // Try with cached KEL first
    let verified = if let Some(kel) = state.node.get_member_kel(&signed_rpc.sender_prefix).await {
        verify_with_kel(&kel).is_ok()
    } else {
        false
    };

    // If not verified, refresh KEL and try again
    if !verified {
        let kel = state
            .node
            .refresh_member_kel(&signed_rpc.sender_prefix)
            .await
            .map_err(|e| ApiError::unauthorized(format!("Failed to fetch sender KEL: {}", e)))?;

        verify_with_kel(&kel)?;
    }

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

/// Public endpoint returning completed proposals with their votes.
///
/// Gossip nodes and other consumers use this to independently verify
/// that core peers were properly approved through multi-party voting.
pub async fn list_completed_proposals(
    State(state): State<Arc<FederationState>>,
) -> Result<Json<CompletedProposalsResponse>, ApiError> {
    Ok(Json(CompletedProposalsResponse {
        additions: state.node.completed_addition_proposals_with_votes().await,
        removals: state.node.completed_removal_proposals_with_votes().await,
        member_prefixes: state.node.member_prefixes(),
        approval_threshold: state.node.approval_threshold(),
    }))
}

// ==================== Admin API ====================

/// Check if request is from localhost.
fn is_localhost(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Request to add a core peer.
#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub peer_id: String,
    pub node_id: String,
    pub kels_url: String,
    pub gossip_multiaddr: String,
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

/// Get a specific proposal with votes (admin, localhost only).
/// Returns either an addition or removal proposal.
pub async fn admin_get_proposal(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<FederationState>>,
    Path(proposal_id): Path<String>,
) -> Result<Json<kels::ProposalWithVotes>, ApiError> {
    if !is_localhost(&addr) {
        return Err(ApiError::forbidden("Admin API is localhost only"));
    }

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
/// 2. Build and verify the full proposal chain (AdditionHistory)
/// 3. Verify each record's SAID is anchored in proposer's KEL
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

    // 2. Build and verify the full proposal chain
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

    // 3. Verify each record's SAID is anchored in proposer's KEL
    for record in &history.records {
        state
            .node
            .verify_anchoring(&record.said, &record.proposer)
            .await
            .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;
    }

    // 4. Submit to Raft
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
        FederationResponse::PeerAlreadyExists(peer_id) => Err(ApiError::bad_request(format!(
            "Peer already exists: {}",
            peer_id
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

    // 2. Build and verify the full proposal chain
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

    // 3. Verify each record's SAID is anchored in proposer's KEL
    for record in &history.records {
        state
            .node
            .verify_anchoring(&record.said, &record.proposer)
            .await
            .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;
    }

    // 4. Submit to Raft
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
        FederationResponse::PeerNotFound(peer_id) => {
            Err(ApiError::not_found(format!("Peer not found: {}", peer_id)))
        }
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
    state
        .node
        .verify_anchoring(&vote.said, &vote.voter)
        .await
        .map_err(|e| ApiError::unauthorized(format!("Anchoring verification failed: {}", e)))?;

    let response = state
        .node
        .vote_core_peer(proposal_id.clone(), vote)
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
            peer,
        } => {
            let message = if approved {
                format!(
                    "Proposal approved! Peer {:?} added to core set.",
                    peer.map(|p| p.said)
                )
            } else {
                format!(
                    "Vote recorded. {} of {} approvals.",
                    current_votes, votes_needed
                )
            };
            Ok(Json(ProposalResponse {
                proposal_id,
                status: if approved {
                    "approved".to_string()
                } else {
                    "pending".to_string()
                },
                votes_needed,
                current_votes,
                message,
            }))
        }
        FederationResponse::RemovalApproved {
            proposal_id,
            peer_id,
            current_votes,
            votes_needed,
        } => Ok(Json(ProposalResponse {
            proposal_id,
            status: "removal_approved".to_string(),
            votes_needed,
            current_votes,
            message: format!("Removal approved! Peer {} removed from core set.", peer_id),
        })),
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

/// Add a regional peer (admin, localhost only).
/// Core peers must go through the proposal system.
pub async fn admin_add_regional_peer(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<FederationState>>,
    Json(req): Json<AddPeerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_localhost(&addr) {
        return Err(ApiError::forbidden("Admin API is localhost only"));
    }

    // Create the peer as regional scope
    let peer = Peer::create(
        req.peer_id.clone(),
        req.node_id.clone(),
        "EAuthorizingKel_____________________________".to_string(),
        true,
        PeerScope::Regional,
        req.kels_url,
        req.gossip_multiaddr,
    )
    .map_err(|e| ApiError::bad_request(format!("Invalid peer data: {}", e)))?;

    // Write directly to local DB (regional peers don't go through Raft)
    use verifiable_storage::Chained;
    use verifiable_storage_postgres::{Order, Query, QueryExecutor};

    let query = Query::<Peer>::new()
        .eq("node_id", &req.node_id)
        .order_by("version", Order::Desc)
        .limit(1);
    let existing: Vec<Peer> = state
        .repo
        .peers
        .pool
        .fetch(query)
        .await
        .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let db_peer = match existing.first() {
        Some(latest) if latest.active && latest.peer_id == peer.peer_id => {
            return Ok(Json(serde_json::json!({
                "status": "ok",
                "message": format!("Regional peer {} already exists", req.peer_id)
            })));
        }
        Some(latest) => {
            let mut updated = latest.clone();
            updated.peer_id = peer.peer_id.clone();
            updated.active = true;
            updated.scope = PeerScope::Regional;
            updated.kels_url = peer.kels_url.clone();
            updated.gossip_multiaddr = peer.gossip_multiaddr.clone();
            updated
                .increment()
                .map_err(|e| ApiError::internal_error(format!("Failed to increment: {}", e)))?;
            updated
        }
        None => peer,
    };

    state
        .repo
        .peers
        .insert(db_peer)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to insert peer: {}", e)))?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Regional peer {} added", req.peer_id)
    })))
}

/// List all peers (core from federation + regional from local database).
///
/// When federation is enabled, core peers come from the Raft state machine
/// and regional peers come from the local PostgreSQL database.
pub async fn list_peers_federated(
    State(state): State<Arc<FederationState>>,
) -> Result<Json<PeersResponse>, ApiError> {
    // Get core peers from federation state machine
    let core_peers = state.node.core_peers().await;

    // Get regional peers from local database
    let query = StorageQuery::<Peer>::new()
        .eq("scope", "regional")
        .order_by("prefix", Order::Asc)
        .order_by("version", Order::Asc);

    let regional_peers: Vec<Peer> = state
        .repo
        .peers
        .pool
        .fetch(query)
        .await
        .map_err(|e| ApiError::internal_error(format!("Storage error: {}", e)))?;

    // Build histories for core peers (each has just a single record)
    let mut histories: Vec<PeerHistory> = core_peers
        .into_iter()
        .filter(|p| p.active)
        .map(|peer| PeerHistory {
            prefix: peer.prefix.clone(),
            records: vec![peer],
        })
        .collect();

    // Group regional peers into histories by prefix
    let mut current_prefix: Option<String> = None;
    let mut current_records: Vec<Peer> = Vec::new();

    for peer in regional_peers {
        if current_prefix.as_ref() != Some(&peer.prefix) {
            if let Some(prefix) = current_prefix.take()
                && !current_records.is_empty()
            {
                // Only include if latest record is active
                if current_records.last().is_some_and(|r| r.active) {
                    histories.push(PeerHistory {
                        prefix,
                        records: std::mem::take(&mut current_records),
                    });
                } else {
                    current_records.clear();
                }
            }
            current_prefix = Some(peer.prefix.clone());
        }
        current_records.push(peer);
    }

    // Don't forget the last regional history
    if let Some(prefix) = current_prefix
        && !current_records.is_empty()
        && current_records.last().is_some_and(|r| r.active)
    {
        histories.push(PeerHistory {
            prefix,
            records: current_records,
        });
    }

    Ok(Json(PeersResponse { peers: histories }))
}

/// Public endpoint for clients to verify peer records are anchored in the registry's KEL.
pub async fn get_registry_kel(
    State(state): State<Arc<RegistryKelState>>,
) -> Result<Json<Kel>, ApiError> {
    let kel = state
        .identity_client
        .get_kel()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(kel))
}

/// Public endpoint to get all cached federation member KELs.
/// Used for high availability - clients can fetch all KELs from any registry.
pub async fn get_registry_kels(
    State(state): State<Arc<FederationState>>,
) -> Result<Json<HashMap<String, Kel>>, ApiError> {
    let mut kels = state.node.get_all_member_kels().await;

    // Add our own fresh KEL (not cached, always current)
    let own_kel = state
        .identity_client
        .get_kel()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch own KEL: {}", e)))?;

    let prefix = own_kel.prefix().ok_or(ApiError::internal_error(
        "Own KEL has no prefix".to_string(),
    ))?;

    kels.insert(prefix.to_string(), own_kel);

    Ok(Json(kels))
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

    // ==================== ApiError From<SignatureError> Tests ====================

    #[test]
    fn test_api_error_from_signature_peer_id_mismatch() {
        let sig_err = SignatureError::PeerIdMismatch {
            expected: "expected".to_string(),
            actual: "actual".to_string(),
        };
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::UNAUTHORIZED);
        assert!(api_err.1.error.contains("Invalid signature"));
    }

    #[test]
    fn test_api_error_from_signature_verification_failed() {
        let sig_err = SignatureError::VerificationFailed;
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(api_err.1.error, "Signature verification failed");
    }

    #[test]
    fn test_api_error_from_signature_invalid_public_key() {
        let sig_err = SignatureError::InvalidPublicKey("bad key".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
    }

    #[test]
    fn test_api_error_from_signature_invalid_signature() {
        let sig_err = SignatureError::InvalidSignature("bad sig".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
    }

    #[test]
    fn test_api_error_from_signature_invalid_peer_id() {
        let sig_err = SignatureError::InvalidPeerId("bad id".to_string());
        let api_err: ApiError = sig_err.into();
        assert_eq!(api_err.0, StatusCode::BAD_REQUEST);
        assert!(api_err.1.error.contains("Invalid request"));
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
