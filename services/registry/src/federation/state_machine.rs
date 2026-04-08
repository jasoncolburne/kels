//! Raft state machine for the peer set.

use std::{
    collections::HashMap,
    io::{self, Cursor},
    iter,
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{info, warn};

use futures::stream::StreamExt;
use kels_core::{Peer, PeerAdditionProposal, PeerRemovalProposal, Proposal, Vote};

/// Verify a SAID is anchored in a member's KEL stored in the MemberKelRepository.
/// Consuming: paginated read + verification + inline anchor check.
async fn verify_member_anchoring_from_repo(
    repo: &crate::raft_store::MemberKelRepository,
    said: &cesr::Digest,
    member_prefix: &cesr::Digest,
) -> Result<(), String> {
    let store = kels_core::RepositoryKelStore::new(Arc::new(
        crate::raft_store::MemberKelRepository::new(repo.pool.clone()),
    ));
    let kel_verification = kels_core::completed_verification(
        &mut kels_core::StorePageLoader::new(&store),
        member_prefix,
        kels_core::page_size(),
        kels_core::max_pages(),
        iter::once(*said),
    )
    .await
    .map_err(|e| format!("Member KEL verification failed: {}", e))?;

    if !kel_verification.anchors_all_saids() {
        return Err(format!("SAID {} not anchored in member's KEL", said));
    }

    Ok(())
}
use openraft::{
    EntryPayload, LogId, OptionalSend, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StoredMembership,
    storage::{EntryResponder, RaftStateMachine},
};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

use super::{
    config::FederationConfig,
    types::{FederationRequest, FederationResponse, MemberSnapshot, TypeConfig},
};

/// State machine that manages the peer set.
///
/// This is the replicated state - all federation members maintain
/// an identical copy through Raft consensus.
#[derive(Debug, Default)]
pub struct StateMachineData {
    /// Last applied log entry
    pub last_applied_log: Option<LogId<TypeConfig>>,
    /// Last membership configuration
    pub last_membership: StoredMembership<TypeConfig>,
    /// Active peers (keyed by peer KEL prefix for efficient lookup)
    pub active_peers_by_kel_prefix: HashMap<cesr::Digest, Peer>,
    /// Inactive (deactivated) peers for audit trail
    pub inactive_peers_by_kel_prefix: HashMap<cesr::Digest, Peer>,
    /// Pending addition proposals awaiting votes (keyed by proposal prefix/proposal_prefix)
    pub pending_addition_proposals: HashMap<cesr::Digest, PeerAdditionProposal>,
    /// Completed addition proposals (full chain per proposal) for audit trail
    pub completed_addition_proposals: Vec<Vec<PeerAdditionProposal>>,
    /// Pending removal proposals awaiting votes (keyed by proposal prefix/proposal_prefix)
    pub pending_removal_proposals: HashMap<cesr::Digest, PeerRemovalProposal>,
    /// Completed removal proposals (full chain per proposal) for audit trail
    pub completed_removal_proposals: Vec<Vec<PeerRemovalProposal>>,
    /// Votes stored by SAID
    pub votes: HashMap<cesr::Digest, Vote>,
}

impl StateMachineData {
    /// Create a new state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get active peers.
    pub fn peers(&self) -> Vec<Peer> {
        self.active_peers_by_kel_prefix.values().cloned().collect()
    }

    /// Get all peers (active + inactive).
    pub fn all_peers(&self) -> Vec<Peer> {
        self.active_peers_by_kel_prefix
            .values()
            .chain(self.inactive_peers_by_kel_prefix.values())
            .cloned()
            .collect()
    }

    /// Get a peer by its KEL prefix (checks active first, then inactive).
    pub fn get_peer(&self, peer_kel_prefix: &cesr::Digest) -> Option<&Peer> {
        self.active_peers_by_kel_prefix
            .get(peer_kel_prefix)
            .or_else(|| self.inactive_peers_by_kel_prefix.get(peer_kel_prefix))
    }

    /// Check whether a peer has an approved proposal backed by sufficient
    /// unique votes from trusted member prefixes.
    ///
    /// Returns the set of verified voter prefixes if a valid proposal exists,
    /// or an empty set if no valid proposal is found. The caller must also
    /// verify each vote's SAID is anchored in the voter's KEL (async check
    /// not possible here).
    pub fn verified_voters_for_peer(
        &self,
        peer_kel_prefix: &cesr::Digest,
        member_prefixes: &std::collections::HashSet<&cesr::Digest>,
    ) -> std::collections::HashSet<cesr::Digest> {
        // Determine the most recent approved proposal action for this peer.
        // For each completed proposal (addition or removal), take the last record.
        // If it's not v0, it was withdrawn — skip it. Otherwise keep its created_at.
        // Sort by created_at; the most recent determines if the peer is added or removed.
        let mut recent_actions: Vec<(bool, &StorageDatetime)> = Vec::new(); // (is_addition, created_at)

        for chain in &self.completed_addition_proposals {
            let Some(last) = chain.last() else {
                continue;
            };
            if last.version != 0 {
                continue; // withdrawn
            }
            if chain
                .first()
                .is_none_or(|v0| &v0.peer_kel_prefix != peer_kel_prefix)
            {
                continue;
            }
            recent_actions.push((true, &last.created_at));
        }

        for chain in &self.completed_removal_proposals {
            let Some(last) = chain.last() else {
                continue;
            };
            if last.version != 0 {
                continue; // withdrawn
            }
            if chain
                .first()
                .is_none_or(|v0| &v0.peer_kel_prefix != peer_kel_prefix)
            {
                continue;
            }
            recent_actions.push((false, &last.created_at));
        }

        recent_actions.sort_by_key(|(_, created_at)| *created_at);

        // If the most recent action is not an addition, peer is not approved
        if !recent_actions
            .last()
            .is_some_and(|(is_addition, _)| *is_addition)
        {
            return std::collections::HashSet::new();
        }

        // Find the most recent non-withdrawn addition chain for this peer
        let approved_chain = self
            .completed_addition_proposals
            .iter()
            .filter(|chain| {
                chain
                    .first()
                    .is_some_and(|v0| &v0.peer_kel_prefix == peer_kel_prefix)
                    && chain.last().is_some_and(|r| r.version == 0)
            })
            .max_by_key(|chain| chain.last().map(|r| &r.created_at));

        let Some(chain) = approved_chain else {
            return std::collections::HashSet::new();
        };

        let proposal_prefix = chain.first().map(|p| p.prefix).unwrap_or_default();

        // Count approval votes from trusted members
        self.votes
            .values()
            .filter(|v| {
                v.proposal == proposal_prefix && v.approve && member_prefixes.contains(&v.voter)
            })
            .map(|v| v.voter)
            .collect()
    }

    /// Apply a request to the state machine.
    fn apply(&mut self, request: FederationRequest) -> FederationResponse {
        match request {
            FederationRequest::AddPeer(peer) => {
                let peer_kel_prefix = peer.kel_prefix;
                info!("Adding peer: {} (node: {})", peer_kel_prefix, peer.node_id);
                self.active_peers_by_kel_prefix
                    .insert(peer_kel_prefix, peer);
                FederationResponse::PeerAdded(peer_kel_prefix.to_string())
            }
            FederationRequest::RemovePeer(peer) => {
                let peer_kel_prefix = peer.kel_prefix;
                if peer.active {
                    warn!("Rejecting RemovePeer for active peer: {}", peer_kel_prefix);
                    return FederationResponse::NotAuthorized(format!(
                        "RemovePeer requires deactivated peer, but {} is still active",
                        peer_kel_prefix
                    ));
                }
                self.active_peers_by_kel_prefix.remove(&peer_kel_prefix);
                info!("Deactivated peer: {}", peer_kel_prefix);
                self.inactive_peers_by_kel_prefix
                    .insert(peer_kel_prefix, peer);
                FederationResponse::PeerRemoved(peer_kel_prefix.to_string())
            }
            FederationRequest::SubmitAdditionProposal(ref submitted) => {
                if submitted.previous.is_none() {
                    // New proposal (v0)
                    if self
                        .active_peers_by_kel_prefix
                        .contains_key(&submitted.peer_kel_prefix)
                    {
                        return FederationResponse::PeerAlreadyExists(submitted.peer_kel_prefix);
                    }

                    for proposal in self.pending_addition_proposals.values() {
                        if proposal.peer_kel_prefix == submitted.peer_kel_prefix {
                            return FederationResponse::ProposalAlreadyExists(proposal.prefix);
                        }
                    }

                    let proposal_prefix = submitted.prefix;

                    info!(
                        proposal_prefix = %proposal_prefix,
                        peer_prefix = %submitted.peer_kel_prefix,
                        proposer = %submitted.proposer,
                        "Created peer addition proposal (v0, awaiting votes)"
                    );

                    self.pending_addition_proposals
                        .insert(proposal_prefix, submitted.clone());

                    FederationResponse::ProposalCreated {
                        proposal_prefix,
                        votes_needed: submitted.threshold,
                        current_votes: 0,
                    }
                } else {
                    // Withdrawal (v1 with previous set)
                    let proposal_prefix = submitted.prefix;

                    let current = match self.pending_addition_proposals.get(&proposal_prefix) {
                        Some(p) => p,
                        None => return FederationResponse::ProposalNotFound(proposal_prefix),
                    };

                    // Chain integrity
                    if submitted.previous.as_ref() != Some(&current.said) {
                        return FederationResponse::SaidMismatch(format!(
                            "Previous SAID mismatch: expected {}, got {:?}",
                            current.said, submitted.previous
                        ));
                    }

                    // Version monotonicity
                    if submitted.version != current.version + 1 {
                        return FederationResponse::NotAuthorized(format!(
                            "Version must be {} but got {}",
                            current.version + 1,
                            submitted.version
                        ));
                    }

                    // Proposer never changes
                    if submitted.proposer != current.proposer {
                        return FederationResponse::NotAuthorized(format!(
                            "Only proposer {} can withdraw proposal",
                            current.proposer
                        ));
                    }

                    // Must be a withdrawal
                    if !submitted.is_withdrawn() {
                        return FederationResponse::NotAuthorized(
                            "Subsequent proposal version must have withdrawn_at set".to_string(),
                        );
                    }

                    // No votes must exist for this proposal
                    let has_votes = self.votes.values().any(|v| v.proposal == proposal_prefix);
                    if has_votes {
                        return FederationResponse::HasVotes(format!(
                            "Cannot withdraw proposal {} — votes have been cast",
                            proposal_prefix
                        ));
                    }

                    let Some(v0) = self.pending_addition_proposals.remove(&proposal_prefix) else {
                        return FederationResponse::InternalError(
                            "Couldn't find proposal when removing from pending".to_string(),
                        );
                    };

                    info!(
                        proposal_prefix = %proposal_prefix,
                        "Addition proposal withdrawn by {}",
                        submitted.proposer
                    );

                    self.completed_addition_proposals
                        .push(vec![v0, submitted.clone()]);
                    FederationResponse::ProposalWithdrawn(proposal_prefix)
                }
            }
            FederationRequest::SubmitRemovalProposal(ref submitted) => {
                if submitted.previous.is_none() {
                    // New removal proposal (v0)
                    if !self
                        .active_peers_by_kel_prefix
                        .contains_key(&submitted.peer_kel_prefix)
                    {
                        return FederationResponse::PeerNotFound(
                            submitted.peer_kel_prefix.to_string(),
                        );
                    }

                    for proposal in self.pending_removal_proposals.values() {
                        if proposal.peer_kel_prefix == submitted.peer_kel_prefix {
                            return FederationResponse::ProposalAlreadyExists(proposal.prefix);
                        }
                    }

                    let proposal_prefix = submitted.prefix;

                    info!(
                        proposal_prefix = %proposal_prefix,
                        peer_prefix = %submitted.peer_kel_prefix,
                        proposer = %submitted.proposer,
                        "Created peer removal proposal (v0, awaiting votes)"
                    );

                    self.pending_removal_proposals
                        .insert(proposal_prefix, submitted.clone());

                    FederationResponse::ProposalCreated {
                        proposal_prefix,
                        votes_needed: submitted.threshold,
                        current_votes: 0,
                    }
                } else {
                    // Withdrawal (v1 with previous set)
                    let proposal_prefix = submitted.prefix;

                    let current = match self.pending_removal_proposals.get(&proposal_prefix) {
                        Some(p) => p,
                        None => return FederationResponse::ProposalNotFound(proposal_prefix),
                    };

                    if submitted.previous.as_ref() != Some(&current.said) {
                        return FederationResponse::SaidMismatch(format!(
                            "Previous SAID mismatch: expected {}, got {:?}",
                            current.said, submitted.previous
                        ));
                    }

                    if submitted.version != current.version + 1 {
                        return FederationResponse::NotAuthorized(format!(
                            "Version must be {} but got {}",
                            current.version + 1,
                            submitted.version
                        ));
                    }

                    if submitted.proposer != current.proposer {
                        return FederationResponse::NotAuthorized(format!(
                            "Only proposer {} can withdraw proposal",
                            current.proposer
                        ));
                    }

                    if !submitted.is_withdrawn() {
                        return FederationResponse::NotAuthorized(
                            "Subsequent proposal version must have withdrawn_at set".to_string(),
                        );
                    }

                    let has_votes = self.votes.values().any(|v| v.proposal == proposal_prefix);
                    if has_votes {
                        return FederationResponse::HasVotes(format!(
                            "Cannot withdraw proposal {} — votes have been cast",
                            proposal_prefix
                        ));
                    }

                    let Some(v0) = self.pending_removal_proposals.remove(&proposal_prefix) else {
                        return FederationResponse::InternalError(
                            "Couldn't find proposal when removing from pending".to_string(),
                        );
                    };

                    info!(
                        proposal_prefix = %proposal_prefix,
                        "Removal proposal withdrawn by {}",
                        submitted.proposer
                    );

                    self.completed_removal_proposals
                        .push(vec![v0, submitted.clone()]);
                    FederationResponse::ProposalWithdrawn(proposal_prefix)
                }
            }
            FederationRequest::VotePeer {
                proposal_prefix,
                vote,
            } => {
                let voter = vote.voter;
                let approve = vote.approve;
                let vote_said = vote.said;

                // Determine if this is an addition or removal proposal
                let is_addition = self
                    .pending_addition_proposals
                    .contains_key(&proposal_prefix);
                let is_removal = self
                    .pending_removal_proposals
                    .contains_key(&proposal_prefix);

                if !is_addition && !is_removal {
                    if self
                        .completed_addition_proposals
                        .iter()
                        .any(|chain| chain.first().is_some_and(|p| p.prefix == proposal_prefix))
                        || self
                            .completed_removal_proposals
                            .iter()
                            .any(|chain| chain.first().is_some_and(|p| p.prefix == proposal_prefix))
                    {
                        return FederationResponse::ProposalNotFound(proposal_prefix);
                    }
                    return FederationResponse::ProposalNotFound(proposal_prefix);
                }

                // Get the proposal's threshold
                let proposal_threshold = if is_addition {
                    match self.pending_addition_proposals.get(&proposal_prefix) {
                        Some(p) => p.threshold,
                        None => {
                            return FederationResponse::InternalError(format!(
                                "Addition proposal {} not found despite passing existence check",
                                proposal_prefix
                            ));
                        }
                    }
                } else {
                    match self.pending_removal_proposals.get(&proposal_prefix) {
                        Some(p) => p.threshold,
                        None => {
                            return FederationResponse::InternalError(format!(
                                "Removal proposal {} not found despite passing existence check",
                                proposal_prefix
                            ));
                        }
                    }
                };

                // Check if already voted
                let already_voted = self
                    .votes
                    .values()
                    .any(|v| v.proposal == proposal_prefix && v.voter == voter);
                if already_voted {
                    return FederationResponse::AlreadyVoted(proposal_prefix);
                }

                // Store vote
                self.votes.insert(vote_said, vote);

                // Count votes
                let current_votes = self
                    .votes
                    .values()
                    .filter(|v| v.proposal == proposal_prefix && v.approve)
                    .count();
                let rejection_count = self
                    .votes
                    .values()
                    .filter(|v| v.proposal == proposal_prefix && !v.approve)
                    .count();

                info!(
                    proposal_prefix = %proposal_prefix,
                    voter = %voter,
                    approve = approve,
                    "Vote recorded ({}/{} approvals, {} rejections)",
                    current_votes,
                    proposal_threshold,
                    rejection_count
                );

                // Check if rejection threshold met — reject before checking approval
                if rejection_count >= kels_core::REJECTION_THRESHOLD {
                    info!(
                        proposal_prefix = %proposal_prefix,
                        rejection_count = rejection_count,
                        "Proposal rejected — rejection threshold met"
                    );
                    if is_addition {
                        if let Some(v0) = self.pending_addition_proposals.remove(&proposal_prefix) {
                            self.completed_addition_proposals.push(vec![v0]);
                        }
                    } else if let Some(v0) = self.pending_removal_proposals.remove(&proposal_prefix)
                    {
                        self.completed_removal_proposals.push(vec![v0]);
                    }
                    return FederationResponse::ProposalRejected(proposal_prefix);
                }

                // Check if approval threshold met
                if current_votes >= proposal_threshold {
                    if is_addition {
                        let v0 = match self.pending_addition_proposals.remove(&proposal_prefix) {
                            Some(a) => a,
                            None => {
                                return FederationResponse::InternalError(
                                    "Couldn't find proposal when removing from pending".to_string(),
                                );
                            }
                        };

                        info!(
                            proposal_prefix = %proposal_prefix,
                            peer_prefix = %v0.peer_kel_prefix,
                            "Proposal approved — leader must create and submit AddPeer"
                        );

                        let proposal_box = Box::new(v0.clone());
                        self.completed_addition_proposals.push(vec![v0]);

                        return FederationResponse::VoteRecorded {
                            proposal_prefix,
                            current_votes,
                            votes_needed: proposal_threshold,
                            approved: true,
                            proposal: Some(proposal_box),
                        };
                    } else {
                        let v0 = match self.pending_removal_proposals.remove(&proposal_prefix) {
                            Some(a) => a,
                            None => {
                                return FederationResponse::InternalError(
                                    "Couldn't find removal proposal when removing from pending"
                                        .to_string(),
                                );
                            }
                        };
                        let peer_kel_prefix = v0.peer_kel_prefix;

                        info!(
                            proposal_prefix = %proposal_prefix,
                            peer_kel_prefix = %peer_kel_prefix,
                            "Removal proposal approved — leader must deactivate, anchor, and submit RemovePeer"
                        );

                        let proposal_box = Box::new(v0.clone());
                        self.completed_removal_proposals.push(vec![v0]);

                        return FederationResponse::RemovalApproved {
                            proposal_prefix,
                            peer_kel_prefix,
                            current_votes,
                            votes_needed: proposal_threshold,
                            proposal: Some(proposal_box),
                        };
                    }
                }

                FederationResponse::VoteRecorded {
                    proposal_prefix,
                    current_votes,
                    votes_needed: proposal_threshold,
                    approved: false,
                    proposal: None,
                }
            }
        }
    }

    /// Create a snapshot of the current state.
    fn snapshot(&self) -> MemberSnapshot {
        MemberSnapshot {
            active_peers: self.active_peers_by_kel_prefix.values().cloned().collect(),
            inactive_peers: self
                .inactive_peers_by_kel_prefix
                .values()
                .cloned()
                .collect(),
            pending_addition_proposals: self.pending_addition_proposals.values().cloned().collect(),
            completed_addition_proposals: self.completed_addition_proposals.clone(),
            pending_removal_proposals: self.pending_removal_proposals.values().cloned().collect(),
            completed_removal_proposals: self.completed_removal_proposals.clone(),
            votes: self.votes.values().cloned().collect(),
        }
    }

    /// Count approval votes for a proposal.
    pub fn approval_count(&self, proposal_prefix: &cesr::Digest) -> usize {
        self.votes
            .values()
            .filter(|v| v.proposal == *proposal_prefix && v.approve)
            .count()
    }

    /// Get a pending proposal by ID.
    pub fn get_proposal(&self, proposal_prefix: &cesr::Digest) -> Option<&PeerAdditionProposal> {
        self.pending_addition_proposals.get(proposal_prefix)
    }

    /// Get all pending proposals.
    pub fn pending_proposals(&self) -> Vec<&PeerAdditionProposal> {
        self.pending_addition_proposals.values().collect()
    }

    /// Restore state from a snapshot and its metadata.
    fn restore(&mut self, snapshot: MemberSnapshot, meta: &SnapshotMeta<TypeConfig>) {
        self.last_applied_log = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();
        self.active_peers_by_kel_prefix = snapshot
            .active_peers
            .into_iter()
            .map(|p| (p.kel_prefix, p))
            .collect();
        self.inactive_peers_by_kel_prefix = snapshot
            .inactive_peers
            .into_iter()
            .map(|p| (p.kel_prefix, p))
            .collect();
        self.pending_addition_proposals = snapshot
            .pending_addition_proposals
            .into_iter()
            .map(|p| (p.prefix, p))
            .collect();
        self.completed_addition_proposals = snapshot.completed_addition_proposals;
        self.pending_removal_proposals = snapshot
            .pending_removal_proposals
            .into_iter()
            .map(|p| (p.prefix, p))
            .collect();
        self.completed_removal_proposals = snapshot.completed_removal_proposals;
        self.votes = snapshot.votes.into_iter().map(|v| (v.said, v)).collect();
        info!(
            "Restored {} active peers, {} inactive peers, {} pending addition proposals, {} completed additions, {} pending removal proposals, {} completed removals, {} votes from snapshot",
            self.active_peers_by_kel_prefix.len(),
            self.inactive_peers_by_kel_prefix.len(),
            self.pending_addition_proposals.len(),
            self.completed_addition_proposals.len(),
            self.pending_removal_proposals.len(),
            self.completed_removal_proposals.len(),
            self.votes.len(),
        );
    }
}

/// Thread-safe state machine store.
#[derive(Clone)]
pub struct StateMachineStore {
    inner: Arc<Mutex<StateMachineData>>,
    /// Federation config
    config: FederationConfig,
    /// Optional PostgreSQL-backed member KEL store for durable persistence
    member_kel_repo: Option<crate::raft_store::MemberKelRepository>,
    /// Identity service URL for fetching own KEL
    identity_url: Option<String>,
}

impl StateMachineStore {
    /// Create a new state machine store.
    pub fn new(config: FederationConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateMachineData::default())),
            config,
            member_kel_repo: None,
            identity_url: None,
        }
    }

    /// Set the member KEL repository for durable persistence.
    pub fn with_member_kel_repo(mut self, repo: crate::raft_store::MemberKelRepository) -> Self {
        self.member_kel_repo = Some(repo);
        self
    }

    /// Set the identity service URL for fetching own KEL.
    pub fn with_identity_url(mut self, url: String) -> Self {
        self.identity_url = Some(url);
        self
    }

    /// Get a reference to the member KEL repository if configured.
    pub fn member_kel_repo(&self) -> Option<&crate::raft_store::MemberKelRepository> {
        self.member_kel_repo.as_ref()
    }

    /// Get access to the inner data.
    pub fn inner(&self) -> &Arc<Mutex<StateMachineData>> {
        &self.inner
    }

    /// Verify a SAID is anchored in a federation member's KEL.
    /// Consuming: reads from MemberKelRepository (DB), verifies with KelVerifier,
    /// checks anchor inline. Does NOT acquire the inner lock.
    pub async fn verify_member_anchoring(
        &self,
        said: &cesr::Digest,
        member_prefix: &cesr::Digest,
    ) -> Result<(), String> {
        if !self.config.is_trusted_prefix(member_prefix) {
            return Err(format!("Unknown member: {}", member_prefix));
        }

        let repo = self
            .member_kel_repo
            .as_ref()
            .ok_or_else(|| "Member KEL repository not configured".to_string())?;

        verify_member_anchoring_from_repo(repo, said, member_prefix).await
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    /// Acquires self.inner lock.
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, io::Error> {
        let sm = self.inner.lock().await;

        let last_applied = sm
            .last_applied_log
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No applied log"))?;

        let snapshot = sm.snapshot();
        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let meta = SnapshotMeta {
            last_log_id: Some(last_applied),
            last_membership: sm.last_membership.clone(),
            snapshot_id: format!(
                "{}-{}",
                last_applied.committed_leader_id(),
                last_applied.index
            ),
        };

        Ok(Snapshot {
            meta,
            snapshot: Cursor::new(data),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = Self;

    /// Acquires self.inner lock.
    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<TypeConfig>>, StoredMembership<TypeConfig>), io::Error> {
        let sm = self.inner.lock().await;
        Ok((sm.last_applied_log, sm.last_membership.clone()))
    }

    /// Acquires self.inner lock.
    async fn apply<S>(&mut self, mut entries: S) -> Result<(), io::Error>
    where
        S: futures::Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>>
            + OptionalSend
            + Unpin,
    {
        let repo = self.member_kel_repo.as_ref();
        let mut sm = self.inner.lock().await;

        while let Some(entry_result) = entries.next().await {
            let (entry, responder): EntryResponder<TypeConfig> = entry_result?;

            sm.last_applied_log = Some(entry.log_id);

            let response = match entry.payload.clone() {
                EntryPayload::Blank => FederationResponse::Ok,
                EntryPayload::Normal(request) => {
                    // For AddPeer, verify votes and KEL anchoring
                    if let FederationRequest::AddPeer(ref peer) = request {
                        let member_prefixes: std::collections::HashSet<&cesr::Digest> =
                            self.config.trusted_prefixes.iter().collect();

                        let candidate_voters =
                            sm.verified_voters_for_peer(&peer.kel_prefix, &member_prefixes);

                        // Find the completed proposal and its threshold, verify each vote
                        let mut proposal_threshold = None;
                        let mut verified_voters = std::collections::HashSet::new();
                        for voter in &candidate_voters {
                            for chain in &sm.completed_addition_proposals {
                                if let Some(v0) = chain.first()
                                    && v0.peer_kel_prefix == peer.kel_prefix
                                    && !chain.last().is_some_and(|p| p.is_withdrawn())
                                {
                                    proposal_threshold = Some(v0.threshold);
                                    let proposal_prefix = &v0.prefix;
                                    for vote in sm.votes.values() {
                                        if vote.proposal == *proposal_prefix
                                            && vote.voter == *voter
                                            && vote.approve
                                            && vote.verify_said().is_ok()
                                            && verify_member_anchoring_from_repo(
                                                repo.ok_or_else(|| {
                                                    io::Error::other(
                                                        "Member KEL repository not configured",
                                                    )
                                                })?,
                                                &vote.said,
                                                &vote.voter,
                                            )
                                            .await
                                            .is_ok()
                                        {
                                            verified_voters.insert(*voter);
                                        }
                                    }
                                }
                            }
                        }

                        let threshold = match proposal_threshold {
                            Some(t) => t,
                            None => {
                                warn!(
                                    peer_kel_prefix = %peer.kel_prefix,
                                    "No completed addition proposal found - rejecting"
                                );
                                if let Some(r) = responder {
                                    r.send(FederationResponse::Ok);
                                }
                                continue;
                            }
                        };

                        // Defense-in-depth: enforce minimum threshold floor (see docs/federation.md)
                        let min_threshold = FederationConfig::compute_approval_threshold(0);
                        if threshold < min_threshold {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                threshold = threshold,
                                min_threshold = min_threshold,
                                "Proposal threshold below minimum - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        if verified_voters.len() < threshold {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                verified = verified_voters.len(),
                                threshold = threshold,
                                "Peer not backed by sufficient verified votes - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        // Verify SAID is anchored in authorizing member's KEL
                        if verify_member_anchoring_from_repo(
                            repo.ok_or_else(|| {
                                io::Error::other("Member KEL repository not configured")
                            })?,
                            &peer.said,
                            &peer.authorizing_kel,
                        )
                        .await
                        .is_err()
                        {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                said = %peer.said,
                                "Peer SAID not found in any member KEL - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        info!(
                            peer_kel_prefix = %peer.kel_prefix,
                            said = %peer.said,
                            "Verified peer"
                        );
                    }

                    // For RemovePeer, verify removal proposal threshold and KEL anchoring
                    if let FederationRequest::RemovePeer(ref peer) = request {
                        let member_prefixes: std::collections::HashSet<&cesr::Digest> =
                            self.config.trusted_prefixes.iter().collect();

                        // Find a completed removal proposal, its threshold, and verify votes
                        let mut proposal_threshold = None;
                        let mut verified_voters = std::collections::HashSet::new();
                        for chain in &sm.completed_removal_proposals {
                            if let Some(v0) = chain.first()
                                && v0.peer_kel_prefix == peer.kel_prefix
                                && !chain.last().is_some_and(|p| p.is_withdrawn())
                            {
                                proposal_threshold = Some(v0.threshold);
                                let proposal_prefix = &v0.prefix;
                                for vote in sm.votes.values() {
                                    if vote.proposal == *proposal_prefix
                                        && vote.approve
                                        && member_prefixes.contains(&vote.voter)
                                        && vote.verify_said().is_ok()
                                        && verify_member_anchoring_from_repo(
                                            repo.ok_or_else(|| {
                                                io::Error::other(
                                                    "Member KEL repository not configured",
                                                )
                                            })?,
                                            &vote.said,
                                            &vote.voter,
                                        )
                                        .await
                                        .is_ok()
                                    {
                                        verified_voters.insert(vote.voter);
                                    }
                                }
                            }
                        }

                        let threshold = match proposal_threshold {
                            Some(t) => t,
                            None => {
                                warn!(
                                    peer_kel_prefix = %peer.kel_prefix,
                                    "No completed removal proposal found - rejecting"
                                );
                                if let Some(r) = responder {
                                    r.send(FederationResponse::Ok);
                                }
                                continue;
                            }
                        };

                        // Defense-in-depth: enforce minimum threshold floor (see docs/federation.md)
                        let min_threshold = FederationConfig::compute_approval_threshold(0);
                        if threshold < min_threshold {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                threshold = threshold,
                                min_threshold = min_threshold,
                                "Removal proposal threshold below minimum - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        if verified_voters.len() < threshold {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                verified = verified_voters.len(),
                                threshold = threshold,
                                "RemovePeer not backed by sufficient verified removal votes - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        // Verify deactivated peer SAID is anchored in authorizing member's KEL
                        if verify_member_anchoring_from_repo(
                            repo.ok_or_else(|| {
                                io::Error::other("Member KEL repository not configured")
                            })?,
                            &peer.said,
                            &peer.authorizing_kel,
                        )
                        .await
                        .is_err()
                        {
                            warn!(
                                peer_kel_prefix = %peer.kel_prefix,
                                said = %peer.said,
                                "Deactivated peer SAID not anchored in member KEL - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        info!(
                            peer_kel_prefix = %peer.kel_prefix,
                            said = %peer.said,
                            "Verified peer removal"
                        );
                    }

                    // Verify vote anchoring
                    if let FederationRequest::VotePeer {
                        ref proposal_prefix,
                        ref vote,
                    } = request
                    {
                        if vote.proposal != *proposal_prefix {
                            warn!(
                                vote_proposal = %vote.proposal,
                                expected = %proposal_prefix,
                                "Vote proposal mismatch - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Vote is for proposal {} but submitted to {}",
                                    vote.proposal, proposal_prefix
                                )));
                            }
                            continue;
                        }

                        if let Some(proposal) = sm.pending_addition_proposals.get(proposal_prefix)
                            && let Err(e) = proposal.verify()
                        {
                            warn!(proposal_prefix = %proposal_prefix, error = %e, "Proposal verification failed - rejecting vote");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal invalid: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        if let Some(proposal) = sm.pending_removal_proposals.get(proposal_prefix)
                            && let Err(e) = proposal.verify()
                        {
                            warn!(proposal_prefix = %proposal_prefix, error = %e, "Removal proposal verification failed - rejecting vote");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Removal proposal invalid: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = vote.verify_said() {
                            warn!(voter = %vote.voter, error = %e, "Vote SAID verification failed - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Vote SAID verification failed: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = verify_member_anchoring_from_repo(
                            repo.ok_or_else(|| {
                                io::Error::other("Member KEL repository not configured")
                            })?,
                            &vote.said,
                            &vote.voter,
                        )
                        .await
                        {
                            warn!(voter = %vote.voter, error = %e, "Vote not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    // Verify addition proposal threshold floor and anchoring
                    if let FederationRequest::SubmitAdditionProposal(ref prop) = request {
                        // Exact-match against current config is in the leader handler;
                        // here we only enforce the floor so replayed entries from smaller
                        // federations are not rejected after config growth.
                        let min_threshold = FederationConfig::compute_approval_threshold(0);
                        if prop.threshold < min_threshold {
                            warn!(
                                proposer = %prop.proposer,
                                proposal_threshold = prop.threshold,
                                min_threshold = min_threshold,
                                "Addition proposal threshold below minimum - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal threshold {} below minimum {}",
                                    prop.threshold, min_threshold
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = verify_member_anchoring_from_repo(
                            repo.ok_or_else(|| {
                                io::Error::other("Member KEL repository not configured")
                            })?,
                            &prop.said,
                            &prop.proposer,
                        )
                        .await
                        {
                            warn!(proposer = %prop.proposer, error = %e, "Addition proposal not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    // Verify removal proposal threshold floor and anchoring
                    if let FederationRequest::SubmitRemovalProposal(ref prop) = request {
                        let min_threshold = FederationConfig::compute_approval_threshold(0);
                        if prop.threshold < min_threshold {
                            warn!(
                                proposer = %prop.proposer,
                                proposal_threshold = prop.threshold,
                                min_threshold = min_threshold,
                                "Removal proposal threshold below minimum - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal threshold {} below minimum {}",
                                    prop.threshold, min_threshold
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = verify_member_anchoring_from_repo(
                            repo.ok_or_else(|| {
                                io::Error::other("Member KEL repository not configured")
                            })?,
                            &prop.said,
                            &prop.proposer,
                        )
                        .await
                        {
                            warn!(proposer = %prop.proposer, error = %e, "Removal proposal not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    sm.apply(request.clone())
                }
                EntryPayload::Membership(membership) => {
                    sm.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    FederationResponse::Ok
                }
            };

            if let Some(r) = responder {
                r.send(response);
            }
        }

        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Cursor<Vec<u8>>, io::Error> {
        Ok(Cursor::new(Vec::new()))
    }

    /// Acquires self.inner lock.
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<TypeConfig>,
        snapshot: Cursor<Vec<u8>>,
    ) -> Result<(), io::Error> {
        let data = snapshot.into_inner();
        let mut core_snapshot: MemberSnapshot = serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Verify all addition proposal chains before restoring
        let original_addition_count = core_snapshot.pending_addition_proposals.len();
        let mut valid_addition_proposals = Vec::new();
        for proposal in core_snapshot.pending_addition_proposals {
            if let Err(e) = proposal.verify() {
                warn!(
                    proposal_prefix = %proposal.prefix,
                    error = %e,
                    "Addition proposal chain verification failed during snapshot restore - skipping"
                );
                continue;
            }
            valid_addition_proposals.push(proposal);
        }

        let removed_addition_count = original_addition_count - valid_addition_proposals.len();
        if removed_addition_count > 0 {
            warn!(
                removed = removed_addition_count,
                "Removed addition proposals with invalid chains during snapshot restore"
            );
        }
        core_snapshot.pending_addition_proposals = valid_addition_proposals;

        // Verify all removal proposal chains before restoring
        let original_removal_count = core_snapshot.pending_removal_proposals.len();
        let mut valid_removal_proposals = Vec::new();
        for proposal in core_snapshot.pending_removal_proposals {
            if let Err(e) = proposal.verify() {
                warn!(
                    proposal_prefix = %proposal.prefix,
                    error = %e,
                    "Removal proposal chain verification failed during snapshot restore - skipping"
                );
                continue;
            }
            valid_removal_proposals.push(proposal);
        }

        let removed_removal_count = original_removal_count - valid_removal_proposals.len();
        if removed_removal_count > 0 {
            warn!(
                removed = removed_removal_count,
                "Removed removal proposals with invalid chains during snapshot restore"
            );
        }
        core_snapshot.pending_removal_proposals = valid_removal_proposals;

        let mut sm = self.inner.lock().await;
        sm.restore(core_snapshot, meta);

        Ok(())
    }

    /// Acquires self.inner lock.
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TypeConfig>>, io::Error> {
        let sm = self.inner.lock().await;

        let last_applied = match sm.last_applied_log {
            Some(log_id) => log_id,
            None => return Ok(None),
        };

        let snapshot = sm.snapshot();
        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let meta = SnapshotMeta {
            last_log_id: Some(last_applied),
            last_membership: sm.last_membership.clone(),
            snapshot_id: format!(
                "{}-{}",
                last_applied.committed_leader_id(),
                last_applied.index
            ),
        };

        Ok(Some(Snapshot {
            meta,
            snapshot: Cursor::new(data),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use openraft::{SnapshotMeta, StoredMembership};
    use verifiable_storage::{Chained, StorageDatetime};

    const TEST_THRESHOLD: usize = 2;

    fn digest(name: &str) -> cesr::Digest {
        cesr::Digest::blake3_256(name.as_bytes())
    }

    fn test_expires_at() -> StorageDatetime {
        (chrono::Utc::now() + chrono::Duration::days(7)).into()
    }

    fn make_test_peer(peer_kel_prefix: &str, node_id: &str) -> Peer {
        Peer::create(
            digest(peer_kel_prefix),
            node_id.to_string(),
            digest("EAuthorizingKel"),
            true,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_kel_prefix),
        )
        .unwrap()
    }

    fn make_inactive_peer(peer_kel_prefix: &str, node_id: &str) -> Peer {
        Peer::create(
            digest(peer_kel_prefix),
            node_id.to_string(),
            digest("EAuthorizingKel"),
            false,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_kel_prefix),
        )
        .unwrap()
    }

    fn make_test_vote(proposal: &cesr::Digest, voter: &str, approve: bool) -> Vote {
        Vote::create(*proposal, digest(voter), approve).unwrap()
    }

    fn make_test_proposal(
        peer_kel_prefix: &str,
        node_id: &str,
        proposer: &str,
    ) -> PeerAdditionProposal {
        PeerAdditionProposal::empty(
            digest(peer_kel_prefix),
            node_id,
            &format!("http://{}:8080", node_id),
            &format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_kel_prefix),
            digest(proposer),
            TEST_THRESHOLD,
            &test_expires_at(),
        )
        .expect("Failed to create test proposal")
    }

    /// Helper to create a withdrawal from a pending proposal
    fn make_withdrawal(current: &PeerAdditionProposal) -> PeerAdditionProposal {
        let mut withdrawn = current.clone();
        withdrawn.withdrawn_at = Some(StorageDatetime::now());
        withdrawn.increment().expect("Failed to increment");
        withdrawn
    }

    /// Helper: submit a proposal, returns proposal_prefix
    fn submit_proposal(sm: &mut StateMachineData, proposal: PeerAdditionProposal) -> cesr::Digest {
        match sm.apply(FederationRequest::SubmitAdditionProposal(proposal)) {
            FederationResponse::ProposalCreated {
                proposal_prefix, ..
            } => proposal_prefix,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        }
    }

    /// Helper: run a full proposal through to approval, returning the proposal_prefix
    fn approve_peer(
        sm: &mut StateMachineData,
        peer_kel_prefix: &str,
        node_id: &str,
    ) -> cesr::Digest {
        let proposal = make_test_proposal(peer_kel_prefix, node_id, "KRegistryA");
        let proposal_prefix = submit_proposal(sm, proposal);

        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });

        let vote_b = make_test_vote(&proposal_prefix, "KRegistryB", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_b,
        });

        proposal_prefix
    }

    fn trusted_member_digests() -> Vec<cesr::Digest> {
        ["KRegistryA", "KRegistryB", "KRegistryC"]
            .into_iter()
            .map(digest)
            .collect()
    }

    fn trusted_members(digests: &[cesr::Digest]) -> std::collections::HashSet<&cesr::Digest> {
        digests.iter().collect()
    }

    // ==================== AddPeer / RemovePeer Tests ====================

    #[test]
    fn test_add_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");
        let response = sm.apply(FederationRequest::AddPeer(peer));
        assert!(matches!(response, FederationResponse::PeerAdded(_)));
        assert_eq!(sm.peers().len(), 1);
        assert!(sm.get_peer(&digest("peer-1")).is_some());
    }

    #[test]
    fn test_add_multiple_peers() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-3", "node-3",
        )));
        assert_eq!(sm.peers().len(), 3);
    }

    #[test]
    fn test_add_peer_overwrites_existing() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        assert_eq!(sm.get_peer(&digest("peer-1")).unwrap().node_id, "node-1");
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-2",
        )));
        assert_eq!(sm.get_peer(&digest("peer-1")).unwrap().node_id, "node-2");
        assert_eq!(sm.peers().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        let peer = sm
            .get_peer(&digest("peer-1"))
            .unwrap()
            .deactivate()
            .unwrap();
        let response = sm.apply(FederationRequest::RemovePeer(peer));
        assert!(matches!(response, FederationResponse::PeerRemoved(_)));
        assert!(sm.peers().is_empty()); // No active peers
        assert!(sm.get_peer(&digest("peer-1")).is_some()); // Still in inactive
        assert!(!sm.get_peer(&digest("peer-1")).unwrap().active);
    }

    #[test]
    fn test_remove_peer_active_rejected() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        // Try to remove with an active peer — should be rejected
        let active_peer = sm.get_peer(&digest("peer-1")).unwrap().clone();
        let response = sm.apply(FederationRequest::RemovePeer(active_peer));
        assert!(matches!(response, FederationResponse::NotAuthorized(_)));
        assert_eq!(sm.peers().len(), 1); // Still active
    }

    #[test]
    fn test_remove_one_of_many_peers() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-3", "node-3",
        )));
        let peer2 = sm
            .get_peer(&digest("peer-2"))
            .unwrap()
            .deactivate()
            .unwrap();
        sm.apply(FederationRequest::RemovePeer(peer2));
        assert_eq!(sm.peers().len(), 2); // 2 active
        assert_eq!(sm.all_peers().len(), 3); // 3 total
        assert!(sm.get_peer(&digest("peer-1")).unwrap().active);
        assert!(!sm.get_peer(&digest("peer-2")).unwrap().active); // deactivated, still findable
        assert!(sm.get_peer(&digest("peer-3")).unwrap().active);
    }

    #[test]
    fn test_deactivated_peer_can_be_reproposed() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        let peer = sm
            .get_peer(&digest("peer-1"))
            .unwrap()
            .deactivate()
            .unwrap();
        sm.apply(FederationRequest::RemovePeer(peer));
        assert!(sm.peers().is_empty());

        // Re-proposing should succeed (deactivated peers don't block proposals)
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let response = sm.apply(FederationRequest::SubmitAdditionProposal(proposal));
        assert!(matches!(
            response,
            FederationResponse::ProposalCreated { .. }
        ));
    }

    #[test]
    fn test_get_peer_not_found() {
        let sm = StateMachineData::new();
        assert!(sm.get_peer(&digest("nonexistent")).is_none());
    }

    #[test]
    fn test_inactive_peer_can_be_added() {
        let mut sm = StateMachineData::new();
        let response = sm.apply(FederationRequest::AddPeer(make_inactive_peer(
            "peer-1", "node-1",
        )));
        assert!(matches!(response, FederationResponse::PeerAdded(_)));
        assert!(!sm.get_peer(&digest("peer-1")).unwrap().active);
    }

    #[test]
    fn test_state_machine_data_default() {
        let sm = StateMachineData::default();
        assert!(sm.active_peers_by_kel_prefix.is_empty());
        assert!(sm.inactive_peers_by_kel_prefix.is_empty());
        assert!(sm.pending_addition_proposals.is_empty());
        assert!(sm.last_applied_log.is_none());
    }

    // ==================== Snapshot Tests ====================

    #[test]
    fn test_snapshot_empty_state() {
        let sm = StateMachineData::new();
        let snapshot = sm.snapshot();
        assert!(snapshot.active_peers.is_empty());
        assert!(snapshot.inactive_peers.is_empty());
    }

    #[test]
    fn test_snapshot_restore() {
        let mut sm1 = StateMachineData::new();
        sm1.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm1.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));

        let snapshot = sm1.snapshot();
        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "test-snapshot".to_string(),
        };

        let mut sm2 = StateMachineData::new();
        sm2.restore(snapshot, &meta);
        assert_eq!(sm2.peers().len(), 2);
        assert!(sm2.get_peer(&digest("peer-1")).is_some());
        assert!(sm2.get_peer(&digest("peer-2")).is_some());
    }

    #[test]
    fn test_peers_returns_cloned_values() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        let peers = sm.peers();
        assert_eq!(peers.len(), 1);
        assert!(sm.get_peer(&digest("peer-1")).is_some());
    }

    // ==================== Proposal Tests ====================

    #[test]
    fn test_submit_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        assert!(sm.get_peer(&digest("peer-1")).is_none());
        assert!(sm.get_proposal(&proposal_prefix).is_some());
    }

    #[test]
    fn test_vote_approves_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });

        let vote_b = make_test_vote(&proposal_prefix, "KRegistryB", true);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_b,
        });

        match response {
            FederationResponse::VoteRecorded {
                proposal_prefix: resp_id,
                current_votes,
                votes_needed,
                approved,
                proposal,
            } => {
                assert_eq!(resp_id, proposal_prefix);
                assert_eq!(current_votes, 2);
                assert_eq!(votes_needed, TEST_THRESHOLD);
                assert!(approved);
                assert!(proposal.is_some());
            }
            _ => panic!("Expected VoteRecorded, got {:?}", response),
        }

        // Peer is NOT in state machine yet — leader must create and submit AddPeer
        assert!(sm.get_peer(&digest("peer-1")).is_none());
        assert!(sm.get_proposal(&proposal_prefix).is_none());
        assert_eq!(sm.completed_addition_proposals.len(), 1);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let vote = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote,
        });

        let vote2 = make_test_vote(&proposal_prefix, "KRegistryA", true);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote2,
        });
        assert!(matches!(response, FederationResponse::AlreadyVoted(_)));
    }

    #[test]
    fn test_proposal_for_existing_peer_rejected() {
        let mut sm = StateMachineData::new();
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));

        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let response = sm.apply(FederationRequest::SubmitAdditionProposal(proposal));
        assert!(matches!(response, FederationResponse::PeerAlreadyExists(_)));
    }

    #[test]
    fn test_withdraw_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_prefix).unwrap().clone();
        let withdrawal = make_withdrawal(&current);

        let response = sm.apply(FederationRequest::SubmitAdditionProposal(withdrawal));

        assert!(matches!(response, FederationResponse::ProposalWithdrawn(_)));
        assert!(sm.get_proposal(&proposal_prefix).is_none());
        assert_eq!(sm.completed_addition_proposals.len(), 1);
        assert_eq!(sm.completed_addition_proposals[0].len(), 2);
        assert!(sm.completed_addition_proposals[0][1].is_withdrawn());
    }

    #[test]
    fn test_only_proposer_can_withdraw() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_prefix).unwrap().clone();
        let mut withdrawal = current.clone();
        withdrawal.proposer = digest("KRegistryB");
        withdrawal.withdrawn_at = Some(StorageDatetime::now());
        let _ = withdrawal.increment();

        let response = sm.apply(FederationRequest::SubmitAdditionProposal(withdrawal));
        assert!(matches!(response, FederationResponse::NotAuthorized(_)));
        assert!(sm.get_proposal(&proposal_prefix).is_some());
    }

    #[test]
    fn test_withdraw_with_votes_rejected() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        // Cast a vote first
        let vote = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote,
        });

        // Now try to withdraw
        let current = sm.get_proposal(&proposal_prefix).unwrap().clone();
        let withdrawal = make_withdrawal(&current);

        let response = sm.apply(FederationRequest::SubmitAdditionProposal(withdrawal));
        assert!(matches!(response, FederationResponse::HasVotes(_)));
        // Proposal should still be pending
        assert!(sm.get_proposal(&proposal_prefix).is_some());
    }

    #[test]
    fn test_vote_on_nonexistent_proposal() {
        let mut sm = StateMachineData::new();
        let nonexistent = digest("nonexistent");
        let vote = make_test_vote(&nonexistent, "KRegistryA", true);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix: nonexistent,
            vote,
        });
        assert!(matches!(response, FederationResponse::ProposalNotFound(_)));
    }

    #[test]
    fn test_rejection_vote_recorded() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });

        let vote_b = make_test_vote(&proposal_prefix, "KRegistryB", false);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_b,
        });

        match response {
            FederationResponse::VoteRecorded {
                current_votes,
                approved,
                ..
            } => {
                assert_eq!(current_votes, 1);
                assert!(!approved);
            }
            _ => panic!("Expected VoteRecorded"),
        }
        assert!(sm.get_peer(&digest("peer-1")).is_none());
    }

    #[test]
    fn test_two_rejections_kill_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        // First rejection — still pending
        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", false);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });
        assert!(matches!(response, FederationResponse::VoteRecorded { .. }));

        // Second rejection — proposal rejected
        let vote_b = make_test_vote(&proposal_prefix, "KRegistryB", false);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_b,
        });
        assert!(
            matches!(response, FederationResponse::ProposalRejected(_)),
            "Expected ProposalRejected, got {:?}",
            response
        );

        // Peer was NOT added
        assert!(sm.get_peer(&digest("peer-1")).is_none());

        // Proposal moved to completed, no longer pending
        assert!(sm.pending_addition_proposals.is_empty());
        assert_eq!(sm.completed_addition_proposals.len(), 1);

        // Further votes fail (proposal not found)
        let vote_c = make_test_vote(&proposal_prefix, "KRegistryC", true);
        let response = sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_c,
        });
        assert!(matches!(response, FederationResponse::ProposalNotFound(_)));

        // Can re-propose the same peer
        let proposal2 = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let response = sm.apply(FederationRequest::SubmitAdditionProposal(proposal2.clone()));
        assert!(matches!(
            response,
            FederationResponse::ProposalCreated { .. }
        ));
    }

    #[test]
    fn test_proposal_snapshot_restore() {
        let mut sm1 = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm1, proposal);

        let snapshot = sm1.snapshot();
        assert_eq!(snapshot.pending_addition_proposals.len(), 1);

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "test-snapshot".to_string(),
        };

        let mut sm2 = StateMachineData::new();
        sm2.restore(snapshot, &meta);
        assert!(sm2.get_proposal(&proposal_prefix).is_some());
    }

    // ==================== Rogue Leader / Vote Verification Tests ====================

    #[test]
    fn test_verified_voters_with_approved_proposal() {
        let mut sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);
        approve_peer(&mut sm, "peer-1", "node-1");

        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert_eq!(voters.len(), 2);
        assert!(voters.contains(&digest("KRegistryA")));
        assert!(voters.contains(&digest("KRegistryB")));
    }

    #[test]
    fn test_verified_voters_no_proposal() {
        let sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);
        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_rogue_leader_adds_peer_without_proposal() {
        let mut sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "rogue-peer",
            "rogue-node",
        )));
        assert!(sm.get_peer(&digest("rogue-peer")).is_some());
        let voters = sm.verified_voters_for_peer(&digest("rogue-peer"), &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_insufficient_votes() {
        let mut sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);
        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });

        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_ignores_untrusted_voter() {
        let mut sm = StateMachineData::new();
        let member_digests: Vec<cesr::Digest> = ["KRegistryA", "KRegistryB"]
            .into_iter()
            .map(digest)
            .collect();
        let members: std::collections::HashSet<&cesr::Digest> = member_digests.iter().collect();

        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_prefix, "KRegistryA", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_a,
        });

        let vote_c = make_test_vote(&proposal_prefix, "KRegistryC", true);
        sm.apply(FederationRequest::VotePeer {
            proposal_prefix,
            vote: vote_c,
        });

        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert_eq!(voters.len(), 1);
        assert!(voters.contains(&digest("KRegistryA")));
    }

    #[test]
    fn test_verified_voters_ignores_rejection_votes() {
        let mut sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);
        approve_peer(&mut sm, "peer-1", "node-1");

        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert_eq!(voters.len(), 2);
    }

    #[test]
    fn test_verified_voters_withdrawn_proposal_not_counted() {
        let mut sm = StateMachineData::new();
        let member_digests = trusted_member_digests();
        let members = trusted_members(&member_digests);

        let proposal = make_test_proposal("peer-1", "node-1", "KRegistryA");
        let proposal_prefix = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_prefix).unwrap().clone();
        let withdrawal = make_withdrawal(&current);
        sm.apply(FederationRequest::SubmitAdditionProposal(withdrawal));

        let voters = sm.verified_voters_for_peer(&digest("peer-1"), &members);
        assert!(voters.is_empty());
    }
}
