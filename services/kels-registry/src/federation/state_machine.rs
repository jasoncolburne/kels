//! Raft state machine for the core peer set.

use std::{
    collections::HashMap,
    io::{self, Cursor},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use futures::stream::StreamExt;
use kels::{Kel, Peer, PeerAdditionProposal, PeerRemovalProposal, PeerScope, Vote};
use openraft::{
    EntryPayload, LogId, OptionalSend, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StoredMembership,
    storage::{EntryResponder, RaftStateMachine},
};
use verifiable_storage::{Chained, ChainedRepository, SelfAddressed, StorageDatetime};
use verifiable_storage_postgres::{Order, Query, QueryExecutor};

use super::{
    config::FederationConfig,
    types::{CorePeerSnapshot, FederationRequest, FederationResponse, TypeConfig},
};
use crate::{identity_client::IdentityClient, peer_store::PeerRepository};

/// State machine that manages the core peer set.
///
/// This is the replicated state - all federation members maintain
/// an identical copy through Raft consensus.
#[derive(Debug, Default)]
pub struct StateMachineData {
    /// Last applied log entry
    pub last_applied_log: Option<LogId<TypeConfig>>,
    /// Last membership configuration
    pub last_membership: StoredMembership<TypeConfig>,
    /// The core peer set (keyed by peer_id for efficient lookup)
    pub peers: HashMap<String, Peer>,
    /// Pending addition proposals awaiting votes (keyed by proposal prefix/proposal_id)
    pub pending_addition_proposals: HashMap<String, PeerAdditionProposal>,
    /// Completed addition proposals (full chain per proposal) for audit trail
    pub completed_addition_proposals: Vec<Vec<PeerAdditionProposal>>,
    /// Pending removal proposals awaiting votes (keyed by proposal prefix/proposal_id)
    pub pending_removal_proposals: HashMap<String, PeerRemovalProposal>,
    /// Completed removal proposals (full chain per proposal) for audit trail
    pub completed_removal_proposals: Vec<Vec<PeerRemovalProposal>>,
    /// Votes stored by SAID
    pub votes: HashMap<String, Vote>,
}

impl StateMachineData {
    /// Create a new state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all core peers.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers.values().cloned().collect()
    }

    /// Get a peer by peer_id.
    pub fn get_peer(&self, peer_id: &str) -> Option<&Peer> {
        self.peers.get(peer_id)
    }

    /// Check whether a core peer has an approved proposal backed by sufficient
    /// unique votes from trusted member prefixes.
    ///
    /// Returns the set of verified voter prefixes if a valid proposal exists,
    /// or an empty set if no valid proposal is found. The caller must also
    /// verify each vote's SAID is anchored in the voter's KEL (async check
    /// not possible here).
    pub fn verified_voters_for_peer(
        &self,
        peer_id: &str,
        member_prefixes: &std::collections::HashSet<&str>,
    ) -> std::collections::HashSet<String> {
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
            if chain.first().is_none_or(|v0| v0.peer_id != peer_id) {
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
            if chain.first().is_none_or(|v0| v0.peer_id != peer_id) {
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
                chain.first().is_some_and(|v0| v0.peer_id == peer_id)
                    && chain.last().is_some_and(|r| r.version == 0)
            })
            .max_by_key(|chain| chain.last().map(|r| &r.created_at));

        let Some(chain) = approved_chain else {
            return std::collections::HashSet::new();
        };

        let proposal_id = chain.first().map(|p| p.prefix.as_str()).unwrap_or("");

        // Count approval votes from trusted members
        self.votes
            .values()
            .filter(|v| {
                v.proposal == proposal_id && v.approve && member_prefixes.contains(v.voter.as_str())
            })
            .map(|v| v.voter.clone())
            .collect()
    }

    /// Apply a request to the state machine.
    fn apply(
        &mut self,
        request: FederationRequest,
        threshold: usize,
        leader_prefix: &str,
    ) -> FederationResponse {
        match request {
            FederationRequest::AddPeer(peer) => {
                let peer_id = peer.peer_id.clone();
                info!("Adding peer: {} (node: {})", peer_id, peer.node_id);
                self.peers.insert(peer_id.clone(), peer);
                FederationResponse::PeerAdded(peer_id)
            }
            FederationRequest::RemovePeer(peer_id) => {
                if self.peers.remove(&peer_id).is_some() {
                    info!("Removed core peer: {}", peer_id);
                    FederationResponse::PeerRemoved(peer_id)
                } else {
                    debug!("Peer not found for removal: {}", peer_id);
                    FederationResponse::PeerNotFound(peer_id)
                }
            }
            FederationRequest::SubmitAdditionProposal(ref submitted) => {
                if submitted.previous.is_none() {
                    // New proposal (v0)
                    if self.peers.contains_key(&submitted.peer_id) {
                        return FederationResponse::PeerAlreadyExists(submitted.peer_id.clone());
                    }

                    for proposal in self.pending_addition_proposals.values() {
                        if proposal.peer_id == submitted.peer_id {
                            return FederationResponse::ProposalAlreadyExists(
                                proposal.prefix.clone(),
                            );
                        }
                    }

                    let proposal_id = submitted.prefix.clone();

                    info!(
                        proposal_id = %proposal_id,
                        peer_id = %submitted.peer_id,
                        proposer = %submitted.proposer,
                        "Created core peer addition proposal (v0, awaiting votes)"
                    );

                    self.pending_addition_proposals
                        .insert(proposal_id.clone(), submitted.clone());

                    FederationResponse::ProposalCreated {
                        proposal_id,
                        votes_needed: threshold,
                        current_votes: 0,
                    }
                } else {
                    // Withdrawal (v1 with previous set)
                    let proposal_id = submitted.prefix.clone();

                    let current = match self.pending_addition_proposals.get(&proposal_id) {
                        Some(p) => p,
                        None => return FederationResponse::ProposalNotFound(proposal_id),
                    };

                    // Chain integrity
                    if submitted.previous.as_deref() != Some(&current.said) {
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
                    let has_votes = self.votes.values().any(|v| v.proposal == proposal_id);
                    if has_votes {
                        return FederationResponse::HasVotes(format!(
                            "Cannot withdraw proposal {} — votes have been cast",
                            proposal_id
                        ));
                    }

                    let Some(v0) = self.pending_addition_proposals.remove(&proposal_id) else {
                        return FederationResponse::InternalError(
                            "Couldn't find proposal when removing from pending".to_string(),
                        );
                    };

                    info!(
                        proposal_id = %proposal_id,
                        "Addition proposal withdrawn by {}",
                        submitted.proposer
                    );

                    self.completed_addition_proposals
                        .push(vec![v0, submitted.clone()]);
                    FederationResponse::ProposalWithdrawn(proposal_id)
                }
            }
            FederationRequest::SubmitRemovalProposal(ref submitted) => {
                if submitted.previous.is_none() {
                    // New removal proposal (v0)
                    if !self.peers.contains_key(&submitted.peer_id) {
                        return FederationResponse::PeerNotFound(submitted.peer_id.clone());
                    }

                    for proposal in self.pending_removal_proposals.values() {
                        if proposal.peer_id == submitted.peer_id {
                            return FederationResponse::ProposalAlreadyExists(
                                proposal.prefix.clone(),
                            );
                        }
                    }

                    let proposal_id = submitted.prefix.clone();

                    info!(
                        proposal_id = %proposal_id,
                        peer_id = %submitted.peer_id,
                        proposer = %submitted.proposer,
                        "Created core peer removal proposal (v0, awaiting votes)"
                    );

                    self.pending_removal_proposals
                        .insert(proposal_id.clone(), submitted.clone());

                    FederationResponse::ProposalCreated {
                        proposal_id,
                        votes_needed: threshold,
                        current_votes: 0,
                    }
                } else {
                    // Withdrawal (v1 with previous set)
                    let proposal_id = submitted.prefix.clone();

                    let current = match self.pending_removal_proposals.get(&proposal_id) {
                        Some(p) => p,
                        None => return FederationResponse::ProposalNotFound(proposal_id),
                    };

                    if submitted.previous.as_deref() != Some(&current.said) {
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

                    let has_votes = self.votes.values().any(|v| v.proposal == proposal_id);
                    if has_votes {
                        return FederationResponse::HasVotes(format!(
                            "Cannot withdraw proposal {} — votes have been cast",
                            proposal_id
                        ));
                    }

                    let Some(v0) = self.pending_removal_proposals.remove(&proposal_id) else {
                        return FederationResponse::InternalError(
                            "Couldn't find proposal when removing from pending".to_string(),
                        );
                    };

                    info!(
                        proposal_id = %proposal_id,
                        "Removal proposal withdrawn by {}",
                        submitted.proposer
                    );

                    self.completed_removal_proposals
                        .push(vec![v0, submitted.clone()]);
                    FederationResponse::ProposalWithdrawn(proposal_id)
                }
            }
            FederationRequest::VoteCorePeer { proposal_id, vote } => {
                let voter = vote.voter.clone();
                let approve = vote.approve;
                let vote_said = vote.said.clone();

                // Determine if this is an addition or removal proposal
                let is_addition = self.pending_addition_proposals.contains_key(&proposal_id);
                let is_removal = self.pending_removal_proposals.contains_key(&proposal_id);

                if !is_addition && !is_removal {
                    if self
                        .completed_addition_proposals
                        .iter()
                        .any(|chain| chain.first().is_some_and(|p| p.prefix == proposal_id))
                        || self
                            .completed_removal_proposals
                            .iter()
                            .any(|chain| chain.first().is_some_and(|p| p.prefix == proposal_id))
                    {
                        return FederationResponse::ProposalNotFound(format!(
                            "{} (already completed)",
                            proposal_id
                        ));
                    }
                    return FederationResponse::ProposalNotFound(proposal_id);
                }

                // Get the proposal's threshold
                let proposal_threshold = if is_addition {
                    self.pending_addition_proposals
                        .get(&proposal_id)
                        .map(|p| p.threshold)
                        .unwrap_or(threshold)
                } else {
                    self.pending_removal_proposals
                        .get(&proposal_id)
                        .map(|p| p.threshold)
                        .unwrap_or(threshold)
                };

                // Check if expired
                let is_expired = if is_addition {
                    self.pending_addition_proposals
                        .get(&proposal_id)
                        .is_some_and(|p| p.is_expired())
                } else {
                    self.pending_removal_proposals
                        .get(&proposal_id)
                        .is_some_and(|p| p.is_expired())
                };

                if is_expired {
                    if is_addition {
                        if let Some(v0) = self.pending_addition_proposals.remove(&proposal_id) {
                            self.completed_addition_proposals.push(vec![v0]);
                        }
                    } else if let Some(v0) = self.pending_removal_proposals.remove(&proposal_id) {
                        self.completed_removal_proposals.push(vec![v0]);
                    }
                    return FederationResponse::ProposalExpired(proposal_id);
                }

                // Check if already voted
                let already_voted = self
                    .votes
                    .values()
                    .any(|v| v.proposal == proposal_id && v.voter == voter);
                if already_voted {
                    return FederationResponse::AlreadyVoted(proposal_id);
                }

                // Store vote
                self.votes.insert(vote_said, vote);

                // Count approval votes
                let current_votes = self
                    .votes
                    .values()
                    .filter(|v| v.proposal == proposal_id && v.approve)
                    .count();

                info!(
                    proposal_id = %proposal_id,
                    voter = %voter,
                    approve = approve,
                    "Vote recorded ({}/{} approvals)",
                    current_votes,
                    proposal_threshold
                );

                // Check if threshold met
                if current_votes >= proposal_threshold {
                    if is_addition {
                        let v0 = match self.pending_addition_proposals.remove(&proposal_id) {
                            Some(a) => a,
                            None => {
                                return FederationResponse::InternalError(
                                    "Couldn't find proposal when removing from pending".to_string(),
                                );
                            }
                        };
                        let peer_id = v0.peer_id.clone();

                        info!(
                            proposal_id = %proposal_id,
                            peer_id = %peer_id,
                            "Proposal approved - adding peer to core set"
                        );

                        let peer = match Peer::create(
                            peer_id.clone(),
                            v0.node_id.clone(),
                            leader_prefix.to_string(),
                            true,
                            PeerScope::Core,
                            v0.kels_url.clone(),
                            v0.gossip_multiaddr.clone(),
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                return FederationResponse::InternalError(format!(
                                    "Couldn't create peer: {}",
                                    e
                                ));
                            }
                        };

                        self.peers.insert(peer_id.clone(), peer.clone());
                        self.completed_addition_proposals.push(vec![v0]);

                        return FederationResponse::VoteRecorded {
                            proposal_id,
                            current_votes,
                            votes_needed: proposal_threshold,
                            approved: true,
                            peer: Some(Box::new(peer)),
                        };
                    } else {
                        let v0 = match self.pending_removal_proposals.remove(&proposal_id) {
                            Some(a) => a,
                            None => {
                                return FederationResponse::InternalError(
                                    "Couldn't find removal proposal when removing from pending"
                                        .to_string(),
                                );
                            }
                        };
                        let peer_id = v0.peer_id.clone();

                        info!(
                            proposal_id = %proposal_id,
                            peer_id = %peer_id,
                            "Removal proposal approved - removing peer from core set"
                        );

                        self.peers.remove(&peer_id);
                        self.completed_removal_proposals.push(vec![v0]);

                        return FederationResponse::RemovalApproved {
                            proposal_id,
                            peer_id,
                            current_votes,
                            votes_needed: proposal_threshold,
                        };
                    }
                }

                FederationResponse::VoteRecorded {
                    proposal_id,
                    current_votes,
                    votes_needed: proposal_threshold,
                    approved: false,
                    peer: None,
                }
            }
        }
    }

    /// Create a snapshot of the current state.
    fn snapshot(&self) -> CorePeerSnapshot {
        CorePeerSnapshot {
            peers: self.peers(),
            pending_addition_proposals: self.pending_addition_proposals.values().cloned().collect(),
            completed_addition_proposals: self.completed_addition_proposals.clone(),
            pending_removal_proposals: self.pending_removal_proposals.values().cloned().collect(),
            completed_removal_proposals: self.completed_removal_proposals.clone(),
            votes: self.votes.values().cloned().collect(),
        }
    }

    /// Count approval votes for a proposal.
    pub fn approval_count(&self, proposal_id: &str) -> usize {
        self.votes
            .values()
            .filter(|v| v.proposal == proposal_id && v.approve)
            .count()
    }

    /// Get a pending proposal by ID.
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&PeerAdditionProposal> {
        self.pending_addition_proposals.get(proposal_id)
    }

    /// Get all pending proposals.
    pub fn pending_proposals(&self) -> Vec<&PeerAdditionProposal> {
        self.pending_addition_proposals.values().collect()
    }

    /// Restore state from a snapshot and its metadata.
    fn restore(&mut self, snapshot: CorePeerSnapshot, meta: &SnapshotMeta<TypeConfig>) {
        self.last_applied_log = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();
        self.peers = snapshot
            .peers
            .into_iter()
            .map(|p| (p.peer_id.clone(), p))
            .collect();
        self.pending_addition_proposals = snapshot
            .pending_addition_proposals
            .into_iter()
            .map(|p| (p.prefix.clone(), p))
            .collect();
        self.completed_addition_proposals = snapshot.completed_addition_proposals;
        self.pending_removal_proposals = snapshot
            .pending_removal_proposals
            .into_iter()
            .map(|p| (p.prefix.clone(), p))
            .collect();
        self.completed_removal_proposals = snapshot.completed_removal_proposals;
        self.votes = snapshot
            .votes
            .into_iter()
            .map(|v| (v.said.clone(), v))
            .collect();
        info!(
            "Restored {} core peers, {} pending addition proposals, {} completed additions, {} pending removal proposals, {} completed removals, {} votes from snapshot",
            self.peers.len(),
            self.pending_addition_proposals.len(),
            self.completed_addition_proposals.len(),
            self.pending_removal_proposals.len(),
            self.completed_removal_proposals.len(),
            self.votes.len()
        );
    }
}

/// Thread-safe state machine store.
#[derive(Clone)]
pub struct StateMachineStore {
    inner: Arc<Mutex<StateMachineData>>,
    identity_client: Arc<IdentityClient>,
    /// Cached KELs from federation members (for SAID verification)
    member_kels: Arc<RwLock<HashMap<String, Kel>>>,
    /// Federation config (for refreshing member KELs)
    config: FederationConfig,
    /// Peer repository for direct DB writes
    peer_repo: Arc<PeerRepository>,
}

impl StateMachineStore {
    /// Create a new state machine store.
    pub fn new(
        identity_client: Arc<IdentityClient>,
        member_kels: Arc<RwLock<HashMap<String, Kel>>>,
        config: FederationConfig,
        peer_repo: Arc<PeerRepository>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateMachineData::default())),
            identity_client,
            member_kels,
            config,
            peer_repo,
        }
    }

    /// Get access to the inner data.
    pub fn inner(&self) -> &Arc<Mutex<StateMachineData>> {
        &self.inner
    }

    /// Refresh all member KELs from their registries.
    async fn refresh_all_member_kels(&self) -> Result<(), String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;

        let mut kels = self.member_kels.write().await;
        for member in &self.config.members {
            let url = format!("{}/api/registry-kel", member.url.trim_end_matches('/'));
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<Kel>().await {
                        Ok(kel) => {
                            if kel.verify().is_ok() {
                                kels.insert(member.prefix.clone(), kel);
                            }
                        }
                        Err(e) => {
                            warn!(member = %member.prefix, error = %e, "Failed to parse member KEL");
                        }
                    }
                }
                Ok(response) => {
                    warn!(member = %member.prefix, status = %response.status(), "Failed to fetch member KEL");
                }
                Err(e) => {
                    warn!(member = %member.prefix, error = %e, "Failed to fetch member KEL");
                }
            }
        }
        Ok(())
    }

    /// Verify a SAID is anchored in a federation member's KEL.
    /// This proves the member signed/authorized the data with the given SAID.
    pub async fn verify_member_anchoring(
        &self,
        said: &str,
        member_prefix: &str,
    ) -> Result<(), String> {
        // Check member is a known federation member
        if !self
            .config
            .members
            .iter()
            .any(|m| m.prefix == member_prefix)
        {
            return Err(format!("Unknown member: {}", member_prefix));
        }

        // Get member's KEL from cache first
        let cached_kel = {
            let kels = self.member_kels.read().await;
            kels.get(member_prefix).cloned()
        };

        // Check cached KEL first
        if let Some(ref kel) = cached_kel
            && kel.contains_anchor(said)
        {
            kel.verify()
                .map_err(|e| format!("Member KEL verification failed: {}", e))?;
            return Ok(());
        }

        // Not found in cache - refresh member's KEL and try again
        if let Err(e) = self.refresh_all_member_kels().await {
            return Err(format!("Failed to fetch member KEL: {}", e));
        }

        let kel = {
            let kels = self.member_kels.read().await;
            kels.get(member_prefix)
                .cloned()
                .ok_or_else(|| format!("Could not fetch KEL for member: {}", member_prefix))?
        };

        // Verify KEL integrity
        kel.verify()
            .map_err(|e| format!("Member KEL verification failed: {}", e))?;

        // Check SAID is anchored in member's KEL - this IS the signature
        if !kel.contains_anchor(said) {
            return Err(format!("SAID {} not anchored in member's KEL", said));
        }

        Ok(())
    }

    /// Upsert a peer to the local DB using the same pattern as admin CLI.
    async fn upsert_peer_to_db(&self, peer: &Peer) -> Result<(), String> {
        // Query for existing peer by node_id
        let query = Query::<Peer>::new()
            .eq("node_id", &peer.node_id)
            .order_by("version", Order::Desc)
            .limit(1);
        let existing: Vec<Peer> = self
            .peer_repo
            .pool
            .fetch(query)
            .await
            .map_err(|e| e.to_string())?;

        let db_peer = match existing.first() {
            Some(latest)
                if latest.active
                    && latest.peer_id == peer.peer_id
                    && latest.scope == PeerScope::Core
                    && latest.kels_url == peer.kels_url
                    && latest.gossip_multiaddr == peer.gossip_multiaddr =>
            {
                // Already exists with same data, skip
                debug!(peer_id = %peer.peer_id, "Peer already exists in local DB");
                return Ok(());
            }
            Some(latest) => {
                // Existing node - clone, update fields, increment version
                let mut updated = latest.clone();
                updated.peer_id = peer.peer_id.clone();
                updated.active = peer.active;
                updated.scope = PeerScope::Core;
                updated.kels_url = peer.kels_url.clone();
                updated.gossip_multiaddr = peer.gossip_multiaddr.clone();
                updated.increment().map_err(|e| e.to_string())?;
                updated
            }
            None => {
                // New peer - create version 0
                Peer::create(
                    peer.peer_id.clone(),
                    peer.node_id.clone(),
                    self.config.self_prefix.clone(),
                    peer.active,
                    PeerScope::Core,
                    peer.kels_url.clone(),
                    peer.gossip_multiaddr.clone(),
                )
                .map_err(|e| e.to_string())?
            }
        };

        self.peer_repo
            .insert(db_peer)
            .await
            .map_err(|e| e.to_string())?;

        info!(peer_id = %peer.peer_id, "Wrote core peer to local DB");
        Ok(())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
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

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<TypeConfig>>, StoredMembership<TypeConfig>), io::Error> {
        let sm = self.inner.lock().await;
        Ok((sm.last_applied_log, sm.last_membership.clone()))
    }

    async fn apply<S>(&mut self, mut entries: S) -> Result<(), io::Error>
    where
        S: futures::Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>>
            + OptionalSend
            + Unpin,
    {
        let mut sm = self.inner.lock().await;

        while let Some(entry_result) = entries.next().await {
            let (entry, responder): EntryResponder<TypeConfig> = entry_result?;

            sm.last_applied_log = Some(entry.log_id);

            let response = match entry.payload.clone() {
                EntryPayload::Blank => FederationResponse::Ok,
                EntryPayload::Normal(request) => {
                    // For AddPeer, verify votes (core peers) and KEL anchoring
                    if let FederationRequest::AddPeer(ref peer) = request {
                        if peer.scope == PeerScope::Core {
                            let threshold = self.config.approval_threshold();
                            let member_prefixes: std::collections::HashSet<&str> = self
                                .config
                                .members
                                .iter()
                                .map(|m| m.prefix.as_str())
                                .collect();

                            let candidate_voters =
                                sm.verified_voters_for_peer(&peer.peer_id, &member_prefixes);

                            // Verify each vote's SAID integrity and KEL anchoring
                            let mut verified_voters = std::collections::HashSet::new();
                            for voter in &candidate_voters {
                                // Find votes for approved proposals for this peer
                                for chain in &sm.completed_addition_proposals {
                                    if let Some(v0) = chain.first()
                                        && v0.peer_id == peer.peer_id
                                        && !chain.last().is_some_and(|p| p.is_withdrawn())
                                    {
                                        let proposal_id = &v0.prefix;
                                        for vote in sm.votes.values() {
                                            if vote.proposal == *proposal_id
                                                && &vote.voter == voter
                                                && vote.approve
                                                && vote.verify_said().is_ok()
                                                && self
                                                    .verify_member_anchoring(
                                                        &vote.said,
                                                        &vote.voter,
                                                    )
                                                    .await
                                                    .is_ok()
                                            {
                                                verified_voters.insert(voter.clone());
                                            }
                                        }
                                    }
                                }
                            }

                            if verified_voters.len() < threshold {
                                warn!(
                                    peer_id = %peer.peer_id,
                                    verified = verified_voters.len(),
                                    threshold = threshold,
                                    "Core peer not backed by sufficient verified votes - rejecting"
                                );
                                if let Some(r) = responder {
                                    r.send(FederationResponse::Ok);
                                }
                                continue;
                            }
                        }

                        // Verify SAID is anchored in authorizing member's KEL
                        if self
                            .verify_member_anchoring(&peer.said, &peer.authorizing_kel)
                            .await
                            .is_err()
                        {
                            warn!(
                                peer_id = %peer.peer_id,
                                said = %peer.said,
                                "Peer SAID not found in any member KEL - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        // Anchor in our own KEL
                        if let Err(e) = self.identity_client.anchor(&peer.said).await {
                            warn!(
                                peer_id = %peer.peer_id,
                                said = %peer.said,
                                error = %e,
                                "Failed to anchor peer SAID in our KEL - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::Ok);
                            }
                            continue;
                        }

                        info!(
                            peer_id = %peer.peer_id,
                            said = %peer.said,
                            "Verified and anchored peer SAID in our KEL"
                        );

                        if let Err(e) = self.upsert_peer_to_db(peer).await {
                            warn!(
                                peer_id = %peer.peer_id,
                                error = %e,
                                "Failed to write peer to local DB"
                            );
                        }
                    }

                    // Verify vote anchoring
                    if let FederationRequest::VoteCorePeer {
                        ref proposal_id,
                        ref vote,
                    } = request
                    {
                        if vote.proposal != *proposal_id {
                            warn!(
                                vote_proposal = %vote.proposal,
                                expected = %proposal_id,
                                "Vote proposal mismatch - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Vote is for proposal {} but submitted to {}",
                                    vote.proposal, proposal_id
                                )));
                            }
                            continue;
                        }

                        if let Some(proposal) = sm.pending_addition_proposals.get(proposal_id)
                            && let Err(e) = proposal.verify()
                        {
                            warn!(proposal_id = %proposal_id, error = %e, "Proposal verification failed - rejecting vote");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal invalid: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        if let Some(proposal) = sm.pending_removal_proposals.get(proposal_id)
                            && let Err(e) = proposal.verify()
                        {
                            warn!(proposal_id = %proposal_id, error = %e, "Removal proposal verification failed - rejecting vote");
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

                        if let Err(e) = self.verify_member_anchoring(&vote.said, &vote.voter).await
                        {
                            warn!(voter = %vote.voter, error = %e, "Vote not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    // Verify addition proposal anchoring
                    if let FederationRequest::SubmitAdditionProposal(ref prop) = request {
                        if prop.threshold != self.config.approval_threshold() {
                            warn!(
                                proposer = %prop.proposer,
                                proposal_threshold = prop.threshold,
                                current_threshold = self.config.approval_threshold(),
                                "Addition proposal threshold mismatch - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal threshold {} doesn't match current threshold {}",
                                    prop.threshold,
                                    self.config.approval_threshold()
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = self
                            .verify_member_anchoring(&prop.said, &prop.proposer)
                            .await
                        {
                            warn!(proposer = %prop.proposer, error = %e, "Addition proposal not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    // Verify removal proposal anchoring
                    if let FederationRequest::SubmitRemovalProposal(ref prop) = request {
                        // Verify threshold matches current
                        if prop.threshold != self.config.approval_threshold() {
                            warn!(
                                proposer = %prop.proposer,
                                proposal_threshold = prop.threshold,
                                current_threshold = self.config.approval_threshold(),
                                "Removal proposal threshold mismatch - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal threshold {} doesn't match current threshold {}",
                                    prop.threshold,
                                    self.config.approval_threshold()
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = self
                            .verify_member_anchoring(&prop.said, &prop.proposer)
                            .await
                        {
                            warn!(proposer = %prop.proposer, error = %e, "Removal proposal not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    let threshold = self.config.approval_threshold();
                    let leader_prefix = &self.config.self_prefix;
                    let response = sm.apply(request.clone(), threshold, leader_prefix);

                    // If a proposal was approved, write the peer to DB and anchor
                    if let FederationResponse::VoteRecorded {
                        approved: true,
                        ref peer,
                        ..
                    } = response
                        && let Some(peer) = peer
                    {
                        if let Err(e) = self.identity_client.anchor(&peer.said).await {
                            if let Some(r) = responder {
                                r.send(FederationResponse::InternalError(format!(
                                    "Failed to anchor approved peer SAID in our KEL: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        if let Err(e) = self.upsert_peer_to_db(peer).await {
                            warn!(
                                peer_id = %peer.peer_id,
                                error = %e,
                                "Failed to write approved peer to local DB"
                            );
                        }
                    }

                    // If a removal proposal was approved, deactivate peer in DB and anchor
                    if let FederationResponse::RemovalApproved { ref peer_id, .. } = response {
                        // Find the peer in DB and deactivate it
                        let query = Query::<Peer>::new()
                            .eq("peer_id", peer_id)
                            .order_by("version", Order::Desc)
                            .limit(1);
                        let existing: Vec<Peer> =
                            self.peer_repo.pool.fetch(query).await.unwrap_or_default();

                        if let Some(latest) = existing.first()
                            && latest.active
                        {
                            match latest.deactivate() {
                                Ok(deactivated) => {
                                    if let Err(e) =
                                        self.identity_client.anchor(&deactivated.said).await
                                    {
                                        warn!(
                                            peer_id = %peer_id,
                                            error = %e,
                                            "Failed to anchor deactivated peer SAID in our KEL"
                                        );
                                    }

                                    if let Err(e) = self.peer_repo.insert(deactivated).await {
                                        warn!(
                                            peer_id = %peer_id,
                                            error = %e,
                                            "Failed to deactivate peer in local DB"
                                        );
                                    } else {
                                        info!(peer_id = %peer_id, "Deactivated removed core peer in local DB");
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        peer_id = %peer_id,
                                        error = %e,
                                        "Failed to create deactivated peer record"
                                    );
                                }
                            }
                        }
                    }

                    response
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

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<TypeConfig>,
        snapshot: Cursor<Vec<u8>>,
    ) -> Result<(), io::Error> {
        let data = snapshot.into_inner();
        let mut core_snapshot: CorePeerSnapshot = serde_json::from_slice(&data)
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
    use kels::PeerScope;
    use openraft::{SnapshotMeta, StoredMembership};
    use verifiable_storage::{Chained, StorageDatetime};

    const TEST_THRESHOLD: usize = 2;
    const TEST_ANCHORING_PREFIX: &str = "ETestLeader";

    fn test_expires_at() -> StorageDatetime {
        (chrono::Utc::now() + chrono::Duration::days(7)).into()
    }

    fn make_test_peer(peer_id: &str, node_id: &str) -> Peer {
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
        )
        .unwrap()
    }

    fn make_inactive_peer(peer_id: &str, node_id: &str) -> Peer {
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            false,
            PeerScope::Core,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
        )
        .unwrap()
    }

    fn make_test_vote(proposal: &str, voter: &str, approve: bool) -> Vote {
        Vote::create(proposal.to_string(), voter.to_string(), approve).unwrap()
    }

    fn make_test_proposal(peer_id: &str, node_id: &str, proposer: &str) -> PeerAdditionProposal {
        PeerAdditionProposal::empty(
            peer_id,
            node_id,
            &format!("http://{}:8080", node_id),
            &format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
            proposer,
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

    /// Helper: submit a proposal, returns proposal_id
    fn submit_proposal(sm: &mut StateMachineData, proposal: PeerAdditionProposal) -> String {
        match sm.apply(
            FederationRequest::SubmitAdditionProposal(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        }
    }

    /// Helper: run a full proposal through to approval, returning the proposal_id
    fn approve_peer(sm: &mut StateMachineData, peer_id: &str, node_id: &str) -> String {
        let proposal = make_test_proposal(peer_id, node_id, "ERegistryA");
        let proposal_id = submit_proposal(sm, proposal);

        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let vote_b = make_test_vote(&proposal_id, "ERegistryB", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_b,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        proposal_id
    }

    fn trusted_members() -> std::collections::HashSet<&'static str> {
        ["ERegistryA", "ERegistryB", "ERegistryC"]
            .into_iter()
            .collect()
    }

    // ==================== AddPeer / RemovePeer Tests ====================

    #[test]
    fn test_add_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");
        let response = sm.apply(
            FederationRequest::AddPeer(peer),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerAdded(_)));
        assert_eq!(sm.peers().len(), 1);
        assert!(sm.get_peer("peer-1").is_some());
    }

    #[test]
    fn test_add_multiple_peers() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-2", "node-2")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-3", "node-3")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.peers().len(), 3);
    }

    #[test]
    fn test_add_peer_overwrites_existing() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-1");
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-2")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-2");
        assert_eq!(sm.peers().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        let response = sm.apply(
            FederationRequest::RemovePeer("peer-1".to_string()),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerRemoved(_)));
        assert!(sm.peers().is_empty());
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let mut sm = StateMachineData::new();
        let response = sm.apply(
            FederationRequest::RemovePeer("nonexistent".to_string()),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerNotFound(_)));
    }

    #[test]
    fn test_remove_one_of_many_peers() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-2", "node-2")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-3", "node-3")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm.apply(
            FederationRequest::RemovePeer("peer-2".to_string()),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.peers().len(), 2);
        assert!(sm.get_peer("peer-1").is_some());
        assert!(sm.get_peer("peer-2").is_none());
        assert!(sm.get_peer("peer-3").is_some());
    }

    #[test]
    fn test_get_peer_not_found() {
        let sm = StateMachineData::new();
        assert!(sm.get_peer("nonexistent").is_none());
    }

    #[test]
    fn test_inactive_peer_can_be_added() {
        let mut sm = StateMachineData::new();
        let response = sm.apply(
            FederationRequest::AddPeer(make_inactive_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerAdded(_)));
        assert!(!sm.get_peer("peer-1").unwrap().active);
    }

    #[test]
    fn test_state_machine_data_default() {
        let sm = StateMachineData::default();
        assert!(sm.peers.is_empty());
        assert!(sm.pending_addition_proposals.is_empty());
        assert!(sm.last_applied_log.is_none());
    }

    // ==================== Snapshot Tests ====================

    #[test]
    fn test_snapshot_empty_state() {
        let sm = StateMachineData::new();
        let snapshot = sm.snapshot();
        assert!(snapshot.peers.is_empty());
    }

    #[test]
    fn test_snapshot_restore() {
        let mut sm1 = StateMachineData::new();
        sm1.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        sm1.apply(
            FederationRequest::AddPeer(make_test_peer("peer-2", "node-2")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let snapshot = sm1.snapshot();
        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "test-snapshot".to_string(),
        };

        let mut sm2 = StateMachineData::new();
        sm2.restore(snapshot, &meta);
        assert_eq!(sm2.peers().len(), 2);
        assert!(sm2.get_peer("peer-1").is_some());
        assert!(sm2.get_peer("peer-2").is_some());
    }

    #[test]
    fn test_peers_returns_cloned_values() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        let peers = sm.peers();
        assert_eq!(peers.len(), 1);
        assert!(sm.get_peer("peer-1").is_some());
    }

    // ==================== Proposal Tests ====================

    #[test]
    fn test_submit_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        assert!(sm.get_peer("peer-1").is_none());
        assert!(sm.get_proposal(&proposal_id).is_some());
    }

    #[test]
    fn test_vote_approves_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let vote_b = make_test_vote(&proposal_id, "ERegistryB", true);
        let response = sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_b,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        match response {
            FederationResponse::VoteRecorded {
                proposal_id: resp_id,
                current_votes,
                votes_needed,
                approved,
                peer,
            } => {
                assert_eq!(resp_id, proposal_id);
                assert_eq!(current_votes, 2);
                assert_eq!(votes_needed, TEST_THRESHOLD);
                assert!(approved);
                assert!(peer.is_some());
            }
            _ => panic!("Expected VoteRecorded, got {:?}", response),
        }

        assert!(sm.get_peer("peer-1").is_some());
        assert!(sm.get_proposal(&proposal_id).is_none());
        assert_eq!(sm.completed_addition_proposals.len(), 1);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let vote = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let vote2 = make_test_vote(&proposal_id, "ERegistryA", true);
        let response = sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id,
                vote: vote2,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::AlreadyVoted(_)));
    }

    #[test]
    fn test_proposal_for_existing_peer_rejected() {
        let mut sm = StateMachineData::new();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("peer-1", "node-1")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let response = sm.apply(
            FederationRequest::SubmitAdditionProposal(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerAlreadyExists(_)));
    }

    #[test]
    fn test_withdraw_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_id).unwrap().clone();
        let withdrawal = make_withdrawal(&current);

        let response = sm.apply(
            FederationRequest::SubmitAdditionProposal(withdrawal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        assert!(matches!(response, FederationResponse::ProposalWithdrawn(_)));
        assert!(sm.get_proposal(&proposal_id).is_none());
        assert_eq!(sm.completed_addition_proposals.len(), 1);
        assert_eq!(sm.completed_addition_proposals[0].len(), 2);
        assert!(sm.completed_addition_proposals[0][1].is_withdrawn());
    }

    #[test]
    fn test_only_proposer_can_withdraw() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_id).unwrap().clone();
        let mut withdrawal = current.clone();
        withdrawal.proposer = "ERegistryB".to_string();
        withdrawal.withdrawn_at = Some(StorageDatetime::now());
        let _ = withdrawal.increment();

        let response = sm.apply(
            FederationRequest::SubmitAdditionProposal(withdrawal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::NotAuthorized(_)));
        assert!(sm.get_proposal(&proposal_id).is_some());
    }

    #[test]
    fn test_withdraw_with_votes_rejected() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        // Cast a vote first
        let vote = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        // Now try to withdraw
        let current = sm.get_proposal(&proposal_id).unwrap().clone();
        let withdrawal = make_withdrawal(&current);

        let response = sm.apply(
            FederationRequest::SubmitAdditionProposal(withdrawal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::HasVotes(_)));
        // Proposal should still be pending
        assert!(sm.get_proposal(&proposal_id).is_some());
    }

    #[test]
    fn test_vote_on_nonexistent_proposal() {
        let mut sm = StateMachineData::new();
        let vote = make_test_vote("nonexistent", "ERegistryA", true);
        let response = sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: "nonexistent".to_string(),
                vote,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::ProposalNotFound(_)));
    }

    #[test]
    fn test_rejection_vote_recorded() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let vote_b = make_test_vote(&proposal_id, "ERegistryB", false);
        let response = sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id,
                vote: vote_b,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

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
        assert!(sm.get_peer("peer-1").is_none());
    }

    #[test]
    fn test_proposal_snapshot_restore() {
        let mut sm1 = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm1, proposal);

        let snapshot = sm1.snapshot();
        assert_eq!(snapshot.pending_addition_proposals.len(), 1);

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "test-snapshot".to_string(),
        };

        let mut sm2 = StateMachineData::new();
        sm2.restore(snapshot, &meta);
        assert!(sm2.get_proposal(&proposal_id).is_some());
    }

    // ==================== Rogue Leader / Vote Verification Tests ====================

    #[test]
    fn test_verified_voters_with_approved_proposal() {
        let mut sm = StateMachineData::new();
        let members = trusted_members();
        approve_peer(&mut sm, "peer-1", "node-1");

        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert_eq!(voters.len(), 2);
        assert!(voters.contains("ERegistryA"));
        assert!(voters.contains("ERegistryB"));
    }

    #[test]
    fn test_verified_voters_no_proposal() {
        let sm = StateMachineData::new();
        let members = trusted_members();
        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_rogue_leader_adds_peer_without_proposal() {
        let mut sm = StateMachineData::new();
        let members = trusted_members();
        sm.apply(
            FederationRequest::AddPeer(make_test_peer("rogue-peer", "rogue-node")),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(sm.get_peer("rogue-peer").is_some());
        let voters = sm.verified_voters_for_peer("rogue-peer", &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_insufficient_votes() {
        let mut sm = StateMachineData::new();
        let members = trusted_members();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id,
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert!(voters.is_empty());
    }

    #[test]
    fn test_verified_voters_ignores_untrusted_voter() {
        let mut sm = StateMachineData::new();
        let members: std::collections::HashSet<&str> =
            ["ERegistryA", "ERegistryB"].into_iter().collect();

        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let vote_c = make_test_vote(&proposal_id, "ERegistryC", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id,
                vote: vote_c,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert_eq!(voters.len(), 1);
        assert!(voters.contains("ERegistryA"));
    }

    #[test]
    fn test_verified_voters_ignores_rejection_votes() {
        let mut sm = StateMachineData::new();
        let members = trusted_members();
        approve_peer(&mut sm, "peer-1", "node-1");

        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert_eq!(voters.len(), 2);
    }

    #[test]
    fn test_verified_voters_withdrawn_proposal_not_counted() {
        let mut sm = StateMachineData::new();
        let members = trusted_members();

        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = submit_proposal(&mut sm, proposal);

        let current = sm.get_proposal(&proposal_id).unwrap().clone();
        let withdrawal = make_withdrawal(&current);
        sm.apply(
            FederationRequest::SubmitAdditionProposal(withdrawal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let voters = sm.verified_voters_for_peer("peer-1", &members);
        assert!(voters.is_empty());
    }
}
