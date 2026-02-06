//! Raft state machine for the core peer set.

use super::config::FederationConfig;
use super::types::{
    CorePeerSnapshot, FederationRequest, FederationResponse, PeerProposal, ProposalStatus,
    TypeConfig, Vote,
};
use crate::identity_client::IdentityClient;
use crate::peer_store::PeerRepository;
use futures::stream::StreamExt;
use kels::{Kel, Peer, PeerScope};
use openraft::storage::EntryResponder;
use openraft::{
    EntryPayload, LogId, OptionalSend, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StoredMembership, storage::RaftStateMachine,
};
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use verifiable_storage::{Chained, ChainedRepository, SelfAddressed};
use verifiable_storage_postgres::{Order, Query, QueryExecutor};

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
    /// Pending proposals awaiting votes (keyed by proposal_id)
    pub pending_proposals: HashMap<String, PeerProposal>,
    /// Completed proposals for audit trail
    pub completed_proposals: Vec<PeerProposal>,
    /// Votes stored by SAID (for privacy - proposals only store SAIDs)
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
                info!("Adding core peer: {} (node: {})", peer_id, peer.node_id);
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
            FederationRequest::ProposeCorePeer(ref peer_proposal) => {
                // Check if peer already exists in core set
                if self.peers.contains_key(&peer_proposal.peer_id) {
                    return FederationResponse::PeerAlreadyExists(peer_proposal.peer_id.clone());
                }

                // Check if there's already a pending proposal for this peer
                for proposal in self.pending_proposals.values() {
                    if proposal.peer_id == peer_proposal.peer_id {
                        return FederationResponse::ProposalAlreadyExists(proposal.prefix.clone());
                    }
                }

                let proposal_id = peer_proposal.prefix.clone();

                info!(
                    proposal_id = %proposal_id,
                    peer_id = %peer_proposal.peer_id,
                    proposer = %peer_proposal.authorizing_kel,
                    "Created empty core peer proposal (v0, awaiting proposer vote)"
                );

                self.pending_proposals
                    .insert(proposal_id.clone(), peer_proposal.clone());

                FederationResponse::ProposalCreated {
                    proposal_id,
                    votes_needed: threshold,
                    current_votes: 0,
                }
            }
            FederationRequest::VoteCorePeer { proposal_id, vote } => {
                // Note: SAID + anchoring verification done in async layer before this is called

                let voter = vote.voter.clone();
                let approve = vote.approve;
                let vote_said = vote.said.clone();

                // Find the proposal
                let proposal = match self.pending_proposals.get_mut(&proposal_id) {
                    Some(p) => p,
                    None => {
                        // Check if it's in completed proposals
                        if self
                            .completed_proposals
                            .iter()
                            .any(|p| p.prefix == proposal_id)
                        {
                            return FederationResponse::ProposalNotFound(format!(
                                "{} (already completed)",
                                proposal_id
                            ));
                        }
                        return FederationResponse::ProposalNotFound(proposal_id);
                    }
                };

                // Check if expired
                if proposal.is_expired() {
                    let Some(mut expired) = self.pending_proposals.remove(&proposal_id) else {
                        return FederationResponse::ProposalNotFound(proposal_id);
                    };
                    expired.status = ProposalStatus::Rejected;
                    // Increment chain to record status change
                    if let Err(e) = expired.increment() {
                        warn!("Failed to increment proposal after expiry: {}", e);
                    }
                    self.completed_proposals.push(expired);
                    return FederationResponse::ProposalExpired(proposal_id);
                }

                // Load existing votes for this proposal (privacy: only SAIDs stored in proposal)
                let existing_votes: Vec<Vote> = proposal
                    .approvals
                    .iter()
                    .chain(proposal.rejections.iter())
                    .filter_map(|said| self.votes.get(said).cloned())
                    .collect();

                // Check if already voted
                if proposal.has_voted(&voter, &existing_votes) {
                    return FederationResponse::AlreadyVoted(proposal_id);
                }

                // Store vote by SAID
                self.votes.insert(vote_said, vote.clone());

                // Record vote and increment the chain (updates SAID, sets previous)
                if let Err(e) = proposal.add_vote(vote, leader_prefix) {
                    warn!("Failed to add vote to proposal: {}", e);
                }
                let current_votes = proposal.approval_count();

                info!(
                    proposal_id = %proposal_id,
                    voter = %voter,
                    approve = approve,
                    "Vote recorded ({}/{} approvals)",
                    current_votes,
                    threshold
                );

                // Check if threshold met
                if current_votes >= threshold {
                    let mut approved = match self.pending_proposals.remove(&proposal_id) {
                        Some(a) => a,
                        None => {
                            return FederationResponse::InternalError(
                                "Couldn't find proposal when removing from pending".to_string(),
                            );
                        }
                    };
                    approved.status = ProposalStatus::Approved;
                    // Increment chain to record status change
                    if let Err(e) = approved.increment() {
                        return FederationResponse::InternalError(format!(
                            "Could not increment approval: {}",
                            e
                        ));
                    }
                    let peer_id = approved.peer_id.clone();

                    info!(
                        proposal_id = %proposal_id,
                        peer_id = %peer_id,
                        "Proposal approved - adding peer to core set"
                    );

                    let peer = match Peer::create(
                        peer_id.clone(),
                        approved.node_id.clone(),
                        true,
                        PeerScope::Core,
                        approved.kels_url.clone(),
                        approved.gossip_multiaddr.clone(),
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            return FederationResponse::InternalError(format!(
                                "Couldn't create peer: {}",
                                e
                            ));
                        }
                    };

                    // Add peer to core set
                    self.peers.insert(peer_id.clone(), peer.clone());
                    self.completed_proposals.push(approved);

                    return FederationResponse::VoteRecorded {
                        proposal_id,
                        current_votes,
                        votes_needed: threshold,
                        status: ProposalStatus::Approved,
                        peer: Some(peer.clone()),
                    };
                }

                FederationResponse::VoteRecorded {
                    proposal_id,
                    current_votes,
                    votes_needed: threshold,
                    status: ProposalStatus::Pending,
                    peer: None,
                }
            }
            FederationRequest::WithdrawProposal {
                proposal_id,
                withdrawer,
            } => {
                let proposal = match self.pending_proposals.get(&proposal_id) {
                    Some(p) => p,
                    None => return FederationResponse::ProposalNotFound(proposal_id),
                };

                // Only proposer can withdraw
                if proposal.proposer != withdrawer {
                    return FederationResponse::NotAuthorized(format!(
                        "Only proposer {} can withdraw proposal",
                        proposal.proposer
                    ));
                }

                let Some(mut withdrawn) = self.pending_proposals.remove(&proposal_id) else {
                    return FederationResponse::ProposalNotFound(proposal_id);
                };
                withdrawn.status = ProposalStatus::Withdrawn;
                if let Err(e) = withdrawn.increment() {
                    warn!("Failed to increment proposal after withdrawal: {}", e);
                }

                info!(
                    proposal_id = %proposal_id,
                    "Proposal withdrawn by {}",
                    withdrawer
                );

                self.completed_proposals.push(withdrawn);
                FederationResponse::ProposalWithdrawn(proposal_id)
            }
        }
    }

    /// Create a snapshot of the current state.
    fn snapshot(&self) -> CorePeerSnapshot {
        CorePeerSnapshot {
            peers: self.peers(),
            pending_proposals: self.pending_proposals.values().cloned().collect(),
            completed_proposals: self.completed_proposals.clone(),
            votes: self.votes.values().cloned().collect(),
        }
    }

    /// Get a pending proposal by ID.
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&PeerProposal> {
        self.pending_proposals.get(proposal_id)
    }

    /// Get all pending proposals.
    pub fn pending_proposals(&self) -> Vec<&PeerProposal> {
        self.pending_proposals.values().collect()
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
        self.pending_proposals = snapshot
            .pending_proposals
            .into_iter()
            .map(|p| (p.prefix.clone(), p))
            .collect();
        self.completed_proposals = snapshot.completed_proposals;
        self.votes = snapshot
            .votes
            .into_iter()
            .map(|v| (v.said.clone(), v))
            .collect();
        info!(
            "Restored {} core peers, {} pending proposals, {} votes from snapshot",
            self.peers.len(),
            self.pending_proposals.len(),
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

    /// Check if a SAID is anchored in any member's KEL, refreshing if needed.
    async fn verify_said_in_member_kel(&self, said: &str) -> bool {
        // First check with cached KELs
        {
            let kels = self.member_kels.read().await;
            for kel in kels.values() {
                if kel.contains_anchor(said) {
                    return true;
                }
            }
        }

        // Not found - refresh all member KELs and try again
        debug!(said = %said, "SAID not in cached KELs, refreshing member KELs");
        if let Err(e) = self.refresh_all_member_kels().await {
            warn!(error = %e, "Failed to refresh member KELs");
            return false;
        }

        // Check again with fresh KELs
        let kels = self.member_kels.read().await;
        for kel in kels.values() {
            if kel.contains_anchor(said) {
                return true;
            }
        }
        false
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
    async fn verify_member_anchoring(&self, said: &str, member_prefix: &str) -> Result<(), String> {
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
                    // For AddPeer, verify SAID is in a member's KEL, then anchor in ours
                    if let FederationRequest::AddPeer(ref peer) = request {
                        // Verify SAID is anchored in some member's KEL (refreshes if needed)
                        if !self.verify_said_in_member_kel(&peer.said).await {
                            warn!(
                                peer_id = %peer.peer_id,
                                said = %peer.said,
                                "Peer SAID not found in any member KEL - rejecting"
                            );
                            // Skip this entry - don't apply
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

                        // Write directly to local DB using upsert pattern
                        if let Err(e) = self.upsert_peer_to_db(peer).await {
                            warn!(
                                peer_id = %peer.peer_id,
                                error = %e,
                                "Failed to write peer to local DB"
                            );
                        }
                    }

                    // Verify vote anchoring for votes (ProposeCorePeer has no vote - proposer votes separately)
                    if let FederationRequest::VoteCorePeer {
                        ref proposal_id,
                        ref vote,
                    } = request
                    {
                        // Verify vote references the correct proposal
                        if vote.proposal != *proposal_id {
                            warn!(
                                vote_proposal = %vote.proposal,
                                expected = %proposal_id,
                                "Vote proposal_prefix mismatch - rejecting"
                            );
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Vote is for proposal {} but submitted to {}",
                                    vote.proposal, proposal_id
                                )));
                            }
                            continue;
                        }

                        // Verify proposal chain integrity before accepting vote
                        if let Some(proposal) = sm.pending_proposals.get(proposal_id)
                            && let Err(e) = proposal.verify()
                        {
                            warn!(proposal_id = %proposal_id, error = %e, "Proposal chain verification failed - rejecting vote");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(format!(
                                    "Proposal chain invalid: {}",
                                    e
                                )));
                            }
                            continue;
                        }

                        // Verify vote SAID integrity
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

                        // Verify vote is anchored in voter's KEL
                        if let Err(e) = self.verify_member_anchoring(&vote.said, &vote.voter).await
                        {
                            warn!(voter = %vote.voter, error = %e, "Vote not anchored - rejecting");
                            if let Some(r) = responder {
                                r.send(FederationResponse::NotAuthorized(e));
                            }
                            continue;
                        }
                    }

                    // Verify proposal request is anchored in proposer's KEL
                    if let FederationRequest::ProposeCorePeer(ref req) = request
                        && let Err(e) = self.verify_member_anchoring(&req.said, &req.proposer).await
                    {
                        warn!(proposer = %req.proposer, error = %e, "Proposal request not anchored - rejecting");
                        if let Some(r) = responder {
                            r.send(FederationResponse::NotAuthorized(e));
                        }
                        continue;
                    }

                    // For proposals that get approved, we also need to write the peer to DB
                    let threshold = self.config.approval_threshold();
                    let leader_prefix = &self.config.self_prefix;
                    let response = sm.apply(request.clone(), threshold, leader_prefix);

                    // If a proposal was approved, write the peer to DB
                    if let FederationResponse::VoteRecorded {
                        status: ProposalStatus::Approved,
                        peer,
                        ..
                    } = &response
                    {
                        // Get the peer from the request (it was a VoteCorePeer that triggered approval)
                        if let FederationRequest::VoteCorePeer { proposal_id, .. } = &request {
                            let Some(peer) = peer else {
                                if let Some(r) = responder {
                                    r.send(FederationResponse::InternalError(
                                        "Failed find peer in response:".to_string(),
                                    ));
                                }
                                continue;
                            };

                            // The peer should now be in sm.peers - find it by checking completed proposals
                            if sm
                                .completed_proposals
                                .iter()
                                .any(|p| &p.prefix == proposal_id)
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

        // Verify all proposal chains before restoring
        let original_count = core_snapshot.pending_proposals.len();
        let mut valid_proposals = Vec::new();
        for proposal in core_snapshot.pending_proposals {
            if let Err(e) = proposal.verify() {
                warn!(
                    proposal_prefix = %proposal.prefix,
                    error = %e,
                    "Proposal chain verification failed during snapshot restore - skipping"
                );
                continue;
            }
            valid_proposals.push(proposal);
        }

        let removed_count = original_count - valid_proposals.len();
        if removed_count > 0 {
            warn!(
                removed = removed_count,
                "Removed proposals with invalid chains during snapshot restore"
            );
        }
        core_snapshot.pending_proposals = valid_proposals;

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
    use crate::federation::Vote;
    use kels::PeerScope;
    use openraft::{SnapshotMeta, StoredMembership};
    use verifiable_storage::StorageDatetime;

    // Default threshold for tests (simulates a 3-member federation)
    const TEST_THRESHOLD: usize = 2;
    // Test anchoring prefix (the leader's prefix)
    const TEST_ANCHORING_PREFIX: &str = "ETestLeader";

    /// Create a test expiration time 7 days in the future
    fn test_expires_at() -> StorageDatetime {
        (chrono::Utc::now() + chrono::Duration::days(7)).into()
    }

    fn make_test_peer(peer_id: &str, node_id: &str) -> Peer {
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
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
            false,
            PeerScope::Core,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
        )
        .unwrap()
    }

    fn make_test_vote(proposal: &str, voter: &str, approve: bool) -> Vote {
        // For tests, we use dummy payload/signature - real validation happens at API layer
        Vote::create(proposal.to_string(), voter.to_string(), approve, None).unwrap()
    }

    #[test]
    fn test_add_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");

        let response = sm.apply(
            FederationRequest::AddPeer(peer.clone()),
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
        assert!(sm.get_peer("peer-1").is_some());
        assert!(sm.get_peer("peer-2").is_some());
        assert!(sm.get_peer("peer-3").is_some());
    }

    #[test]
    fn test_add_peer_overwrites_existing() {
        let mut sm = StateMachineData::new();

        let peer1 = make_test_peer("peer-1", "node-1");
        let peer1_updated = make_test_peer("peer-1", "node-2");

        sm.apply(
            FederationRequest::AddPeer(peer1),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-1");

        sm.apply(
            FederationRequest::AddPeer(peer1_updated),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-2");
        assert_eq!(sm.peers().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");

        sm.apply(
            FederationRequest::AddPeer(peer),
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

        // Create mock metadata for the snapshot
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

        // Verify it's a clone by checking we can still access the original
        assert!(sm.get_peer("peer-1").is_some());
    }

    #[test]
    fn test_inactive_peer_can_be_added() {
        let mut sm = StateMachineData::new();
        let peer = make_inactive_peer("peer-1", "node-1");

        let response = sm.apply(
            FederationRequest::AddPeer(peer),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );
        assert!(matches!(response, FederationResponse::PeerAdded(_)));

        let stored_peer = sm.get_peer("peer-1").unwrap();
        assert!(!stored_peer.active);
    }

    #[test]
    fn test_state_machine_data_default() {
        let sm = StateMachineData::default();
        assert!(sm.peers.is_empty());
        assert!(sm.pending_proposals.is_empty());
        assert!(sm.last_applied_log.is_none());
    }

    // ==================== Proposal Tests ====================

    /// Helper to create a test proposal
    fn make_test_proposal(peer_id: &str, node_id: &str, proposer: &str) -> PeerProposal {
        PeerProposal::empty(
            peer_id,
            node_id,
            &format!("http://{}:8080", node_id),
            &format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
            proposer,
            &test_expires_at(),
        )
        .expect("Failed to create test proposal")
    }

    #[test]
    fn test_propose_core_peer() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");

        // Create empty proposal (proposer must vote separately)
        let response = sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        let proposal_id = match response {
            FederationResponse::ProposalCreated {
                proposal_id,
                votes_needed,
                current_votes,
            } => {
                assert_eq!(votes_needed, TEST_THRESHOLD);
                assert_eq!(current_votes, 0); // Empty proposal, no votes yet
                proposal_id
            }
            _ => panic!("Expected ProposalCreated, got {:?}", response),
        };

        // Peer should NOT be in core set yet
        assert!(sm.get_peer("peer-1").is_none());
        // Proposal should be pending
        assert!(sm.get_proposal(&proposal_id).is_some());
    }

    #[test]
    fn test_vote_approves_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");

        // Create empty proposal
        let proposal_id = match sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        // First vote from proposer
        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        // Second vote should approve (threshold=2)
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
                status,
                peer,
            } => {
                assert_eq!(resp_id, proposal_id);
                assert_eq!(current_votes, 2);
                assert_eq!(votes_needed, TEST_THRESHOLD);
                assert_eq!(status, ProposalStatus::Approved);
                assert_ne!(peer, None);
            }
            _ => panic!("Expected VoteRecorded, got {:?}", response),
        }

        // Peer should now be in core set
        assert!(sm.get_peer("peer-1").is_some());
        // Proposal should be completed
        assert!(sm.get_proposal(&proposal_id).is_none());
        assert_eq!(sm.completed_proposals.len(), 1);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");

        // Create empty proposal
        let proposal_id = match sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        // First vote from proposer
        let vote = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        // Proposer tries to vote again
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
        let peer = make_test_peer("peer-1", "node-1");

        // Add peer directly
        sm.apply(
            FederationRequest::AddPeer(peer),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        // Try to propose the same peer
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let response = sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        assert!(matches!(response, FederationResponse::PeerAlreadyExists(_)));
    }

    #[test]
    fn test_withdraw_proposal() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = match sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        let response = sm.apply(
            FederationRequest::WithdrawProposal {
                proposal_id: proposal_id.clone(),
                withdrawer: "ERegistryA".to_string(),
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        assert!(matches!(response, FederationResponse::ProposalWithdrawn(_)));
        assert!(sm.get_proposal(&proposal_id).is_none());
        assert_eq!(sm.completed_proposals.len(), 1);
        assert_eq!(sm.completed_proposals[0].status, ProposalStatus::Withdrawn);
    }

    #[test]
    fn test_only_proposer_can_withdraw() {
        let mut sm = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = match sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        // Different registry tries to withdraw
        let response = sm.apply(
            FederationRequest::WithdrawProposal {
                proposal_id: proposal_id.clone(),
                withdrawer: "ERegistryB".to_string(),
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        assert!(matches!(response, FederationResponse::NotAuthorized(_)));
        // Proposal should still exist
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
        let proposal_id = match sm.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        // First vote from proposer (approval)
        let vote_a = make_test_vote(&proposal_id, "ERegistryA", true);
        sm.apply(
            FederationRequest::VoteCorePeer {
                proposal_id: proposal_id.clone(),
                vote: vote_a,
            },
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        );

        // Vote to reject from another member
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
                status,
                ..
            } => {
                assert_eq!(current_votes, 1); // Still only 1 approval (rejection doesn't count)
                assert_eq!(status, ProposalStatus::Pending);
            }
            _ => panic!("Expected VoteRecorded"),
        }

        // Peer should NOT be in core set
        assert!(sm.get_peer("peer-1").is_none());
    }

    #[test]
    fn test_proposal_snapshot_restore() {
        let mut sm1 = StateMachineData::new();
        let proposal = make_test_proposal("peer-1", "node-1", "ERegistryA");
        let proposal_id = match sm1.apply(
            FederationRequest::ProposeCorePeer(proposal),
            TEST_THRESHOLD,
            TEST_ANCHORING_PREFIX,
        ) {
            FederationResponse::ProposalCreated { proposal_id, .. } => proposal_id,
            r => panic!("Expected ProposalCreated, got {:?}", r),
        };

        let snapshot = sm1.snapshot();
        assert_eq!(snapshot.pending_proposals.len(), 1);

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "test-snapshot".to_string(),
        };

        let mut sm2 = StateMachineData::new();
        sm2.restore(snapshot, &meta);

        assert!(sm2.get_proposal(&proposal_id).is_some());
    }
}
