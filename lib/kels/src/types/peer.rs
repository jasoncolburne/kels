//! Peer allowlist & federation

#![allow(clippy::too_many_arguments)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

use super::Kel;
use crate::KelsError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRequest<T> {
    pub payload: T,
    pub peer_id: String,
    pub public_key: String,
    pub signature: String,
}

/// Scope of a peer in the registry federation.
///
/// - `Core`: Replicated to all registries via Raft consensus
/// - `Regional`: Local to this registry only, not shared across federation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerScope {
    /// Core peers are replicated across all registries in the federation via Raft consensus.
    /// Changes to core peers require consensus from the federation leader.
    Core,
    /// Regional peers are local to this registry only.
    /// They are not shared across the federation and can be managed independently.
    #[default]
    Regional,
}

impl PeerScope {
    /// Returns the string representation of the scope.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerScope::Core => "core",
            PeerScope::Regional => "regional",
        }
    }
}

impl std::str::FromStr for PeerScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "core" => Ok(PeerScope::Core),
            "regional" => Ok(PeerScope::Regional),
            _ => Err(format!("Unknown peer scope: {}", s)),
        }
    }
}

impl std::fmt::Display for PeerScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "peer")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    pub peer_id: String,
    pub node_id: String,
    pub authorizing_kel: String,
    pub active: bool,
    /// Scope of this peer: core (replicated) or regional (local-only)
    pub scope: PeerScope,
    /// HTTP URL for the KELS service
    pub kels_url: String,
    /// libp2p multiaddr for gossip connections
    pub gossip_multiaddr: String,
}

impl Peer {
    /// Derive the HTTP URL for the gossip service from the multiaddr.
    /// Assumes HTTP is on port 80 on the same host as the gossip service.
    /// e.g., `/dns4/kels-gossip.ns.kels/tcp/4001` -> `http://kels-gossip.ns.kels:80`
    pub fn gossip_http_url(&self) -> Option<String> {
        // Parse multiaddr to extract host
        // Format: /dns4/<host>/tcp/<port> or /ip4/<ip>/tcp/<port>
        let parts: Vec<&str> = self.gossip_multiaddr.split('/').collect();
        if parts.len() >= 4 {
            let addr_type = parts[1];
            let host = parts[2];
            if addr_type == "dns4" || addr_type == "ip4" {
                return Some(format!("http://{}:80", host));
            }
        }
        None
    }

    pub fn deactivate(&self) -> Result<Self, verifiable_storage::StorageError> {
        let mut peer = self.clone();
        peer.active = false;
        peer.increment()?;
        Ok(peer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerHistory {
    pub prefix: String,
    pub records: Vec<Peer>,
}

impl PeerHistory {
    pub fn verify(
        &self,
        trusted_prefixes: &HashSet<&'static str>,
        kels: &[&Kel],
    ) -> Result<(), KelsError> {
        for kel in kels {
            if !kel.verify_prefix(trusted_prefixes) {
                return Err(KelsError::RegistryFailure(format!(
                    "Could not verify KEL {} as trusted",
                    kel.prefix().unwrap_or("unknown")
                )));
            }
        }

        let mut last_said: Option<String> = None;
        for (i, peer_record) in self.records.iter().enumerate() {
            peer_record.verify()?;

            if let Some(said) = last_said {
                if let Some(previous) = peer_record.previous.clone() {
                    if previous != said {
                        return Err(KelsError::RegistryFailure(format!(
                            "Peer record {} previous doesn't match {}",
                            peer_record.said, said
                        )));
                    }
                } else {
                    return Err(KelsError::RegistryFailure(format!(
                        "Peer record {} is unchained from {}",
                        peer_record.said, said
                    )));
                }
            }

            if i as u64 != peer_record.version {
                return Err(KelsError::RegistryFailure(format!(
                    "Peer record {} has incorrect version {}",
                    peer_record.said, peer_record.version
                )));
            }

            last_said = Some(peer_record.said.clone());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersResponse {
    pub peers: Vec<PeerHistory>,
}

/// Status of a core peer proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal is waiting for votes.
    Pending,
    /// Threshold met, peer was added/removed from core set.
    Approved,
    /// Proposal was rejected (majority rejected or expired).
    Rejected,
    /// Proposal was withdrawn by proposer.
    Withdrawn,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::Pending => write!(f, "Pending"),
            ProposalStatus::Approved => write!(f, "Approved"),
            ProposalStatus::Rejected => write!(f, "Rejected"),
            ProposalStatus::Withdrawn => write!(f, "Withdrawn"),
        }
    }
}

/// A vote on a proposal with a tamper-evident SAID.
///
/// Votes are simple self-addressed structs (not chained). Each vote is immutable
/// after creation. The `proposal` field binds this vote to a specific proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SelfAddressed)]
pub struct Vote {
    /// Self-Addressing IDentifier - content hash for tamper evidence.
    #[said]
    pub said: String,
    /// The proposal prefix this vote is for (must match proposal.prefix).
    pub proposal: String,
    /// The voter's registry prefix.
    pub voter: String,
    /// Whether the voter approves (true) or rejects (false).
    pub approve: bool,
    /// When the vote was cast.
    #[created_at]
    pub voted_at: StorageDatetime,
}

/// A proposal to add a core peer, requiring multi-party approval.
///
/// Uses chaining for tamper-evident audit trail:
/// - `prefix`: Stable proposal identifier (derived from inception) - use as proposal_id
/// - `said`: Changes with each update
/// - `previous`: Links to previous version for full history
///
/// Proposals are immutable after creation, except for withdrawal by the proposer.
/// Proposal chain: v0 (creation) → optionally v1 (withdrawal). No intermediate versions.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct PeerAdditionProposal {
    /// Self-Addressing IDentifier - changes with each update.
    #[said]
    pub said: String,
    /// Stable proposal identifier (derived from inception SAID).
    #[prefix]
    pub prefix: String,
    /// SAID of previous version (None for inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[previous]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    /// The peer_id being proposed.
    pub peer_id: String,
    /// The node_id being proposed.
    pub node_id: String,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub proposer: String,
    /// Approval threshold at time of proposal creation.
    pub threshold: usize,
    /// When the proposal was created/updated.
    #[created_at]
    pub created_at: StorageDatetime,
    /// When the proposal expires.
    pub expires_at: StorageDatetime,
    /// If set, this proposal has been withdrawn by the proposer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<StorageDatetime>,
}

impl PeerAdditionProposal {
    /// Create a new empty proposal (v0, no votes yet).
    ///
    /// The prefix (proposal ID) is derived from content - no UUID needed.
    /// The proposer must submit their vote separately via VoteCorePeer.
    pub fn empty(
        peer_id: &str,
        node_id: &str,
        kels_url: &str,
        gossip_multiaddr: &str,
        proposer: &str,
        threshold: usize,
        expires_at: &StorageDatetime,
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            peer_id.to_string(),
            node_id.to_string(),
            kels_url.to_string(),
            gossip_multiaddr.to_string(),
            proposer.to_string(),
            threshold,
            expires_at.clone(),
            None,
        )
    }

    /// Get the proposal ID (which is the prefix).
    pub fn proposal_id(&self) -> &str {
        &self.prefix
    }

    /// Check if proposal has expired.
    pub fn is_expired(&self) -> bool {
        StorageDatetime::now() > self.expires_at
    }

    /// Check if this proposal has been withdrawn.
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn_at.is_some()
    }
}

/// A proposal chain (1-2 records: v0 creation, optionally v1 withdrawal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionHistory {
    pub prefix: String,
    pub records: Vec<PeerAdditionProposal>,
}

impl AdditionHistory {
    /// Verify structural integrity of the proposal chain.
    ///
    /// Checks SAID/prefix on each record, chain linkage (previous pointers),
    /// version monotonicity, proposer consistency, chain length (1-2 records),
    /// and withdrawal validity. Does NOT verify anchoring — caller must do that.
    pub fn verify(&self) -> Result<(), KelsError> {
        if self.records.is_empty() {
            return Err(KelsError::RegistryFailure(
                "Empty proposal chain".to_string(),
            ));
        }

        // Only v0 and optionally v1 (withdrawal) are valid
        if self.records.len() > 2 {
            return Err(KelsError::RegistryFailure(format!(
                "Proposal chain has {} records, expected 1 or 2",
                self.records.len()
            )));
        }

        let mut last_said: Option<String> = None;
        for (i, record) in self.records.iter().enumerate() {
            // Verify SAID and prefix
            record.verify()?;

            // Prefix must match the chain prefix
            if record.prefix != self.prefix {
                return Err(KelsError::RegistryFailure(format!(
                    "Proposal record {} prefix {} doesn't match chain prefix {}",
                    record.said, record.prefix, self.prefix
                )));
            }

            // Chain linkage
            if let Some(said) = &last_said {
                if record.previous.as_deref() != Some(said) {
                    return Err(KelsError::RegistryFailure(format!(
                        "Proposal record {} previous doesn't match {}",
                        record.said, said
                    )));
                }
            } else if record.previous.is_some() {
                return Err(KelsError::RegistryFailure(format!(
                    "First proposal record {} has unexpected previous",
                    record.said
                )));
            }

            // Version monotonicity
            if i as u64 != record.version {
                return Err(KelsError::RegistryFailure(format!(
                    "Proposal record {} has incorrect version {}",
                    record.said, record.version
                )));
            }

            // Proposer must be consistent across the chain
            if record.proposer != self.records[0].proposer {
                return Err(KelsError::RegistryFailure(format!(
                    "Proposal record {} proposer {} doesn't match inception proposer {}",
                    record.said, record.proposer, self.records[0].proposer
                )));
            }

            last_said = Some(record.said.clone());
        }

        // If v1 exists, it must be a withdrawal
        if self.records.len() == 2 && !self.records[1].is_withdrawn() {
            return Err(KelsError::RegistryFailure(
                "Second proposal record must be a withdrawal".to_string(),
            ));
        }

        Ok(())
    }

    /// Whether the latest record is a withdrawal.
    pub fn is_withdrawn(&self) -> bool {
        self.records.last().is_some_and(|r| r.is_withdrawn())
    }

    /// Get the inception record (v0).
    pub fn inception(&self) -> Option<&PeerAdditionProposal> {
        self.records.first()
    }

    /// Get the latest record.
    pub fn latest(&self) -> Option<&PeerAdditionProposal> {
        self.records.last()
    }
}

/// A completed addition proposal bundled with its votes (the full DAG).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionWithVotes {
    pub history: AdditionHistory,
    pub votes: Vec<Vote>,
}

impl AdditionWithVotes {
    /// Verify the full DAG: proposal chain integrity + vote SAIDs + vote references.
    ///
    /// Also checks invariant: withdrawn proposals must have zero votes.
    /// Does NOT verify anchoring — caller must do that.
    pub fn verify(&self) -> Result<(), KelsError> {
        // Verify proposal chain
        self.history.verify()?;

        let proposal_prefix = &self.history.prefix;

        // Verify each vote
        for vote in &self.votes {
            // Verify vote SAID (Vote is SelfAddressed, not Chained)
            vote.verify_said()?;

            // Vote must reference this proposal
            if vote.proposal != *proposal_prefix {
                return Err(KelsError::RegistryFailure(format!(
                    "Vote {} references proposal {} but chain prefix is {}",
                    vote.said, vote.proposal, proposal_prefix
                )));
            }
        }

        // Invariant: withdrawn proposals must have zero votes
        if self.history.is_withdrawn() && !self.votes.is_empty() {
            return Err(KelsError::RegistryFailure(format!(
                "Withdrawn proposal {} has {} votes — tampered data",
                proposal_prefix,
                self.votes.len()
            )));
        }

        Ok(())
    }

    /// Compute the proposal status from the chain state and votes.
    pub fn status(&self, threshold: usize) -> ProposalStatus {
        if self.history.is_withdrawn() {
            return ProposalStatus::Withdrawn;
        }
        if self.approval_count() >= threshold {
            return ProposalStatus::Approved;
        }
        if self.is_expired() {
            return ProposalStatus::Rejected;
        }
        ProposalStatus::Pending
    }

    /// Count of approval votes.
    pub fn approval_count(&self) -> usize {
        self.votes.iter().filter(|v| v.approve).count()
    }

    /// Count of rejection votes.
    pub fn rejection_count(&self) -> usize {
        self.votes.iter().filter(|v| !v.approve).count()
    }

    /// Whether the proposal has expired.
    pub fn is_expired(&self) -> bool {
        self.history.inception().is_some_and(|p| p.is_expired())
    }

    /// The proposal prefix (stable identifier).
    pub fn proposal_id(&self) -> &str {
        &self.history.prefix
    }

    /// The proposer's registry prefix.
    pub fn proposer(&self) -> Option<&str> {
        self.history.inception().map(|p| p.proposer.as_str())
    }

    /// Unique voters who have voted.
    pub fn voters(&self) -> Vec<&str> {
        self.votes.iter().map(|v| v.voter.as_str()).collect()
    }
}

/// A proposal to remove a core peer, requiring multi-party approval.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct PeerRemovalProposal {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[previous]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    pub peer_id: String,
    pub proposer: String,
    pub threshold: usize,
    #[created_at]
    pub created_at: StorageDatetime,
    pub expires_at: StorageDatetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<StorageDatetime>,
}

impl PeerRemovalProposal {
    pub fn empty(
        peer_id: &str,
        proposer: &str,
        threshold: usize,
        expires_at: &StorageDatetime,
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            peer_id.to_string(),
            proposer.to_string(),
            threshold,
            expires_at.clone(),
            None,
        )
    }

    pub fn proposal_id(&self) -> &str {
        &self.prefix
    }

    pub fn is_expired(&self) -> bool {
        StorageDatetime::now() > self.expires_at
    }

    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn_at.is_some()
    }
}

/// A removal proposal chain (1-2 records: v0 creation, optionally v1 withdrawal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalHistory {
    pub prefix: String,
    pub records: Vec<PeerRemovalProposal>,
}

impl RemovalHistory {
    pub fn verify(&self) -> Result<(), KelsError> {
        if self.records.is_empty() {
            return Err(KelsError::RegistryFailure(
                "Empty removal proposal chain".to_string(),
            ));
        }

        if self.records.len() > 2 {
            return Err(KelsError::RegistryFailure(format!(
                "Removal proposal chain has {} records, expected 1 or 2",
                self.records.len()
            )));
        }

        let mut last_said: Option<String> = None;
        for (i, record) in self.records.iter().enumerate() {
            record.verify()?;

            if record.prefix != self.prefix {
                return Err(KelsError::RegistryFailure(format!(
                    "Removal proposal record {} prefix {} doesn't match chain prefix {}",
                    record.said, record.prefix, self.prefix
                )));
            }

            if let Some(said) = &last_said {
                if record.previous.as_deref() != Some(said) {
                    return Err(KelsError::RegistryFailure(format!(
                        "Removal proposal record {} previous doesn't match {}",
                        record.said, said
                    )));
                }
            } else if record.previous.is_some() {
                return Err(KelsError::RegistryFailure(format!(
                    "First removal proposal record {} has unexpected previous",
                    record.said
                )));
            }

            if i as u64 != record.version {
                return Err(KelsError::RegistryFailure(format!(
                    "Removal proposal record {} has incorrect version {}",
                    record.said, record.version
                )));
            }

            if record.proposer != self.records[0].proposer {
                return Err(KelsError::RegistryFailure(format!(
                    "Removal proposal record {} proposer {} doesn't match inception proposer {}",
                    record.said, record.proposer, self.records[0].proposer
                )));
            }

            last_said = Some(record.said.clone());
        }

        if self.records.len() == 2 && !self.records[1].is_withdrawn() {
            return Err(KelsError::RegistryFailure(
                "Second removal proposal record must be a withdrawal".to_string(),
            ));
        }

        Ok(())
    }

    pub fn is_withdrawn(&self) -> bool {
        self.records.last().is_some_and(|r| r.is_withdrawn())
    }

    pub fn inception(&self) -> Option<&PeerRemovalProposal> {
        self.records.first()
    }

    pub fn latest(&self) -> Option<&PeerRemovalProposal> {
        self.records.last()
    }
}

/// A completed removal proposal bundled with its votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalWithVotes {
    pub history: RemovalHistory,
    pub votes: Vec<Vote>,
}

impl RemovalWithVotes {
    pub fn verify(&self) -> Result<(), KelsError> {
        self.history.verify()?;

        let proposal_prefix = &self.history.prefix;

        for vote in &self.votes {
            vote.verify_said()?;

            if vote.proposal != *proposal_prefix {
                return Err(KelsError::RegistryFailure(format!(
                    "Vote {} references proposal {} but chain prefix is {}",
                    vote.said, vote.proposal, proposal_prefix
                )));
            }
        }

        if self.history.is_withdrawn() && !self.votes.is_empty() {
            return Err(KelsError::RegistryFailure(format!(
                "Withdrawn removal proposal {} has {} votes — tampered data",
                proposal_prefix,
                self.votes.len()
            )));
        }

        Ok(())
    }

    pub fn status(&self, threshold: usize) -> ProposalStatus {
        if self.history.is_withdrawn() {
            return ProposalStatus::Withdrawn;
        }
        if self.approval_count() >= threshold {
            return ProposalStatus::Approved;
        }
        if self.is_expired() {
            return ProposalStatus::Rejected;
        }
        ProposalStatus::Pending
    }

    pub fn approval_count(&self) -> usize {
        self.votes.iter().filter(|v| v.approve).count()
    }

    pub fn is_expired(&self) -> bool {
        self.history.inception().is_some_and(|p| p.is_expired())
    }

    pub fn proposal_id(&self) -> &str {
        &self.history.prefix
    }

    pub fn proposer(&self) -> Option<&str> {
        self.history.inception().map(|p| p.proposer.as_str())
    }
}

/// Response from the completed proposals endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedProposalsResponse {
    pub additions: Vec<AdditionWithVotes>,
    pub removals: Vec<RemovalWithVotes>,
    pub member_prefixes: Vec<String>,
    pub approval_threshold: usize,
}
