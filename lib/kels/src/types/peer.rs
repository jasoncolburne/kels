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
    /// Threshold met, peer was added to core set.
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
/// Votes are chained so they can be updated (e.g., to withdraw a proposal).
/// The proposer withdraws by updating their vote with `withdrawn_at` set.
///
/// The `proposal` field binds this vote to a specific proposal.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct Vote {
    /// Self-Addressing IDentifier - content hash for tamper evidence.
    #[said]
    pub said: String,
    /// Stable identifier for this vote chain (derived from inception SAID).
    #[prefix]
    pub prefix: String,
    /// SAID of previous version (None for inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[previous]
    pub previous: Option<String>,
    /// Version number.
    #[version]
    pub version: u64,
    /// The proposal prefix this vote is for (must match proposal.prefix).
    pub proposal: String,
    /// The voter's registry prefix.
    pub voter: String,
    /// Whether the voter approves (true) or rejects (false).
    pub approve: bool,
    /// If set, this vote represents a withdrawal of the proposal (proposer only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<StorageDatetime>,
}

/// A proposal to add a core peer, requiring multi-party approval.
///
/// Uses chaining for tamper-evident audit trail:
/// - `prefix`: Stable proposal identifier (derived from inception) - use as proposal_id
/// - `said`: Changes with each update (votes added, status changes)
/// - `previous`: Links to previous version for full history
#[allow(clippy::too_many_arguments)]
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct PeerProposal {
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
    /// Registry prefix of the leader (may change each iteration)
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub authorizing_kel: String,
    pub proposer: String,
    /// SAIDs of approval votes. Each vote's proposal_prefix must match this proposal's prefix.
    pub approvals: Vec<String>,
    /// SAIDs of rejection votes.
    pub rejections: Vec<String>,
    /// When the proposal was created/updated.
    #[created_at]
    pub created_at: StorageDatetime,
    /// When the proposal expires.
    pub expires_at: StorageDatetime,
    /// Current status of the proposal.
    pub status: ProposalStatus,
}

impl PeerProposal {
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
        expires_at: &StorageDatetime,
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            peer_id.to_string(),
            node_id.to_string(),
            kels_url.to_string(),
            gossip_multiaddr.to_string(),
            proposer.to_string(),
            proposer.to_string(),
            vec![],
            vec![],
            expires_at.clone(),
            ProposalStatus::Pending,
        )
    }

    /// Get the proposal ID (which is the prefix).
    pub fn proposal_id(&self) -> &str {
        &self.prefix
    }

    /// Add a vote and increment the chain (updates SAID, sets previous).
    /// The leader_prefix is updated to the registry processing this vote.
    pub fn add_vote(
        &mut self,
        vote: Vote,
        leader_prefix: &str,
    ) -> Result<(), verifiable_storage::StorageError> {
        match vote.approve {
            true => self.approvals.push(vote.said),
            false => self.rejections.push(vote.said),
        }
        self.authorizing_kel = leader_prefix.to_string();
        self.increment()
    }

    /// Check if proposal has expired.
    pub fn is_expired(&self) -> bool {
        StorageDatetime::now() > self.expires_at
    }

    /// Count approvals.
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }

    /// Count rejections.
    pub fn rejection_count(&self) -> usize {
        self.rejections.len()
    }

    /// Check if a registry has already voted by checking the provided votes.
    pub fn has_voted(&self, voter: &str, votes: &[Vote]) -> bool {
        votes.iter().any(|v| v.voter == voter)
    }
}

/// A completed proposal bundled with its votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalWithVotes {
    pub proposal: PeerProposal,
    pub votes: Vec<Vote>,
}

/// Response from the completed proposals endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedProposalsResponse {
    pub proposals: Vec<ProposalWithVotes>,
    pub member_prefixes: Vec<String>,
    pub approval_threshold: usize,
}
