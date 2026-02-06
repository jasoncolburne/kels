//! Type definitions for federation consensus.

#![allow(clippy::too_many_arguments)]

use kels::Peer;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use verifiable_storage::Chained;
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Node ID type for Raft (numeric).
pub type FederationNodeId = u64;

/// Federation error types.
#[derive(Error, Debug)]
pub enum FederationError {
    #[error("Not the federation leader. Leader: {leader_prefix:?} at {leader_url:?}")]
    NotLeader {
        leader_prefix: Option<String>,
        leader_url: Option<String>,
    },

    #[error("Raft error: {0}")]
    RaftError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid peer scope: {0}")]
    InvalidScope(String),

    #[error("Unknown member: {0}")]
    UnknownMember(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
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

impl fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[allow(clippy::too_many_arguments)]
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

/// Request types for federation state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FederationRequest {
    /// Add a peer (used for regional peers or internal).
    AddPeer(Peer),
    /// Remove a peer (by peer_id).
    RemovePeer(String),

    /// Propose a new core peer (requires multi-party approval).
    /// Creates an empty proposal v0. Proposer must then submit their vote separately.
    /// The proposal_id is derived from content (returned in response).
    ProposeCorePeer(PeerProposal),

    /// Vote on a core peer proposal.
    VoteCorePeer {
        /// The proposal being voted on.
        proposal_id: String,
        /// The signed vote.
        vote: Vote,
    },

    /// Withdraw a pending proposal (proposer only).
    WithdrawProposal {
        /// The proposal to withdraw.
        proposal_id: String,
        /// Registry prefix of the withdrawer (must match proposer).
        withdrawer: String,
    },
}

impl fmt::Display for FederationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationRequest::AddPeer(peer) => write!(f, "AddPeer({})", peer.peer_id),
            FederationRequest::RemovePeer(peer_id) => write!(f, "RemovePeer({})", peer_id),
            FederationRequest::ProposeCorePeer(proposal) => {
                write!(
                    f,
                    "ProposeCorePeer(peer={}, proposer={})",
                    proposal.peer_id, proposal.authorizing_kel
                )
            }
            FederationRequest::VoteCorePeer { proposal_id, vote } => {
                write!(
                    f,
                    "VoteCorePeer({}, voter={}, approve={})",
                    proposal_id, vote.voter, vote.approve
                )
            }
            FederationRequest::WithdrawProposal {
                proposal_id,
                withdrawer,
            } => {
                write!(
                    f,
                    "WithdrawProposal({}, withdrawer={})",
                    proposal_id, withdrawer
                )
            }
        }
    }
}

/// Response types from federation state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FederationResponse {
    /// Operation succeeded.
    Ok,
    /// Peer was added.
    PeerAdded(String),
    /// Peer was removed.
    PeerRemoved(String),
    /// Peer not found.
    PeerNotFound(String),
    /// Proposal created successfully.
    ProposalCreated {
        proposal_id: String,
        votes_needed: usize,
        current_votes: usize,
    },
    /// Proposal already exists for this peer.
    ProposalAlreadyExists(String),
    /// Vote recorded on proposal.
    VoteRecorded {
        proposal_id: String,
        current_votes: usize,
        votes_needed: usize,
        status: ProposalStatus,
        peer: Option<Box<Peer>>,
    },
    /// Proposal not found.
    ProposalNotFound(String),
    /// Already voted on this proposal.
    AlreadyVoted(String),
    /// Proposal expired.
    ProposalExpired(String),
    /// Proposal withdrawn.
    ProposalWithdrawn(String),
    /// Not authorized (e.g., only proposer can withdraw).
    NotAuthorized(String),
    /// Peer already exists in core set or pending proposal.
    PeerAlreadyExists(String),
    /// Internal error
    InternalError(String),
}

impl fmt::Display for FederationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationResponse::Ok => write!(f, "Ok"),
            FederationResponse::PeerAdded(id) => write!(f, "PeerAdded({})", id),
            FederationResponse::PeerRemoved(id) => write!(f, "PeerRemoved({})", id),
            FederationResponse::PeerNotFound(id) => write!(f, "PeerNotFound({})", id),
            FederationResponse::ProposalCreated {
                proposal_id,
                votes_needed,
                current_votes,
            } => {
                write!(
                    f,
                    "ProposalCreated({}, {}/{} votes)",
                    proposal_id, current_votes, votes_needed
                )
            }
            FederationResponse::ProposalAlreadyExists(id) => {
                write!(f, "ProposalAlreadyExists({})", id)
            }
            FederationResponse::VoteRecorded {
                proposal_id,
                current_votes,
                votes_needed,
                status,
                peer,
            } => {
                write!(
                    f,
                    "VoteRecorded({}, {}/{} votes, {}, peer={:?})",
                    proposal_id,
                    current_votes,
                    votes_needed,
                    status,
                    peer.clone().map(|p| p.said)
                )
            }
            FederationResponse::ProposalNotFound(id) => write!(f, "ProposalNotFound({})", id),
            FederationResponse::AlreadyVoted(id) => write!(f, "AlreadyVoted({})", id),
            FederationResponse::ProposalExpired(id) => write!(f, "ProposalExpired({})", id),
            FederationResponse::ProposalWithdrawn(id) => write!(f, "ProposalWithdrawn({})", id),
            FederationResponse::NotAuthorized(msg) => write!(f, "NotAuthorized({})", msg),
            FederationResponse::PeerAlreadyExists(id) => write!(f, "PeerAlreadyExists({})", id),
            FederationResponse::InternalError(msg) => write!(f, "InternalError({})", msg),
        }
    }
}

// Use the declare_raft_types! macro for OpenRaft 0.10
openraft::declare_raft_types!(
    /// OpenRaft type configuration for our federation.
    pub TypeConfig:
        D = FederationRequest,
        R = FederationResponse,
);

/// Snapshot data for the core peer set.
///
/// Note: Metadata (last_applied_log, last_membership) is stored in SnapshotMeta,
/// not duplicated here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorePeerSnapshot {
    /// The core peer set data.
    pub peers: Vec<Peer>,
    /// Pending proposals awaiting votes.
    #[serde(default)]
    pub pending_proposals: Vec<PeerProposal>,
    /// Completed proposals (approved, rejected, withdrawn) for audit trail.
    #[serde(default)]
    pub completed_proposals: Vec<PeerProposal>,
    /// Votes stored by SAID (for privacy - proposals only store SAIDs).
    #[serde(default)]
    pub votes: Vec<Vote>,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use kels::PeerScope;

    #[test]
    fn test_federation_request_serialization() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let request = FederationRequest::AddPeer(peer.clone());
        let json = serde_json::to_string(&request).unwrap();
        let parsed: FederationRequest = serde_json::from_str(&json).unwrap();

        match parsed {
            FederationRequest::AddPeer(p) => {
                assert_eq!(p.peer_id, "12D3KooWExample");
                assert_eq!(p.scope, PeerScope::Core);
            }
            _ => panic!("Expected AddPeer"),
        }
    }

    #[test]
    fn test_federation_response_serialization() {
        let response = FederationResponse::PeerAdded("test-peer".to_string());
        let json = serde_json::to_string(&response).unwrap();
        let parsed: FederationResponse = serde_json::from_str(&json).unwrap();

        match parsed {
            FederationResponse::PeerAdded(s) => assert_eq!(s, "test-peer"),
            _ => panic!("Expected PeerAdded"),
        }
    }

    #[test]
    fn test_federation_request_display() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let request = FederationRequest::AddPeer(peer);
        assert_eq!(format!("{}", request), "AddPeer(12D3KooWExample)");

        let request = FederationRequest::RemovePeer("peer-123".to_string());
        assert_eq!(format!("{}", request), "RemovePeer(peer-123)");
    }

    #[test]
    fn test_federation_response_display_all_variants() {
        assert_eq!(format!("{}", FederationResponse::Ok), "Ok");
        assert_eq!(
            format!("{}", FederationResponse::PeerAdded("p1".to_string())),
            "PeerAdded(p1)"
        );
        assert_eq!(
            format!("{}", FederationResponse::PeerRemoved("p2".to_string())),
            "PeerRemoved(p2)"
        );
        assert_eq!(
            format!("{}", FederationResponse::PeerNotFound("p3".to_string())),
            "PeerNotFound(p3)"
        );
    }

    #[test]
    fn test_federation_error_display() {
        let err = FederationError::NotLeader {
            leader_prefix: Some("ELeader".to_string()),
            leader_url: Some("http://leader".to_string()),
        };
        assert!(err.to_string().contains("Not the federation leader"));

        let err = FederationError::NotLeader {
            leader_prefix: None,
            leader_url: None,
        };
        assert!(err.to_string().contains("Not the federation leader"));

        let err = FederationError::RaftError("raft failed".to_string());
        assert!(err.to_string().contains("raft failed"));

        let err = FederationError::StorageError("storage failed".to_string());
        assert!(err.to_string().contains("storage failed"));

        let err = FederationError::NetworkError("network failed".to_string());
        assert!(err.to_string().contains("network failed"));

        let err = FederationError::ConfigError("config failed".to_string());
        assert!(err.to_string().contains("config failed"));

        let err = FederationError::InvalidScope("bad scope".to_string());
        assert!(err.to_string().contains("bad scope"));

        let err = FederationError::UnknownMember("unknown".to_string());
        assert!(err.to_string().contains("unknown"));

        let err = FederationError::VerificationFailed("verify failed".to_string());
        assert!(err.to_string().contains("verify failed"));

        let err = FederationError::SerializationError("serialize failed".to_string());
        assert!(err.to_string().contains("serialize failed"));
    }

    #[test]
    fn test_federation_request_equality() {
        let peer = Peer::create(
            "peer-1".to_string(),
            "node-1".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-1:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        // Clone the peer to test equality with same data
        let req1 = FederationRequest::AddPeer(peer.clone());
        let req2 = FederationRequest::AddPeer(peer);
        assert_eq!(req1, req2);

        let req3 = FederationRequest::RemovePeer("peer-1".to_string());
        let req4 = FederationRequest::RemovePeer("peer-1".to_string());
        assert_eq!(req3, req4);

        assert_ne!(req1, req3);
    }

    #[test]
    fn test_federation_response_equality() {
        assert_eq!(FederationResponse::Ok, FederationResponse::Ok);
        assert_eq!(
            FederationResponse::PeerAdded("a".to_string()),
            FederationResponse::PeerAdded("a".to_string())
        );
        assert_ne!(
            FederationResponse::PeerAdded("a".to_string()),
            FederationResponse::PeerRemoved("a".to_string())
        );
    }

    #[test]
    fn test_core_peer_snapshot_default() {
        let snapshot = CorePeerSnapshot::default();
        assert!(snapshot.peers.is_empty());
    }

    #[test]
    fn test_core_peer_snapshot_serialization() {
        let peer = Peer::create(
            "peer-1".to_string(),
            "node-1".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-1:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let snapshot = CorePeerSnapshot {
            peers: vec![peer.clone()],
            pending_proposals: vec![],
            completed_proposals: vec![],
            votes: vec![],
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: CorePeerSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].peer_id, "peer-1");
        assert!(parsed.pending_proposals.is_empty());
        assert!(parsed.completed_proposals.is_empty());
    }
}
