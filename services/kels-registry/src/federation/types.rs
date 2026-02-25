//! Type definitions for federation consensus.

#![allow(clippy::too_many_arguments)]

use std::fmt;

use std::collections::HashMap;

use kels::{
    Peer, PeerAdditionProposal, PeerRemovalProposal, Proposal, SignedKeyEvent, Verification, Vote,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

    #[error("Unknown member: {0}")]
    UnknownMember(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Request types for federation state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FederationRequest {
    /// Add a peer (used for regional peers or internal).
    AddPeer(Peer),
    /// Remove a peer (deactivated, anchored).
    RemovePeer(Peer),

    /// Submit an addition proposal (create or withdraw).
    SubmitAdditionProposal(PeerAdditionProposal),

    /// Submit a removal proposal (create or withdraw).
    SubmitRemovalProposal(PeerRemovalProposal),

    /// Vote on a peer proposal.
    VotePeer {
        /// The proposal being voted on.
        proposal_id: String,
        /// The signed vote.
        vote: Vote,
    },

    /// Submit key events for a member's KEL.
    SubmitKeyEvents(Vec<SignedKeyEvent>),
}

impl fmt::Display for FederationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationRequest::AddPeer(peer) => write!(f, "AddPeer({})", peer.peer_prefix),
            FederationRequest::RemovePeer(peer) => write!(f, "RemovePeer({})", peer.peer_prefix),
            FederationRequest::SubmitAdditionProposal(proposal) => {
                if proposal.is_withdrawn() {
                    write!(
                        f,
                        "SubmitAdditionProposal(withdraw, peer={}, proposer={})",
                        proposal.peer_prefix, proposal.proposer
                    )
                } else {
                    write!(
                        f,
                        "SubmitAdditionProposal(create, peer={}, proposer={})",
                        proposal.peer_prefix, proposal.proposer
                    )
                }
            }
            FederationRequest::SubmitRemovalProposal(proposal) => {
                if proposal.is_withdrawn() {
                    write!(
                        f,
                        "SubmitRemovalProposal(withdraw, peer={}, proposer={})",
                        proposal.peer_prefix, proposal.proposer
                    )
                } else {
                    write!(
                        f,
                        "SubmitRemovalProposal(create, peer={}, proposer={})",
                        proposal.peer_prefix, proposal.proposer
                    )
                }
            }
            FederationRequest::VotePeer { proposal_id, vote } => {
                write!(
                    f,
                    "VotePeer({}, voter={}, approve={})",
                    proposal_id, vote.voter, vote.approve
                )
            }
            FederationRequest::SubmitKeyEvents(events) => {
                let prefix = events
                    .first()
                    .map(|e| e.event.prefix.as_str())
                    .unwrap_or("empty");
                write!(
                    f,
                    "SubmitKeyEvents(prefix={}, count={})",
                    prefix,
                    events.len()
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
        approved: bool,
        /// When approved, includes the proposal so the leader can create the Peer.
        proposal: Option<Box<PeerAdditionProposal>>,
    },
    /// Proposal not found.
    ProposalNotFound(String),
    /// Already voted on this proposal.
    AlreadyVoted(String),
    /// Proposal expired.
    ProposalExpired(String),
    /// Proposal rejected (rejection threshold met).
    ProposalRejected(String),
    /// Proposal withdrawn.
    ProposalWithdrawn(String),
    /// Not authorized (e.g., only proposer can withdraw).
    NotAuthorized(String),
    /// Peer already exists or has a pending proposal.
    PeerAlreadyExists(String),
    /// Removal proposal approved — leader must deactivate, anchor, and submit RemovePeer.
    RemovalApproved {
        proposal_id: String,
        peer_prefix: String,
        current_votes: usize,
        votes_needed: usize,
        /// When approved, includes the removal proposal so the leader can deactivate the Peer.
        proposal: Option<Box<PeerRemovalProposal>>,
    },
    /// SAID mismatch (retry-able).
    SaidMismatch(String),
    /// Votes exist — cannot withdraw.
    HasVotes(String),
    /// Internal error
    InternalError(String),
    /// Key events accepted into Raft state.
    KeyEventsAccepted { prefix: String, new_count: usize },
    /// Key events rejected.
    KeyEventsRejected(String),
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
                approved,
                proposal,
            } => {
                write!(
                    f,
                    "VoteRecorded({}, {}/{} votes, approved={}, proposal={:?})",
                    proposal_id,
                    current_votes,
                    votes_needed,
                    approved,
                    proposal.as_ref().map(|p| &p.peer_prefix)
                )
            }
            FederationResponse::ProposalNotFound(id) => write!(f, "ProposalNotFound({})", id),
            FederationResponse::AlreadyVoted(id) => write!(f, "AlreadyVoted({})", id),
            FederationResponse::ProposalExpired(id) => write!(f, "ProposalExpired({})", id),
            FederationResponse::ProposalRejected(id) => write!(f, "ProposalRejected({})", id),
            FederationResponse::ProposalWithdrawn(id) => write!(f, "ProposalWithdrawn({})", id),
            FederationResponse::NotAuthorized(msg) => write!(f, "NotAuthorized({})", msg),
            FederationResponse::PeerAlreadyExists(id) => write!(f, "PeerAlreadyExists({})", id),
            FederationResponse::RemovalApproved {
                proposal_id,
                peer_prefix,
                ..
            } => {
                write!(f, "RemovalApproved({}, peer={})", proposal_id, peer_prefix)
            }
            FederationResponse::SaidMismatch(msg) => write!(f, "SaidMismatch({})", msg),
            FederationResponse::HasVotes(msg) => write!(f, "HasVotes({})", msg),
            FederationResponse::InternalError(msg) => write!(f, "InternalError({})", msg),
            FederationResponse::KeyEventsAccepted { prefix, new_count } => {
                write!(
                    f,
                    "KeyEventsAccepted(prefix={}, count={})",
                    prefix, new_count
                )
            }
            FederationResponse::KeyEventsRejected(msg) => {
                write!(f, "KeyEventsRejected({})", msg)
            }
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

/// Snapshot data for the peer set.
///
/// Note: Metadata (last_applied_log, last_membership) is stored in SnapshotMeta,
/// not duplicated here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberSnapshot {
    /// Active peers.
    pub active_peers: Vec<Peer>,
    /// Inactive (deactivated) peers for audit trail.
    #[serde(default)]
    pub inactive_peers: Vec<Peer>,
    /// Pending addition proposals awaiting votes.
    #[serde(default)]
    pub pending_addition_proposals: Vec<PeerAdditionProposal>,
    /// Completed addition proposals (full chain per proposal) for audit trail.
    #[serde(default)]
    pub completed_addition_proposals: Vec<Vec<PeerAdditionProposal>>,
    #[serde(default)]
    pub pending_removal_proposals: Vec<PeerRemovalProposal>,
    #[serde(default)]
    pub completed_removal_proposals: Vec<Vec<PeerRemovalProposal>>,
    /// Votes stored by SAID.
    #[serde(default)]
    pub votes: Vec<Vote>,
    /// Federation member verified contexts (replicated via Raft).
    #[serde(default)]
    pub member_contexts: HashMap<String, Verification>,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_request_serialization() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let request = FederationRequest::AddPeer(peer.clone());
        let json = serde_json::to_string(&request).unwrap();
        let parsed: FederationRequest = serde_json::from_str(&json).unwrap();

        match parsed {
            FederationRequest::AddPeer(p) => {
                assert_eq!(p.peer_prefix, "12D3KooWExample");
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
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let request = FederationRequest::AddPeer(peer);
        assert_eq!(format!("{}", request), "AddPeer(12D3KooWExample)");

        let deactivated = Peer::create(
            "peer-123".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            false,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let request = FederationRequest::RemovePeer(deactivated);
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
            "http://node-1:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        // Clone the peer to test equality with same data
        let req1 = FederationRequest::AddPeer(peer.clone());
        let req2 = FederationRequest::AddPeer(peer);
        assert_eq!(req1, req2);

        let deactivated1 = Peer::create(
            "peer-1".to_string(),
            "node-1".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            false,
            "http://node-1:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let deactivated2 = deactivated1.clone();
        let req3 = FederationRequest::RemovePeer(deactivated1);
        let req4 = FederationRequest::RemovePeer(deactivated2);
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
    fn test_peer_snapshot_default() {
        let snapshot = MemberSnapshot::default();
        assert!(snapshot.active_peers.is_empty());
        assert!(snapshot.inactive_peers.is_empty());
    }

    #[test]
    fn test_peer_snapshot_serialization() {
        let peer = Peer::create(
            "peer-1".to_string(),
            "node-1".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            "http://node-1:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let snapshot = MemberSnapshot {
            active_peers: vec![peer.clone()],
            inactive_peers: vec![],
            pending_addition_proposals: vec![],
            completed_addition_proposals: vec![],
            pending_removal_proposals: vec![],
            completed_removal_proposals: vec![],
            votes: vec![],
            member_contexts: HashMap::new(),
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: MemberSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.active_peers.len(), 1);
        assert_eq!(parsed.active_peers[0].peer_prefix, "peer-1");
        assert!(parsed.inactive_peers.is_empty());
        assert!(parsed.pending_addition_proposals.is_empty());
        assert!(parsed.completed_addition_proposals.is_empty());
    }
}
