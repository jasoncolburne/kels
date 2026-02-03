//! Type definitions for federation consensus.

use kels::Peer;
use serde::{Deserialize, Serialize};
use std::fmt;
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

    #[error("Invalid peer scope: {0}")]
    InvalidScope(String),

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
    /// Add a peer to the core peer set.
    AddPeer(Peer),
    /// Remove a peer from the core peer set (by peer_id).
    RemovePeer(String),
}

impl fmt::Display for FederationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationRequest::AddPeer(peer) => write!(f, "AddPeer({})", peer.peer_id),
            FederationRequest::RemovePeer(peer_id) => write!(f, "RemovePeer({})", peer_id),
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
}

impl fmt::Display for FederationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationResponse::Ok => write!(f, "Ok"),
            FederationResponse::PeerAdded(id) => write!(f, "PeerAdded({})", id),
            FederationResponse::PeerRemoved(id) => write!(f, "PeerRemoved({})", id),
            FederationResponse::PeerNotFound(id) => write!(f, "PeerNotFound({})", id),
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
            true,
            PeerScope::Core,
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
            true,
            PeerScope::Core,
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
            true,
            PeerScope::Core,
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
            true,
            PeerScope::Core,
        )
        .unwrap();
        let snapshot = CorePeerSnapshot {
            peers: vec![peer.clone()],
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: CorePeerSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].peer_id, "peer-1");
    }
}
