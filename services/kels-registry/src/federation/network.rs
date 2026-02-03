//! Network layer for federation Raft RPC.
//!
//! Provides HTTP-based communication between federation members.
//! All RPC messages are signed with the sender's identity key and
//! verified against the sender's KEL by the receiver.

use super::config::FederationConfig;
use super::types::{FederationError, TypeConfig};
use crate::identity_client::IdentityClient;
use openraft::error::{RPCError, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{BasicNode, SnapshotMeta, Vote};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Node ID type (same as in types.rs).
pub type FederationNodeId = u64;

/// Snapshot transfer data for federation RPC.
///
/// In OpenRaft 0.10, snapshots are transferred as complete units rather than chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotTransfer {
    pub vote: Vote<TypeConfig>,
    pub meta: SnapshotMeta<TypeConfig>,
    pub data: Vec<u8>,
}

/// Federation RPC request types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum FederationRpc {
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<TypeConfig>),
    Snapshot(SnapshotTransfer),
}

/// Federation RPC response types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum FederationRpcResponse {
    AppendEntries(AppendEntriesResponse<TypeConfig>),
    Vote(VoteResponse<TypeConfig>),
    Snapshot(SnapshotResponse<TypeConfig>),
    Error { message: String },
}

/// Signed federation RPC wrapper.
///
/// All federation RPC messages are signed by the sender and verified
/// by the receiver using the sender's KEL (current public key from KEL).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedFederationRpc {
    /// The RPC payload as a JSON string (this is what gets signed)
    pub payload: String,
    /// Sender's registry prefix (used to look up their KEL)
    pub sender_prefix: String,
    /// QB64-encoded signature over the payload
    pub signature: String,
}

/// Network layer for federation communication.
#[derive(Clone)]
pub struct FederationNetwork {
    config: FederationConfig,
    client: reqwest::Client,
    identity_client: Arc<IdentityClient>,
}

impl FederationNetwork {
    /// Create a new federation network layer.
    pub fn new(config: FederationConfig, identity_client: Arc<IdentityClient>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            config,
            client,
            identity_client,
        }
    }

    /// Send an RPC request to a target node.
    async fn send_rpc(
        &self,
        target: FederationNodeId,
        rpc: FederationRpc,
    ) -> Result<FederationRpcResponse, FederationError> {
        let member = self.config.member_by_id(target).ok_or_else(|| {
            FederationError::NetworkError(format!("Unknown target node: {}", target))
        })?;

        let url = format!("{}/api/federation/rpc", member.url.trim_end_matches('/'));

        debug!(
            "Sending RPC to {} ({}): {:?}",
            target,
            url,
            std::mem::discriminant(&rpc)
        );

        // Serialize RPC to JSON string for signing
        let payload = serde_json::to_string(&rpc)
            .map_err(|e| FederationError::SerializationError(e.to_string()))?;

        // Sign the payload
        let sign_result = self
            .identity_client
            .sign(&payload)
            .await
            .map_err(|e| FederationError::NetworkError(format!("Signing failed: {}", e)))?;

        // Wrap in signed envelope
        let signed_rpc = SignedFederationRpc {
            payload,
            sender_prefix: self.config.self_prefix.clone(),
            signature: sign_result.signature,
        };

        let response = self
            .client
            .post(&url)
            .json(&signed_rpc)
            .send()
            .await
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(FederationError::NetworkError(format!(
                "RPC failed with status: {}",
                response.status()
            )));
        }

        let rpc_response: FederationRpcResponse = response
            .json()
            .await
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;

        Ok(rpc_response)
    }
}

/// Connection to a single federation member.
pub struct FederationConnection {
    target: FederationNodeId,
    network: Arc<FederationNetwork>,
}

impl FederationConnection {
    fn new(target: FederationNodeId, network: Arc<FederationNetwork>) -> Self {
        Self { target, network }
    }
}

impl RaftNetworkV2<TypeConfig> for FederationConnection {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<TypeConfig>, RPCError<TypeConfig>> {
        let rpc = FederationRpc::AppendEntries(req);
        let response = self
            .network
            .send_rpc(self.target, rpc)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        match response {
            FederationRpcResponse::AppendEntries(r) => Ok(r),
            FederationRpcResponse::Error { message } => Err(RPCError::Unreachable(
                Unreachable::new(&FederationError::NetworkError(message)),
            )),
            _ => Err(RPCError::Unreachable(Unreachable::new(
                &FederationError::NetworkError("Unexpected response type".to_string()),
            ))),
        }
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote<TypeConfig>,
        snapshot: openraft::Snapshot<TypeConfig>,
        _cancel: impl std::future::Future<Output = openraft::error::ReplicationClosed>
        + openraft::OptionalSend
        + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, openraft::error::StreamingError<TypeConfig>> {
        // Extract the snapshot data from the Cursor
        let data: Vec<u8> = snapshot.snapshot.into_inner();

        let transfer = SnapshotTransfer {
            vote,
            meta: snapshot.meta,
            data,
        };

        let rpc = FederationRpc::Snapshot(transfer);
        let response = self
            .network
            .send_rpc(self.target, rpc)
            .await
            .map_err(|e| openraft::error::StreamingError::Unreachable(Unreachable::new(&e)))?;

        match response {
            FederationRpcResponse::Snapshot(r) => Ok(r),
            FederationRpcResponse::Error { message } => {
                Err(openraft::error::StreamingError::Unreachable(
                    Unreachable::new(&FederationError::NetworkError(message)),
                ))
            }
            _ => Err(openraft::error::StreamingError::Unreachable(
                Unreachable::new(&FederationError::NetworkError(
                    "Unexpected response type".to_string(),
                )),
            )),
        }
    }

    async fn vote(
        &mut self,
        req: VoteRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
        let rpc = FederationRpc::Vote(req);
        let response = self
            .network
            .send_rpc(self.target, rpc)
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;

        match response {
            FederationRpcResponse::Vote(r) => Ok(r),
            FederationRpcResponse::Error { message } => Err(RPCError::Unreachable(
                Unreachable::new(&FederationError::NetworkError(message)),
            )),
            _ => Err(RPCError::Unreachable(Unreachable::new(
                &FederationError::NetworkError("Unexpected response type".to_string()),
            ))),
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for FederationNetwork {
    type Network = FederationConnection;

    async fn new_client(&mut self, target: FederationNodeId, _node: &BasicNode) -> Self::Network {
        FederationConnection::new(target, Arc::new(self.clone()))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use openraft::Vote;

    #[test]
    fn test_rpc_serialization() {
        let vote_req = VoteRequest {
            vote: Vote::new(1, 0),
            last_log_id: None,
        };

        let rpc = FederationRpc::Vote(vote_req);
        let json = serde_json::to_string(&rpc).unwrap();
        assert!(json.contains("vote"));

        let parsed: FederationRpc = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, FederationRpc::Vote(_)));
    }

    #[test]
    fn test_rpc_response_serialization() {
        let response = FederationRpcResponse::Error {
            message: "Test error".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Test error"));

        let parsed: FederationRpcResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            FederationRpcResponse::Error { message } => assert_eq!(message, "Test error"),
            _ => panic!("Expected Error response"),
        }
    }

    #[test]
    fn test_signed_federation_rpc_serialization() {
        let signed_rpc = SignedFederationRpc {
            payload: r#"{"type":"vote","data":{"vote":{"leader_id":{"term":1,"node_id":0},"committed":false},"last_log_id":null}}"#.to_string(),
            sender_prefix: "ETestPrefix123456789012345678901234567890123".to_string(),
            signature: "0BSignatureData".to_string(),
        };

        let json = serde_json::to_string(&signed_rpc).unwrap();
        assert!(json.contains("payload"));
        assert!(json.contains("senderPrefix"));
        assert!(json.contains("signature"));

        let parsed: SignedFederationRpc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sender_prefix, signed_rpc.sender_prefix);
        assert_eq!(parsed.signature, signed_rpc.signature);
        assert_eq!(parsed.payload, signed_rpc.payload);
    }

    #[test]
    fn test_snapshot_transfer_serialization() {
        let transfer = SnapshotTransfer {
            vote: Vote::new(1, 0),
            meta: SnapshotMeta {
                last_log_id: None,
                last_membership: openraft::StoredMembership::default(),
                snapshot_id: "test-snapshot-1".to_string(),
            },
            data: vec![1, 2, 3, 4, 5],
        };

        let json = serde_json::to_string(&transfer).unwrap();
        assert!(json.contains("vote"));
        assert!(json.contains("meta"));
        assert!(json.contains("data"));

        let parsed: SnapshotTransfer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed.meta.snapshot_id, "test-snapshot-1");
    }

    #[test]
    fn test_rpc_response_vote_serialization() {
        let response = FederationRpcResponse::Vote(VoteResponse {
            vote: Vote::new(1, 0),
            vote_granted: true,
            last_log_id: None,
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("vote"));
        assert!(json.contains("vote_granted"));

        let parsed: FederationRpcResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            FederationRpcResponse::Vote(v) => assert!(v.vote_granted),
            _ => panic!("Expected Vote response"),
        }
    }

    #[test]
    fn test_snapshot_transfer_with_data() {
        let transfer = SnapshotTransfer {
            vote: Vote::new(2, 1),
            meta: SnapshotMeta {
                last_log_id: None,
                last_membership: openraft::StoredMembership::default(),
                snapshot_id: "snapshot-2-10".to_string(),
            },
            data: b"snapshot data here".to_vec(),
        };

        let rpc = FederationRpc::Snapshot(transfer);
        let json = serde_json::to_string(&rpc).unwrap();
        assert!(json.contains("snapshot"));
        assert!(json.contains("snapshot-2-10"));

        let parsed: FederationRpc = serde_json::from_str(&json).unwrap();
        match parsed {
            FederationRpc::Snapshot(t) => {
                assert_eq!(t.meta.snapshot_id, "snapshot-2-10");
                assert_eq!(t.data, b"snapshot data here".to_vec());
            }
            _ => panic!("Expected Snapshot RPC"),
        }
    }
}
