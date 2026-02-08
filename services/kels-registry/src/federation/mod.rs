//! Federation module for multi-registry consensus using Raft.
//!
//! This module implements registry federation using OpenRaft for consensus.
//! Multiple registries can form a federation where:
//! - Core peers are replicated across all registries via Raft consensus
//! - Regional peers remain local to each registry
//! - Leader election handles automatic failover
//!
//! # Architecture
//!
//! ```text
//!     Registry A (Leader) ◄──► Registry B (Follower) ◄──► Registry C (Follower)
//!            │                        │                        │
//!            └────────────────────────┴────────────────────────┘
//!                      Core Peer Set (replicated via Raft)
//! ```

mod config;
pub mod network;
mod state_machine;
mod storage;
pub mod sync;
mod types;

pub use config::{FederationConfig, FederationMember};
pub use network::{
    FederationNetwork, FederationRpc, FederationRpcResponse, SignedFederationRpc, SnapshotTransfer,
};
pub use state_machine::{StateMachineData, StateMachineStore};
pub use storage::LogStore;
pub use types::{
    FederationError, FederationNodeId, FederationRequest, FederationResponse, PeerProposal,
    ProposalStatus, TypeConfig, Vote,
};

use crate::repository::RegistryRepository;
use kels::{Peer, PeerScope};
use openraft::Raft;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Federation node that participates in multi-registry consensus.
///
/// Each registry runs a FederationNode that:
/// - Participates in Raft consensus with other registries
/// - Replicates core peer set changes
/// - Caches member KELs for signature verification
pub struct FederationNode {
    /// The Raft consensus instance
    raft: Raft<TypeConfig>,
    /// Federation configuration
    config: FederationConfig,
    /// State machine store (for reading state)
    state_machine: StateMachineStore,
    /// Cached KELs for federation members (for signature verification)
    member_kels: Arc<RwLock<HashMap<String, kels::Kel>>>,
}

impl FederationNode {
    /// Create a new federation node.
    ///
    /// # Arguments
    /// * `config` - Federation configuration
    /// * `identity_client` - Client for signing RPC messages
    /// * `repository` - Registry repository with Raft storage components
    pub async fn new(
        config: FederationConfig,
        identity_client: Arc<crate::identity_client::IdentityClient>,
        repository: &RegistryRepository,
    ) -> Result<Self, FederationError> {
        let node_id = config.self_node_id()?;

        // Create member KELs cache (shared with state machine for verification)
        let member_kels = Arc::new(RwLock::new(HashMap::new()));

        // Create storage components (PostgreSQL-backed for persistence)
        let log_store = LogStore::new(
            Arc::new(repository.raft_votes.clone()),
            Arc::new(repository.raft_logs.clone()),
            Arc::new(repository.raft_state.clone()),
            node_id,
        );
        let state_machine = StateMachineStore::new(
            identity_client.clone(),
            member_kels.clone(),
            config.clone(),
            Arc::new(repository.peers.clone()),
        );

        // Create network layer (with signing capability)
        let network = FederationNetwork::new(config.clone(), identity_client);

        // Create Raft instance
        let raft_config = openraft::Config {
            cluster_name: "kels-federation".to_string(),
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        };

        let raft = Raft::new(
            node_id,
            Arc::new(raft_config),
            network,
            log_store,
            state_machine.clone(),
        )
        .await
        .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(Self {
            raft,
            config,
            state_machine,
            member_kels,
        })
    }

    /// Initialize the federation cluster.
    ///
    /// This should be called once when bootstrapping a new federation.
    /// All member nodes should be started, then one node calls initialize().
    pub async fn initialize(&self) -> Result<(), FederationError> {
        let members: BTreeMap<FederationNodeId, openraft::BasicNode> = self
            .config
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (i as u64, openraft::BasicNode::new(m.url.clone())))
            .collect();

        info!("Initializing federation with {} members", members.len());

        self.raft
            .initialize(members)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(())
    }

    /// Check if this node is the current leader.
    pub async fn is_leader(&self) -> bool {
        let node_id = self.config.self_node_id().ok();
        match (self.raft.current_leader().await, node_id) {
            (Some(leader), Some(self_id)) => leader == self_id,
            _ => false,
        }
    }

    /// Get the current leader's node ID, if known.
    pub async fn leader(&self) -> Option<FederationNodeId> {
        self.raft.current_leader().await
    }

    /// Get the current leader's prefix, if known.
    pub async fn leader_prefix(&self) -> Option<String> {
        self.leader().await.and_then(|id| {
            self.config
                .members
                .get(id as usize)
                .map(|m| m.prefix.clone())
        })
    }

    /// Get the current leader's URL, if known.
    pub async fn leader_url(&self) -> Option<String> {
        self.leader()
            .await
            .and_then(|id| self.config.members.get(id as usize).map(|m| m.url.clone()))
    }

    /// Get the federation configuration.
    pub fn config(&self) -> &FederationConfig {
        &self.config
    }

    /// Propose adding a core peer (leader only).
    ///
    /// This will replicate the peer to all registries via Raft consensus.
    pub async fn add_core_peer(&self, peer: Peer) -> Result<(), FederationError> {
        if peer.scope != PeerScope::Core {
            return Err(FederationError::InvalidScope(
                "Peer must have Core scope".to_string(),
            ));
        }

        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::AddPeer(peer);
        self.raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(())
    }

    /// Propose removing a core peer (leader only).
    pub async fn remove_core_peer(&self, peer_id: &str) -> Result<(), FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::RemovePeer(peer_id.to_string());
        self.raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(())
    }

    /// Propose adding a core peer with multi-party approval (leader only).
    ///
    /// Creates an empty proposal (v0) that requires approval from multiple federation
    /// members before the peer is added to the core set. The proposer must then
    /// submit their vote separately via vote_core_peer(). The proposal ID (prefix) is
    /// derived from content and returned in the response.
    pub async fn propose_core_peer(
        &self,
        proposal: PeerProposal,
    ) -> Result<FederationResponse, FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::ProposeCorePeer(proposal);

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Vote on a core peer proposal (leader only).
    ///
    /// # Arguments
    /// * `proposal_id` - The proposal to vote on
    /// * `vote` - The signed vote
    pub async fn vote_core_peer(
        &self,
        proposal_id: String,
        vote: Vote,
    ) -> Result<FederationResponse, FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::VoteCorePeer { proposal_id, vote };

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Withdraw a pending proposal (leader only).
    ///
    /// Only the original proposer can withdraw their proposal.
    pub async fn withdraw_proposal(
        &self,
        proposal_id: String,
        withdrawer: String,
    ) -> Result<FederationResponse, FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::WithdrawProposal {
            proposal_id,
            withdrawer,
        };

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Get all pending proposals from the state machine.
    pub async fn pending_proposals(&self) -> Vec<PeerProposal> {
        self.state_machine
            .inner()
            .lock()
            .await
            .pending_proposals
            .values()
            .cloned()
            .collect()
    }

    /// Get a specific proposal by ID.
    pub async fn get_proposal(&self, proposal_id: &str) -> Option<PeerProposal> {
        self.state_machine
            .inner()
            .lock()
            .await
            .pending_proposals
            .get(proposal_id)
            .cloned()
    }

    /// Get the approval threshold for proposals.
    pub fn approval_threshold(&self) -> usize {
        self.config.approval_threshold()
    }

    /// Get the current core peer set from the state machine.
    pub async fn core_peers(&self) -> Vec<Peer> {
        self.state_machine.inner().lock().await.peers()
    }

    /// Get access to the underlying Raft instance.
    ///
    /// Used by handlers to forward RPC requests.
    pub fn raft(&self) -> &Raft<TypeConfig> {
        &self.raft
    }

    /// Get federation status information.
    pub async fn status(&self) -> FederationStatus {
        FederationStatus {
            node_id: self.config.self_node_id().unwrap_or(0),
            self_prefix: self.config.self_prefix.clone(),
            is_leader: self.is_leader().await,
            leader_id: self.leader().await,
            leader_prefix: self.leader_prefix().await,
            leader_url: self.leader_url().await,
            term: 0,           // TODO: Get from metrics when API is understood
            last_log_index: 0, // TODO: Get from metrics when API is understood
            last_applied: 0,   // TODO: Get from metrics when API is understood
            members: self
                .config
                .members
                .iter()
                .map(|m| m.prefix.clone())
                .collect(),
        }
    }

    /// Populate member KEL cache on startup.
    pub async fn populate_member_kel_cache(&self) -> Result<(), FederationError> {
        info!("Populating member KEL cache...");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;

        for member in &self.config.members {
            match fetch_member_kel(&client, &member.url).await {
                Ok(kel) => {
                    info!("Cached KEL for member {}", member.prefix);
                    self.member_kels
                        .write()
                        .await
                        .insert(member.prefix.clone(), kel);
                }
                Err(e) => {
                    warn!("Failed to fetch KEL for member {}: {}", member.prefix, e);
                }
            }
        }

        Ok(())
    }

    /// Refresh a specific member's KEL (called on verification failure).
    pub async fn refresh_member_kel(&self, prefix: &str) -> Result<kels::Kel, FederationError> {
        let member = self
            .config
            .members
            .iter()
            .find(|m| m.prefix == prefix)
            .ok_or_else(|| FederationError::UnknownMember(prefix.to_string()))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| FederationError::NetworkError(e.to_string()))?;

        let kel = fetch_member_kel(&client, &member.url).await?;
        self.member_kels
            .write()
            .await
            .insert(prefix.to_string(), kel.clone());

        Ok(kel)
    }

    /// Get a cached member KEL.
    pub async fn get_member_kel(&self, prefix: &str) -> Option<kels::Kel> {
        self.member_kels.read().await.get(prefix).cloned()
    }

    /// Get all cached member KELs.
    pub async fn get_all_member_kels(&self) -> HashMap<String, kels::Kel> {
        self.member_kels.read().await.clone()
    }
}

/// Fetch a member's KEL from their registry.
async fn fetch_member_kel(
    client: &reqwest::Client,
    registry_url: &str,
) -> Result<kels::Kel, FederationError> {
    let url = format!("{}/api/registry-kel", registry_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| FederationError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(FederationError::NetworkError(format!(
            "Failed to fetch KEL: {}",
            response.status()
        )));
    }

    let kel: kels::Kel = response
        .json()
        .await
        .map_err(|e| FederationError::NetworkError(e.to_string()))?;

    // Verify KEL integrity
    kel.verify()
        .map_err(|e| FederationError::VerificationFailed(e.to_string()))?;

    Ok(kel)
}

/// Federation status information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationStatus {
    pub node_id: FederationNodeId,
    pub self_prefix: String,
    pub is_leader: bool,
    pub leader_id: Option<FederationNodeId>,
    pub leader_prefix: Option<String>,
    pub leader_url: Option<String>,
    pub term: u64,
    pub last_log_index: u64,
    pub last_applied: u64,
    pub members: Vec<String>,
}
