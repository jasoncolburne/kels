//! Federation module for multi-registry consensus using Raft.
//!
//! This module implements registry federation using OpenRaft for consensus.
//! Multiple registries can form a federation where:
//! - Peers are replicated across all registries via Raft consensus
//! - Leader election handles automatic failover
//!
//! # Architecture
//!
//! ```text
//!     Registry A (Leader) ◄──► Registry B (Follower) ◄──► Registry C (Follower)
//!            │                        │                        │
//!            └────────────────────────┴────────────────────────┘
//!                        Peer Set (replicated via Raft)
//! ```

mod config;
pub mod network;
mod state_machine;
mod storage;
pub mod sync;
mod types;

pub use config::{FederationConfig, FederationMember};
use kels::{
    AdditionHistory, AdditionWithVotes, PeerAdditionProposal, PeerRemovalProposal, RemovalHistory,
    RemovalWithVotes, Vote,
};
pub use network::{
    FederationNetwork, FederationRpc, FederationRpcResponse, SignedFederationRpc, SnapshotTransfer,
};
pub use state_machine::{StateMachineData, StateMachineStore};
pub use storage::LogStore;
pub use types::{
    FederationError, FederationNodeId, FederationRequest, FederationResponse, TypeConfig,
};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use kels::Peer;
use openraft::Raft;

use crate::repository::RegistryRepository;

/// Federation node that participates in multi-registry consensus.
///
/// Each registry runs a FederationNode that:
/// - Participates in Raft consensus with other registries
/// - Replicates peer set changes
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
        identity_client: Arc<kels::IdentityClient>,
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
            .map(|m| (m.id, openraft::BasicNode::new(m.url.clone())))
            .collect();

        info!("Initializing federation with {} members", members.len());

        self.raft
            .initialize(members)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(())
    }

    /// Grow-only sync of Raft voter set to match compiled-in federation members.
    ///
    /// Compares the current Raft voter set against the compiled-in config. If new
    /// members exist in config that are not yet voters, adds them as learners first
    /// (blocking until they catch up), then promotes them to voters.
    ///
    /// This is grow-only: if the config has fewer members than the current voter set,
    /// no voters are removed. This prevents a node compiled without a new prefix from
    /// undoing an expansion made by an updated node.
    pub async fn sync_membership(&self) -> Result<(), FederationError> {
        let current_voters: BTreeSet<FederationNodeId> = self.raft.voter_ids().collect();
        let expected_voters: BTreeSet<FederationNodeId> =
            self.config.members.iter().map(|m| m.id).collect();

        let new_members: Vec<&FederationMember> = self
            .config
            .members
            .iter()
            .filter(|m| !current_voters.contains(&m.id))
            .collect();

        if new_members.is_empty() {
            return Ok(());
        }

        info!(
            "Syncing federation membership: adding {} new member(s)",
            new_members.len()
        );

        // Add each new member as a learner (blocking — waits for log catch-up)
        for member in &new_members {
            info!(
                "Adding learner: node_id={}, prefix={}",
                member.id, member.prefix
            );
            self.raft
                .add_learner(
                    member.id,
                    openraft::BasicNode::new(member.url.clone()),
                    true,
                )
                .await
                .map_err(|e| FederationError::RaftError(e.to_string()))?;
        }

        // Promote all new learners to voters
        info!("Promoting {} learner(s) to voters", new_members.len());

        // Use the full expected voter set to ensure all members are voters
        self.raft
            .change_membership(expected_voters, true)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        info!("Federation membership synced successfully");
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
        self.leader()
            .await
            .and_then(|id| self.config.member_by_id(id).map(|m| m.prefix.clone()))
    }

    /// Get the current leader's URL, if known.
    pub async fn leader_url(&self) -> Option<String> {
        self.leader()
            .await
            .and_then(|id| self.config.member_by_id(id).map(|m| m.url.clone()))
    }

    /// Get the federation configuration.
    pub fn config(&self) -> &FederationConfig {
        &self.config
    }

    /// Propose adding a peer (leader only).
    ///
    /// This will replicate the peer to all registries via Raft consensus.
    pub async fn add_peer(&self, peer: Peer) -> Result<(), FederationError> {
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

    /// Propose removing a peer (leader only).
    pub async fn remove_peer(&self, peer_prefix: &str) -> Result<(), FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::RemovePeer(peer_prefix.to_string());
        self.raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(())
    }

    /// Submit an addition proposal (create or withdraw) via Raft consensus (leader only).
    ///
    /// For new proposals (v0): creates an empty proposal requiring multi-party approval.
    /// For withdrawals (v1 with withdrawn_at set): withdraws a pending proposal.
    pub async fn submit_addition_proposal(
        &self,
        proposal: PeerAdditionProposal,
    ) -> Result<FederationResponse, FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::SubmitAdditionProposal(proposal);

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Submit a removal proposal (create or withdraw) via Raft consensus (leader only).
    pub async fn submit_removal_proposal(
        &self,
        proposal: PeerRemovalProposal,
    ) -> Result<FederationResponse, FederationError> {
        if !self.is_leader().await {
            return Err(FederationError::NotLeader {
                leader_prefix: self.leader_prefix().await,
                leader_url: self.leader_url().await,
            });
        }

        let request = FederationRequest::SubmitRemovalProposal(proposal);

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Vote on a peer proposal (leader only).
    pub async fn vote_peer(
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

        let request = FederationRequest::VotePeer { proposal_id, vote };

        let result = self
            .raft
            .client_write(request)
            .await
            .map_err(|e| FederationError::RaftError(e.to_string()))?;

        Ok(result.response().clone())
    }

    /// Verify a SAID is anchored in a federation member's KEL.
    /// Delegates to StateMachineStore which has built-in retry (checks cache, refreshes if not found).
    pub async fn verify_anchoring(&self, said: &str, member_prefix: &str) -> Result<(), String> {
        self.state_machine
            .verify_member_anchoring(said, member_prefix)
            .await
    }

    /// Get all pending addition proposals with their votes from the state machine.
    pub async fn pending_addition_proposals_with_votes(&self) -> Vec<AdditionWithVotes> {
        let sm = self.state_machine.inner().lock().await;
        sm.pending_addition_proposals
            .values()
            .map(|p| {
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == p.prefix)
                    .cloned()
                    .collect();
                AdditionWithVotes {
                    history: AdditionHistory {
                        prefix: p.prefix.clone(),
                        records: vec![p.clone()],
                    },
                    votes,
                }
            })
            .collect()
    }

    /// Get all pending removal proposals with their votes from the state machine.
    pub async fn pending_removal_proposals_with_votes(&self) -> Vec<RemovalWithVotes> {
        let sm = self.state_machine.inner().lock().await;
        sm.pending_removal_proposals
            .values()
            .map(|p| {
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == p.prefix)
                    .cloned()
                    .collect();
                RemovalWithVotes {
                    history: RemovalHistory {
                        prefix: p.prefix.clone(),
                        records: vec![p.clone()],
                    },
                    votes,
                }
            })
            .collect()
    }

    /// Get a specific addition proposal by ID (raw, for chain building).
    pub async fn get_addition_proposal(&self, proposal_id: &str) -> Option<PeerAdditionProposal> {
        self.state_machine
            .inner()
            .lock()
            .await
            .pending_addition_proposals
            .get(proposal_id)
            .cloned()
    }

    /// Get a specific removal proposal by ID (raw, for chain building).
    pub async fn get_removal_proposal(&self, proposal_id: &str) -> Option<PeerRemovalProposal> {
        self.state_machine
            .inner()
            .lock()
            .await
            .pending_removal_proposals
            .get(proposal_id)
            .cloned()
    }

    /// Get a specific addition proposal with its votes (searches pending and completed).
    pub async fn get_addition_proposal_with_votes(
        &self,
        proposal_id: &str,
    ) -> Option<AdditionWithVotes> {
        let sm = self.state_machine.inner().lock().await;

        // Check pending first
        if let Some(p) = sm.pending_addition_proposals.get(proposal_id) {
            let votes: Vec<Vote> = sm
                .votes
                .values()
                .filter(|v| v.proposal == p.prefix)
                .cloned()
                .collect();
            return Some(AdditionWithVotes {
                history: AdditionHistory {
                    prefix: p.prefix.clone(),
                    records: vec![p.clone()],
                },
                votes,
            });
        }

        // Check completed
        sm.completed_addition_proposals
            .iter()
            .find(|chain| chain.first().is_some_and(|p| p.prefix == proposal_id))
            .map(|chain| {
                let prefix = chain[0].prefix.clone();
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == prefix)
                    .cloned()
                    .collect();
                AdditionWithVotes {
                    history: AdditionHistory {
                        prefix,
                        records: chain.clone(),
                    },
                    votes,
                }
            })
    }

    /// Get a specific removal proposal with its votes (searches pending and completed).
    pub async fn get_removal_proposal_with_votes(
        &self,
        proposal_id: &str,
    ) -> Option<RemovalWithVotes> {
        let sm = self.state_machine.inner().lock().await;

        // Check pending first
        if let Some(p) = sm.pending_removal_proposals.get(proposal_id) {
            let votes: Vec<Vote> = sm
                .votes
                .values()
                .filter(|v| v.proposal == p.prefix)
                .cloned()
                .collect();
            return Some(RemovalWithVotes {
                history: RemovalHistory {
                    prefix: p.prefix.clone(),
                    records: vec![p.clone()],
                },
                votes,
            });
        }

        // Check completed
        sm.completed_removal_proposals
            .iter()
            .find(|chain| chain.first().is_some_and(|p| p.prefix == proposal_id))
            .map(|chain| {
                let prefix = chain[0].prefix.clone();
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == prefix)
                    .cloned()
                    .collect();
                RemovalWithVotes {
                    history: RemovalHistory {
                        prefix,
                        records: chain.clone(),
                    },
                    votes,
                }
            })
    }

    /// Get the approval threshold for proposals.
    pub fn approval_threshold(&self) -> usize {
        self.config.approval_threshold()
    }

    /// Get the current peer set from the state machine.
    pub async fn peers(&self) -> Vec<Peer> {
        self.state_machine.inner().lock().await.peers()
    }

    /// Get all completed addition proposals (full chains) with their votes.
    pub async fn completed_addition_proposals_with_votes(&self) -> Vec<AdditionWithVotes> {
        let sm = self.state_machine.inner().lock().await;
        sm.completed_addition_proposals
            .iter()
            .filter_map(|chain| {
                let prefix = chain.first()?.prefix.clone();
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == prefix)
                    .cloned()
                    .collect();
                Some(AdditionWithVotes {
                    history: AdditionHistory {
                        prefix,
                        records: chain.clone(),
                    },
                    votes,
                })
            })
            .collect()
    }

    /// Get all completed removal proposals (full chains) with their votes.
    pub async fn completed_removal_proposals_with_votes(&self) -> Vec<RemovalWithVotes> {
        let sm = self.state_machine.inner().lock().await;
        sm.completed_removal_proposals
            .iter()
            .filter_map(|chain| {
                let prefix = chain.first()?.prefix.clone();
                let votes: Vec<Vote> = sm
                    .votes
                    .values()
                    .filter(|v| v.proposal == prefix)
                    .cloned()
                    .collect();
                Some(RemovalWithVotes {
                    history: RemovalHistory {
                        prefix,
                        records: chain.clone(),
                    },
                    votes,
                })
            })
            .collect()
    }

    /// Get the trusted member prefixes.
    pub fn member_prefixes(&self) -> Vec<String> {
        self.config.member_prefixes()
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
