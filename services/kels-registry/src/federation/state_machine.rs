//! Raft state machine for the core peer set.

use super::config::FederationConfig;
use super::types::{CorePeerSnapshot, FederationRequest, FederationResponse, TypeConfig};
use crate::identity_client::IdentityClient;
use futures::stream::StreamExt;
use kels::{Kel, Peer};
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
    fn apply(&mut self, request: FederationRequest) -> FederationResponse {
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
        }
    }

    /// Create a snapshot of the current state (just the peer data).
    fn snapshot(&self) -> CorePeerSnapshot {
        CorePeerSnapshot {
            peers: self.peers(),
        }
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
        info!("Restored {} core peers from snapshot", self.peers.len());
    }
}

/// Thread-safe state machine store.
#[derive(Clone, Debug)]
pub struct StateMachineStore {
    inner: Arc<Mutex<StateMachineData>>,
    identity_client: Arc<IdentityClient>,
    /// Cached KELs from federation members (for SAID verification)
    member_kels: Arc<RwLock<HashMap<String, Kel>>>,
    /// Federation config (for refreshing member KELs)
    config: FederationConfig,
}

impl StateMachineStore {
    /// Create a new state machine store.
    pub fn new(
        identity_client: Arc<IdentityClient>,
        member_kels: Arc<RwLock<HashMap<String, Kel>>>,
        config: FederationConfig,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateMachineData::default())),
            identity_client,
            member_kels,
            config,
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
                    }
                    sm.apply(request)
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
        let core_snapshot: CorePeerSnapshot = serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

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
mod tests {
    use super::*;
    use kels::PeerScope;
    use openraft::{SnapshotMeta, StoredMembership};

    fn make_test_peer(peer_id: &str, node_id: &str) -> Peer {
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            true,
            PeerScope::Core,
        )
        .unwrap()
    }

    fn make_inactive_peer(peer_id: &str, node_id: &str) -> Peer {
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            false,
            PeerScope::Core,
        )
        .unwrap()
    }

    #[test]
    fn test_add_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");

        let response = sm.apply(FederationRequest::AddPeer(peer.clone()));
        assert!(matches!(response, FederationResponse::PeerAdded(_)));

        assert_eq!(sm.peers().len(), 1);
        assert!(sm.get_peer("peer-1").is_some());
    }

    #[test]
    fn test_add_multiple_peers() {
        let mut sm = StateMachineData::new();

        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-3", "node-3",
        )));

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

        sm.apply(FederationRequest::AddPeer(peer1));
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-1");

        sm.apply(FederationRequest::AddPeer(peer1_updated));
        assert_eq!(sm.get_peer("peer-1").unwrap().node_id, "node-2");
        assert_eq!(sm.peers().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut sm = StateMachineData::new();
        let peer = make_test_peer("peer-1", "node-1");

        sm.apply(FederationRequest::AddPeer(peer));
        let response = sm.apply(FederationRequest::RemovePeer("peer-1".to_string()));

        assert!(matches!(response, FederationResponse::PeerRemoved(_)));
        assert!(sm.peers().is_empty());
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let mut sm = StateMachineData::new();
        let response = sm.apply(FederationRequest::RemovePeer("nonexistent".to_string()));
        assert!(matches!(response, FederationResponse::PeerNotFound(_)));
    }

    #[test]
    fn test_remove_one_of_many_peers() {
        let mut sm = StateMachineData::new();

        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-3", "node-3",
        )));

        sm.apply(FederationRequest::RemovePeer("peer-2".to_string()));

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
        sm1.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));
        sm1.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-2", "node-2",
        )));

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
        sm.apply(FederationRequest::AddPeer(make_test_peer(
            "peer-1", "node-1",
        )));

        let peers = sm.peers();
        assert_eq!(peers.len(), 1);

        // Verify it's a clone by checking we can still access the original
        assert!(sm.get_peer("peer-1").is_some());
    }

    #[test]
    fn test_inactive_peer_can_be_added() {
        let mut sm = StateMachineData::new();
        let peer = make_inactive_peer("peer-1", "node-1");

        let response = sm.apply(FederationRequest::AddPeer(peer));
        assert!(matches!(response, FederationResponse::PeerAdded(_)));

        let stored_peer = sm.get_peer("peer-1").unwrap();
        assert!(!stored_peer.active);
    }

    #[test]
    fn test_state_machine_data_default() {
        let sm = StateMachineData::default();
        assert!(sm.peers.is_empty());
        assert!(sm.last_applied_log.is_none());
    }
}
