//! Allowlist-based connection filtering for libp2p.
//!
//! Disconnects peers not in the authorized allowlist after connection establishment.

use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::{
    CloseConnection, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// NetworkBehaviour that disconnects peers not in the allowlist.
///
/// After a connection is established and the peer's identity is verified via Noise,
/// this behaviour checks if the peer is in the allowlist. If not found, it signals
/// for an allowlist refresh and holds the peer in a pending state. After refresh,
/// `verify_pending_peers` should be called to disconnect still-unauthorized peers.
pub struct AllowlistBehaviour {
    /// Shared allowlist of authorized PeerIds mapped to their Peer data
    allowlist: SharedAllowlist,
    /// Peers awaiting verification after allowlist refresh
    pending_verification: HashSet<PeerId>,
    /// Pending disconnections to emit
    pending_disconnects: HashSet<PeerId>,
    /// Channel to signal that allowlist refresh is needed
    refresh_tx: mpsc::Sender<()>,
}

impl AllowlistBehaviour {
    /// Create a new AllowlistBehaviour with the given shared allowlist.
    ///
    /// Returns the behaviour and a receiver that signals when refresh is needed.
    pub fn new(allowlist: SharedAllowlist) -> (Self, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel(1);
        (
            Self {
                allowlist,
                pending_verification: HashSet::new(),
                pending_disconnects: HashSet::new(),
                refresh_tx: tx,
            },
            rx,
        )
    }

    /// Check if a peer is in the allowlist (non-blocking).
    fn is_peer_allowed(&self, peer: &PeerId) -> bool {
        self.allowlist
            .try_read()
            .map(|guard| guard.contains_key(peer))
            .unwrap_or(false)
    }

    /// Called after allowlist refresh completes.
    /// Checks pending peers and schedules disconnects for those still not allowed.
    pub async fn verify_pending_peers(&mut self) {
        let allowlist = self.allowlist.read().await;
        for peer_id in self.pending_verification.drain() {
            if !allowlist.contains_key(&peer_id) {
                warn!(
                    peer_id = %peer_id,
                    "Peer not in allowlist after refresh, disconnecting"
                );
                self.pending_disconnects.insert(peer_id);
            } else {
                info!(
                    peer_id = %peer_id,
                    "Peer authorized after allowlist refresh"
                );
            }
        }
    }
}

impl NetworkBehaviour for AllowlistBehaviour {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // Can't check allowlist here - peer identity not yet known
        Ok(())
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        // Allow outbound connections - we initiated them
        Ok(vec![])
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.is_peer_allowed(&peer) {
            debug!(
                peer_id = %peer,
                "Unknown peer connected, triggering allowlist refresh"
            );
            // Add to pending verification and signal for refresh
            self.pending_verification.insert(peer);
            // Try to send refresh signal (ignore if channel full - refresh already pending)
            let _ = self.refresh_tx.try_send(());
        }
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Allow outbound connections - we initiated them intentionally
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                other_established,
                ..
            }) => {
                // Only check on first connection from this peer
                if other_established == 0
                    && !self.is_peer_allowed(&peer_id)
                    && !self.pending_verification.contains(&peer_id)
                {
                    debug!(
                        peer_id = %peer_id,
                        "Unknown peer connected (swarm event), triggering allowlist refresh"
                    );
                    self.pending_verification.insert(peer_id);
                    let _ = self.refresh_tx.try_send(());
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, .. }) => {
                // Remove from pending lists if present
                self.pending_disconnects.remove(&peer_id);
                self.pending_verification.remove(&peer_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // Dummy handler emits no events
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(&peer_id) = self.pending_disconnects.iter().next() {
            self.pending_disconnects.remove(&peer_id);
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::All,
            });
        }
        Poll::Pending
    }
}

#[derive(Error, Debug)]
pub enum AllowlistRefreshError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KEL verification failed: {0}")]
    KelVerificationFailed(String),
}

// Use types from kels library
use kels::MultiRegistryClient;
use verifiable_storage::Chained;

/// Shared allowlist type - maps PeerId to full Peer data
pub type SharedAllowlist = Arc<RwLock<HashMap<PeerId, kels::Peer>>>;

/// Get this node's scope from the allowlist.
/// Returns Regional as a safe default if not found.
pub async fn get_local_scope(peer_id: &PeerId, allowlist: &SharedAllowlist) -> kels::PeerScope {
    let guard = allowlist.read().await;
    guard
        .get(peer_id)
        .map(|peer| peer.scope)
        .unwrap_or(kels::PeerScope::Regional)
}

/// Fetch peers from registry and update the allowlist with full KEL verification.
///
/// This performs cryptographic verification:
/// 1. Fetches the registry's KEL and verifies its integrity
/// 2. Checks that the registry prefix matches the expected trust anchor
/// 3. Verifies each peer's SAID is anchored in the registry's KEL
///
/// Returns the number of authorized peers in the updated allowlist.
pub async fn refresh_allowlist(
    registry_client: &mut MultiRegistryClient,
    registry_prefix: &str,
    allowlist: &SharedAllowlist,
) -> Result<usize, AllowlistRefreshError> {
    let original_peers = allowlist.read().await;
    let original_saids: HashSet<_> = original_peers.values().map(|p| p.said.clone()).collect();
    drop(original_peers);

    // Fetch peers
    debug!("Fetching peers");
    let response = registry_client
        .fetch_peers(registry_prefix)
        .await
        .map_err(|e| AllowlistRefreshError::KelVerificationFailed(e.to_string()))?;

    let mut authorized_peers = HashMap::new();

    for history in response.peers {
        // Get the latest (last) record
        if let Some(latest) = history.records.last() {
            // Verify the peer record's SAID matches its content
            if let Err(e) = latest.verify() {
                warn!(
                    peer_id = %latest.peer_id,
                    said = %latest.said,
                    error = %e,
                    "Peer record SAID verification failed, skipping"
                );
                continue;
            }

            // Fetch and verify the registry's KEL
            debug!("Verifying registry KEL");
            let registry_kel = registry_client
                .fetch_registry_kel(&latest.authorizing_kel, true)
                .await
                .map_err(|e| AllowlistRefreshError::KelVerificationFailed(e.to_string()))?;

            // Verify the peer's SAID is anchored in the registry's KEL
            if !registry_kel.contains_anchor(&latest.said) {
                warn!(
                    peer_id = %latest.peer_id,
                    said = %latest.said,
                    "Peer SAID not anchored in registry KEL, skipping"
                );
                continue;
            }

            if latest.active {
                match PeerId::from_str(&latest.peer_id) {
                    Ok(peer_id) => {
                        authorized_peers.insert(peer_id, latest.clone());
                    }
                    Err(e) => {
                        warn!(
                            peer_id = %latest.peer_id,
                            error = %e,
                            "Failed to parse PeerId, skipping"
                        );
                    }
                }
            }
        }
    }

    let count = authorized_peers.len();

    if original_saids.len() != count
        || authorized_peers
            .iter()
            .any(|(_, p)| !original_saids.contains(&p.said))
    {
        // Update the shared allowlist
        *allowlist.write().await = authorized_peers;

        info!(
            "Allowlist refreshed with {} verified authorized peers",
            count
        );
    }

    Ok(count)
}

/// Run the allowlist refresh loop in the background.
///
/// Periodically fetches the peer list from the registry and updates the allowlist.
/// Performs full KEL verification against the trust anchor.
pub async fn run_allowlist_refresh_loop(
    registry_client: &mut MultiRegistryClient,
    registry_prefix: &str,
    allowlist: SharedAllowlist,
    refresh_interval: Duration,
) {
    info!(
        "Starting allowlist refresh loop (interval: {:?})",
        refresh_interval
    );

    loop {
        match refresh_allowlist(registry_client, registry_prefix, &allowlist).await {
            Ok(count) => {
                debug!("Allowlist refresh successful: {} peers", count);
            }
            Err(e) => {
                error!("Allowlist refresh failed: {}", e);
            }
        }

        tokio::time::sleep(refresh_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer(peer_id: &PeerId) -> kels::Peer {
        kels::Peer {
            said: "test-said".to_string(),
            prefix: "test-prefix".to_string(),
            previous: None,
            version: 1,
            created_at: verifiable_storage::StorageDatetime::now(),
            peer_id: peer_id.to_string(),
            node_id: "test-node".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            scope: kels::PeerScope::Core,
            kels_url: "http://test:8080".to_string(),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/4001".to_string(),
        }
    }

    #[test]
    fn test_allowlist_behaviour_creation() {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let (behaviour, _refresh_rx) = AllowlistBehaviour::new(allowlist);
        assert!(behaviour.pending_disconnects.is_empty());
    }

    #[test]
    fn test_allowlist_behaviour_initial_state() {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let (behaviour, _rx) = AllowlistBehaviour::new(allowlist);
        assert!(behaviour.pending_verification.is_empty());
        assert!(behaviour.pending_disconnects.is_empty());
    }

    #[test]
    fn test_is_peer_allowed_empty_allowlist() {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let (behaviour, _rx) = AllowlistBehaviour::new(allowlist);
        // Generate a random PeerId
        let peer_id = PeerId::random();
        assert!(!behaviour.is_peer_allowed(&peer_id));
    }

    #[tokio::test]
    async fn test_is_peer_allowed_with_peer() {
        let peer_id = PeerId::random();
        let mut map = HashMap::new();
        map.insert(peer_id, create_test_peer(&peer_id));
        let allowlist = Arc::new(RwLock::new(map));
        let (behaviour, _rx) = AllowlistBehaviour::new(allowlist);
        assert!(behaviour.is_peer_allowed(&peer_id));
    }

    #[tokio::test]
    async fn test_verify_pending_peers_removes_unauthorized() {
        let allowlist = Arc::new(RwLock::new(HashMap::new()));
        let (mut behaviour, _rx) = AllowlistBehaviour::new(allowlist);

        let peer_id = PeerId::random();
        behaviour.pending_verification.insert(peer_id);

        behaviour.verify_pending_peers().await;

        assert!(behaviour.pending_verification.is_empty());
        assert!(behaviour.pending_disconnects.contains(&peer_id));
    }

    #[tokio::test]
    async fn test_verify_pending_peers_keeps_authorized() {
        let peer_id = PeerId::random();
        let mut map = HashMap::new();
        map.insert(peer_id, create_test_peer(&peer_id));
        let allowlist = Arc::new(RwLock::new(map));
        let (mut behaviour, _rx) = AllowlistBehaviour::new(allowlist);

        behaviour.pending_verification.insert(peer_id);

        behaviour.verify_pending_peers().await;

        assert!(behaviour.pending_verification.is_empty());
        assert!(!behaviour.pending_disconnects.contains(&peer_id));
    }

    // ==================== AllowlistRefreshError Tests ====================

    #[test]
    fn test_allowlist_refresh_error_http_display() {
        // We can't easily create a reqwest::Error, so test the KelVerificationFailed variant
        let err = AllowlistRefreshError::KelVerificationFailed("Invalid KEL".to_string());
        assert_eq!(err.to_string(), "KEL verification failed: Invalid KEL");
    }

    #[test]
    fn test_allowlist_refresh_error_kel_verification_display() {
        let err = AllowlistRefreshError::KelVerificationFailed("SAID mismatch".to_string());
        assert!(err.to_string().contains("SAID mismatch"));
    }
}
