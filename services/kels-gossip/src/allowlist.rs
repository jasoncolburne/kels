//! Allowlist-based connection filtering for libp2p.
//!
//! Disconnects peers not in the authorized allowlist after connection establishment.

use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::{
    CloseConnection, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm,
    NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
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
    /// Shared allowlist of authorized PeerIds
    allowlist: Arc<RwLock<HashSet<PeerId>>>,
    /// Peers awaiting verification after allowlist refresh
    pending_verification: HashSet<PeerId>,
    /// Pending disconnections to emit
    pending_disconnects: Vec<PeerId>,
    /// Channel to signal that allowlist refresh is needed
    refresh_tx: mpsc::Sender<()>,
}

impl AllowlistBehaviour {
    /// Create a new AllowlistBehaviour with the given shared allowlist.
    ///
    /// Returns the behaviour and a receiver that signals when refresh is needed.
    pub fn new(allowlist: Arc<RwLock<HashSet<PeerId>>>) -> (Self, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel(1);
        (
            Self {
                allowlist,
                pending_verification: HashSet::new(),
                pending_disconnects: Vec::new(),
                refresh_tx: tx,
            },
            rx,
        )
    }

    /// Called after allowlist refresh completes.
    /// Checks pending peers and schedules disconnects for those still not allowed.
    pub async fn verify_pending_peers(&mut self) {
        let allowlist = self.allowlist.read().await;
        for peer_id in self.pending_verification.drain() {
            if !allowlist.contains(&peer_id) {
                warn!(
                    peer_id = %peer_id,
                    "Peer not in allowlist after refresh, disconnecting"
                );
                if !self.pending_disconnects.contains(&peer_id) {
                    self.pending_disconnects.push(peer_id);
                }
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
        // Check allowlist using try_read (non-blocking, safe in async context)
        let allowed = self
            .allowlist
            .try_read()
            .map(|guard| guard.contains(&peer))
            .unwrap_or(false);
        if !allowed {
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
                if other_established == 0 {
                    let allowed = self
                        .allowlist
                        .try_read()
                        .map(|guard| guard.contains(&peer_id))
                        .unwrap_or(false);
                    if !allowed && !self.pending_verification.contains(&peer_id) {
                        debug!(
                            peer_id = %peer_id,
                            "Unknown peer connected (swarm event), triggering allowlist refresh"
                        );
                        self.pending_verification.insert(peer_id);
                        let _ = self.refresh_tx.try_send(());
                    }
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, .. }) => {
                // Remove from pending lists if present
                self.pending_disconnects.retain(|p| p != &peer_id);
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
        if let Some(peer_id) = self.pending_disconnects.pop() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::All,
            });
        }
        Poll::Pending
    }
}

// ==================== Allowlist Refresh ====================

#[derive(Error, Debug)]
pub enum AllowlistRefreshError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid PeerId: {0}")]
    InvalidPeerId(String),
    #[error("KEL verification failed: {0}")]
    KelVerificationFailed(String),
    #[error("Registry prefix mismatch: expected {expected}, got {actual:?}")]
    PrefixMismatch {
        expected: String,
        actual: Option<String>,
    },
    #[error("Peer SAID not anchored in registry KEL: {0}")]
    SaidNotAnchored(String),
}

// Use types from kels library
use kels::{Kel, PeersResponse};
use verifiable_storage::Versioned;

/// Shared allowlist type
pub type SharedAllowlist = Arc<RwLock<HashSet<PeerId>>>;

/// Fetch peers from registry and update the allowlist with full KEL verification.
///
/// This performs cryptographic verification:
/// 1. Fetches the registry's KEL and verifies its integrity
/// 2. Checks that the registry prefix matches the expected trust anchor
/// 3. Verifies each peer's SAID is anchored in the registry's KEL
///
/// Returns the number of authorized peers in the updated allowlist.
pub async fn refresh_allowlist(
    registry_url: &str,
    registry_prefix: &str,
    allowlist: &SharedAllowlist,
) -> Result<usize, AllowlistRefreshError> {
    let client = reqwest::Client::new();

    // Fetch and verify the registry's KEL
    let kel_url = format!("{}/api/registry-kel", registry_url);
    debug!("Fetching registry KEL from {}", kel_url);
    let registry_kel: Kel = client.get(&kel_url).send().await?.json().await?;

    // Verify KEL integrity (SAIDs, signatures, chaining, rotation hashes)
    if let Err(e) = registry_kel.verify() {
        return Err(AllowlistRefreshError::KelVerificationFailed(e.to_string()));
    }

    // Check that the registry prefix matches our trust anchor
    let actual_prefix = registry_kel.prefix().map(|s| s.to_string());
    if actual_prefix.as_deref() != Some(registry_prefix) {
        return Err(AllowlistRefreshError::PrefixMismatch {
            expected: registry_prefix.to_string(),
            actual: actual_prefix,
        });
    }

    // Fetch peers
    let peers_url = format!("{}/api/peers", registry_url);
    debug!("Fetching peers from {}", peers_url);
    let peers_response = client.get(&peers_url).send().await?;
    let peers_text = peers_response.text().await?;
    debug!("Peers response: {}", peers_text);
    let response: PeersResponse = serde_json::from_str(&peers_text)
        .map_err(|e| AllowlistRefreshError::KelVerificationFailed(format!("JSON parse error: {} - body: {}", e, peers_text)))?;

    let mut authorized_peers = HashSet::new();

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
                        authorized_peers.insert(peer_id);
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

    // Update the shared allowlist
    {
        let mut allowlist_guard = allowlist.write().await;
        *allowlist_guard = authorized_peers;
    }

    info!(
        "Allowlist refreshed with {} verified authorized peers",
        count
    );
    Ok(count)
}

/// Run the allowlist refresh loop in the background.
///
/// Periodically fetches the peer list from the registry and updates the allowlist.
/// Performs full KEL verification against the trust anchor.
pub async fn run_allowlist_refresh_loop(
    registry_url: String,
    registry_prefix: String,
    allowlist: SharedAllowlist,
    refresh_interval: Duration,
) {
    info!(
        "Starting allowlist refresh loop (interval: {:?})",
        refresh_interval
    );

    loop {
        match refresh_allowlist(&registry_url, &registry_prefix, &allowlist).await {
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

    #[test]
    fn test_allowlist_behaviour_creation() {
        let allowlist = Arc::new(RwLock::new(HashSet::new()));
        let (behaviour, _refresh_rx) = AllowlistBehaviour::new(allowlist);
        assert!(behaviour.pending_disconnects.is_empty());
    }
}
