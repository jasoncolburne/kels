//! Peer allowlist & federation

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
