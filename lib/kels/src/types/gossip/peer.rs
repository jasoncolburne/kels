//! Peer types for gossip network

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

use crate::{KelVerification, KelsError};

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "peer")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    #[said]
    pub said: cesr::Digest,
    #[prefix]
    pub prefix: cesr::Digest,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    pub kel_prefix: cesr::Digest,
    pub node_id: String,
    pub authorizing_kel: cesr::Digest,
    pub active: bool,
    /// Base domain for service discovery (e.g., "node-a.kels").
    /// Derive service URLs: http://kels.{base_domain}, http://sadstore.{base_domain}
    pub base_domain: String,
    /// Gossip address (host:port)
    pub gossip_addr: String,
}

impl Peer {
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
    pub prefix: cesr::Digest,
    pub records: Vec<Peer>,
}

impl PeerHistory {
    /// Verify peer records against verified KEL contexts.
    pub fn verify_with_contexts(
        &self,
        trusted_prefixes: &HashSet<&'static str>,
        kel_verifications: &[&KelVerification],
    ) -> Result<(), KelsError> {
        for kel_verification in kel_verifications {
            if !trusted_prefixes.contains(kel_verification.prefix().as_ref()) {
                return Err(KelsError::RegistryFailure(format!(
                    "Could not verify KEL {} as trusted",
                    kel_verification.prefix()
                )));
            }
        }

        self.verify_records()
    }

    fn verify_records(&self) -> Result<(), KelsError> {
        let mut last_said: Option<cesr::Digest> = None;
        for (i, peer_record) in self.records.iter().enumerate() {
            peer_record.verify()?;

            if let Some(said) = last_said {
                if let Some(previous) = peer_record.previous.as_ref() {
                    if *previous != said {
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

            last_said = Some(peer_record.said);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersResponse {
    pub peers: Vec<PeerHistory>,
}
