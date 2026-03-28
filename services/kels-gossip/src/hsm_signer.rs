//! Identity-backed signers for gossip and registry operations.
//!
//! Provides:
//! - `IdentityGossipSigner`: implements `gossip::net::Signer` for gossip protocol handshakes
//! - `KelsPeerVerifier`: implements `gossip::net::PeerVerifier` for peer authentication
//! - `IdentitySigner`: implements `kels::PeerSigner` for signed API requests
//!
//! All signing goes through the identity service, which holds the node's single
//! cryptographic identity (HSM-backed key pair + KEL).

use cesr::{Matter, Signature as CesrSignature, VerificationKey};
use thiserror::Error;
use tracing::warn;

use gossip::identity::NodePrefix;
use gossip::net::{Error as GossipError, PeerVerifier, Signer};

use crate::allowlist::SharedAllowlist;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("Identity service error: {0}")]
    Identity(String),
    #[error("CESR error: {0}")]
    Cesr(#[from] cesr::CesrError),
    #[error("Key error: {0}")]
    Key(String),
}

// ============================================================================
// IdentityGossipSigner — implements gossip::net::Signer
// ============================================================================

/// Identity service-backed signer for the gossip protocol handshake.
///
/// Signs handshake data via the identity service, which uses the same key
/// that backs the node's identity KEL. This ensures the handshake public key
/// matches the KEL public key that peers verify against.
pub struct IdentityGossipSigner {
    identity_client: kels::IdentityClient,
    node_prefix: NodePrefix,
    requires_kem_1024: crate::allowlist::RequiresKem1024,
}

impl IdentityGossipSigner {
    pub fn new(
        identity_url: &str,
        peer_prefix: &str,
        requires_kem_1024: crate::allowlist::RequiresKem1024,
    ) -> Result<Self, SignerError> {
        let node_prefix = NodePrefix::option_from_str(peer_prefix).ok_or_else(|| {
            SignerError::Key(format!(
                "Invalid peer prefix (expected 44 chars): {}",
                peer_prefix
            ))
        })?;

        Ok(Self {
            identity_client: kels::IdentityClient::new(identity_url),
            node_prefix,
            requires_kem_1024,
        })
    }
}

impl Signer for IdentityGossipSigner {
    fn node_prefix(&self) -> NodePrefix {
        self.node_prefix
    }

    fn kem_algorithm(&self) -> cesr::EncapsulationKeyCode {
        if self
            .requires_kem_1024
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            cesr::EncapsulationKeyCode::MlKem1024
        } else {
            cesr::EncapsulationKeyCode::MlKem768
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, GossipError> {
        // The handshake data is a JSON string (from transport::handshake_payload)
        let data_str = std::str::from_utf8(data)
            .map_err(|e| GossipError::Handshake(format!("Handshake data is not UTF-8: {}", e)))?;

        let result = self
            .identity_client
            .sign(data_str)
            .await
            .map_err(|e| GossipError::Handshake(format!("Identity sign failed: {}", e)))?;

        // Return CESR-encoded signature (qb64 bytes) — type is embedded in the encoding
        Ok(result.signature.into_bytes())
    }
}

// ============================================================================
// KelsPeerVerifier — implements gossip::net::PeerVerifier
// ============================================================================

/// Verifies peer identity during gossip handshake using the allowlist and KEL.
///
/// Authorization is checked against the allowlist (prefix only). If the peer is
/// not in the local allowlist, a one-shot refresh from the registry is attempted
/// before rejecting.
/// Authentication is checked against the peer's KEL (public key from last
/// establishment event). On key mismatch (rotation), re-fetches the KEL and retries.
pub struct KelsPeerVerifier {
    allowlist: SharedAllowlist,
    kels_url: String,
    federation_registry_urls: Vec<String>,
    node_id: String,
    registry_kel_store: std::sync::Arc<dyn kels::KelStore>,
    requires_kem_1024: crate::allowlist::RequiresKem1024,
}

impl KelsPeerVerifier {
    pub fn new(
        allowlist: SharedAllowlist,
        kels_url: &str,
        federation_registry_urls: Vec<String>,
        node_id: String,
        registry_kel_store: std::sync::Arc<dyn kels::KelStore>,
        requires_kem_1024: crate::allowlist::RequiresKem1024,
    ) -> Self {
        Self {
            allowlist,
            kels_url: kels_url.to_string(),
            federation_registry_urls,
            node_id,
            registry_kel_store,
            requires_kem_1024,
        }
    }

    /// Check if a peer is in the allowlist (without refreshing).
    async fn is_in_allowlist(&self, prefix: &str) -> Result<bool, GossipError> {
        let guard = self.allowlist.read().await;
        Ok(guard.contains_key(prefix))
    }

    /// Refresh the allowlist from the registry, then check again.
    async fn is_in_allowlist_refreshed(&self, prefix: &str) -> Result<bool, GossipError> {
        if let Err(e) = crate::allowlist::refresh_allowlist(
            &self.federation_registry_urls,
            self.registry_kel_store.as_ref(),
            &self.allowlist,
            Some(&self.node_id),
            &self.requires_kem_1024,
            &self.kels_url,
        )
        .await
        {
            tracing::warn!("Allowlist refresh during handshake failed: {}", e);
        }

        self.is_in_allowlist(prefix).await
    }

    /// Get the current public key from a peer's verified KEL.
    async fn public_key_from_key_events(
        &self,
        prefix: &str,
    ) -> Result<VerificationKey, GossipError> {
        // Consuming: verify KEL (paginated) to extract trusted public key
        let source = kels::HttpKelSource::new(&self.kels_url, "/api/v1/kels/kel/{prefix}");
        let kel_verification = kels::verify_key_events(
            prefix,
            &source,
            kels::KelVerifier::new(prefix),
            kels::page_size(),
            kels::max_pages(),
        )
        .await
        .map_err(|e| {
            GossipError::VerificationFailed(format!("KEL verify for {}: {}", prefix, e))
        })?;

        if kel_verification.is_divergent() {
            return Err(GossipError::VerificationFailed(format!(
                "KEL for {} is divergent",
                prefix
            )));
        }

        let qb64_key = kel_verification.current_public_key().ok_or_else(|| {
            GossipError::VerificationFailed(format!("No public key in KEL for {}", prefix))
        })?;

        VerificationKey::from_qb64(qb64_key).map_err(|e| {
            GossipError::VerificationFailed(format!("CESR pubkey decode for {}: {}", prefix, e))
        })
    }

    /// Verify a CESR-encoded signature against a public key from the KEL.
    fn verify_signature(
        &self,
        data: &[u8],
        signature_qb64: &[u8],
        public_key: &VerificationKey,
    ) -> Result<(), GossipError> {
        let sig_str = std::str::from_utf8(signature_qb64)
            .map_err(|e| GossipError::VerificationFailed(format!("Signature not UTF-8: {}", e)))?;

        let cesr_sig = CesrSignature::from_qb64(sig_str)
            .map_err(|e| GossipError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        public_key.verify(data, &cesr_sig).map_err(|e| {
            GossipError::VerificationFailed(format!("Signature verification failed: {}", e))
        })
    }

    /// Attempt verification: fetch public key from local KEL, verify signature.
    /// Returns Ok(true) on success, Ok(false) on KEL not found (so retry_once!
    /// will trigger the refresh path).
    async fn try_verify(
        &self,
        prefix: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, GossipError> {
        let kel_key = match self.public_key_from_key_events(prefix).await {
            Ok(key) => key,
            Err(_) => return Ok(false), // KEL not found locally — trigger refresh
        };
        self.verify_signature(data, signature, &kel_key)?;
        Ok(true)
    }

    /// Re-fetch the peer's KEL from their KELS instance, submit it locally, then verify.
    async fn try_verify_refreshed(
        &self,
        prefix: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, GossipError> {
        // Look up the peer's remote KELS URL from the allowlist
        let peer_kels_url = {
            let guard = self.allowlist.read().await;
            guard
                .get(prefix)
                .map(|p| p.kels_url.clone())
                .ok_or_else(|| {
                    GossipError::VerificationFailed(format!("Peer {} not in allowlist", prefix))
                })?
        };

        // Forward KEL from peer's KELS to our local KELS (paginated)
        let source = kels::HttpKelSource::new(&peer_kels_url, "/api/v1/kels/kel/{prefix}");
        let sink = kels::HttpKelSink::new(&self.kels_url, "/api/v1/kels/events");
        if let Err(e) = kels::forward_key_events(
            prefix,
            &source,
            &sink,
            kels::page_size(),
            kels::max_pages(),
            None,
        )
        .await
        {
            warn!(prefix, error = %e, "failed to refresh peer KEL, retrying verification with cached state");
        }

        // Retry verification with the now-updated local KEL
        self.try_verify(prefix, data, signature).await
    }
}

impl PeerVerifier for KelsPeerVerifier {
    async fn verify_peer(
        &self,
        peer: &NodePrefix,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), GossipError> {
        let prefix_str = peer.to_option_string().ok_or_else(|| {
            GossipError::VerificationFailed("Invalid peer prefix encoding".to_string())
        })?;

        // Authorization: check peer is in allowlist, refresh once if not found
        let authorized = kels::retry_once!(
            self.is_in_allowlist(&prefix_str),
            |ok: &bool| *ok,
            self.is_in_allowlist_refreshed(&prefix_str),
        )
        .map_err(|e| {
            GossipError::VerificationFailed(format!("Allowlist check for {}: {}", prefix_str, e))
        })?;

        if authorized != Some(true) {
            return Err(GossipError::VerificationFailed(format!(
                "Peer {} not in allowlist",
                prefix_str
            )));
        }

        // Authentication: verify against local KEL, refresh from peer on mismatch
        let verified = kels::retry_once!(
            self.try_verify(&prefix_str, data, signature),
            |ok: &bool| *ok,
            self.try_verify_refreshed(&prefix_str, data, signature),
        )
        .map_err(|e| {
            GossipError::VerificationFailed(format!("KEL verification for {}: {}", prefix_str, e))
        })?;

        match verified {
            Some(true) => Ok(()),
            _ => Err(GossipError::VerificationFailed(format!(
                "Peer {} handshake key does not match KEL",
                prefix_str
            ))),
        }
    }
}

// ============================================================================
// IdentitySigner — implements kels::PeerSigner
// ============================================================================

/// Registry signer implementation using the identity service.
///
/// Signs registry API requests via the identity service, ensuring the same
/// key is used for all signing operations (gossip handshakes, registry requests).
pub struct IdentitySigner {
    identity_client: kels::IdentityClient,
    peer_prefix: String,
}

impl IdentitySigner {
    pub fn new(identity_url: &str, peer_prefix: String) -> Self {
        Self {
            identity_client: kels::IdentityClient::new(identity_url),
            peer_prefix,
        }
    }
}

#[async_trait::async_trait]
impl kels::PeerSigner for IdentitySigner {
    async fn sign(&self, data: &[u8]) -> Result<kels::SignResult, kels::KelsError> {
        let data_str = std::str::from_utf8(data)
            .map_err(|e| kels::KelsError::SigningFailed(format!("Data is not UTF-8: {}", e)))?;

        let result = self
            .identity_client
            .sign(data_str)
            .await
            .map_err(|e| kels::KelsError::SigningFailed(e.to_string()))?;

        Ok(kels::SignResult {
            signature: result.signature,
            peer_prefix: self.peer_prefix.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;

    // ==================== SignerError Display Tests ====================

    #[test]
    fn test_signer_error_identity_display() {
        let err = SignerError::Identity("service unavailable".to_string());
        assert_eq!(
            err.to_string(),
            "Identity service error: service unavailable"
        );
    }

    #[test]
    fn test_signer_error_key_display() {
        let err = SignerError::Key("Invalid key format".to_string());
        assert_eq!(err.to_string(), "Key error: Invalid key format");
    }

    // ==================== IdentitySigner Tests ====================

    #[test]
    fn test_identity_registry_signer_new() {
        let signer = IdentitySigner::new(
            "http://identity:80",
            "ETestPeerPrefix_____________________________".to_string(),
        );
        assert_eq!(
            signer.peer_prefix,
            "ETestPeerPrefix_____________________________"
        );
    }

    // ==================== KelsPeerVerifier Tests ====================

    #[test]
    fn test_kels_peer_verifier_verify_valid_signature() {
        let (cesr_pubkey, cesr_privkey) = cesr::generate_ml_dsa_65().unwrap();

        let data = b"test data to sign";
        let cesr_sig = cesr_privkey.sign(data).unwrap();
        let sig_qb64 = cesr_sig.qb64().into_bytes();

        let allowlist = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let store: Arc<dyn kels::KelStore> =
            Arc::new(kels::FileKelStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let requires_kem_1024 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let verifier = KelsPeerVerifier::new(
            allowlist,
            "http://localhost:8080",
            vec![],
            String::new(),
            store,
            requires_kem_1024,
        );

        let result = verifier.verify_signature(data, &sig_qb64, &cesr_pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kels_peer_verifier_verify_bad_signature() {
        let (cesr_pubkey, _) = cesr::generate_ml_dsa_65().unwrap();

        let bad_sig = b"0BAAbadbadbadbadbad";

        let allowlist = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let store: Arc<dyn kels::KelStore> =
            Arc::new(kels::FileKelStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let requires_kem_1024 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let verifier = KelsPeerVerifier::new(
            allowlist,
            "http://localhost:8080",
            vec![],
            String::new(),
            store,
            requires_kem_1024,
        );

        let result = verifier.verify_signature(b"test data", bad_sig, &cesr_pubkey);
        assert!(result.is_err());
    }
}
