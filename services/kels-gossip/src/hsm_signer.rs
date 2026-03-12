//! Identity-backed signers for gossip and registry operations.
//!
//! Provides:
//! - `IdentityGossipSigner`: implements `gossip::net::Signer` for gossip protocol handshakes
//! - `KelsPeerVerifier`: implements `gossip::net::PeerVerifier` for peer authentication
//! - `IdentitySigner`: implements `kels::PeerSigner` for signed API requests
//!
//! All signing goes through the identity service, which holds the node's single
//! cryptographic identity (HSM-backed key pair + KEL).

use cesr::{Matter, PublicKey as CesrPublicKey, Signature as CesrSignature};
use p256::{
    PublicKey as P256PublicKey,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier},
};
use thiserror::Error;

use gossip::identity::NodePrefix;
use gossip::net::{Error as GossipError, PeerVerifier, SignatureBundle, Signer};

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

/// Decode a CESR qb64 public key to compressed SEC1 bytes (33 bytes).
fn cesr_pubkey_to_compressed(cesr_key: &CesrPublicKey) -> Result<Vec<u8>, SignerError> {
    let raw = cesr_key.raw();
    if raw.len() != 33 {
        return Err(SignerError::Key(format!(
            "Expected 33-byte compressed key, got {} bytes",
            raw.len()
        )));
    }
    Ok(raw.to_vec())
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
}

impl IdentityGossipSigner {
    pub fn new(identity_url: &str, peer_prefix: &str) -> Result<Self, SignerError> {
        let node_prefix = NodePrefix::option_from_str(peer_prefix).ok_or_else(|| {
            SignerError::Key(format!(
                "Invalid peer prefix (expected 44 chars): {}",
                peer_prefix
            ))
        })?;

        Ok(Self {
            identity_client: kels::IdentityClient::new(identity_url),
            node_prefix,
        })
    }
}

impl Signer for IdentityGossipSigner {
    fn node_prefix(&self) -> NodePrefix {
        self.node_prefix
    }

    async fn ecdh(&self, peer_public_key: &[u8]) -> Result<[u8; 32], GossipError> {
        let result = self
            .identity_client
            .ecdh(peer_public_key)
            .await
            .map_err(|e| GossipError::Handshake(format!("Identity ECDH failed: {}", e)))?;

        let mut secret = [0u8; 32];
        if result.len() != 32 {
            return Err(GossipError::Handshake(format!(
                "ECDH shared secret wrong length: {} (expected 32)",
                result.len()
            )));
        }
        secret.copy_from_slice(&result);
        Ok(secret)
    }

    async fn sign(&self, data: &[u8]) -> Result<SignatureBundle, GossipError> {
        // The handshake data is a JSON string (from transport::handshake_payload)
        let data_str = std::str::from_utf8(data)
            .map_err(|e| GossipError::Handshake(format!("Handshake data is not UTF-8: {}", e)))?;

        let result = self
            .identity_client
            .sign(data_str)
            .await
            .map_err(|e| GossipError::Handshake(format!("Identity sign failed: {}", e)))?;

        // Decode CESR signature to raw bytes (r||s, 64 bytes)
        let cesr_sig = CesrSignature::from_qb64(&result.signature)
            .map_err(|e| GossipError::Handshake(format!("CESR signature decode: {}", e)))?;
        let signature = cesr_sig.raw().to_vec();

        // Decode CESR public key to compressed SEC1 bytes (33 bytes)
        let cesr_pubkey = CesrPublicKey::from_qb64(&result.public_key)
            .map_err(|e| GossipError::Handshake(format!("CESR pubkey decode: {}", e)))?;
        let public_key = cesr_pubkey_to_compressed(&cesr_pubkey)
            .map_err(|e| GossipError::Handshake(format!("pubkey decompress: {}", e)))?;

        Ok(SignatureBundle {
            signature,
            public_key,
        })
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
}

impl KelsPeerVerifier {
    pub fn new(
        allowlist: SharedAllowlist,
        kels_url: &str,
        federation_registry_urls: Vec<String>,
        node_id: String,
        registry_kel_store: std::sync::Arc<dyn kels::KelStore>,
    ) -> Self {
        Self {
            allowlist,
            kels_url: kels_url.to_string(),
            federation_registry_urls,
            node_id,
            registry_kel_store,
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
        )
        .await
        {
            tracing::warn!("Allowlist refresh during handshake failed: {}", e);
        }

        self.is_in_allowlist(prefix).await
    }

    /// Get the current public key from a peer's KEL as compressed SEC1 bytes.
    async fn public_key_from_key_events(&self, prefix: &str) -> Result<Vec<u8>, GossipError> {
        // Consuming: verify KEL (paginated) to extract trusted public key for signing
        let source = kels::HttpKelSource::new(&self.kels_url, "/api/kels/kel/{prefix}");
        let kel_verification = kels::verify_key_events(
            prefix,
            &source,
            kels::KelVerifier::new(prefix),
            kels::MAX_EVENTS_PER_KEL_QUERY,
            kels::max_verification_pages(),
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

        let cesr_pubkey = CesrPublicKey::from_qb64(qb64_key).map_err(|e| {
            GossipError::VerificationFailed(format!("CESR pubkey decode for {}: {}", prefix, e))
        })?;

        cesr_pubkey_to_compressed(&cesr_pubkey)
            .map_err(|e| GossipError::VerificationFailed(format!("pubkey for {}: {}", prefix, e)))
    }

    /// Verify signature using P-256 ECDSA.
    fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), GossipError> {
        let p256_pubkey = P256PublicKey::from_sec1_bytes(public_key)
            .map_err(|e| GossipError::VerificationFailed(format!("Invalid public key: {}", e)))?;
        let verifying_key = VerifyingKey::from(&p256_pubkey);

        let sig = P256Signature::from_slice(signature)
            .map_err(|e| GossipError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        verifying_key.verify(data, &sig).map_err(|e| {
            GossipError::VerificationFailed(format!("Signature verification failed: {}", e))
        })
    }

    /// Attempt verification: fetch public key from local KEL, compare with handshake
    /// key, verify signature. Returns Ok(true) on success, Ok(false) on key mismatch
    /// or KEL not found (so retry_once! will trigger the refresh path).
    async fn try_verify(
        &self,
        prefix: &str,
        data: &[u8],
        signature: &[u8],
        handshake_key: &[u8],
    ) -> Result<bool, GossipError> {
        let kel_key = match self.public_key_from_key_events(prefix).await {
            Ok(key) => key,
            Err(_) => return Ok(false), // KEL not found locally — trigger refresh
        };
        if kel_key != handshake_key {
            return Ok(false);
        }
        self.verify_signature(data, signature, handshake_key)?;
        Ok(true)
    }

    /// Re-fetch the peer's KEL from their KELS instance, submit it locally, then verify.
    async fn try_verify_refreshed(
        &self,
        prefix: &str,
        data: &[u8],
        signature: &[u8],
        handshake_key: &[u8],
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
        let source = kels::HttpKelSource::new(&peer_kels_url, "/api/kels/kel/{prefix}");
        let sink = kels::HttpKelSink::new(&self.kels_url, "/api/kels/events");
        let _ = kels::forward_key_events(
            prefix,
            &source,
            &sink,
            kels::MAX_EVENTS_PER_KEL_QUERY,
            kels::max_verification_pages(),
            None,
        )
        .await;

        // Retry verification with the now-updated local KEL
        self.try_verify(prefix, data, signature, handshake_key)
            .await
    }
}

impl PeerVerifier for KelsPeerVerifier {
    async fn verify_peer(
        &self,
        peer: &NodePrefix,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
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
            self.try_verify(&prefix_str, data, signature, public_key),
            |ok: &bool| *ok,
            self.try_verify_refreshed(&prefix_str, data, signature, public_key),
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

    // ==================== cesr_pubkey_to_compressed Tests ====================

    #[test]
    fn test_cesr_pubkey_to_compressed_valid() {
        use p256::ecdsa::SigningKey;

        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);

        let cesr_key =
            CesrPublicKey::from_raw(cesr::KeyCode::Secp256r1, compressed.as_bytes().to_vec())
                .unwrap();

        let result = cesr_pubkey_to_compressed(&cesr_key);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 33);
        assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    }

    // ==================== KelsPeerVerifier Tests ====================

    #[test]
    fn test_kels_peer_verifier_verify_valid_signature() {
        use p256::ecdsa::{SigningKey, signature::Signer as _};

        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let public_key = compressed.as_bytes();

        let data = b"test data to sign";
        let sig: P256Signature = signing_key.sign(data);
        let sig_bytes = sig.to_bytes();

        let allowlist = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let store: Arc<dyn kels::KelStore> =
            Arc::new(kels::FileKelStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let verifier = KelsPeerVerifier::new(
            allowlist,
            "http://localhost:8080",
            vec![],
            String::new(),
            store,
        );

        let result = verifier.verify_signature(data, &sig_bytes, public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kels_peer_verifier_verify_bad_signature() {
        use p256::ecdsa::SigningKey;

        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let public_key = compressed.as_bytes();

        let bad_sig = vec![1u8; 64];

        let allowlist = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let store: Arc<dyn kels::KelStore> =
            Arc::new(kels::FileKelStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let verifier = KelsPeerVerifier::new(
            allowlist,
            "http://localhost:8080",
            vec![],
            String::new(),
            store,
        );

        let result = verifier.verify_signature(b"test data", &bad_sig, public_key);
        assert!(result.is_err());
    }
}
