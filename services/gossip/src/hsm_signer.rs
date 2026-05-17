//! Identity-backed signers for gossip and registry operations.
//!
//! Provides:
//! - `IdentityGossipSigner`: implements `kels_gossip_core::net::Signer` for gossip protocol handshakes
//! - `KelsPeerVerifier`: implements `kels_gossip_core::net::PeerVerifier` for peer authentication
//! - `IdentitySigner`: implements `kels_core::PeerSigner` for signed API requests
//!
//! All signing goes through the identity service, which holds the node's single
//! cryptographic identity (HSM-backed key pair + KEL).

use cesr::{Matter, Signature as CesrSignature, VerificationKey};
use thiserror::Error;

use kels_gossip_core::net::{Error as GossipError, PeerVerifier, Signer};

use crate::authorization::{FederationEvaluator, SharedFederationState, is_peer_authorized};

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
// IdentityGossipSigner — implements kels_gossip_core::net::Signer
// ============================================================================

/// Identity service-backed signer for the gossip protocol handshake.
///
/// Signs handshake data via the identity service, which uses the same key
/// that backs the node's identity KEL. This ensures the handshake public key
/// matches the KEL public key that peers verify against.
pub struct IdentityGossipSigner {
    identity_client: kels_core::IdentityClient,
    node_prefix: cesr::Digest256,
}

impl IdentityGossipSigner {
    pub fn new(identity_url: &str, node_prefix: cesr::Digest256) -> Result<Self, SignerError> {
        Ok(Self {
            identity_client: kels_core::IdentityClient::new(identity_url).map_err(|e| {
                SignerError::Identity(format!("Failed to build identity client: {}", e))
            })?,
            node_prefix,
        })
    }
}

impl Signer for IdentityGossipSigner {
    fn node_prefix(&self) -> cesr::Digest256 {
        self.node_prefix
    }

    fn kem_algorithm(&self) -> cesr::EncapsulationKeyCode {
        cesr::EncapsulationKeyCode::MlKem1024
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
        Ok(result.signature.qb64().into_bytes())
    }
}

// ============================================================================
// KelsPeerVerifier — implements kels_gossip_core::net::PeerVerifier
// ============================================================================

/// Verifies peer identity during the gossip handshake using the federation
/// IEL `authPolicy` (post-#190 federation-as-identity model).
///
/// Two phases, in order:
/// 1. **Authentication.** Fetch the peer's KEL via the local KELS service,
///    extract the current signing-key public key, verify the handshake
///    transcript signature against it. The wire protocol presents the
///    peer's KEL prefix (today's encoding); KEL key rotation is picked up
///    on the next handshake's chain re-walk.
/// 2. **Authorization.** Run `evaluate_signed_policy` against the federation
///    IEL's current `authPolicy` with the verified KEL prefix as the
///    sole verified-prefix input. The `iel(X)` evaluator resolves each
///    member identity's IEL to its current `authPolicy` (a single
///    `kel(K_peer)` leaf for degenerate peer identities) and checks for
///    a match. Any one member match satisfies `any(...)`.
///
/// Re-fetch-on-mismatch (the prior allowlist-driven flow) is parked for
/// #195 when address SELs provide the per-peer URL needed to pull a remote
/// KEL update.
pub struct KelsPeerVerifier {
    federation_state: SharedFederationState,
    federation_evaluator: FederationEvaluator,
    kels_url: String,
}

impl KelsPeerVerifier {
    pub fn new(
        federation_state: SharedFederationState,
        federation_evaluator: FederationEvaluator,
        kels_url: String,
    ) -> Self {
        Self {
            federation_state,
            federation_evaluator,
            kels_url,
        }
    }

    /// Fetch the peer's current signing-key public key by walking its KEL
    /// (via the local KELS service) and reading the tip's establishment-key
    /// material.
    async fn public_key_from_key_events(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<VerificationKey, GossipError> {
        let source = kels_core::HttpKelSource::new(&self.kels_url, "/api/v1/kels/kel/fetch")
            .map_err(|e| {
                GossipError::VerificationFailed(format!("Failed to build HTTP client: {}", e))
            })?;
        let kel_verification = kels_core::verify_key_events(
            prefix,
            &source,
            kels_core::KelVerifier::new(prefix),
            kels_core::page_size(),
            kels_core::max_pages(),
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

        let vk = kel_verification.current_public_key().ok_or_else(|| {
            GossipError::VerificationFailed(format!("No public key in KEL for {}", prefix))
        })?;

        Ok(vk.clone())
    }

}

/// Verify a CESR-encoded signature against a public key. Free function so
/// it's exercisable from tests without standing up a full
/// `KelsPeerVerifier`.
fn verify_signature(
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

impl PeerVerifier for KelsPeerVerifier {
    async fn verify_peer(
        &self,
        peer: &cesr::Digest256,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), GossipError> {
        // Phase 1: authenticate signature against the peer's local KEL tip.
        let kel_key = self.public_key_from_key_events(peer).await?;
        verify_signature(data, signature, &kel_key)?;

        // Phase 2: authorize via federation IEL's current authPolicy.
        let federation = self.federation_state.read().await;
        let state = federation.as_ref().ok_or_else(|| {
            GossipError::VerificationFailed(
                "federation IEL state not yet loaded — refusing handshake".to_string(),
            )
        })?;
        let authorized = is_peer_authorized(state, peer, &self.federation_evaluator)
            .await
            .map_err(|e| {
                GossipError::VerificationFailed(format!(
                    "federation authorization check for {peer}: {e}"
                ))
            })?;
        if !authorized {
            return Err(GossipError::VerificationFailed(format!(
                "Peer {peer} is not authorized by the federation IEL's current authPolicy"
            )));
        }
        Ok(())
    }
}

// ============================================================================
// IdentitySigner — implements kels_core::PeerSigner
// ============================================================================

/// Registry signer implementation using the identity service.
///
/// Signs registry API requests via the identity service, ensuring the same
/// key is used for all signing operations (gossip handshakes, registry requests).
pub struct IdentitySigner {
    identity_client: kels_core::IdentityClient,
    peer_kel_prefix: cesr::Digest256,
}

impl IdentitySigner {
    pub fn new(
        identity_url: &str,
        peer_kel_prefix: cesr::Digest256,
    ) -> Result<Self, kels_core::KelsError> {
        Ok(Self {
            identity_client: kels_core::IdentityClient::new(identity_url)?,
            peer_kel_prefix,
        })
    }
}

#[async_trait::async_trait]
impl kels_core::PeerSigner for IdentitySigner {
    async fn sign(&self, data: &[u8]) -> Result<kels_core::SignResult, kels_core::KelsError> {
        let data_str = std::str::from_utf8(data).map_err(|e| {
            kels_core::KelsError::SigningFailed(format!("Data is not UTF-8: {}", e))
        })?;

        let result = self
            .identity_client
            .sign(data_str)
            .await
            .map_err(|e| kels_core::KelsError::SigningFailed(e.to_string()))?;

        Ok(kels_core::SignResult {
            signature: result.signature,
            peer_kel_prefix: self.peer_kel_prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

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
        let peer_kel_prefix = test_digest("test-peer-prefix");
        let signer = IdentitySigner::new("http://identity:80", peer_kel_prefix).unwrap();
        assert_eq!(signer.peer_kel_prefix, peer_kel_prefix);
    }

    // ==================== verify_signature Tests ====================

    #[test]
    fn test_verify_signature_valid() {
        let (cesr_pubkey, cesr_privkey) = cesr::generate_ml_dsa_65().unwrap();

        let data = b"test data to sign";
        let cesr_sig = cesr_privkey.sign(data).unwrap();
        let sig_qb64 = cesr_sig.qb64().into_bytes();

        let result = verify_signature(data, &sig_qb64, &cesr_pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_signature_bad() {
        let (cesr_pubkey, _) = cesr::generate_ml_dsa_65().unwrap();

        let bad_sig = b"0BAAbadbadbadbadbad";

        let result = verify_signature(b"test data", bad_sig, &cesr_pubkey);
        assert!(result.is_err());
    }
}
