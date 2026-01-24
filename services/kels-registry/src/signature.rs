//! Signature verification for authenticated registry requests.
//!
//! Verifies that requests are signed by authorized peers using CESR-encoded
//! public keys and signatures.

use cesr::{Matter, PublicKey, Signature};
use libp2p_identity::PeerId;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::EncodedPoint;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("PeerId mismatch: expected {expected}, got {actual}")]
    PeerIdMismatch { expected: String, actual: String },
    #[error("Invalid PeerId: {0}")]
    InvalidPeerId(String),
}

/// Verify a signed request.
///
/// This function:
/// 1. Decodes the public key from CESR qb64 format
/// 2. Verifies the PeerId matches the public key
/// 3. Verifies the signature over the payload
///
/// Note: Allowlist checking is done separately by the caller.
pub fn verify_signature(
    payload_json: &[u8],
    peer_id_str: &str,
    public_key_qb64: &str,
    signature_qb64: &str,
) -> Result<PeerId, SignatureError> {
    // Parse CESR-encoded public key (compressed SEC1 format, 33 bytes)
    let public_key = PublicKey::from_qb64(public_key_qb64)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Decompress the public key for libp2p PeerId derivation
    // CESR stores compressed (33 bytes), libp2p needs uncompressed (65 bytes)
    let compressed_bytes = public_key.raw();
    let encoded_point = EncodedPoint::from_bytes(compressed_bytes)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    let p256_pubkey: p256::PublicKey = p256::PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| {
            SignatureError::InvalidPublicKey("Failed to parse compressed public key".to_string())
        })?;

    // Convert to uncompressed format for libp2p
    let uncompressed = p256_pubkey.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();

    // Derive PeerId from uncompressed public key
    let libp2p_pubkey = libp2p_identity::ecdsa::PublicKey::try_from_bytes(uncompressed_bytes)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;
    let libp2p_keypair_pubkey = libp2p_identity::PublicKey::from(libp2p_pubkey);
    let derived_peer_id = libp2p_keypair_pubkey.to_peer_id();

    // Parse the claimed PeerId
    let claimed_peer_id = PeerId::from_str(peer_id_str)
        .map_err(|e| SignatureError::InvalidPeerId(e.to_string()))?;

    if derived_peer_id != claimed_peer_id {
        return Err(SignatureError::PeerIdMismatch {
            expected: claimed_peer_id.to_string(),
            actual: derived_peer_id.to_string(),
        });
    }

    // Parse CESR-encoded signature
    let signature = Signature::from_qb64(signature_qb64)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?;

    // Verify signature using CESR's verification
    public_key
        .verify(payload_json, &signature)
        .map_err(|_| SignatureError::VerificationFailed)?;

    Ok(derived_peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_error_display() {
        let err = SignatureError::VerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }
}
