//! Signature verification tests for the shared libkels p2p_signature module.

#[cfg(test)]
mod tests {
    use cesr::Matter;
    use kels::p2p_signature::{SignatureError, verify_signature};

    // ==================== SignatureError Display Tests ====================

    #[test]
    fn test_signature_error_display() {
        let err = SignatureError::VerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }

    #[test]
    fn test_signature_error_invalid_public_key_display() {
        let err = SignatureError::InvalidPublicKey("bad key format".to_string());
        assert_eq!(err.to_string(), "Invalid public key: bad key format");
    }

    #[test]
    fn test_signature_error_invalid_signature_display() {
        let err = SignatureError::InvalidSignature("bad sig".to_string());
        assert_eq!(err.to_string(), "Invalid signature: bad sig");
    }

    #[test]
    fn test_signature_error_peer_id_mismatch_display() {
        let err = SignatureError::PeerIdMismatch {
            expected: "12D3KooWExpected".to_string(),
            actual: "12D3KooWActual".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "PeerId mismatch: expected 12D3KooWExpected, got 12D3KooWActual"
        );
    }

    #[test]
    fn test_signature_error_invalid_peer_id_display() {
        let err = SignatureError::InvalidPeerId("not a valid peer id".to_string());
        assert_eq!(err.to_string(), "Invalid PeerId: not a valid peer id");
    }

    // ==================== verify_signature Error Path Tests ====================

    #[test]
    fn test_verify_signature_invalid_public_key_not_qb64() {
        let result = verify_signature(
            b"payload",
            "12D3KooWFakeId",
            "not_a_valid_qb64_key",
            "0BAAA_signature",
        );
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_verify_signature_invalid_public_key_empty() {
        let result = verify_signature(b"payload", "12D3KooWFakeId", "", "0BAAA_signature");
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_verify_signature_invalid_peer_id_format() {
        // Use a valid CESR public key but invalid peer_id format
        // Create a valid compressed public key (33 bytes starting with 02 or 03)
        let compressed_key_bytes: [u8; 33] = [
            0x02, // compressed even prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let cesr_pubkey =
            cesr::PublicKey::from_raw(cesr::KeyCode::Secp256r1, compressed_key_bytes.to_vec())
                .unwrap();
        let pubkey_qb64 = cesr_pubkey.qb64();

        let result = verify_signature(
            b"payload",
            "not-a-valid-peer-id",
            &pubkey_qb64,
            "0BAAA_signature",
        );
        // Should fail at peer_id parsing
        assert!(matches!(result, Err(SignatureError::InvalidPeerId(_))));
    }

    // Helper function to generate a valid public key and peer_id using p256
    fn generate_valid_key_and_peer_id() -> (String, String) {
        use cesr::Matter;
        use p256::ecdsa::SigningKey;

        // Use a deterministic seed for reproducibility
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Get compressed public key (33 bytes)
        let compressed = verifying_key.to_encoded_point(true);
        let compressed_bytes = compressed.as_bytes();

        // Create CESR public key
        let cesr_pubkey =
            cesr::PublicKey::from_raw(cesr::KeyCode::Secp256r1, compressed_bytes.to_vec()).unwrap();
        let pubkey_qb64 = cesr_pubkey.qb64();

        // Derive PeerId from uncompressed key
        let uncompressed = verifying_key.to_encoded_point(false);
        let libp2p_pubkey =
            libp2p_identity::ecdsa::PublicKey::try_from_bytes(uncompressed.as_bytes()).unwrap();
        let libp2p_public = libp2p_identity::PublicKey::from(libp2p_pubkey);
        let peer_id = libp2p_public.to_peer_id();

        (pubkey_qb64, peer_id.to_string())
    }

    // Helper function to generate a different valid key and peer_id
    fn generate_different_valid_key_and_peer_id() -> (String, String) {
        use cesr::Matter;
        use p256::ecdsa::SigningKey;

        // Use a different seed
        let seed: [u8; 32] = [
            0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Get compressed public key (33 bytes)
        let compressed = verifying_key.to_encoded_point(true);
        let compressed_bytes = compressed.as_bytes();

        // Create CESR public key
        let cesr_pubkey =
            cesr::PublicKey::from_raw(cesr::KeyCode::Secp256r1, compressed_bytes.to_vec()).unwrap();
        let pubkey_qb64 = cesr_pubkey.qb64();

        // Derive PeerId from uncompressed key
        let uncompressed = verifying_key.to_encoded_point(false);
        let libp2p_pubkey =
            libp2p_identity::ecdsa::PublicKey::try_from_bytes(uncompressed.as_bytes()).unwrap();
        let libp2p_public = libp2p_identity::PublicKey::from(libp2p_pubkey);
        let peer_id = libp2p_public.to_peer_id();

        (pubkey_qb64, peer_id.to_string())
    }

    #[test]
    fn test_verify_signature_peer_id_mismatch() {
        let (pubkey_qb64, _actual_peer_id) = generate_valid_key_and_peer_id();
        let (_other_pubkey, wrong_peer_id) = generate_different_valid_key_and_peer_id();

        // Verify with mismatched peer_id (key from one, peer_id from another)
        let result = verify_signature(
            b"payload",
            &wrong_peer_id,
            &pubkey_qb64,
            "0BAAA_placeholder_sig",
        );

        // Should fail with peer_id mismatch
        assert!(matches!(result, Err(SignatureError::PeerIdMismatch { .. })));
    }

    #[test]
    fn test_verify_signature_invalid_signature_format() {
        let (pubkey_qb64, peer_id) = generate_valid_key_and_peer_id();

        let result = verify_signature(b"payload", &peer_id, &pubkey_qb64, "not_a_valid_signature");
        // Should fail at signature parsing
        assert!(matches!(result, Err(SignatureError::InvalidSignature(_))));
    }
}
