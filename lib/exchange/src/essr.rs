//! ESSR (Encrypt-Sender-Sign-Receiver) authenticated encryption.
//!
//! Provides four UnForgeability properties:
//! - **TUF-PTXT/TUF-CTXT**: Third party can't forge plaintext or ciphertext
//! - **RUF-PTXT**: Receiver can't forge sender attribution (sender inside ciphertext)
//! - **RUF-CTXT**: Attacker can't strip/replace signature (recipient in signed plaintext)

use cesr::{DecapsulationKey, EncapsulationKey, Matter, Signature, SigningKey, VerificationKey};
use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

use kels_core::{aes_gcm_decrypt, aes_gcm_encrypt, derive_aes_key};

use crate::error::ExchangeError;

/// Blake3 KDF context for ESSR key derivation.
const ESSR_KDF_CONTEXT: &str = "kels/essr/v1";

/// Inner payload (encrypted). Sender inside ciphertext provides RUF-PTXT.
///
/// The `topic` tells the recipient how to parse the payload without exposing
/// the message type to the mail service (it's inside the ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EssrInner {
    /// Sender's KEL prefix (must match envelope sender for consistency).
    pub sender: String,
    /// Topic for payload interpretation (e.g. `"kels/v1/exchange"`, `"kels/v1/document"`).
    pub topic: String,
    /// Opaque content, interpretation determined by topic.
    pub payload: Vec<u8>,
}

/// Outer envelope (signed). Recipient in signed plaintext provides anti-KCI.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct EssrEnvelope {
    #[said]
    pub said: String,
    /// Sender's KEL prefix (plaintext, for routing).
    pub sender: String,
    /// Serial of sender's latest establishment event at signing time.
    pub sender_serial: u64,
    /// Recipient's KEL prefix (signed plaintext, anti-KCI).
    pub recipient: String,
    /// CESR-encoded ML-KEM ciphertext.
    pub kem_ciphertext: String,
    /// Base64-encoded AES-GCM-256 ciphertext.
    pub encrypted_payload: String,
    /// CESR-encoded AES-GCM nonce.
    pub nonce: String,
    #[created_at]
    pub created_at: StorageDatetime,
}

/// Signed ESSR envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEssrEnvelope {
    pub envelope: EssrEnvelope,
    /// CESR-encoded ML-DSA signature over the serialized envelope.
    pub signature: String,
}

/// Seal an inner payload into a signed ESSR envelope.
///
/// Steps:
/// 1. Serialize inner payload (sender + topic + data)
/// 2. ML-KEM encapsulate to get shared secret
/// 3. Derive AES key via blake3 KDF
/// 4. AES-GCM-256 encrypt the inner payload
/// 5. Build envelope with SAID
/// 6. ML-DSA sign the serialized envelope
pub fn seal(
    inner: &EssrInner,
    sender_serial: u64,
    recipient_prefix: &str,
    recipient_encap_key: &EncapsulationKey,
    sender_signing_key: &SigningKey,
) -> Result<SignedEssrEnvelope, ExchangeError> {
    // 1. Serialize inner
    let inner_json = serde_json::to_vec(inner)?;

    // 2. ML-KEM encapsulate
    let (kem_ciphertext, shared_secret) = recipient_encap_key
        .encapsulate()
        .map_err(|e| ExchangeError::SealFailed(format!("ML-KEM encapsulate failed: {e}")))?;

    // 3. Derive AES key
    let aes_key = derive_aes_key(ESSR_KDF_CONTEXT, &shared_secret);

    // 4. Generate random nonce and encrypt
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .unwrap_or_else(|e| unreachable!("getrandom failed: {}", e));

    let ciphertext = aes_gcm_encrypt(&aes_key, &nonce_bytes, &inner_json)
        .map_err(|e| ExchangeError::SealFailed(e.to_string()))?;

    // 5. Build envelope with SAID
    let mut envelope = EssrEnvelope {
        said: String::new(),
        sender: inner.sender.clone(),
        sender_serial,
        recipient: recipient_prefix.to_string(),
        kem_ciphertext: kem_ciphertext.qb64(),
        encrypted_payload: base64_encode(&ciphertext),
        nonce: base64_encode(&nonce_bytes),
        created_at: StorageDatetime::now(),
    };

    envelope
        .derive_said()
        .map_err(|e| ExchangeError::SealFailed(format!("SAID derivation failed: {e}")))?;

    // 6. Sign the serialized envelope
    let envelope_json = serde_json::to_vec(&envelope)?;
    let signature = sender_signing_key
        .sign(&envelope_json)
        .map_err(|e| ExchangeError::SealFailed(format!("ML-DSA sign failed: {e}")))?;

    Ok(SignedEssrEnvelope {
        envelope,
        signature: signature.qb64(),
    })
}

/// Open a signed ESSR envelope, verifying signature and decrypting the inner payload.
///
/// Steps:
/// 1. Verify envelope SAID
/// 2. Verify ML-DSA signature using sender's verification key
/// 3. ML-KEM decapsulate to recover shared secret
/// 4. Derive AES key via blake3 KDF
/// 5. AES-GCM-256 decrypt
/// 6. Verify inner sender matches envelope sender
pub fn open(
    signed_envelope: &SignedEssrEnvelope,
    recipient_decap_key: &DecapsulationKey,
    sender_verification_key: &VerificationKey,
) -> Result<EssrInner, ExchangeError> {
    // 1. Verify SAID
    signed_envelope
        .envelope
        .verify_said()
        .map_err(|e| ExchangeError::SaidVerification(e.to_string()))?;

    // 2. Verify signature
    let envelope_json = serde_json::to_vec(&signed_envelope.envelope)?;
    let signature = Signature::from_qb64(&signed_envelope.signature)
        .map_err(|e| ExchangeError::SignatureVerification(format!("invalid signature: {e}")))?;
    sender_verification_key
        .verify(&envelope_json, &signature)
        .map_err(|e| ExchangeError::SignatureVerification(e.to_string()))?;

    // 3. ML-KEM decapsulate
    let kem_ciphertext =
        cesr::KemCiphertext::from_qb64(&signed_envelope.envelope.kem_ciphertext)
            .map_err(|e| ExchangeError::OpenFailed(format!("invalid KEM ciphertext: {e}")))?;
    let shared_secret = recipient_decap_key
        .decapsulate(&kem_ciphertext)
        .map_err(|e| ExchangeError::OpenFailed(format!("ML-KEM decapsulate failed: {e}")))?;

    // 4. Derive AES key
    let aes_key = derive_aes_key(ESSR_KDF_CONTEXT, &shared_secret);

    // 5. Decrypt
    let nonce_bytes = base64_decode(&signed_envelope.envelope.nonce)
        .map_err(|e| ExchangeError::OpenFailed(format!("invalid nonce: {e}")))?;
    let nonce: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| ExchangeError::OpenFailed("nonce must be 12 bytes".into()))?;

    let ciphertext = base64_decode(&signed_envelope.envelope.encrypted_payload)
        .map_err(|e| ExchangeError::OpenFailed(format!("invalid ciphertext: {e}")))?;

    let plaintext = aes_gcm_decrypt(&aes_key, &nonce, &ciphertext)
        .map_err(|e| ExchangeError::OpenFailed(e.to_string()))?;

    // 6. Deserialize and verify sender consistency
    let inner: EssrInner = serde_json::from_slice(&plaintext)?;

    if inner.sender != signed_envelope.envelope.sender {
        return Err(ExchangeError::SenderMismatch {
            envelope: signed_envelope.envelope.sender.clone(),
            inner: inner.sender,
        });
    }

    Ok(inner)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_keypairs() -> (
        SigningKey,
        VerificationKey,
        EncapsulationKey,
        DecapsulationKey,
    ) {
        let (vk, sk) = cesr::generate_ml_dsa_65().unwrap();
        let (ek, dk) = cesr::generate_ml_kem_768().unwrap();
        (sk, vk, ek, dk)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (sender_sk, sender_vk, recipient_ek, recipient_dk) = test_keypairs();

        let inner = EssrInner {
            sender: "sender-prefix-abc".to_string(),
            topic: "kels/v1/exchange".to_string(),
            payload: b"hello world".to_vec(),
        };

        let signed = seal(&inner, 0, "recipient-prefix-xyz", &recipient_ek, &sender_sk).unwrap();

        // Verify SAID is set
        assert!(!signed.envelope.said.is_empty());
        assert_eq!(signed.envelope.sender, "sender-prefix-abc");
        assert_eq!(signed.envelope.recipient, "recipient-prefix-xyz");

        let opened = open(&signed, &recipient_dk, &sender_vk).unwrap();
        assert_eq!(opened.sender, inner.sender);
        assert_eq!(opened.topic, inner.topic);
        assert_eq!(opened.payload, inner.payload);
    }

    #[test]
    fn wrong_decapsulation_key_fails() {
        let (sender_sk, _sender_vk, recipient_ek, _recipient_dk) = test_keypairs();
        let (_other_ek, other_dk) = cesr::generate_ml_kem_768().unwrap();

        let inner = EssrInner {
            sender: "sender".to_string(),
            topic: "test".to_string(),
            payload: b"secret".to_vec(),
        };

        let signed = seal(&inner, 0, "recipient", &recipient_ek, &sender_sk).unwrap();
        let result = open(&signed, &other_dk, &_sender_vk);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_verification_key_fails() {
        let (sender_sk, _sender_vk, recipient_ek, recipient_dk) = test_keypairs();
        let (other_vk, _other_sk) = cesr::generate_ml_dsa_65().unwrap();

        let inner = EssrInner {
            sender: "sender".to_string(),
            topic: "test".to_string(),
            payload: b"secret".to_vec(),
        };

        let signed = seal(&inner, 0, "recipient", &recipient_ek, &sender_sk).unwrap();
        let result = open(&signed, &recipient_dk, &other_vk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sender_sk, sender_vk, recipient_ek, recipient_dk) = test_keypairs();

        let inner = EssrInner {
            sender: "sender".to_string(),
            topic: "test".to_string(),
            payload: b"secret".to_vec(),
        };

        let mut signed = seal(&inner, 0, "recipient", &recipient_ek, &sender_sk).unwrap();

        // Tamper with encrypted payload — signature will fail
        signed.envelope.encrypted_payload = base64_encode(b"tampered");
        let result = open(&signed, &recipient_dk, &sender_vk);
        assert!(result.is_err());
    }

    #[test]
    fn sender_mismatch_detected() {
        let (sender_sk, sender_vk, recipient_ek, recipient_dk) = test_keypairs();

        let inner = EssrInner {
            sender: "real-sender".to_string(),
            topic: "test".to_string(),
            payload: b"data".to_vec(),
        };

        let mut signed = seal(&inner, 0, "recipient", &recipient_ek, &sender_sk).unwrap();

        // Change envelope sender after signing — SAID check will catch this
        signed.envelope.sender = "fake-sender".to_string();
        let result = open(&signed, &recipient_dk, &sender_vk);
        assert!(result.is_err());
    }
}
