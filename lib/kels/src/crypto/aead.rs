//! AES-GCM-256 authenticated encryption primitives.
//!
//! Provides encrypt/decrypt operations and blake3-based key derivation for use
//! by both the gossip transport layer and the ESSR exchange protocol.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, consts::U12},
};

use crate::error::KelsError;

/// Derive a 256-bit AES key from input key material using blake3's keyed derivation.
///
/// The `context` string provides domain separation (e.g. `"kels/essr/v1"`).
pub fn derive_aes_key(context: &str, input_key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, input_key_material)
}

/// Create an `Aes256Gcm` cipher from a 32-byte key.
pub fn cipher_from_key(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

/// Encrypt plaintext with AES-GCM-256.
///
/// `nonce` must be exactly 12 bytes. Returns ciphertext with appended 16-byte auth tag.
pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, KelsError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::<U12>::from(*nonce);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| KelsError::CryptoError("AES-GCM-256 encryption failed".into()))
}

/// Decrypt ciphertext with AES-GCM-256.
///
/// `nonce` must be exactly 12 bytes. `ciphertext` includes the 16-byte auth tag.
pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KelsError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::<U12>::from(*nonce);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| KelsError::CryptoError("AES-GCM-256 decryption failed".into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_aes_key("test/context", b"some-secret-material");
        let nonce = [0u8; 12];
        let plaintext = b"hello world";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_aes_key("context/1", b"material");
        let key2 = derive_aes_key("context/2", b"material");
        let nonce = [0u8; 12];

        let ciphertext = aes_gcm_encrypt(&key1, &nonce, b"secret").unwrap();
        assert!(aes_gcm_decrypt(&key2, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = derive_aes_key("test", b"material");
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];

        let ciphertext = aes_gcm_encrypt(&key, &nonce1, b"secret").unwrap();
        assert!(aes_gcm_decrypt(&key, &nonce2, &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_aes_key("test", b"material");
        let nonce = [0u8; 12];

        let mut ciphertext = aes_gcm_encrypt(&key, &nonce, b"secret").unwrap();
        ciphertext[0] ^= 0xff;
        assert!(aes_gcm_decrypt(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let key1 = derive_aes_key("context/a", b"same-material");
        let key2 = derive_aes_key("context/b", b"same-material");
        assert_ne!(key1, key2);
    }
}
