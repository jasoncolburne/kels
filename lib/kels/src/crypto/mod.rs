//! Cryptographic primitives for KELS.
//!
//! - **keys**: Key provider traits and software key management
//! - **aead**: AES-GCM-256 encrypt/decrypt and blake3 key derivation
//! - **generate_nonce**: Cryptographic nonce generation

pub mod aead;
pub mod keys;

use cesr::Digest;

pub use aead::{aes_gcm_decrypt, aes_gcm_encrypt, cipher_from_key, derive_aes_key};
pub use keys::*;

/// Generate a cryptographic nonce: 32 random bytes hashed with BLAKE3-256, CESR-encoded.
pub fn generate_nonce() -> cesr::Digest {
    let mut entropy = [0u8; 32];
    #[allow(clippy::expect_used)]
    getrandom::getrandom(&mut entropy).expect("getrandom failed");
    Digest::blake3_256(&entropy)
}
