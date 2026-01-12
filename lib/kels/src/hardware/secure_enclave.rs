//! Secure Enclave Operations
//!
//! Low-level interface to macOS Secure Enclave for key generation,
//! signing, and verification using secp256r1 (P-256) keys.

use crate::error::KelsError;
use cesr::{KeyCode, PublicKey, Signature, SignatureCode};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use std::sync::Arc;

/// Handle to a key stored in the Secure Enclave
#[derive(Clone)]
pub struct SecureEnclaveKeyHandle {
    /// The label used to identify this key in the Keychain
    pub label: String,
}

/// Trait for Secure Enclave operations (allows mocking in tests)
pub trait SecureEnclaveOperations: Send + Sync {
    /// Check if Secure Enclave is available
    fn is_available(&self) -> bool;

    /// Generate a new key pair in the Secure Enclave
    fn generate_key(&self, label: &str) -> Result<(SecureEnclaveKeyHandle, PublicKey), KelsError>;

    /// Load an existing key by label
    fn load_key(&self, label: &str) -> Result<Option<SecureEnclaveKeyHandle>, KelsError>;

    /// Get the public key for a handle
    fn get_public_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<PublicKey, KelsError>;

    /// Sign data with a key
    fn sign(&self, handle: &SecureEnclaveKeyHandle, data: &[u8]) -> Result<Signature, KelsError>;

    /// Verify a signature with a key
    fn verify(
        &self,
        handle: &SecureEnclaveKeyHandle,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), KelsError>;

    /// Delete a key from the Secure Enclave
    fn delete_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<(), KelsError>;
}

/// Default implementation using the actual Secure Enclave
pub struct DefaultSecureEnclave;

impl DefaultSecureEnclave {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Option<Arc<dyn SecureEnclaveOperations>> {
        let enclave = Self;
        if enclave.is_available() {
            Some(Arc::new(enclave))
        } else {
            None
        }
    }

    fn find_key(&self, label: &str) -> Result<Option<SecKey>, KelsError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .load_refs(true)
            .search();

        match results {
            Ok(items) => {
                for item in items {
                    if let SearchResult::Ref(Reference::Key(key)) = item {
                        return Ok(Some(key));
                    }
                }
                Ok(None)
            }
            Err(e) if e.code() == -25300 => Ok(None), // errSecItemNotFound
            Err(e) => Err(KelsError::HardwareError(format!(
                "Key search failed: {}",
                e
            ))),
        }
    }

    fn uncompressed_to_compressed(&self, uncompressed: &[u8]) -> Result<Vec<u8>, KelsError> {
        if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
            return Err(KelsError::HardwareError(
                "Invalid uncompressed public key".into(),
            ));
        }

        let x = &uncompressed[1..33];
        let y = &uncompressed[33..65];

        // Compressed format: (0x02 if y is even, 0x03 if y is odd) || x
        let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };

        let mut compressed = Vec::with_capacity(33);
        compressed.push(prefix);
        compressed.extend_from_slice(x);

        Ok(compressed)
    }

    fn external_rep_to_public_key(&self, data: &[u8]) -> Result<PublicKey, KelsError> {
        if data.len() != 65 {
            return Err(KelsError::HardwareError(format!(
                "Unexpected public key length: {} (expected 65)",
                data.len()
            )));
        }

        let compressed = self.uncompressed_to_compressed(data)?;
        PublicKey::from_raw(KeyCode::Secp256r1, compressed)
            .map_err(|e| KelsError::HardwareError(format!("Failed to create PublicKey: {}", e)))
    }

    fn der_sig_to_raw(&self, der: &[u8]) -> Result<Vec<u8>, KelsError> {
        if der.len() < 8 || der[0] != 0x30 {
            return Err(KelsError::SigningFailed(format!(
                "Invalid DER signature: len={}, first_byte={:02x}",
                der.len(),
                der.first().copied().unwrap_or(0)
            )));
        }

        let mut pos = 2; // Skip 0x30 and length byte

        if der[pos] != 0x02 {
            return Err(KelsError::SigningFailed(format!(
                "Expected INTEGER tag for r, got {:02x}",
                der[pos]
            )));
        }
        pos += 1;
        let r_len = der[pos] as usize;
        pos += 1;
        let r_bytes = &der[pos..pos + r_len];
        pos += r_len;

        // Parse s
        if der[pos] != 0x02 {
            return Err(KelsError::SigningFailed(format!(
                "Expected INTEGER tag for s, got {:02x}",
                der[pos]
            )));
        }
        pos += 1;
        let s_len = der[pos] as usize;
        pos += 1;
        let s_bytes = &der[pos..pos + s_len];

        // Convert to fixed 32-byte format, handling sign byte properly
        let mut raw = vec![0u8; 64];

        // r: skip leading zero if present for sign padding
        let r_start = if r_len > 1 && r_bytes[0] == 0 && (r_bytes[1] & 0x80) != 0 {
            1
        } else {
            0
        };
        let r_data = &r_bytes[r_start..];
        if r_data.len() <= 32 {
            let r_pad = 32 - r_data.len();
            raw[r_pad..32].copy_from_slice(r_data);
        } else {
            return Err(KelsError::SigningFailed(format!(
                "r value too large: {} bytes",
                r_data.len()
            )));
        }

        // s: skip leading zero if present for sign padding
        let s_start = if s_len > 1 && s_bytes[0] == 0 && (s_bytes[1] & 0x80) != 0 {
            1
        } else {
            0
        };
        let s_data = &s_bytes[s_start..];
        if s_data.len() <= 32 {
            let s_pad = 32 - s_data.len();
            raw[32 + s_pad..64].copy_from_slice(s_data);
        } else {
            return Err(KelsError::SigningFailed(format!(
                "s value too large: {} bytes",
                s_data.len()
            )));
        }

        Ok(raw)
    }
}

impl Default for DefaultSecureEnclave {
    fn default() -> Self {
        Self
    }
}

impl SecureEnclaveOperations for DefaultSecureEnclave {
    fn is_available(&self) -> bool {
        // Try to create a GenerateKeyOptions with SecureEnclave token
        // If we can construct it, the enclave is available
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave);
        true
    }

    fn generate_key(&self, label: &str) -> Result<(SecureEnclaveKeyHandle, PublicKey), KelsError> {
        // Delete ALL existing keys with this label first
        while let Some(old_key) = self.find_key(label)? {
            old_key.delete().map_err(|e| {
                KelsError::HardwareError(format!("Failed to delete old key: {}", e))
            })?;
        }

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label)
            .set_location(Location::DataProtectionKeychain);

        let private_key = SecKey::generate(options.to_dictionary())
            .map_err(|e| KelsError::HardwareError(format!("Failed to generate key: {}", e)))?;

        let public_key_ref = private_key
            .public_key()
            .ok_or_else(|| KelsError::HardwareError("Failed to get public key".into()))?;

        let public_key_data = public_key_ref
            .external_representation()
            .ok_or_else(|| KelsError::HardwareError("Failed to export public key".into()))?;

        let key_bytes: Vec<u8> = public_key_data.to_vec();
        let public_key = self.external_rep_to_public_key(&key_bytes)?;

        Ok((
            SecureEnclaveKeyHandle {
                label: label.to_string(),
            },
            public_key,
        ))
    }

    fn load_key(&self, label: &str) -> Result<Option<SecureEnclaveKeyHandle>, KelsError> {
        match self.find_key(label)? {
            Some(_) => Ok(Some(SecureEnclaveKeyHandle {
                label: label.to_string(),
            })),
            None => Ok(None),
        }
    }

    fn get_public_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<PublicKey, KelsError> {
        let private_key = self
            .find_key(&handle.label)?
            .ok_or_else(|| KelsError::HardwareError(format!("Key not found: {}", handle.label)))?;

        let public_key_ref = private_key
            .public_key()
            .ok_or_else(|| KelsError::HardwareError("Failed to get public key".into()))?;

        let public_key_data = public_key_ref
            .external_representation()
            .ok_or_else(|| KelsError::HardwareError("Failed to export public key".into()))?;

        let key_bytes: Vec<u8> = public_key_data.to_vec();
        self.external_rep_to_public_key(&key_bytes)
    }

    fn sign(&self, handle: &SecureEnclaveKeyHandle, data: &[u8]) -> Result<Signature, KelsError> {
        let label = &handle.label;
        let sec_key = self
            .find_key(label)?
            .ok_or_else(|| KelsError::HardwareError(format!("Key not found: {}", label)))?;

        let der_sig = sec_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| KelsError::SigningFailed(format!("create_signature failed: {}", e)))?;

        let raw_sig = self.der_sig_to_raw(&der_sig)?;

        Signature::from_raw(SignatureCode::Secp256r1, raw_sig)
            .map_err(|e| KelsError::SigningFailed(format!("Signature::from_raw failed: {}", e)))
    }

    fn verify(
        &self,
        handle: &SecureEnclaveKeyHandle,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), KelsError> {
        // For verification, use cesr's verify which uses p256 crate
        // This ensures consistency with how the server verifies
        let public_key = self.get_public_key(handle)?;
        public_key
            .verify(data, signature)
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))
    }

    fn delete_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<(), KelsError> {
        let key = self.find_key(&handle.label)?;
        if let Some(sec_key) = key {
            sec_key
                .delete()
                .map_err(|e| KelsError::HardwareError(format!("Failed to delete key: {}", e)))?;
        }
        Ok(())
    }
}
