//! Secure Enclave Operations via Apple CryptoKit
//!
//! Supports secp256r1 (P-256), ML-DSA-65, and ML-DSA-87 key operations
//! using the Secure Enclave on macOS/iOS.

use cesr::{PublicKey, Signature, SignatureCode, VerificationKeyCode};

use crate::error::KelsError;

/// Handle to a key stored in the Secure Enclave
#[derive(Clone)]
pub struct SecureEnclaveKeyHandle {
    /// The label used to identify this key
    pub label: String,
    /// The algorithm used for this key
    pub algorithm: VerificationKeyCode,
    /// Opaque data representation for SE keys, or seed bytes for software CryptoKit keys
    pub key_data: Vec<u8>,
}

/// Trait for Secure Enclave operations (allows mocking in tests)
pub trait SecureEnclaveOperations: Send + Sync {
    /// Check if Secure Enclave is available
    fn is_available(&self) -> bool;

    /// Generate a new key pair
    ///
    fn generate_key(
        &self,
        label: &str,
        algorithm: VerificationKeyCode,
    ) -> Result<(SecureEnclaveKeyHandle, PublicKey), KelsError>;

    /// Get the public key for a handle
    fn get_public_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<PublicKey, KelsError>;

    /// Sign data with a key
    fn sign(&self, handle: &SecureEnclaveKeyHandle, data: &[u8]) -> Result<Signature, KelsError>;

    /// Delete a key
    fn delete_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<(), KelsError>;
}

/// Default implementation using Apple CryptoKit
pub struct DefaultSecureEnclave;

impl DefaultSecureEnclave {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Option<std::sync::Arc<dyn SecureEnclaveOperations>> {
        let enclave = Self;
        if enclave.is_available() {
            Some(std::sync::Arc::new(enclave))
        } else {
            None
        }
    }
}

impl Default for DefaultSecureEnclave {
    fn default() -> Self {
        Self
    }
}

impl SecureEnclaveOperations for DefaultSecureEnclave {
    fn is_available(&self) -> bool {
        apple_cryptokit::se_is_available()
    }

    fn generate_key(
        &self,
        label: &str,
        algorithm: VerificationKeyCode,
    ) -> Result<(SecureEnclaveKeyHandle, PublicKey), KelsError> {
        use apple_cryptokit::quantum::{
            SEMLDsa65PrivateKey, SEMLDsa87PrivateKey, SignaturePublicKey,
        };

        match algorithm {
            VerificationKeyCode::MlDsa65 => {
                let se_key = SEMLDsa65PrivateKey::generate()
                    .map_err(|e| KelsError::HardwareError(format!("SE keygen failed: {}", e)))?;
                let pub_bytes = se_key
                    .public_key()
                    .map_err(|e| KelsError::HardwareError(format!("SE public key failed: {}", e)))?
                    .to_bytes();
                let public_key = PublicKey::from_raw(VerificationKeyCode::MlDsa65, pub_bytes)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))?;
                let handle = SecureEnclaveKeyHandle {
                    label: label.to_string(),
                    algorithm,
                    key_data: se_key.data_representation().to_vec(),
                };
                Ok((handle, public_key))
            }
            VerificationKeyCode::MlDsa87 => {
                let se_key = SEMLDsa87PrivateKey::generate()
                    .map_err(|e| KelsError::HardwareError(format!("SE keygen failed: {}", e)))?;
                let pub_bytes = se_key
                    .public_key()
                    .map_err(|e| KelsError::HardwareError(format!("SE public key failed: {}", e)))?
                    .to_bytes();
                let public_key = PublicKey::from_raw(VerificationKeyCode::MlDsa87, pub_bytes)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))?;
                let handle = SecureEnclaveKeyHandle {
                    label: label.to_string(),
                    algorithm,
                    key_data: se_key.data_representation().to_vec(),
                };
                Ok((handle, public_key))
            }
            VerificationKeyCode::Secp256r1 => {
                use apple_cryptokit::asymmetric::SEP256PrivateKey;

                let se_key = SEP256PrivateKey::generate().map_err(|e| {
                    KelsError::HardwareError(format!("SE P256 keygen failed: {}", e))
                })?;
                let pub_key = se_key.public_key().map_err(|e| {
                    KelsError::HardwareError(format!("SE P256 public key failed: {}", e))
                })?;

                let raw_pub = pub_key.as_bytes();
                let x = &raw_pub[..32];
                let y = &raw_pub[32..64];
                let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
                let mut compressed = Vec::with_capacity(33);
                compressed.push(prefix);
                compressed.extend_from_slice(x);

                let public_key = PublicKey::from_raw(VerificationKeyCode::Secp256r1, compressed)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))?;
                let handle = SecureEnclaveKeyHandle {
                    label: label.to_string(),
                    algorithm,
                    key_data: se_key.data_representation().to_vec(),
                };
                Ok((handle, public_key))
            }
        }
    }

    fn get_public_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<PublicKey, KelsError> {
        use apple_cryptokit::quantum::{
            SEMLDsa65PrivateKey, SEMLDsa87PrivateKey, SignaturePublicKey,
        };

        match handle.algorithm {
            VerificationKeyCode::MlDsa65 => {
                let se_key = SEMLDsa65PrivateKey::from_data_representation(&handle.key_data);
                let pub_bytes = se_key
                    .public_key()
                    .map_err(|e| KelsError::HardwareError(format!("SE public key failed: {}", e)))?
                    .to_bytes();
                PublicKey::from_raw(VerificationKeyCode::MlDsa65, pub_bytes)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))
            }
            VerificationKeyCode::MlDsa87 => {
                let se_key = SEMLDsa87PrivateKey::from_data_representation(&handle.key_data);
                let pub_bytes = se_key
                    .public_key()
                    .map_err(|e| KelsError::HardwareError(format!("SE public key failed: {}", e)))?
                    .to_bytes();
                PublicKey::from_raw(VerificationKeyCode::MlDsa87, pub_bytes)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))
            }
            VerificationKeyCode::Secp256r1 => {
                use apple_cryptokit::asymmetric::SEP256PrivateKey;

                let se_key = SEP256PrivateKey::from_data_representation(&handle.key_data);
                let pub_key = se_key.public_key().map_err(|e| {
                    KelsError::HardwareError(format!("SE P256 public key failed: {}", e))
                })?;

                let raw_pub = pub_key.as_bytes();
                let x = &raw_pub[..32];
                let y = &raw_pub[32..64];
                let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
                let mut compressed = Vec::with_capacity(33);
                compressed.push(prefix);
                compressed.extend_from_slice(x);

                PublicKey::from_raw(VerificationKeyCode::Secp256r1, compressed)
                    .map_err(|e| KelsError::HardwareError(format!("CESR key failed: {}", e)))
            }
        }
    }

    fn sign(&self, handle: &SecureEnclaveKeyHandle, data: &[u8]) -> Result<Signature, KelsError> {
        use apple_cryptokit::quantum::{SEMLDsa65PrivateKey, SEMLDsa87PrivateKey};

        match handle.algorithm {
            VerificationKeyCode::MlDsa65 => {
                let se_key = SEMLDsa65PrivateKey::from_data_representation(&handle.key_data);
                let sig_bytes = se_key
                    .sign(data)
                    .map_err(|e| KelsError::SigningFailed(format!("SE sign failed: {}", e)))?;
                Signature::from_raw(SignatureCode::MlDsa65, sig_bytes)
                    .map_err(|e| KelsError::SigningFailed(e.to_string()))
            }
            VerificationKeyCode::MlDsa87 => {
                let se_key = SEMLDsa87PrivateKey::from_data_representation(&handle.key_data);
                let sig_bytes = se_key
                    .sign(data)
                    .map_err(|e| KelsError::SigningFailed(format!("SE sign failed: {}", e)))?;
                Signature::from_raw(SignatureCode::MlDsa87, sig_bytes)
                    .map_err(|e| KelsError::SigningFailed(e.to_string()))
            }
            VerificationKeyCode::Secp256r1 => {
                use apple_cryptokit::asymmetric::SEP256PrivateKey;

                let se_key = SEP256PrivateKey::from_data_representation(&handle.key_data);
                let sig = se_key
                    .sign(data)
                    .map_err(|e| KelsError::SigningFailed(format!("SE P256 sign failed: {}", e)))?;
                Signature::from_raw(SignatureCode::Secp256r1, sig.as_bytes().to_vec())
                    .map_err(|e| KelsError::SigningFailed(e.to_string()))
            }
        }
    }

    fn delete_key(&self, handle: &SecureEnclaveKeyHandle) -> Result<(), KelsError> {
        match handle.algorithm {
            VerificationKeyCode::Secp256r1 => {
                use apple_cryptokit::asymmetric::SEP256PrivateKey;

                let se_key = SEP256PrivateKey::from_data_representation(&handle.key_data);
                se_key
                    .delete()
                    .map_err(|e| KelsError::HardwareError(format!("SE key delete failed: {}", e)))
            }
            // ML-DSA SE keys don't support Keychain deletion yet
            _ => Ok(()),
        }
    }
}

/// Delete all Secure Enclave keys belonging to this app from the Keychain.
/// Check if the Secure Enclave is available on this device.
pub fn se_is_available() -> bool {
    apple_cryptokit::se_is_available()
}

pub fn se_delete_all_keys() -> Result<(), KelsError> {
    apple_cryptokit::asymmetric::se_delete_all_keys()
        .map_err(|e| KelsError::HardwareError(format!("Failed to delete all SE keys: {}", e)))
}
