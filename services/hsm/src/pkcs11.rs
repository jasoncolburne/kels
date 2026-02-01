//! PKCS#11 wrapper for SoftHSM2
//!
//! Provides a simplified interface to SoftHSM2 via cryptoki.
//! Keys are identified by their label and looked up each time.

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    #[error("No slot available")]
    NoSlotAvailable,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// HSM context managing PKCS#11 session
pub struct HsmContext {
    #[allow(dead_code)]
    pkcs11: Arc<Pkcs11>,
    session: Mutex<Session>,
}

impl HsmContext {
    /// Initialize HSM context with SoftHSM2
    pub fn new(library_path: &str, slot_index: usize, pin: &str) -> Result<Self, HsmError> {
        let pkcs11 = Pkcs11::new(library_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots
            .get(slot_index)
            .copied()
            .ok_or(HsmError::NoSlotAvailable)?;

        let session = pkcs11.open_rw_session(slot)?;
        session.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

        Ok(Self {
            pkcs11: Arc::new(pkcs11),
            session: Mutex::new(session),
        })
    }

    /// Generate a new secp256r1 keypair with the given label
    ///
    /// Returns the public key bytes (uncompressed EC point)
    pub fn generate_keypair(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        let session = self.session.lock().map_err(|_| {
            HsmError::InternalError("Session lock poisoned during key generation".into())
        })?;

        let label_bytes = label.as_bytes().to_vec();
        // OID for secp256r1: 1.2.840.10045.3.1.7
        let ec_params = hex::decode("06082a8648ce3d030107")
            .map_err(|e| HsmError::SigningFailed(format!("Invalid EC params: {}", e)))?;

        let pub_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::EcParams(ec_params.clone()),
            Attribute::Label(label_bytes.clone()),
        ];

        let priv_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Label(label_bytes),
        ];

        let (pub_handle, _priv_handle) =
            session.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)?;

        // Extract public key point
        let attrs = session.get_attributes(pub_handle, &[AttributeType::EcPoint])?;

        attrs
            .iter()
            .find_map(|attr| {
                if let Attribute::EcPoint(bytes) = attr {
                    Some(bytes.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| HsmError::SigningFailed("Failed to get public key".into()))
    }

    /// Find a key by label
    fn find_key(
        &self,
        session: &Session,
        label: &str,
        class: ObjectClass,
    ) -> Result<cryptoki::object::ObjectHandle, HsmError> {
        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let handles = session.find_objects(&template)?;
        handles
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.to_string()))
    }

    /// Get public key bytes for a label
    pub fn get_public_key(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        let session = self.session.lock().map_err(|_| {
            HsmError::InternalError("Session lock poisoned during public key retrieval".into())
        })?;

        let pub_handle = self.find_key(&session, label, ObjectClass::PUBLIC_KEY)?;

        let attrs = session.get_attributes(pub_handle, &[AttributeType::EcPoint])?;

        attrs
            .iter()
            .find_map(|attr| {
                if let Attribute::EcPoint(bytes) = attr {
                    Some(bytes.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| HsmError::SigningFailed("Failed to get public key".into()))
    }

    /// Sign data with ECDSA-SHA256
    pub fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let session = self
            .session
            .lock()
            .map_err(|_| HsmError::InternalError("Session lock poisoned during signing".into()))?;

        let priv_handle = self.find_key(&session, label, ObjectClass::PRIVATE_KEY)?;

        // Hash the data with SHA-256 first (SoftHSM2 doesn't support EcdsaSha256 mechanism)
        let hash = Sha256::digest(data);

        // Sign the hash with raw ECDSA
        session
            .sign(&Mechanism::Ecdsa, priv_handle, &hash)
            .map_err(Into::into)
    }

    /// Check if a key exists
    pub fn key_exists(&self, label: &str) -> bool {
        let Ok(session) = self.session.lock() else {
            return false;
        };
        self.find_key(&session, label, ObjectClass::PRIVATE_KEY)
            .is_ok()
    }

    /// List all key labels
    pub fn list_keys(&self) -> Result<Vec<String>, HsmError> {
        let session = self.session.lock().map_err(|_| {
            HsmError::InternalError("Session lock poisoned during key listing".into())
        })?;

        let template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let handles = session.find_objects(&template)?;

        let mut labels = Vec::new();
        for handle in handles {
            if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::Label]) {
                for attr in attrs {
                    if let Attribute::Label(label_bytes) = attr
                        && let Ok(label) = String::from_utf8(label_bytes)
                    {
                        labels.push(label);
                    }
                }
            }
        }

        Ok(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HsmError Display Tests ====================

    #[test]
    fn test_hsm_error_no_slot_display() {
        let err = HsmError::NoSlotAvailable;
        assert_eq!(err.to_string(), "No slot available");
    }

    #[test]
    fn test_hsm_error_key_not_found_display() {
        let err = HsmError::KeyNotFound("mykey".to_string());
        assert_eq!(err.to_string(), "Key not found: mykey");
    }

    #[test]
    fn test_hsm_error_signing_failed_display() {
        let err = HsmError::SigningFailed("operation failed".to_string());
        assert_eq!(err.to_string(), "Signing failed: operation failed");
    }

    #[test]
    fn test_hsm_error_internal_error_display() {
        let err = HsmError::InternalError("lock poisoned".to_string());
        assert_eq!(err.to_string(), "Internal error: lock poisoned");
    }
}
