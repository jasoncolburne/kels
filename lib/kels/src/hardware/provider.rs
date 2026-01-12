//! Hardware Key Provider
//!
//! Provides Secure Enclave-backed key storage for the KeyProvider enum.

use crate::error::KelsError;
use cesr::{PublicKey, Signature};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::secure_enclave::{
    DefaultSecureEnclave, SecureEnclaveKeyHandle, SecureEnclaveOperations,
};

/// Hardware-backed key provider using macOS Secure Enclave.
///
/// Keys are stored persistently in the Secure Enclave and identified by labels.
/// The provider manages current, next, and recovery keys.
/// The recovery key is a dedicated key for recovery events (rec/ror).
///
/// Two-phase rotation support:
/// - `pending_current_handle` / `pending_next_handle`: Staged signing key rotation
/// - `pending_recovery_handle`: Staged recovery key rotation
pub struct HardwareKeyProvider {
    enclave: Arc<dyn SecureEnclaveOperations>,
    label_prefix: String,
    next_label_generation: RwLock<u64>,
    current_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    next_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    // Pending handles for two-phase rotation
    pending_current_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    pending_next_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    pending_recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
}

impl HardwareKeyProvider {
    /// Create a new HardwareKeyProvider with fresh keys.
    ///
    /// Returns None if Secure Enclave is not available on this device.
    pub fn new(label_prefix: &str) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;
        Some(Self {
            enclave,
            label_prefix: label_prefix.to_string(),
            next_label_generation: RwLock::new(0),
            current_handle: RwLock::new(None),
            next_handle: RwLock::new(None),
            recovery_handle: RwLock::new(None),
            pending_current_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    /// Create a HardwareKeyProvider with existing key handles.
    ///
    /// Used to restore state from persisted labels.
    pub fn with_handles(
        label_prefix: &str,
        current_label: Option<String>,
        next_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        Self::with_all_handles(
            label_prefix,
            current_label,
            next_label,
            None,
            next_label_generation,
        )
    }

    /// Create a HardwareKeyProvider with all handles including recovery.
    ///
    /// Used to restore state from persisted labels.
    pub fn with_all_handles(
        label_prefix: &str,
        current_label: Option<String>,
        next_label: Option<String>,
        recovery_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;

        // Load current key if label provided
        let current_handle = if let Some(label) = current_label {
            match enclave.load_key(&label) {
                Ok(Some(handle)) => Some(handle),
                Ok(None) => {
                    eprintln!("Warning: Current key not found: {}", label);
                    None
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load current key: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let next_handle = if let Some(label) = next_label {
            match enclave.load_key(&label) {
                Ok(Some(handle)) => Some(handle),
                Ok(None) => {
                    eprintln!("Warning: Next key not found: {}", label);
                    None
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load next key: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Load recovery key if label provided
        let recovery_handle = if let Some(label) = recovery_label {
            match enclave.load_key(&label) {
                Ok(Some(handle)) => Some(handle),
                Ok(None) => {
                    eprintln!("Warning: Recovery key not found: {}", label);
                    None
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load recovery key: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Some(Self {
            enclave,
            label_prefix: label_prefix.to_string(),
            next_label_generation: RwLock::new(next_label_generation),
            current_handle: RwLock::new(current_handle),
            next_handle: RwLock::new(next_handle),
            recovery_handle: RwLock::new(recovery_handle),
            pending_current_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    /// Clone the provider asynchronously (for adversary injection testing).
    /// Creates a new provider with the same key handles.
    pub async fn clone_async(&self) -> Self {
        Self {
            enclave: Arc::clone(&self.enclave),
            label_prefix: self.label_prefix.clone(),
            next_label_generation: RwLock::new(*self.next_label_generation.read().await),
            current_handle: RwLock::new(self.current_handle.read().await.clone()),
            next_handle: RwLock::new(self.next_handle.read().await.clone()),
            recovery_handle: RwLock::new(self.recovery_handle.read().await.clone()),
            pending_current_handle: RwLock::new(self.pending_current_handle.read().await.clone()),
            pending_next_handle: RwLock::new(self.pending_next_handle.read().await.clone()),
            pending_recovery_handle: RwLock::new(self.pending_recovery_handle.read().await.clone()),
        }
    }

    /// Get the recovery key's label for persistence.
    pub async fn recovery_label(&self) -> Option<String> {
        self.recovery_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    /// Get the current key's label for persistence.
    pub async fn current_label(&self) -> Option<String> {
        self.current_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    /// Get the next key's label for persistence.
    pub async fn next_label(&self) -> Option<String> {
        self.next_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    /// Get the next label generation for persistence.
    pub async fn next_label_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    fn generate_label(&self, generation: u64) -> String {
        format!("{}-{}", self.label_prefix, generation)
    }

    // Primitive operations for KeyProvider enum delegation

    pub async fn has_current(&self) -> bool {
        self.current_handle.read().await.is_some()
    }

    pub async fn has_next(&self) -> bool {
        self.next_handle.read().await.is_some()
    }

    pub async fn has_recovery(&self) -> bool {
        self.recovery_handle.read().await.is_some()
    }

    pub async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        // Preemptively delete any existing key with this label
        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.current_handle.write().await = Some(handle);
        Ok(public_key)
    }

    pub async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        // Preemptively delete any existing key with this label
        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.next_handle.write().await = Some(handle);
        Ok(public_key)
    }

    pub async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        // Preemptively delete any existing key with this label
        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.recovery_handle.write().await = Some(handle);
        Ok(public_key)
    }

    pub fn promote_next_to_current(&mut self) {
        // Promote next → current (no previous key caching with dedicated recovery key)
        *self.current_handle.get_mut() = self.next_handle.get_mut().take();
    }

    /// Prepare recovery key rotation - generates new key but doesn't replace yet.
    /// Returns (current_recovery_pub, new_recovery_pub).
    pub async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        // Get current recovery public key
        let current_recovery = {
            let recovery = self.recovery_handle.read().await;
            let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
            self.enclave.get_public_key(handle)?
        };

        // Generate new recovery key into pending slot
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        // Preemptively delete any existing key with this label
        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, new_recovery_pub) = self.enclave.generate_key(&label)?;
        *self.pending_recovery_handle.write().await = Some(handle);

        Ok((current_recovery, new_recovery_pub))
    }

    /// Commit the prepared rotation - replaces current recovery key with new.
    pub async fn commit_recovery_rotation(&mut self) {
        // Move pending to recovery (old key is NOT deleted - will be cleaned up on decommission)
        *self.recovery_handle.write().await = self.pending_recovery_handle.write().await.take();
    }

    /// Prepare signing key rotation - stages next→current and generates new next.
    /// Returns the new current public key.
    ///
    /// Does NOT modify the actual key state - call `commit_rotation()` after
    /// successful KELS submission, or the pending keys will be discarded.
    pub async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        // Take the next handle and stage it as pending current
        let next_handle = self.next_handle.write().await.take();
        let next_handle = next_handle.ok_or(KelsError::NoNextKey)?;

        // Get the public key before staging
        let new_current_pub = self.enclave.get_public_key(&next_handle)?;

        // Stage it as pending current
        *self.pending_current_handle.write().await = Some(next_handle);

        // Generate new next key into pending slot
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        // Preemptively delete any existing key with this label
        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (new_next_handle, _new_next_pub) = self.enclave.generate_key(&label)?;
        *self.pending_next_handle.write().await = Some(new_next_handle);

        Ok(new_current_pub)
    }

    /// Get the pending next public key (after prepare_rotation).
    pub async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError> {
        let pending_next = self.pending_next_handle.read().await;
        let handle = pending_next.as_ref().ok_or(KelsError::NoNextKey)?;
        self.enclave.get_public_key(handle)
    }

    /// Sign with the pending current key (after prepare_rotation).
    pub async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let pending_current = self.pending_current_handle.read().await;
        let handle = pending_current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.sign(handle, data)
    }

    /// Commit the prepared signing key rotation.
    pub async fn commit_rotation(&mut self) {
        // Move pending current → current (old key is NOT deleted - will be cleaned up on decommission)
        *self.current_handle.write().await = self.pending_current_handle.write().await.take();

        // Move pending next → next
        *self.next_handle.write().await = self.pending_next_handle.write().await.take();
    }

    /// Rollback a prepared signing key rotation (if KELS rejects).
    /// Deletes the pending next key and restores next_handle.
    pub async fn rollback_rotation(&mut self) {
        // Delete the newly generated pending next key
        if let Some(ref handle) = *self.pending_next_handle.read().await
            && let Err(e) = self.enclave.delete_key(handle)
        {
            eprintln!("Warning: Failed to delete pending next key: {}", e);
        }

        // Move pending current back to next (it was the original next)
        *self.next_handle.write().await = self.pending_current_handle.write().await.take();

        // Clear pending next
        *self.pending_next_handle.write().await = None;
    }

    /// Rollback a prepared recovery key rotation (if KELS rejects).
    /// Deletes the pending recovery key.
    pub async fn rollback_recovery_rotation(&mut self) {
        // Delete the newly generated pending recovery key
        if let Some(ref handle) = *self.pending_recovery_handle.read().await
            && let Err(e) = self.enclave.delete_key(handle)
        {
            eprintln!("Warning: Failed to delete pending recovery key: {}", e);
        }

        // Clear pending
        *self.pending_recovery_handle.write().await = None;
    }

    /// Delete all keys from the Secure Enclave (for decommission).
    /// Walks through all generated labels from 0 to current generation.
    pub async fn delete_all_keys(&mut self) {
        let generation = *self.next_label_generation.read().await;

        // Delete all keys by walking through label history
        for i in 0..generation {
            let label = self.generate_label(i);
            let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle { label });
        }

        // Clear all handles
        *self.current_handle.write().await = None;
        *self.next_handle.write().await = None;
        *self.recovery_handle.write().await = None;
        *self.pending_current_handle.write().await = None;
        *self.pending_next_handle.write().await = None;
        *self.pending_recovery_handle.write().await = None;
    }

    /// Get the current label generation (for cleanup tracking).
    pub async fn current_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    /// Delete keys created from start_generation up to (but not including) current generation.
    /// Used to clean up keys created during adversarial injection.
    pub async fn delete_keys_from_generation(&self, start_generation: u64) {
        let current_generation = *self.next_label_generation.read().await;

        for i in start_generation..current_generation {
            let label = self.generate_label(i);
            let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle { label });
        }
    }

    // Async operations called by KeyProvider enum

    pub async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.get_public_key(handle)
    }

    pub async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        let next = self.next_handle.read().await;
        let handle = next.as_ref().ok_or(KelsError::NoNextKey)?;
        self.enclave.get_public_key(handle)
    }

    pub async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.get_public_key(handle)
    }

    pub async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.sign(handle, data)
    }

    pub async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.sign(handle, data)
    }

    pub async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.verify(handle, data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[tokio::test]
    async fn test_hardware_provider_availability() {
        if let Some(mut provider) = HardwareKeyProvider::new("test-adns-provider") {
            // Clean up any existing test keys
            if let Some(label) = provider.current_label().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
            if let Some(label) = provider.next_label().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }

            // Generate keys using primitive methods
            let pub1 = provider.generate_into_current().await.unwrap();
            let pub2 = provider.generate_into_next().await.unwrap();

            // Verify we can get the public keys
            let current = provider.current_public_key().await.unwrap();
            let next = provider.next_public_key().await.unwrap();

            assert_eq!(pub1.raw(), current.raw());
            assert_eq!(pub2.raw(), next.raw());

            // Test signing
            let data = b"test message";
            let sig = provider.sign(data).await.unwrap();

            // Test verification
            provider.verify(data, &sig).await.unwrap();

            // Clean up
            if let Some(label) = provider.current_label().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
            if let Some(label) = provider.next_label().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
        } else {
            println!("Secure Enclave not available, skipping test");
        }
    }
}
