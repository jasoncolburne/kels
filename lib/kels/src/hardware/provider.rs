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
/// Uses unified signing_handles Vec where:
/// - `signing_handles[len-2]` = current key (when len >= 2)
/// - `signing_handles[len-1]` = next key (when len >= 2)
/// - `signing_handles[0..len-2]` = historical keys
/// The recovery key is a dedicated key for recovery events (rec/ror).
///
/// Two-phase rotation support:
/// - `pending_next_handle`: Staged next key during rotation
/// - `pending_recovery_handle`: Staged recovery key rotation
pub struct HardwareKeyProvider {
    enclave: Arc<dyn SecureEnclaveOperations>,
    key_namespace: String,
    next_label_generation: RwLock<u64>,
    /// All signing key handles: historical (0..len-2), current (len-2), next (len-1)
    signing_handles: RwLock<Vec<SecureEnclaveKeyHandle>>,
    recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    // Pending handles for two-phase rotation
    pending_next_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    pending_recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
}

impl HardwareKeyProvider {
    /// Create a new HardwareKeyProvider with fresh keys.
    ///
    /// Returns None if Secure Enclave is not available on this device.
    pub fn new(key_namespace: &str) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;
        Some(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            next_label_generation: RwLock::new(0),
            signing_handles: RwLock::new(Vec::new()),
            recovery_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    /// Create a HardwareKeyProvider with all signing key handles and optional recovery.
    ///
    /// `signing_labels` should contain all signing key labels in order:
    /// historical keys first, then current (len-2), then next (len-1).
    ///
    /// Used to restore state from persisted labels.
    pub fn with_all_handles(
        key_namespace: &str,
        signing_labels: Vec<String>,
        recovery_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;

        // Load all signing key handles
        let mut signing_handles = Vec::new();
        for label in signing_labels {
            match enclave.load_key(&label) {
                Ok(Some(handle)) => signing_handles.push(handle),
                Ok(None) => {
                    eprintln!("Warning: Signing key not found: {}", label);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load signing key: {}", e);
                }
            }
        }

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
            key_namespace: key_namespace.to_string(),
            next_label_generation: RwLock::new(next_label_generation),
            signing_handles: RwLock::new(signing_handles),
            recovery_handle: RwLock::new(recovery_handle),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    /// Clone the provider asynchronously (for adversary injection testing).
    /// Creates a new provider with the same key handles.
    pub async fn clone_async(&self) -> Self {
        Self {
            enclave: Arc::clone(&self.enclave),
            key_namespace: self.key_namespace.clone(),
            next_label_generation: RwLock::new(*self.next_label_generation.read().await),
            signing_handles: RwLock::new(self.signing_handles.read().await.clone()),
            recovery_handle: RwLock::new(self.recovery_handle.read().await.clone()),
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

    /// Get all signing key labels for persistence.
    pub async fn signing_labels(&self) -> Vec<String> {
        self.signing_handles
            .read()
            .await
            .iter()
            .map(|h| h.label.clone())
            .collect()
    }

    /// Get the current signing key's label (for persistence).
    pub async fn current_label(&self) -> Option<String> {
        let handles = self.signing_handles.read().await;
        match handles.len() {
            0 => None,
            1 => Some(handles[0].label.clone()),
            n => Some(handles[n - 2].label.clone()),
        }
    }

    /// Get the next signing key's label (for persistence).
    pub async fn next_label(&self) -> Option<String> {
        let handles = self.signing_handles.read().await;
        if handles.len() >= 2 {
            Some(handles[handles.len() - 1].label.clone())
        } else {
            None
        }
    }

    /// Get the next label generation for persistence.
    pub async fn next_label_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    fn generate_label(&self, generation: u64) -> String {
        format!("{}-{}", self.key_namespace, generation)
    }

    // Primitive operations for KeyProvider enum delegation

    pub async fn has_current(&self) -> bool {
        let handles = self.signing_handles.read().await;
        match handles.len() {
            0 => false,
            1 => true, // Single key acts as current
            _ => true, // len-2 is current
        }
    }

    pub async fn has_next(&self) -> bool {
        self.signing_handles.read().await.len() >= 2
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

        // For inception: push as first key (will be current until next is added)
        let mut handles = self.signing_handles.write().await;
        if handles.is_empty() {
            handles.push(handle);
        } else {
            // Insert at len-1 position (before next, or as current if only one key)
            let insert_pos = if handles.len() == 1 {
                0
            } else {
                handles.len() - 1
            };
            handles.insert(insert_pos, handle);
        }
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

        // Push as next key (always at end)
        self.signing_handles.write().await.push(handle);
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
        // With unified model, promotion is automatic - just remove next
        // Next (len-1) becomes current (len-2), old current becomes historical
        // This is a no-op since the Vec structure handles it automatically
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

    /// Prepare signing key rotation - generates new next key.
    /// Returns the new current public key (what was next).
    ///
    /// Does NOT modify the actual key state - call `commit_rotation()` after
    /// successful KELS submission, or the pending keys will be discarded.
    pub async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        // Get the current next key's public key (will become new current)
        let handles = self.signing_handles.read().await;
        if handles.len() < 2 {
            return Err(KelsError::NoNextKey);
        }
        let new_current_pub = self.enclave.get_public_key(&handles[handles.len() - 1])?;
        drop(handles);

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
    /// This is the current next key that will become current after commit.
    pub async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let handles = self.signing_handles.read().await;
        if handles.len() < 2 {
            return Err(KelsError::NoCurrentKey);
        }
        // Sign with the current next key (will become current)
        self.enclave.sign(&handles[handles.len() - 1], data)
    }

    /// Commit the prepared signing key rotation.
    /// Pushes the pending next key to the Vec, making:
    /// - old current (len-3) historical
    /// - old next (len-2) current
    /// - new next (len-1) next
    pub async fn commit_rotation(&mut self) {
        // Push the pending next key to the Vec
        if let Some(new_next) = self.pending_next_handle.write().await.take() {
            self.signing_handles.write().await.push(new_next);
        }
    }

    /// Rollback a prepared signing key rotation (if KELS rejects).
    /// Deletes the pending next key that was staged.
    pub async fn rollback_rotation(&mut self) {
        // Delete the newly generated pending next key
        if let Some(ref handle) = *self.pending_next_handle.read().await
            && let Err(e) = self.enclave.delete_key(handle)
        {
            eprintln!("Warning: Failed to delete pending next key: {}", e);
        }

        // Clear pending next - signing_handles wasn't modified yet
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
    pub async fn delete_all_keys(&mut self) {
        // Delete all signing keys
        {
            let mut handles = self.signing_handles.write().await;
            for handle in handles.drain(..) {
                let _ = self.enclave.delete_key(&handle);
            }
        }

        // Delete recovery key
        if let Some(handle) = self.recovery_handle.write().await.take() {
            let _ = self.enclave.delete_key(&handle);
        }

        // Delete pending keys
        if let Some(handle) = self.pending_next_handle.write().await.take() {
            let _ = self.enclave.delete_key(&handle);
        }
        if let Some(handle) = self.pending_recovery_handle.write().await.take() {
            let _ = self.enclave.delete_key(&handle);
        }
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
        let handles = self.signing_handles.read().await;
        let handle = match handles.len() {
            0 => return Err(KelsError::NoCurrentKey),
            1 => &handles[0],     // Single key acts as current
            n => &handles[n - 2], // len-2 is current
        };
        self.enclave.get_public_key(handle)
    }

    pub async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        let handles = self.signing_handles.read().await;
        if handles.len() < 2 {
            return Err(KelsError::NoNextKey);
        }
        self.enclave.get_public_key(&handles[handles.len() - 1])
    }

    pub async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.get_public_key(handle)
    }

    pub async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let handles = self.signing_handles.read().await;
        let handle = match handles.len() {
            0 => return Err(KelsError::NoCurrentKey),
            1 => &handles[0],
            n => &handles[n - 2],
        };
        self.enclave.sign(handle, data)
    }

    pub async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.sign(handle, data)
    }

    pub async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let handles = self.signing_handles.read().await;
        let handle = match handles.len() {
            0 => return Err(KelsError::NoCurrentKey),
            1 => &handles[0],
            n => &handles[n - 2],
        };
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
            provider.delete_all_keys().await;

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
            provider.delete_all_keys().await;
        } else {
            println!("Secure Enclave not available, skipping test");
        }
    }
}
