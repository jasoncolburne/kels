//! Hardware Key Provider - Secure Enclave backed key storage

use crate::crypto::KeyProvider;
use crate::error::KelsError;
use cesr::{PublicKey, Signature};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::secure_enclave::{
    DefaultSecureEnclave, SecureEnclaveKeyHandle, SecureEnclaveOperations,
};

/// Secure Enclave backed keys. Manages current, next, recovery keys with two-phase rotation.
pub struct HardwareKeyProvider {
    enclave: Arc<dyn SecureEnclaveOperations>,
    key_namespace: String,
    next_label_generation: RwLock<u64>,
    current_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    next_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    pending_next_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
    pending_recovery_handle: RwLock<Option<SecureEnclaveKeyHandle>>,
}

impl HardwareKeyProvider {
    // ==================== Constructors ====================

    pub fn new(key_namespace: &str) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;
        Some(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            next_label_generation: RwLock::new(0),
            current_handle: RwLock::new(None),
            next_handle: RwLock::new(None),
            recovery_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    pub fn with_all_handles(
        key_namespace: &str,
        current_label: Option<String>,
        next_label: Option<String>,
        recovery_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;

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
            current_handle: RwLock::new(current_handle),
            next_handle: RwLock::new(next_handle),
            recovery_handle: RwLock::new(recovery_handle),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        })
    }

    pub fn with_handles(
        key_namespace: &str,
        current_label: Option<String>,
        next_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        Self::with_all_handles(
            key_namespace,
            current_label,
            next_label,
            None,
            next_label_generation,
        )
    }

    // ==================== Non-trait Methods ====================

    pub async fn clone_async(&self) -> Self {
        Self {
            enclave: Arc::clone(&self.enclave),
            key_namespace: self.key_namespace.clone(),
            next_label_generation: RwLock::new(*self.next_label_generation.read().await),
            current_handle: RwLock::new(self.current_handle.read().await.clone()),
            next_handle: RwLock::new(self.next_handle.read().await.clone()),
            recovery_handle: RwLock::new(self.recovery_handle.read().await.clone()),
            pending_next_handle: RwLock::new(self.pending_next_handle.read().await.clone()),
            pending_recovery_handle: RwLock::new(self.pending_recovery_handle.read().await.clone()),
        }
    }

    pub async fn current_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    pub async fn delete_all_keys(&mut self) {
        let generation = *self.next_label_generation.read().await;

        for i in 0..generation {
            let label = self.generate_label(i);
            let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle { label });
        }

        *self.current_handle.write().await = None;
        *self.next_handle.write().await = None;
        *self.recovery_handle.write().await = None;
        *self.pending_next_handle.write().await = None;
        *self.pending_recovery_handle.write().await = None;
    }

    pub async fn delete_keys_from_generation(&self, start_generation: u64) {
        let current_generation = *self.next_label_generation.read().await;

        for i in start_generation..current_generation {
            let label = self.generate_label(i);
            let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle { label });
        }
    }

    pub fn promote_next_to_current(&mut self) {
        *self.current_handle.get_mut() = self.next_handle.get_mut().take();
    }

    fn generate_label(&self, generation: u64) -> String {
        format!("{}-{}", self.key_namespace, generation)
    }
}

// ==================== KeyProvider impl ====================

#[async_trait::async_trait]
impl KeyProvider for HardwareKeyProvider {
    async fn current_handle(&self) -> Option<String> {
        self.current_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.get_public_key(handle)
    }

    async fn next_handle(&self) -> Option<String> {
        self.next_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    async fn next_label_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        let next = self.next_handle.read().await;
        let handle = next.as_ref().ok_or(KelsError::NoNextKey)?;
        self.enclave.get_public_key(handle)
    }

    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError> {
        let pending_next = self.pending_next_handle.read().await;
        let handle = pending_next.as_ref().ok_or(KelsError::NoNextKey)?;
        self.enclave.get_public_key(handle)
    }

    async fn recovery_handle(&self) -> Option<String> {
        self.recovery_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.label.clone())
    }

    async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.get_public_key(handle)
    }

    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.current_handle.write().await = Some(handle);
        Ok(public_key)
    }

    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.next_handle.write().await = Some(handle);
        Ok(public_key)
    }

    async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        *self.recovery_handle.write().await = Some(handle);
        Ok(public_key)
    }

    async fn has_current(&self) -> bool {
        self.current_handle.read().await.is_some()
    }

    async fn has_next(&self) -> bool {
        self.next_handle.read().await.is_some()
    }

    async fn has_recovery(&self) -> bool {
        self.recovery_handle.read().await.is_some()
    }

    async fn commit_recovery_rotation(&mut self) {
        *self.recovery_handle.write().await = self.pending_recovery_handle.write().await.take();
    }

    async fn commit_rotation(&mut self) {
        if let Some(pending_next) = self.pending_next_handle.write().await.take() {
            *self.current_handle.write().await = self.next_handle.write().await.take();
            *self.next_handle.write().await = Some(pending_next);
        }
    }

    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        let current_recovery = {
            let recovery = self.recovery_handle.read().await;
            let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
            self.enclave.get_public_key(handle)?
        };

        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, new_recovery_pub) = self.enclave.generate_key(&label)?;
        *self.pending_recovery_handle.write().await = Some(handle);

        Ok((current_recovery, new_recovery_pub))
    }

    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        let new_current_pub = {
            let next_handle = self.next_handle.read().await;
            let handle = next_handle.as_ref().ok_or(KelsError::NoNextKey)?;
            self.enclave.get_public_key(handle)?
        };

        let mut generation = self.next_label_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (new_next_handle, _new_next_pub) = self.enclave.generate_key(&label)?;
        *self.pending_next_handle.write().await = Some(new_next_handle);

        Ok(new_current_pub)
    }

    async fn rollback_recovery_rotation(&mut self) {
        if let Some(ref handle) = *self.pending_recovery_handle.read().await
            && let Err(e) = self.enclave.delete_key(handle)
        {
            eprintln!("Warning: Failed to delete pending recovery key: {}", e);
        }
        *self.pending_recovery_handle.write().await = None;
    }

    async fn rollback_rotation(&mut self) {
        if let Some(ref handle) = *self.pending_next_handle.read().await
            && let Err(e) = self.enclave.delete_key(handle)
        {
            eprintln!("Warning: Failed to delete pending next key: {}", e);
        }
        *self.pending_next_handle.write().await = None;
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.sign(handle, data)
    }

    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let next_handle = self.next_handle.read().await;
        let handle = next_handle.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.sign(handle, data)
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let recovery = self.recovery_handle.read().await;
        let handle = recovery.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.enclave.sign(handle, data)
    }

    async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let current = self.current_handle.read().await;
        let handle = current.as_ref().ok_or(KelsError::NoCurrentKey)?;
        self.enclave.verify(handle, data, signature)
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[tokio::test]
    async fn test_hardware_provider_availability() {
        if let Some(mut provider) = HardwareKeyProvider::new("test-kels-provider") {
            if let Some(label) = provider.current_handle().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
            if let Some(label) = provider.next_handle().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }

            let pub1 = provider.generate_into_current().await.unwrap();
            let pub2 = provider.generate_into_next().await.unwrap();

            let current = provider.current_public_key().await.unwrap();
            let next = provider.next_public_key().await.unwrap();

            assert_eq!(pub1.raw(), current.raw());
            assert_eq!(pub2.raw(), next.raw());

            let data = b"test message";
            let sig = provider.sign(data).await.unwrap();

            provider.verify(data, &sig).await.unwrap();

            if let Some(label) = provider.current_handle().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
            if let Some(label) = provider.next_handle().await
                && let Some(enclave) = DefaultSecureEnclave::new()
            {
                let _ = enclave.delete_key(&SecureEnclaveKeyHandle { label });
            }
        } else {
            println!("Secure Enclave not available, skipping test");
        }
    }
}
