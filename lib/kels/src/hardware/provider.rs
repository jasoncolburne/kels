//! Hardware Key Provider - Secure Enclave backed key storage

use std::sync::Arc;
use tokio::sync::RwLock;

use cesr::{Matter, PublicKey, Signature};

use crate::{compute_rotation_hash, crypto::KeyProvider, error::KelsError};

use super::secure_enclave::{
    DefaultSecureEnclave, SecureEnclaveKeyHandle, SecureEnclaveOperations,
};

/// Secure Enclave backed keys. Manages current, next, recovery keys with two-phase rotation.
pub struct HardwareKeyProvider {
    enclave: Arc<dyn SecureEnclaveOperations>,
    key_namespace: String,
    signing_generation: RwLock<u64>,
    recovery_generation: RwLock<u64>,
    key_handles: RwLock<Vec<SecureEnclaveKeyHandle>>,
    recovery_handles: RwLock<Vec<SecureEnclaveKeyHandle>>,
}

impl Clone for HardwareKeyProvider {
    fn clone(&self) -> Self {
        let signing_gen = *self.signing_generation.blocking_read();
        let recovery_gen = *self.recovery_generation.blocking_read();
        let key_handles = self.key_handles.blocking_read().clone();
        let recovery_handles = self.recovery_handles.blocking_read().clone();

        Self {
            enclave: Arc::clone(&self.enclave),
            key_namespace: self.key_namespace.clone(),
            signing_generation: RwLock::new(signing_gen),
            recovery_generation: RwLock::new(recovery_gen),
            key_handles: RwLock::new(key_handles),
            recovery_handles: RwLock::new(recovery_handles),
        }
    }
}

impl HardwareKeyProvider {
    // ==================== Constructors ====================

    pub fn new(key_namespace: &str) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;
        Some(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            signing_generation: RwLock::new(0),
            recovery_generation: RwLock::new(0),
            key_handles: RwLock::new(Vec::new()),
            recovery_handles: RwLock::new(Vec::new()),
        })
    }

    pub fn with_all_handles(
        key_namespace: &str,
        signing_generation: u64,
        recovery_generation: u64,
    ) -> Result<Self, KelsError> {
        let enclave = DefaultSecureEnclave::new().ok_or(KelsError::HardwareError(
            "Could not instantiate secure enclave".to_string(),
        ))?;

        let key_handles = match signing_generation {
            0 => Vec::new(),
            1 => {
                let label = Self::generate_label_internal(key_namespace, 0);

                let handle = match enclave.load_key(&label) {
                    Ok(Some(handle)) => handle,
                    _ => {
                        return Err(KelsError::HardwareError(
                            "Signing key not found".to_string(),
                        ));
                    }
                };

                vec![handle]
            }
            _ => {
                let first_label =
                    Self::generate_label_internal(key_namespace, signing_generation - 2);
                let second_label =
                    Self::generate_label_internal(key_namespace, signing_generation - 1);

                let first_handle = match enclave.load_key(&first_label) {
                    Ok(Some(handle)) => handle,
                    _ => {
                        return Err(KelsError::HardwareError(
                            "Signing key not found".to_string(),
                        ));
                    }
                };

                let second_handle = match enclave.load_key(&second_label) {
                    Ok(Some(handle)) => handle,
                    _ => {
                        return Err(KelsError::HardwareError(
                            "Signing key not found".to_string(),
                        ));
                    }
                };

                vec![first_handle, second_handle]
            }
        };

        let recovery_handles = if recovery_generation > 0 {
            let recovery_label =
                Self::generate_recovery_label_internal(key_namespace, recovery_generation - 1);
            match enclave.load_key(&recovery_label) {
                Ok(Some(handle)) => vec![handle],
                _ => {
                    return Err(KelsError::HardwareError(
                        "Recovery key not found".to_string(),
                    ));
                }
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            signing_generation: RwLock::new(signing_generation),
            recovery_generation: RwLock::new(recovery_generation),
            key_handles: RwLock::new(key_handles),
            recovery_handles: RwLock::new(recovery_handles),
        })
    }

    // ==================== Non-trait Methods ====================

    pub async fn clone_async(&self) -> Self {
        Self {
            enclave: Arc::clone(&self.enclave),
            key_namespace: self.key_namespace.clone(),
            signing_generation: RwLock::new(*self.signing_generation.read().await),
            recovery_generation: RwLock::new(*self.recovery_generation.read().await),
            key_handles: RwLock::new(self.key_handles.read().await.clone()),
            recovery_handles: RwLock::new(self.recovery_handles.read().await.clone()),
        }
    }

    pub async fn signing_generation(&self) -> u64 {
        *self.signing_generation.read().await
    }

    pub async fn recovery_generation(&self) -> u64 {
        *self.recovery_generation.read().await
    }

    fn generate_label(&self, generation: u64) -> String {
        Self::generate_label_internal(&self.key_namespace, generation)
    }

    fn generate_label_internal(key_namespace: &str, generation: u64) -> String {
        format!("{}-{}", key_namespace, generation)
    }

    fn generate_recovery_label(&self, generation: u64) -> String {
        Self::generate_recovery_label_internal(&self.key_namespace, generation)
    }

    fn generate_recovery_label_internal(key_namespace: &str, generation: u64) -> String {
        format!("{}-recovery-{}", key_namespace, generation)
    }

    async fn generate_internal(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.signing_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(handle);

        Ok(public_key)
    }

    async fn generate_recovery_internal(&mut self) -> Result<PublicKey, KelsError> {
        let mut generation = self.recovery_generation.write().await;
        let label = self.generate_recovery_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, public_key) = self.enclave.generate_key(&label)?;
        let mut key_handles = self.recovery_handles.write().await;
        key_handles.push(handle);

        Ok(public_key)
    }
}

// ==================== KeyProvider impl ====================

#[async_trait::async_trait]
impl KeyProvider for HardwareKeyProvider {
    async fn signing_generation(&self) -> u64 {
        *self.signing_generation.read().await
    }

    async fn recovery_generation(&self) -> u64 {
        *self.recovery_generation.read().await
    }

    async fn current_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        key_handles.first().map(|h| h.label.clone())
    }

    async fn next_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        key_handles.get(1).map(|h| h.label.clone())
    }

    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        // this is correct
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let index = key_handles.len() - 2;
        let key_handle = key_handles.get(index);

        if let Some(handle) = key_handle {
            self.enclave.get_public_key(handle)
        } else {
            return Err(KelsError::KeyNotFound("Public key not found".to_string()));
        }
    }

    async fn generate_initial_keys(&mut self) -> Result<(PublicKey, String, String), KelsError> {
        let current_pub = self.generate_internal().await?;
        let next_pub = self.generate_internal().await?.qb64();
        let recovery_pub = self.generate_recovery_internal().await?.qb64();

        let next_hash = compute_rotation_hash(&next_pub);
        let recovery_hash = compute_rotation_hash(&recovery_pub);

        Ok((current_pub, next_hash, recovery_hash))
    }

    async fn has_current(&self) -> bool {
        let key_handles = self.key_handles.read().await;
        !key_handles.is_empty()
    }

    async fn has_next(&self) -> bool {
        let key_handles = self.key_handles.read().await;
        key_handles.len() > 1
    }

    async fn has_staged(&self) -> bool {
        let key_handles = self.key_handles.read().await;
        key_handles.len() > 2
    }

    async fn has_recovery(&self) -> bool {
        let key_handles = self.recovery_handles.read().await;
        !key_handles.is_empty()
    }

    async fn has_staged_recovery(&self) -> bool {
        let key_handles = self.recovery_handles.read().await;
        key_handles.len() > 1
    }

    async fn stage_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        let new_current_pub = {
            let key_handles = self.key_handles.read().await;
            let length = key_handles.len();
            let handle = &key_handles[length - 1];
            self.enclave.get_public_key(handle)?
        };

        let mut generation = self.signing_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (new_next_handle, _new_next_pub) = self.enclave.generate_key(&label)?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(new_next_handle.clone());
        let new_next_pub = self.enclave.get_public_key(&new_next_handle)?.qb64();
        let next_hash = compute_rotation_hash(&new_next_pub);

        Ok((new_current_pub, next_hash))
    }

    async fn stage_recovery_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if self.has_staged_recovery().await {
            return Err(KelsError::AlreadyStagedRecovery);
        }

        let current_recovery = {
            let key_handles = self.recovery_handles.read().await;
            let handle = &key_handles[0];
            self.enclave.get_public_key(handle)?
        };

        let mut generation = self.recovery_generation.write().await;
        let label = self.generate_recovery_label(*generation);
        *generation += 1;

        let _ = self.enclave.delete_key(&SecureEnclaveKeyHandle {
            label: label.clone(),
        });

        let (handle, new_recovery_pub) = self.enclave.generate_key(&label)?;
        let mut key_handles = self.recovery_handles.write().await;
        key_handles.push(handle);

        let new_pub_qb64 = new_recovery_pub.qb64();
        let recovery_hash = compute_rotation_hash(&new_pub_qb64);

        Ok((current_recovery, recovery_hash))
    }

    async fn commit(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut key_handles = self.recovery_handles.write().await;
            let length = key_handles.len();
            *key_handles = key_handles[(length - 1)..].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let length = key_handles.len();
        *key_handles = key_handles[(length - 2)..].to_vec();

        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut key_handles = self.recovery_handles.write().await;
            let mut generation = self.recovery_generation.write().await;

            *generation -= (key_handles.len() as u64) - 1;
            *key_handles = key_handles[..1].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let mut generation = self.signing_generation.write().await;

        *generation -= (key_handles.len() as u64) - 2;
        *key_handles = key_handles[..2].to_vec();

        Ok(())
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        // this is correct, the error makes sense to the user
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let length = key_handles.len();
        let handle = &key_handles[length - 2];

        self.enclave.sign(handle, data)
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let key_handles = self.recovery_handles.read().await;
        let handle = &key_handles[0];

        self.enclave.sign(handle, data)
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

            let (pub1, _hash1, _recovery_hash1) = provider.generate_initial_keys().await.unwrap();

            let current = provider.current_public_key().await.unwrap();
            assert_eq!(pub1.raw(), current.raw());

            let data = b"test message";
            let sig = provider.sign(data).await.unwrap();

            current.verify(data, &sig).unwrap();

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
