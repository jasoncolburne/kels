//! Hardware Key Provider - Secure Enclave backed key storage

use std::sync::Arc;
use tokio::sync::RwLock;

use base64::Engine;
use cesr::{Signature, VerificationKey, VerificationKeyCode};
use serde::{Deserialize, Serialize};

use crate::{
    compute_rotation_hash,
    crypto::{KeyProvider, KeyStateStore},
    error::KelsError,
};

use super::secure_enclave::{
    DefaultSecureEnclave, SecureEnclaveKeyHandle, SecureEnclaveOperations,
};

/// Secure Enclave backed keys. Manages current, next, recovery keys with two-phase rotation.
pub struct HardwareKeyProvider {
    enclave: Arc<dyn SecureEnclaveOperations>,
    key_namespace: String,
    signing_algorithm: VerificationKeyCode,
    recovery_algorithm: VerificationKeyCode,
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
            signing_algorithm: self.signing_algorithm,
            recovery_algorithm: self.recovery_algorithm,

            signing_generation: RwLock::new(signing_gen),
            recovery_generation: RwLock::new(recovery_gen),
            key_handles: RwLock::new(key_handles),
            recovery_handles: RwLock::new(recovery_handles),
        }
    }
}

impl HardwareKeyProvider {
    // ==================== Constructors ====================

    pub fn new(
        key_namespace: &str,
        signing_algorithm: VerificationKeyCode,
        recovery_algorithm: VerificationKeyCode,
    ) -> Option<Self> {
        let enclave = DefaultSecureEnclave::new()?;
        Some(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            signing_algorithm,
            recovery_algorithm,
            signing_generation: RwLock::new(0),
            recovery_generation: RwLock::new(0),
            key_handles: RwLock::new(Vec::new()),
            recovery_handles: RwLock::new(Vec::new()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_handles(
        key_namespace: &str,
        signing_algorithm: VerificationKeyCode,
        recovery_algorithm: VerificationKeyCode,
        signing_generation: u64,
        recovery_generation: u64,
        key_handles: Vec<SecureEnclaveKeyHandle>,
        recovery_handles: Vec<SecureEnclaveKeyHandle>,
    ) -> Result<Self, KelsError> {
        let enclave = DefaultSecureEnclave::new().ok_or(KelsError::HardwareError(
            "Could not instantiate secure enclave".to_string(),
        ))?;

        Ok(Self {
            enclave,
            key_namespace: key_namespace.to_string(),
            signing_algorithm,
            recovery_algorithm,
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
            signing_algorithm: self.signing_algorithm,
            recovery_algorithm: self.recovery_algorithm,

            signing_generation: RwLock::new(*self.signing_generation.read().await),
            recovery_generation: RwLock::new(*self.recovery_generation.read().await),
            key_handles: RwLock::new(self.key_handles.read().await.clone()),
            recovery_handles: RwLock::new(self.recovery_handles.read().await.clone()),
        }
    }

    /// Delete all SE keys held by this provider
    pub async fn delete_all_keys(&self) {
        let key_handles = self.key_handles.read().await;
        for handle in key_handles.iter() {
            let _ = self.enclave.delete_key(handle);
        }
        let recovery_handles = self.recovery_handles.read().await;
        for handle in recovery_handles.iter() {
            let _ = self.enclave.delete_key(handle);
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

    async fn generate_internal(&mut self) -> Result<VerificationKey, KelsError> {
        let mut generation = self.signing_generation.write().await;
        let label = self.generate_label(*generation);
        *generation += 1;

        let (handle, public_key) = self.enclave.generate_key(&label, self.signing_algorithm)?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(handle);

        Ok(public_key)
    }

    async fn generate_recovery_internal(&mut self) -> Result<VerificationKey, KelsError> {
        let mut generation = self.recovery_generation.write().await;
        let label = self.generate_recovery_label(*generation);
        *generation += 1;

        let (handle, public_key) = self.enclave.generate_key(&label, self.recovery_algorithm)?;
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

    async fn current_public_key(&self) -> Result<VerificationKey, KelsError> {
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
            return Err(KelsError::HsmKeyNotFound(
                "Public key not found".to_string(),
            ));
        }
    }

    async fn generate_initial_keys(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest, cesr::Digest), KelsError> {
        let current_pub = self.generate_internal().await?;
        let next_pub = self.generate_internal().await?;
        let recovery_pub = self.generate_recovery_internal().await?;

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

    async fn stage_rotation(&mut self) -> Result<(VerificationKey, cesr::Digest), KelsError> {
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

        let (new_next_handle, new_next_pub) =
            self.enclave.generate_key(&label, self.signing_algorithm)?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(new_next_handle);
        let next_hash = compute_rotation_hash(&new_next_pub);

        Ok((new_current_pub, next_hash))
    }

    async fn stage_recovery_rotation(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest), KelsError> {
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

        let (handle, new_recovery_pub) =
            self.enclave.generate_key(&label, self.recovery_algorithm)?;
        let mut key_handles = self.recovery_handles.write().await;
        key_handles.push(handle);

        let recovery_hash = compute_rotation_hash(&new_recovery_pub);

        Ok((current_recovery, recovery_hash))
    }

    async fn commit(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut key_handles = self.recovery_handles.write().await;
            let length = key_handles.len();
            for handle in &key_handles[..(length - 1)] {
                let _ = self.enclave.delete_key(handle);
            }
            *key_handles = key_handles[(length - 1)..].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let length = key_handles.len();
        for handle in &key_handles[..(length - 2)] {
            let _ = self.enclave.delete_key(handle);
        }
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

            for handle in &key_handles[1..] {
                let _ = self.enclave.delete_key(handle);
            }
            *generation -= (key_handles.len() as u64) - 1;
            *key_handles = key_handles[..1].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let mut generation = self.signing_generation.write().await;

        for handle in &key_handles[2..] {
            let _ = self.enclave.delete_key(handle);
        }
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

    async fn set_signing_algorithm(
        &mut self,
        algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        self.signing_algorithm = algorithm;
        Ok(())
    }

    async fn set_recovery_algorithm(
        &mut self,
        algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        self.recovery_algorithm = algorithm;
        Ok(())
    }

    async fn save_state(
        &self,
        store: &dyn KeyStateStore,
        prefix: &cesr::Digest,
    ) -> Result<(), KelsError> {
        let key_handles = self.key_handles.read().await;
        let recovery_handles = self.recovery_handles.read().await;

        let state = HardwareKeyState {
            signing_generation: *self.signing_generation.read().await,
            recovery_generation: *self.recovery_generation.read().await,
            signing_algorithm: self.signing_algorithm,
            recovery_algorithm: self.recovery_algorithm,

            key_handles: key_handles
                .iter()
                .map(PersistedHandle::from_handle)
                .collect(),
            recovery_handles: recovery_handles
                .iter()
                .map(PersistedHandle::from_handle)
                .collect(),
        };

        let data =
            serde_json::to_vec(&state).map_err(|e| KelsError::StorageError(e.to_string()))?;
        store.save(prefix, &data)
    }

    async fn restore_state(
        &mut self,
        store: &dyn KeyStateStore,
        prefix: &cesr::Digest,
    ) -> Result<bool, KelsError> {
        let Some(data) = store.load(prefix)? else {
            return Ok(false);
        };

        let state: HardwareKeyState =
            serde_json::from_slice(&data).map_err(|e| KelsError::StorageError(e.to_string()))?;

        *self.signing_generation.write().await = state.signing_generation;
        *self.recovery_generation.write().await = state.recovery_generation;

        self.signing_algorithm = state.signing_algorithm;
        self.recovery_algorithm = state.recovery_algorithm;

        let key_handles: Vec<SecureEnclaveKeyHandle> = state
            .key_handles
            .iter()
            .filter_map(|h| h.to_handle())
            .collect();
        let recovery_handles: Vec<SecureEnclaveKeyHandle> = state
            .recovery_handles
            .iter()
            .filter_map(|h| h.to_handle())
            .collect();

        *self.key_handles.write().await = key_handles;
        *self.recovery_handles.write().await = recovery_handles;

        Ok(true)
    }
}

// ==================== Persistence Types ====================

#[derive(Serialize, Deserialize)]
struct HardwareKeyState {
    signing_generation: u64,
    recovery_generation: u64,
    signing_algorithm: VerificationKeyCode,
    recovery_algorithm: VerificationKeyCode,
    key_handles: Vec<PersistedHandle>,
    recovery_handles: Vec<PersistedHandle>,
}

#[derive(Serialize, Deserialize)]
struct PersistedHandle {
    label: String,
    algorithm: VerificationKeyCode,
    key_data_b64: String,
}

impl PersistedHandle {
    fn from_handle(handle: &SecureEnclaveKeyHandle) -> Self {
        Self {
            label: handle.label.clone(),
            algorithm: handle.algorithm,
            key_data_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&handle.key_data),
        }
    }

    fn to_handle(&self) -> Option<SecureEnclaveKeyHandle> {
        let key_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.key_data_b64)
            .ok()?;
        Some(SecureEnclaveKeyHandle {
            label: self.label.clone(),
            algorithm: self.algorithm,
            key_data,
        })
    }
}
