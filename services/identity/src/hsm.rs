//! HSM Client - HTTP client for the HSM service

use async_trait::async_trait;
use cesr::{Matter, PublicKey, Signature};
use kels::KelsError;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyHandle(String);

impl KeyHandle {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for KeyHandle {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for KeyHandle {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[async_trait]
pub trait HsmOperations: Send + Sync {
    async fn generate_keypair(&self, label: &str) -> Result<(KeyHandle, PublicKey), KelsError>;
    async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError>;
    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Signature, KelsError>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateKeyRequest {
    label: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateKeyResponse {
    label: String,
    public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignResponse {
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

pub struct HsmClient {
    client: Client,
    base_url: String,
}

impl HsmClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    async fn request_error(&self, response: reqwest::Response) -> KelsError {
        match response.json::<ErrorResponse>().await {
            Ok(e) => KelsError::HardwareError(e.error),
            Err(e) => KelsError::HardwareError(format!("Failed to parse error: {}", e)),
        }
    }
}

#[async_trait]
impl HsmOperations for HsmClient {
    async fn generate_keypair(&self, label: &str) -> Result<(KeyHandle, PublicKey), KelsError> {
        let url = format!("{}/api/hsm/keys", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&GenerateKeyRequest { label: label.to_string() })
            .send()
            .await
            .map_err(|e| KelsError::HardwareError(format!("HSM request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(self.request_error(response).await);
        }

        let resp: GenerateKeyResponse = response
            .json()
            .await
            .map_err(|e| KelsError::HardwareError(format!("Failed to parse response: {}", e)))?;

        let public_key = PublicKey::from_qb64(&resp.public_key)
            .map_err(|e| KelsError::HardwareError(format!("Invalid CESR public key: {}", e)))?;

        Ok((KeyHandle::new(resp.label), public_key))
    }

    async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError> {
        let url = format!("{}/api/hsm/keys/{}/public", self.base_url, handle.as_str());

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KelsError::HardwareError(format!("HSM request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(self.request_error(response).await);
        }

        let resp: PublicKeyResponse = response
            .json()
            .await
            .map_err(|e| KelsError::HardwareError(format!("Failed to parse response: {}", e)))?;

        PublicKey::from_qb64(&resp.public_key)
            .map_err(|e| KelsError::HardwareError(format!("Invalid CESR public key: {}", e)))
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Signature, KelsError> {
        let url = format!("{}/api/hsm/keys/{}/sign", self.base_url, handle.as_str());

        let request = SignRequest {
            data: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, data),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| KelsError::HardwareError(format!("HSM request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(self.request_error(response).await);
        }

        let resp: SignResponse = response
            .json()
            .await
            .map_err(|e| KelsError::HardwareError(format!("Failed to parse response: {}", e)))?;

        Signature::from_qb64(&resp.signature)
            .map_err(|e| KelsError::HardwareError(format!("Invalid CESR signature: {}", e)))
    }
}

use kels::ExternalKeyProvider;
use std::sync::Arc;
use tokio::sync::RwLock;

/// HSM-backed key provider with two-phase rotation support.
///
/// Pending handles stage key changes before commit, enabling rollback on failure.
pub struct HsmKeyProvider {
    hsm: Arc<dyn HsmOperations>,
    label_prefix: String,
    next_label_generation: RwLock<u64>,
    current_handle: RwLock<Option<KeyHandle>>,
    next_handle: RwLock<Option<KeyHandle>>,
    recovery_handle: RwLock<Option<KeyHandle>>,
    pending_current_handle: RwLock<Option<KeyHandle>>,
    pending_next_handle: RwLock<Option<KeyHandle>>,
    pending_recovery_handle: RwLock<Option<KeyHandle>>,
}

impl std::fmt::Debug for HsmKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmKeyProvider")
            .field("label_prefix", &self.label_prefix)
            .finish_non_exhaustive()
    }
}

impl HsmKeyProvider {
    pub fn new(hsm: Arc<dyn HsmOperations>, label_prefix: &str, start_generation: u64) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            next_label_generation: RwLock::new(start_generation),
            current_handle: RwLock::new(None),
            next_handle: RwLock::new(None),
            recovery_handle: RwLock::new(None),
            pending_current_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        }
    }

    /// Restore from persisted state.
    pub fn with_handles(
        hsm: Arc<dyn HsmOperations>,
        label_prefix: &str,
        next_label_generation: u64,
        current_handle: KeyHandle,
        next_handle: KeyHandle,
    ) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            next_label_generation: RwLock::new(next_label_generation),
            current_handle: RwLock::new(Some(current_handle)),
            next_handle: RwLock::new(Some(next_handle)),
            recovery_handle: RwLock::new(None),
            pending_current_handle: RwLock::new(None),
            pending_next_handle: RwLock::new(None),
            pending_recovery_handle: RwLock::new(None),
        }
    }

    pub async fn current_handle(&self) -> Option<KeyHandle> {
        self.current_handle.read().await.clone()
    }

    pub async fn next_handle(&self) -> Option<KeyHandle> {
        self.next_handle.read().await.clone()
    }

    pub async fn next_label_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    async fn generate_new_key(&self) -> Result<(KeyHandle, PublicKey), KelsError> {
        let mut generation = self.next_label_generation.write().await;
        let label = format!("{}-{}", self.label_prefix, *generation);
        *generation += 1;
        self.hsm.generate_keypair(&label).await
    }
}

#[async_trait]
impl ExternalKeyProvider for HsmKeyProvider {
    async fn has_current(&self) -> bool {
        self.current_handle.read().await.is_some()
    }

    async fn has_next(&self) -> bool {
        self.next_handle.read().await.is_some()
    }

    async fn has_recovery(&self) -> bool {
        self.recovery_handle.read().await.is_some()
    }

    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let (handle, public_key) = self.generate_new_key().await?;
        *self.current_handle.write().await = Some(handle);
        Ok(public_key)
    }

    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let (handle, public_key) = self.generate_new_key().await?;
        *self.next_handle.write().await = Some(handle);
        Ok(public_key)
    }

    async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let (handle, public_key) = self.generate_new_key().await?;
        *self.recovery_handle.write().await = Some(handle);
        Ok(public_key)
    }

    fn promote_next_to_current(&mut self) {
        *self.current_handle.get_mut() = self.next_handle.get_mut().take();
    }

    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        let handle = self.current_handle.read().await;
        let handle = handle
            .as_ref()
            .ok_or_else(|| KelsError::HardwareError("No current key".to_string()))?;
        self.hsm.get_public_key(handle).await
    }

    async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        let handle = self.next_handle.read().await;
        let handle = handle
            .as_ref()
            .ok_or_else(|| KelsError::HardwareError("No next key".to_string()))?;
        self.hsm.get_public_key(handle).await
    }

    async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        let handle = self.recovery_handle.read().await;
        let handle = handle.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.hsm.get_public_key(handle).await
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let handle = self.current_handle.read().await;
        let handle = handle
            .as_ref()
            .ok_or_else(|| KelsError::HardwareError("No current key".to_string()))?;
        self.hsm.sign(handle, data).await
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let handle = self.recovery_handle.read().await;
        let handle = handle.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        self.hsm.sign(handle, data).await
    }

    async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let public_key = self.current_public_key().await?;
        public_key
            .verify(data, signature)
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))
    }

    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        let current_recovery = {
            let handle = self.recovery_handle.read().await;
            let handle = handle.as_ref().ok_or(KelsError::NoRecoveryKey)?;
            self.hsm.get_public_key(handle).await?
        };

        let (handle, new_recovery_pub) = self.generate_new_key().await?;
        *self.pending_recovery_handle.write().await = Some(handle);

        Ok((current_recovery, new_recovery_pub))
    }

    async fn commit_recovery_rotation(&mut self) {
        *self.recovery_handle.write().await = self.pending_recovery_handle.write().await.take();
    }

    async fn current_handle(&self) -> Option<String> {
        self.current_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.as_str().to_string())
    }

    async fn next_handle(&self) -> Option<String> {
        self.next_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.as_str().to_string())
    }

    async fn recovery_handle(&self) -> Option<String> {
        self.recovery_handle
            .read()
            .await
            .as_ref()
            .map(|h| h.as_str().to_string())
    }

    async fn next_label_generation(&self) -> u64 {
        *self.next_label_generation.read().await
    }

    async fn rollback_recovery_rotation(&mut self) {
        *self.pending_recovery_handle.write().await = None;
    }

    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        let next_handle = self.next_handle.write().await.take();
        let next_handle =
            next_handle.ok_or_else(|| KelsError::HardwareError("No next key".to_string()))?;

        let new_current_pub = self.hsm.get_public_key(&next_handle).await?;
        *self.pending_current_handle.write().await = Some(next_handle);

        let (new_next_handle, _new_next_pub) = self.generate_new_key().await?;
        *self.pending_next_handle.write().await = Some(new_next_handle);

        Ok(new_current_pub)
    }

    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError> {
        let pending_next = self.pending_next_handle.read().await;
        let handle = pending_next
            .as_ref()
            .ok_or_else(|| KelsError::HardwareError("No pending next key".to_string()))?;
        self.hsm.get_public_key(handle).await
    }

    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let pending_current = self.pending_current_handle.read().await;
        let handle = pending_current
            .as_ref()
            .ok_or_else(|| KelsError::HardwareError("No pending current key".to_string()))?;
        self.hsm.sign(handle, data).await
    }

    async fn commit_rotation(&mut self) {
        *self.current_handle.write().await = self.pending_current_handle.write().await.take();
        *self.next_handle.write().await = self.pending_next_handle.write().await.take();
    }

    async fn rollback_rotation(&mut self) {
        // Restore next from pending_current (it was the original next)
        *self.next_handle.write().await = self.pending_current_handle.write().await.take();
        *self.pending_next_handle.write().await = None;
    }
}
