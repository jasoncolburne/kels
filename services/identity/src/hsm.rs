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
            Err(e) => e.into(),
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, KelsError> {
        if !response.status().is_success() {
            return Err(self.request_error(response).await);
        }
        Ok(response.json().await?)
    }
}

#[async_trait]
impl HsmOperations for HsmClient {
    async fn generate_keypair(&self, label: &str) -> Result<(KeyHandle, PublicKey), KelsError> {
        let url = format!("{}/api/hsm/keys", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&GenerateKeyRequest {
                label: label.to_string(),
            })
            .send()
            .await?;

        let resp: GenerateKeyResponse = self.parse_response(response).await?;

        let public_key = PublicKey::from_qb64(&resp.public_key)?;

        Ok((KeyHandle::new(resp.label), public_key))
    }

    async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError> {
        let url = format!("{}/api/hsm/keys/{}/public", self.base_url, handle.as_str());

        let response = self.client.get(&url).send().await?;

        let resp: PublicKeyResponse = self.parse_response(response).await?;

        Ok(PublicKey::from_qb64(&resp.public_key)?)
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Signature, KelsError> {
        let url = format!("{}/api/hsm/keys/{}/sign", self.base_url, handle.as_str());

        let request = SignRequest {
            data: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, data),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let resp: SignResponse = self.parse_response(response).await?;

        Ok(Signature::from_qb64(&resp.signature)?)
    }
}

use kels::{KeyProvider, compute_rotation_hash};
use std::sync::Arc;
use tokio::sync::RwLock;

/// HSM-backed key provider with two-phase rotation support.
///
/// Uses vector-based key handle storage where:
/// - key_handles[len-2] = current key
/// - key_handles[len-1] = next key
/// - len > 2 means rotation is staged
///
/// Same pattern for recovery_handles:
/// - recovery_handles[0] = current recovery key
/// - len > 1 means recovery rotation is staged
pub struct HsmKeyProvider {
    hsm: Arc<dyn HsmOperations>,
    label_prefix: String,
    signing_generation: RwLock<u64>,
    recovery_generation: RwLock<u64>,
    key_handles: RwLock<Vec<KeyHandle>>,
    recovery_handles: RwLock<Vec<KeyHandle>>,
}

impl std::fmt::Debug for HsmKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmKeyProvider")
            .field("label_prefix", &self.label_prefix)
            .finish_non_exhaustive()
    }
}

impl HsmKeyProvider {
    pub fn new(
        hsm: Arc<dyn HsmOperations>,
        label_prefix: &str,
        signing_generation: u64,
        recovery_generation: u64,
    ) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            signing_generation: RwLock::new(signing_generation),
            recovery_generation: RwLock::new(recovery_generation),
            key_handles: RwLock::new(Vec::new()),
            recovery_handles: RwLock::new(Vec::new()),
        }
    }

    /// Restore from persisted state.
    pub fn with_handles(
        hsm: Arc<dyn HsmOperations>,
        label_prefix: &str,
        signing_generation: u64,
        recovery_generation: u64,
        current_handle: KeyHandle,
        next_handle: KeyHandle,
        recovery_handle: KeyHandle,
    ) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            signing_generation: RwLock::new(signing_generation),
            recovery_generation: RwLock::new(recovery_generation),
            key_handles: RwLock::new(vec![current_handle, next_handle]),
            recovery_handles: RwLock::new(vec![recovery_handle]),
        }
    }

    async fn generate_signing_key(&self) -> Result<(KeyHandle, PublicKey), KelsError> {
        let mut generation = self.signing_generation.write().await;
        let label = format!("{}-{}", self.label_prefix, *generation);
        *generation += 1;
        self.hsm.generate_keypair(&label).await
    }

    async fn generate_recovery_key(&self) -> Result<(KeyHandle, PublicKey), KelsError> {
        let mut generation = self.recovery_generation.write().await;
        let label = format!("{}-recovery-{}", self.label_prefix, *generation);
        *generation += 1;
        self.hsm.generate_keypair(&label).await
    }
}

#[async_trait]
impl KeyProvider for HsmKeyProvider {
    async fn signing_generation(&self) -> u64 {
        *self.signing_generation.read().await
    }

    async fn recovery_generation(&self) -> u64 {
        *self.recovery_generation.read().await
    }

    async fn current_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        if key_handles.len() >= 2 {
            key_handles
                .get(key_handles.len() - 2)
                .map(|h| h.as_str().to_string())
        } else {
            None
        }
    }

    async fn next_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        key_handles.last().map(|h| h.as_str().to_string())
    }

    async fn recovery_handle(&self) -> Option<String> {
        let recovery_handles = self.recovery_handles.read().await;
        recovery_handles.first().map(|h| h.as_str().to_string())
    }

    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let index = key_handles.len() - 2;
        let handle = key_handles
            .get(index)
            .ok_or(KelsError::KeyNotFound("Current key not found".to_string()))?;
        self.hsm.get_public_key(handle).await
    }

    async fn generate_initial_keys(&mut self) -> Result<(PublicKey, String, String), KelsError> {
        let (current_handle, current_pub) = self.generate_signing_key().await?;
        let (next_handle, next_pub) = self.generate_signing_key().await?;
        let (recovery_handle, recovery_pub) = self.generate_recovery_key().await?;

        let next_hash = compute_rotation_hash(&next_pub.qb64());
        let recovery_hash = compute_rotation_hash(&recovery_pub.qb64());

        let mut key_handles = self.key_handles.write().await;
        *key_handles = vec![current_handle, next_handle];

        let mut recovery_handles = self.recovery_handles.write().await;
        *recovery_handles = vec![recovery_handle];

        Ok((current_pub, next_hash, recovery_hash))
    }

    async fn has_current(&self) -> bool {
        !self.key_handles.read().await.is_empty()
    }

    async fn has_next(&self) -> bool {
        self.key_handles.read().await.len() > 1
    }

    async fn has_staged(&self) -> bool {
        self.key_handles.read().await.len() > 2
    }

    async fn has_recovery(&self) -> bool {
        !self.recovery_handles.read().await.is_empty()
    }

    async fn has_staged_recovery(&self) -> bool {
        self.recovery_handles.read().await.len() > 1
    }

    async fn commit(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut recovery_handles = self.recovery_handles.write().await;
            let length = recovery_handles.len();
            *recovery_handles = recovery_handles[(length - 1)..].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let length = key_handles.len();
        *key_handles = key_handles[(length - 2)..].to_vec();

        Ok(())
    }

    async fn stage_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        let new_current_pub = {
            let key_handles = self.key_handles.read().await;
            let length = key_handles.len();
            let handle = &key_handles[length - 1];
            self.hsm.get_public_key(handle).await?
        };

        let (new_next_handle, new_next_pub) = self.generate_signing_key().await?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(new_next_handle);

        let next_hash = compute_rotation_hash(&new_next_pub.qb64());

        Ok((new_current_pub, next_hash))
    }

    async fn stage_recovery_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        if self.has_staged_recovery().await {
            return Err(KelsError::AlreadyStagedRecovery);
        }

        let current_recovery = {
            let recovery_handles = self.recovery_handles.read().await;
            let handle = &recovery_handles[0];
            self.hsm.get_public_key(handle).await?
        };

        let (new_recovery_handle, new_recovery_pub) = self.generate_recovery_key().await?;
        let mut recovery_handles = self.recovery_handles.write().await;
        recovery_handles.push(new_recovery_handle);

        let recovery_hash = compute_rotation_hash(&new_recovery_pub.qb64());

        Ok((current_recovery, recovery_hash))
    }

    async fn rollback(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut recovery_handles = self.recovery_handles.write().await;
            let mut generation = self.recovery_generation.write().await;

            *generation -= (recovery_handles.len() as u64) - 1;
            *recovery_handles = recovery_handles[..1].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let mut generation = self.signing_generation.write().await;

        *generation -= (key_handles.len() as u64) - 2;
        *key_handles = key_handles[..2].to_vec();

        Ok(())
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let length = key_handles.len();
        let handle = &key_handles[length - 2];

        self.hsm.sign(handle, data).await
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let recovery_handles = self.recovery_handles.read().await;
        let handle = &recovery_handles[0];

        self.hsm.sign(handle, data).await
    }
}
