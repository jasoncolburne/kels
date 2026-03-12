use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::CredentialError;

/// Content-addressable store for any SelfAddressed JSON chunk, keyed by SAID.
/// Used by `expand_all` and the disclosure DSL to look up compacted fields.
#[async_trait]
pub trait ChunkStore: Send + Sync {
    async fn store_chunk(
        &self,
        said: &str,
        value: &serde_json::Value,
    ) -> Result<(), CredentialError>;
    async fn get_chunk(&self, said: &str) -> Result<Option<serde_json::Value>, CredentialError>;
}

/// In-memory HashMap-based implementation of `ChunkStore`.
/// Useful for tests, CLI tools, and lightweight use cases.
pub struct InMemoryChunkStore {
    chunks: Mutex<HashMap<String, serde_json::Value>>,
}

impl InMemoryChunkStore {
    pub fn new() -> Self {
        Self {
            chunks: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryChunkStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChunkStore for InMemoryChunkStore {
    async fn store_chunk(
        &self,
        said: &str,
        value: &serde_json::Value,
    ) -> Result<(), CredentialError> {
        let mut chunks = self
            .chunks
            .lock()
            .map_err(|e| CredentialError::StorageError(format!("lock poisoned: {}", e)))?;
        chunks.insert(said.to_string(), value.clone());
        Ok(())
    }

    async fn get_chunk(&self, said: &str) -> Result<Option<serde_json::Value>, CredentialError> {
        let chunks = self
            .chunks
            .lock()
            .map_err(|e| CredentialError::StorageError(format!("lock poisoned: {}", e)))?;
        Ok(chunks.get(said).cloned())
    }
}

use crate::credential::CredentialValue;
use crate::verification::CredentialVerification;

/// Verified credential storage. Only stores credentials that have been
/// through `verify_credential`. A revoked credential is still a valid
/// verification result — revocation status is recorded, not rejected.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn store_credential(
        &self,
        credential: &CredentialValue,
        verification: &CredentialVerification,
    ) -> Result<(), CredentialError>;
    async fn get_credential(
        &self,
        said: &str,
    ) -> Result<Option<(CredentialValue, CredentialVerification)>, CredentialError>;
}

/// In-memory HashMap-based implementation of `CredentialStore`.
/// Useful for tests, CLI tools, and lightweight use cases.
pub struct InMemoryCredentialStore {
    credentials: Mutex<HashMap<String, (CredentialValue, CredentialVerification)>>,
}

impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn store_credential(
        &self,
        credential: &CredentialValue,
        verification: &CredentialVerification,
    ) -> Result<(), CredentialError> {
        let said = credential.said().ok_or_else(|| {
            CredentialError::InvalidCredential("credential missing SAID".to_string())
        })?;
        let mut creds = self
            .credentials
            .lock()
            .map_err(|e| CredentialError::StorageError(format!("lock poisoned: {}", e)))?;
        creds.insert(said.to_string(), (credential.clone(), verification.clone()));
        Ok(())
    }

    async fn get_credential(
        &self,
        said: &str,
    ) -> Result<Option<(CredentialValue, CredentialVerification)>, CredentialError> {
        let creds = self
            .credentials
            .lock()
            .map_err(|e| CredentialError::StorageError(format!("lock poisoned: {}", e)))?;
        Ok(creds.get(said).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_chunk_store_roundtrip() {
        let store = InMemoryChunkStore::new();
        let value = serde_json::json!({"said": "EAbc", "data": "test"});

        store.store_chunk("EAbc", &value).await.unwrap();
        let retrieved = store.get_chunk("EAbc").await.unwrap();
        assert_eq!(retrieved, Some(value));
    }

    #[tokio::test]
    async fn test_in_memory_chunk_store_missing() {
        let store = InMemoryChunkStore::new();
        let result = store.get_chunk("nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_in_memory_chunk_store_overwrite() {
        let store = InMemoryChunkStore::new();
        let v1 = serde_json::json!({"said": "EAbc", "data": "first"});
        let v2 = serde_json::json!({"said": "EAbc", "data": "second"});

        store.store_chunk("EAbc", &v1).await.unwrap();
        store.store_chunk("EAbc", &v2).await.unwrap();

        let retrieved = store.get_chunk("EAbc").await.unwrap();
        assert_eq!(retrieved, Some(v2));
    }

    #[tokio::test]
    async fn test_in_memory_credential_store_roundtrip() {
        use std::collections::BTreeMap;

        let store = InMemoryCredentialStore::new();
        let cv = CredentialValue::from_value(serde_json::json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "issuer": "EIssuer123456789012345678901234567890abcde",
            "schema": "ESchema23456789012345678901234567890abcdef",
        }))
        .unwrap();

        let verification = CredentialVerification {
            credential_said: "EAbc1234567890123456789012345678901234567890".to_string(),
            issuer: "EIssuer123456789012345678901234567890abcde".to_string(),
            subject: None,
            is_issued: true,
            is_revoked: false,
            schema_valid: None,
            edge_verifications: BTreeMap::new(),
        };

        store.store_credential(&cv, &verification).await.unwrap();
        let retrieved = store
            .get_credential("EAbc1234567890123456789012345678901234567890")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let (ret_cv, ret_v) = retrieved.unwrap();
        assert_eq!(ret_cv.said(), cv.said());
        assert_eq!(ret_v.credential_said, verification.credential_said);
        assert!(ret_v.is_issued);
        assert!(!ret_v.is_revoked);
    }

    #[tokio::test]
    async fn test_in_memory_credential_store_missing() {
        let store = InMemoryCredentialStore::new();
        let result = store.get_credential("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
