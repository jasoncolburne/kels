use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::{compaction::compact, error::CredentialError};

/// Content-addressable store for any SelfAddressed JSON chunk, keyed by SAID.
/// Used by compaction, expansion, and the disclosure DSL.
#[async_trait]
pub trait SADStore: Send + Sync {
    async fn store_chunks(&self, chunks: &HashMap<String, Value>) -> Result<(), CredentialError>;

    async fn get_chunks(
        &self,
        saids: &HashSet<String>,
    ) -> Result<HashMap<String, Value>, CredentialError>;

    async fn get_chunk(&self, said: &str) -> Result<Option<Value>, CredentialError> {
        let set = HashSet::from([said.to_string()]);
        let mut chunks = self.get_chunks(&set).await?;
        Ok(chunks.remove(said))
    }

    async fn store_chunk(&self, said: &str, value: &Value) -> Result<(), CredentialError> {
        let map = HashMap::from([(said.to_string(), value.clone())]);
        self.store_chunks(&map).await
    }
}

/// Compact credential values and store all resulting chunks in a single batch.
pub async fn store_credentials(
    mut values: Vec<serde_json::Value>,
    sad_store: &dyn SADStore,
) -> Result<(), CredentialError> {
    let mut all_chunks = HashMap::new();
    for value in &mut values {
        let chunks = compact(value)?;
        all_chunks.extend(chunks);
    }
    sad_store.store_chunks(&all_chunks).await
}

/// In-memory HashMap-based implementation of `SADStore`.
/// Useful for tests, CLI tools, and lightweight use cases.
pub struct InMemorySADStore {
    chunks: RwLock<HashMap<String, Value>>,
}

impl InMemorySADStore {
    pub fn new() -> Self {
        Self {
            chunks: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySADStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SADStore for InMemorySADStore {
    async fn store_chunks(&self, chunks: &HashMap<String, Value>) -> Result<(), CredentialError> {
        let mut store = self.chunks.write().await;
        store.extend(chunks.iter().map(|(k, v)| (k.to_owned(), v.to_owned())));
        Ok(())
    }

    async fn get_chunks(
        &self,
        saids: &HashSet<String>,
    ) -> Result<HashMap<String, Value>, CredentialError> {
        let store = self.chunks.read().await;
        Ok(saids
            .iter()
            .filter_map(|said| store.get(said).map(|v| (said.to_owned(), v.to_owned())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_sad_store_roundtrip() {
        let store = InMemorySADStore::new();
        let value = serde_json::json!({"said": "EAbc", "data": "test"});

        store.store_chunk("EAbc", &value).await.unwrap();
        let retrieved = store.get_chunk("EAbc").await.unwrap();
        assert_eq!(retrieved, Some(value));
    }

    #[tokio::test]
    async fn test_in_memory_sad_store_missing() {
        let store = InMemorySADStore::new();
        let result = store.get_chunk("nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_in_memory_sad_store_overwrite() {
        let store = InMemorySADStore::new();
        let v1 = serde_json::json!({"said": "EAbc", "data": "first"});
        let v2 = serde_json::json!({"said": "EAbc", "data": "second"});

        store.store_chunk("EAbc", &v1).await.unwrap();
        store.store_chunk("EAbc", &v2).await.unwrap();

        let retrieved = store.get_chunk("EAbc").await.unwrap();
        assert_eq!(retrieved, Some(v2));
    }

    #[tokio::test]
    async fn test_in_memory_sad_store_batch() {
        let store = InMemorySADStore::new();
        let mut map = HashMap::new();
        map.insert(
            "EA".to_string(),
            serde_json::json!({"said": "EA", "data": "a"}),
        );
        map.insert(
            "EB".to_string(),
            serde_json::json!({"said": "EB", "data": "b"}),
        );

        store.store_chunks(&map).await.unwrap();

        let set = HashSet::from(["EA".to_string(), "EB".to_string()]);
        let retrieved = store.get_chunks(&set).await.unwrap();
        assert_eq!(retrieved.len(), 2);
    }
}
