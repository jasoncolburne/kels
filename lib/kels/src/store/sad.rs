//! Self-Addressed Data storage trait and file-based implementation

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cesr::Matter;
use tokio::{sync::RwLock, task::spawn_blocking};

use crate::error::KelsError;

/// Trait for persisting self-addressed data objects by SAID.
#[async_trait]
pub trait SadStore: Send + Sync {
    /// Store a self-addressed JSON object by its SAID.
    async fn store(
        &self,
        said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError>;

    /// Load a self-addressed JSON object by SAID. Returns None if not found.
    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError>;

    /// List stored SAIDs (paginated). Returns `(saids, has_more)`.
    /// SAIDs are returned in sorted order after `since` (exclusive).
    async fn list(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError>;

    /// Delete a self-addressed object by SAID. No-op if not found.
    async fn delete(&self, said: &cesr::Digest256) -> Result<(), KelsError>;

    /// Load, returning NotFound error if missing.
    async fn load_or_not_found(
        &self,
        said: &cesr::Digest256,
    ) -> Result<serde_json::Value, KelsError> {
        self.load(said)
            .await?
            .ok_or_else(|| KelsError::NotFound(said.to_string()))
    }

    /// Batch store. Default iterates over entries.
    async fn store_batch(
        &self,
        items: &HashMap<cesr::Digest256, serde_json::Value>,
    ) -> Result<(), KelsError> {
        for (said, value) in items {
            self.store(said, value).await?;
        }
        Ok(())
    }

    /// Batch load. Default iterates; returns only found items.
    async fn load_batch(
        &self,
        saids: &HashSet<cesr::Digest256>,
    ) -> Result<HashMap<cesr::Digest256, serde_json::Value>, KelsError> {
        let mut result = HashMap::new();
        for said in saids {
            if let Some(value) = self.load(said).await? {
                result.insert(*said, value);
            }
        }
        Ok(result)
    }
}

/// File-based SAD store for CLI and desktop apps.
/// Each object is stored as a pretty-printed JSON file named `{said}.json`.
pub struct FileSadStore {
    sad_dir: std::path::PathBuf,
}

impl FileSadStore {
    pub async fn new(sad_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let sad_dir = sad_dir.into();
        let dir = sad_dir.clone();
        spawn_blocking(move || {
            std::fs::create_dir_all(&dir).map_err(|e| KelsError::StorageError(e.to_string()))
        })
        .await
        .map_err(|e| KelsError::StorageError(e.to_string()))??;
        Ok(Self { sad_dir })
    }

    fn sad_path(&self, said: &cesr::Digest256) -> std::path::PathBuf {
        self.sad_dir.join(format!("{}.json", said))
    }
}

#[async_trait]
impl SadStore for FileSadStore {
    async fn store(
        &self,
        said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        let path = self.sad_path(said);
        let json = serde_json::to_string_pretty(value)
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        spawn_blocking(move || {
            std::fs::write(&path, json).map_err(|e| KelsError::StorageError(e.to_string()))
        })
        .await
        .map_err(|e| KelsError::StorageError(e.to_string()))?
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        let path = self.sad_path(said);
        spawn_blocking(move || match std::fs::read_to_string(&path) {
            Ok(data) => {
                let value = serde_json::from_str(&data)
                    .map_err(|e| KelsError::StorageError(e.to_string()))?;
                Ok(Some(value))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KelsError::StorageError(e.to_string())),
        })
        .await
        .map_err(|e| KelsError::StorageError(e.to_string()))?
    }

    async fn list(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        let sad_dir = self.sad_dir.clone();
        let since = since.copied();
        spawn_blocking(move || {
            let mut saids = Vec::new();
            let entries =
                std::fs::read_dir(&sad_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|e| KelsError::StorageError(e.to_string()))?;
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json")
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && let Ok(digest) = cesr::Digest256::from_qb64(stem)
                {
                    saids.push(digest);
                }
            }
            saids.sort();

            if let Some(cursor) = since.as_ref() {
                saids.retain(|s| s > cursor);
            }

            let has_more = saids.len() > limit;
            saids.truncate(limit);
            Ok((saids, has_more))
        })
        .await
        .map_err(|e| KelsError::StorageError(e.to_string()))?
    }

    async fn delete(&self, said: &cesr::Digest256) -> Result<(), KelsError> {
        let path = self.sad_path(said);
        spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KelsError::StorageError(e.to_string())),
        })
        .await
        .map_err(|e| KelsError::StorageError(e.to_string()))?
    }
}

/// In-memory SAD store for tests and lightweight use cases.
pub struct InMemorySadStore {
    chunks: RwLock<HashMap<cesr::Digest256, serde_json::Value>>,
}

impl InMemorySadStore {
    pub fn new() -> Self {
        Self {
            chunks: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySadStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SadStore for InMemorySadStore {
    async fn store(
        &self,
        said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        self.chunks.write().await.insert(*said, value.clone());
        Ok(())
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        Ok(self.chunks.read().await.get(said).cloned())
    }

    async fn list(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        let store = self.chunks.read().await;
        let mut saids: Vec<cesr::Digest256> = store.keys().copied().collect();
        saids.sort();

        if let Some(cursor) = since {
            saids.retain(|s| s > cursor);
        }

        let has_more = saids.len() > limit;
        saids.truncate(limit);
        Ok((saids, has_more))
    }

    async fn delete(&self, said: &cesr::Digest256) -> Result<(), KelsError> {
        self.chunks.write().await.remove(said);
        Ok(())
    }

    async fn store_batch(
        &self,
        items: &HashMap<cesr::Digest256, serde_json::Value>,
    ) -> Result<(), KelsError> {
        let mut store = self.chunks.write().await;
        store.extend(items.iter().map(|(k, v)| (*k, v.clone())));
        Ok(())
    }

    async fn load_batch(
        &self,
        saids: &HashSet<cesr::Digest256>,
    ) -> Result<HashMap<cesr::Digest256, serde_json::Value>, KelsError> {
        let store = self.chunks.read().await;
        Ok(saids
            .iter()
            .filter_map(|said| store.get(said).map(|v| (*said, v.clone())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_new_creates_directory() {
        let temp = TempDir::new().unwrap();
        let subdir = temp.path().join("sad");
        assert!(!subdir.exists());

        let _store = FileSadStore::new(&subdir).await.unwrap();
        assert!(subdir.exists());
    }

    #[tokio::test]
    async fn test_store_and_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let said = test_digest("abc123");
        let value = serde_json::json!({"said": said.as_ref(), "data": "hello"});
        store.store(&said, &value).await.unwrap();

        let loaded = store.load(&said).await.unwrap();
        assert_eq!(loaded, Some(value));
    }

    #[tokio::test]
    async fn test_load_not_found() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let result = store.load(&test_digest("nonexistent")).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_load_or_not_found() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let result = store.load_or_not_found(&test_digest("nonexistent")).await;
        assert!(matches!(result, Err(KelsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_returns_saids() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let said_a = test_digest("aaa");
        let said_b = test_digest("bbb");
        store
            .store(&said_a, &serde_json::json!({"said": said_a.as_ref()}))
            .await
            .unwrap();
        store
            .store(&said_b, &serde_json::json!({"said": said_b.as_ref()}))
            .await
            .unwrap();

        let (saids, has_more) = store.list(None, 100).await.unwrap();
        assert!(saids.contains(&said_a));
        assert!(saids.contains(&said_b));
        assert_eq!(saids.len(), 2);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let (saids, has_more) = store.list(None, 100).await.unwrap();
        assert!(saids.is_empty());
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_list_pagination() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        // Use SAIDs that sort deterministically
        let said_a = test_digest("aaa");
        let said_b = test_digest("bbb");
        let said_c = test_digest("ccc");
        store
            .store(&said_a, &serde_json::json!({"said": said_a.as_ref()}))
            .await
            .unwrap();
        store
            .store(&said_b, &serde_json::json!({"said": said_b.as_ref()}))
            .await
            .unwrap();
        store
            .store(&said_c, &serde_json::json!({"said": said_c.as_ref()}))
            .await
            .unwrap();

        let (page1, has_more) = store.list(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(has_more);

        // Use last element of first page as cursor
        let cursor = page1.last().unwrap();
        let (page2, has_more) = store.list(Some(cursor), 2).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_delete_removes_file() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        let said = test_digest("abc");
        store
            .store(&said, &serde_json::json!({"said": said.as_ref()}))
            .await
            .unwrap();
        assert!(temp.path().join(format!("{}.json", said)).exists());

        store.delete(&said).await.unwrap();
        assert!(!temp.path().join(format!("{}.json", said)).exists());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).await.unwrap();

        store.delete(&test_digest("nonexistent")).await.unwrap();
    }

    // InMemorySadStore tests

    #[tokio::test]
    async fn test_in_memory_roundtrip() {
        let store = InMemorySadStore::new();
        let said = test_digest("abc");
        let value = serde_json::json!({"said": said.as_ref(), "data": "test"});

        store.store(&said, &value).await.unwrap();
        let loaded = store.load(&said).await.unwrap();
        assert_eq!(loaded, Some(value));
    }

    #[tokio::test]
    async fn test_in_memory_missing() {
        let store = InMemorySadStore::new();
        let result = store.load(&test_digest("nonexistent")).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_in_memory_overwrite() {
        let store = InMemorySadStore::new();
        let said = test_digest("abc");
        let v1 = serde_json::json!({"said": said.as_ref(), "data": "first"});
        let v2 = serde_json::json!({"said": said.as_ref(), "data": "second"});

        store.store(&said, &v1).await.unwrap();
        store.store(&said, &v2).await.unwrap();

        let loaded = store.load(&said).await.unwrap();
        assert_eq!(loaded, Some(v2));
    }

    #[tokio::test]
    async fn test_in_memory_batch() {
        let store = InMemorySadStore::new();
        let said_a = test_digest("aaa");
        let said_b = test_digest("bbb");
        let mut items = HashMap::new();
        items.insert(
            said_a,
            serde_json::json!({"said": said_a.as_ref(), "data": "a"}),
        );
        items.insert(
            said_b,
            serde_json::json!({"said": said_b.as_ref(), "data": "b"}),
        );

        store.store_batch(&items).await.unwrap();

        let saids = HashSet::from([said_a, said_b]);
        let loaded = store.load_batch(&saids).await.unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_list() {
        let store = InMemorySadStore::new();
        let said_a = test_digest("aaa");
        let said_b = test_digest("bbb");
        store.store(&said_a, &serde_json::json!({})).await.unwrap();
        store.store(&said_b, &serde_json::json!({})).await.unwrap();

        let (saids, has_more) = store.list(None, 100).await.unwrap();
        assert_eq!(saids.len(), 2);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_in_memory_delete() {
        let store = InMemorySadStore::new();
        let said = test_digest("abc");
        store.store(&said, &serde_json::json!({})).await.unwrap();

        store.delete(&said).await.unwrap();
        assert_eq!(store.load(&said).await.unwrap(), None);
    }
}
