//! Self-Addressed Data storage trait and file-based implementation

use async_trait::async_trait;

use crate::error::KelsError;

/// Trait for persisting self-addressed data objects by SAID.
#[async_trait]
pub trait SadStore: Send + Sync {
    /// Store a self-addressed JSON object by its SAID.
    async fn store(&self, said: &str, value: &serde_json::Value) -> Result<(), KelsError>;

    /// Load a self-addressed JSON object by SAID.
    async fn load(&self, said: &str) -> Result<serde_json::Value, KelsError>;

    /// List stored SAIDs (paginated). Returns `(saids, has_more)`.
    /// SAIDs are returned in sorted order after `since` (exclusive).
    async fn list(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest>, bool), KelsError>;

    /// Delete a self-addressed object by SAID. No-op if not found.
    async fn delete(&self, said: &str) -> Result<(), KelsError>;
}

/// File-based SAD store for CLI and desktop apps.
/// Each object is stored as a pretty-printed JSON file named `{said}.json`.
pub struct FileSadStore {
    sad_dir: std::path::PathBuf,
}

impl FileSadStore {
    pub fn new(sad_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let sad_dir = sad_dir.into();
        std::fs::create_dir_all(&sad_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self { sad_dir })
    }

    fn sad_path(&self, said: &str) -> std::path::PathBuf {
        self.sad_dir.join(format!("{}.json", said))
    }
}

#[async_trait]
impl SadStore for FileSadStore {
    async fn store(&self, said: &str, value: &serde_json::Value) -> Result<(), KelsError> {
        let path = self.sad_path(said);
        let json = serde_json::to_string_pretty(value)
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn load(&self, said: &str) -> Result<serde_json::Value, KelsError> {
        let path = self.sad_path(said);
        let data = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KelsError::NotFound(said.to_string())
            } else {
                KelsError::StorageError(e.to_string())
            }
        })?;
        serde_json::from_str(&data).map_err(|e| KelsError::StorageError(e.to_string()))
    }

    async fn list(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest>, bool), KelsError> {
        use cesr::Matter;

        let mut said_strings = Vec::new();
        let entries =
            std::fs::read_dir(&self.sad_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| KelsError::StorageError(e.to_string()))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                said_strings.push(stem.to_string());
            }
        }
        said_strings.sort();

        if let Some(cursor) = since {
            said_strings.retain(|s| s.as_str() > cursor);
        }

        let has_more = said_strings.len() > limit;
        said_strings.truncate(limit);
        let saids = said_strings
            .into_iter()
            .map(|s| cesr::Digest::from_qb64(&s).map_err(|e| KelsError::CryptoError(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((saids, has_more))
    }

    async fn delete(&self, said: &str) -> Result<(), KelsError> {
        let path = self.sad_path(said);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_said(label: &str) -> String {
        cesr::Digest::blake3_256(label.as_bytes()).to_string()
    }

    #[test]
    fn test_new_creates_directory() {
        let temp = TempDir::new().unwrap();
        let subdir = temp.path().join("sad");
        assert!(!subdir.exists());

        let _store = FileSadStore::new(&subdir).unwrap();
        assert!(subdir.exists());
    }

    #[tokio::test]
    async fn test_store_and_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let said = test_said("abc123");
        let value = serde_json::json!({"said": said, "data": "hello"});
        store.store(&said, &value).await.unwrap();

        let loaded = store.load(&said).await.unwrap();
        assert_eq!(loaded, value);
    }

    #[tokio::test]
    async fn test_load_not_found() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let result = store.load("nonexistent").await;
        assert!(matches!(result, Err(KelsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_returns_saids() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let said_a = test_said("aaa");
        let said_b = test_said("bbb");
        store
            .store(&said_a, &serde_json::json!({"said": said_a}))
            .await
            .unwrap();
        store
            .store(&said_b, &serde_json::json!({"said": said_b}))
            .await
            .unwrap();

        let (saids, has_more) = store.list(None, 100).await.unwrap();
        let said_strings: Vec<String> = saids.iter().map(|s| s.to_string()).collect();
        assert!(said_strings.contains(&said_a));
        assert!(said_strings.contains(&said_b));
        assert_eq!(saids.len(), 2);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let (saids, has_more) = store.list(None, 100).await.unwrap();
        assert!(saids.is_empty());
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_list_pagination() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        // Use SAIDs that sort deterministically
        let said_a = test_said("aaa");
        let said_b = test_said("bbb");
        let said_c = test_said("ccc");
        store
            .store(&said_a, &serde_json::json!({"said": said_a}))
            .await
            .unwrap();
        store
            .store(&said_b, &serde_json::json!({"said": said_b}))
            .await
            .unwrap();
        store
            .store(&said_c, &serde_json::json!({"said": said_c}))
            .await
            .unwrap();

        let (page1, has_more) = store.list(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(has_more);

        // Use last element of first page as cursor
        let cursor = page1.last().unwrap().to_string();
        let (page2, has_more) = store.list(Some(&cursor), 2).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_delete_removes_file() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let said = test_said("abc");
        store
            .store(&said, &serde_json::json!({"said": said}))
            .await
            .unwrap();
        assert!(temp.path().join(format!("{}.json", said)).exists());

        store.delete(&said).await.unwrap();
        assert!(!temp.path().join(format!("{}.json", said)).exists());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        store.delete("nonexistent").await.unwrap();
    }
}
