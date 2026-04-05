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

    /// List all stored SAIDs.
    async fn list(&self) -> Result<Vec<String>, KelsError>;

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

    async fn list(&self) -> Result<Vec<String>, KelsError> {
        let mut saids = Vec::new();
        let entries =
            std::fs::read_dir(&self.sad_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| KelsError::StorageError(e.to_string()))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                saids.push(stem.to_string());
            }
        }
        Ok(saids)
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

        let value = serde_json::json!({"said": "abc123", "data": "hello"});
        store.store("abc123", &value).await.unwrap();

        let loaded = store.load("abc123").await.unwrap();
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

        store
            .store("aaa", &serde_json::json!({"said": "aaa"}))
            .await
            .unwrap();
        store
            .store("bbb", &serde_json::json!({"said": "bbb"}))
            .await
            .unwrap();

        let mut saids = store.list().await.unwrap();
        saids.sort();
        assert_eq!(saids, vec!["aaa", "bbb"]);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        let saids = store.list().await.unwrap();
        assert!(saids.is_empty());
    }

    #[tokio::test]
    async fn test_delete_removes_file() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        store
            .store("abc", &serde_json::json!({"said": "abc"}))
            .await
            .unwrap();
        assert!(temp.path().join("abc.json").exists());

        store.delete("abc").await.unwrap();
        assert!(!temp.path().join("abc.json").exists());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let temp = TempDir::new().unwrap();
        let store = FileSadStore::new(temp.path()).unwrap();

        store.delete("nonexistent").await.unwrap();
    }
}
