//! File-based KEL storage

use async_trait::async_trait;

use super::KelStore;
use crate::{error::KelsError, types::SignedKeyEvent};

/// File-based KEL store for CLI and desktop apps
pub struct FileKelStore {
    kel_dir: std::path::PathBuf,
    owner_prefix: std::sync::RwLock<Option<String>>,
}

impl FileKelStore {
    pub fn new(kel_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(None),
        })
    }

    /// Owner prefix protects authoritative KEL from being overwritten by server-fetched data.
    pub fn with_owner(
        kel_dir: impl Into<std::path::PathBuf>,
        owner_prefix: String,
    ) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(Some(owner_prefix)),
        })
    }

    fn kel_path(&self, prefix: &str) -> std::path::PathBuf {
        self.kel_dir.join(format!("{}.kel.json", prefix))
    }
    fn owner_tail_path(&self, prefix: &str) -> std::path::PathBuf {
        self.kel_dir.join(format!("{}.owner_tail", prefix))
    }
}

#[async_trait]
impl KelStore for FileKelStore {
    fn owner_prefix(&self) -> Option<String> {
        self.owner_prefix.read().ok().and_then(|g| g.clone())
    }
    fn set_owner_prefix(&self, prefix: Option<&str>) {
        if let Ok(mut guard) = self.owner_prefix.write() {
            *guard = prefix.map(|s| s.to_string());
        }
    }

    async fn load(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        let path = self.kel_path(prefix);
        if !path.exists() {
            return Ok((vec![], false));
        }
        let contents =
            std::fs::read_to_string(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let events: Vec<SignedKeyEvent> = serde_json::from_str(&contents)?;

        let start = offset as usize;
        if start >= events.len() {
            return Ok((vec![], false));
        }
        let end = (start + limit as usize).min(events.len());
        let page = events[start..end].to_vec();
        let has_more = end < events.len();
        Ok((page, has_more))
    }

    async fn save(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        use std::io::Write;
        let path = self.kel_path(prefix);
        let contents = serde_json::to_string_pretty(events)?;
        let mut file =
            std::fs::File::create(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.sync_all()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
        let path = self.kel_path(prefix);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        }
        let tail_path = self.owner_tail_path(prefix);
        if tail_path.exists() {
            let _ = std::fs::remove_file(&tail_path);
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
        let subdir = temp.path().join("kels");
        assert!(!subdir.exists());

        let _store = FileKelStore::new(&subdir).unwrap();
        assert!(subdir.exists());
    }

    #[test]
    fn test_new_with_existing_directory() {
        let temp = TempDir::new().unwrap();
        let _store = FileKelStore::new(temp.path()).unwrap();
        assert!(temp.path().exists());
    }

    #[test]
    fn test_with_owner_sets_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::with_owner(temp.path(), "my_prefix".to_string()).unwrap();
        assert_eq!(store.owner_prefix(), Some("my_prefix".to_string()));
    }

    #[test]
    fn test_owner_prefix_initially_none() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();
        assert_eq!(store.owner_prefix(), None);
    }

    #[test]
    fn test_set_owner_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        store.set_owner_prefix(Some("new_owner"));
        assert_eq!(store.owner_prefix(), Some("new_owner".to_string()));

        store.set_owner_prefix(None);
        assert_eq!(store.owner_prefix(), None);
    }

    #[tokio::test]
    async fn test_load_nonexistent_returns_empty() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (events, has_more) = store.load("nonexistent", crate::LOAD_ALL, 0).await.unwrap();
        assert!(events.is_empty());
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;
        let event_count = events.len();

        store.save(&prefix, &events).await.unwrap();

        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert_eq!(loaded.len(), event_count);
    }

    #[tokio::test]
    async fn test_save_creates_json_file() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        store.save(&prefix, &events).await.unwrap();

        let expected_path = temp.path().join(format!("{}.kel.json", prefix));
        assert!(expected_path.exists());

        // Verify it's valid JSON
        let contents = std::fs::read_to_string(&expected_path).unwrap();
        let _: Vec<SignedKeyEvent> = serde_json::from_str(&contents).unwrap();
    }

    #[tokio::test]
    async fn test_delete_removes_file() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        store.save(&prefix, &events).await.unwrap();

        let path = temp.path().join(format!("{}.kel.json", prefix));
        assert!(path.exists());

        store.delete(&prefix).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        // Should not error when deleting non-existent
        store.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn test_load_invalid_json_returns_error() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        // Write invalid JSON
        let path = temp.path().join("bad.kel.json");
        std::fs::write(&path, "not valid json").unwrap();

        let result = store.load("bad", crate::LOAD_ALL, 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_isolation_between_prefixes() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix1, events1) = crate::store::create_test_events().await;
        let (prefix2, events2) = crate::store::create_test_events().await;

        store.save(&prefix1, &events1).await.unwrap();
        store.save(&prefix2, &events2).await.unwrap();

        // Both should be loadable independently
        let (loaded1, _) = store.load(&prefix1, crate::LOAD_ALL, 0).await.unwrap();
        let (loaded2, _) = store.load(&prefix2, crate::LOAD_ALL, 0).await.unwrap();

        assert!(!loaded1.is_empty());
        assert!(!loaded2.is_empty());

        // Delete one shouldn't affect the other
        store.delete(&prefix1).await.unwrap();
        let (e1, _) = store.load(&prefix1, crate::LOAD_ALL, 0).await.unwrap();
        let (e2, _) = store.load(&prefix2, crate::LOAD_ALL, 0).await.unwrap();
        assert!(e1.is_empty());
        assert!(!e2.is_empty());
    }

    #[tokio::test]
    async fn test_cache_skips_owner_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        // Set this KEL's prefix as the owner
        store.set_owner_prefix(Some(&prefix));

        // Cache should skip saving because it's the owner's KEL
        store.cache(&prefix, &events).await.unwrap();

        // KEL should NOT be saved
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_cache_saves_non_owner_kel() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        // Set a different owner prefix
        store.set_owner_prefix(Some("different_prefix"));

        // Cache should save because it's not the owner's KEL
        store.cache(&prefix, &events).await.unwrap();

        // KEL should be saved
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(!loaded.is_empty());
    }
}
