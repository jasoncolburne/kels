//! File-based KEL storage

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;
use crate::store::KelStore;
use crate::types::SignedKeyEvent;

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

    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        let path = self.kel_path(prefix);
        if !path.exists() {
            return Ok(None);
        }
        let contents =
            std::fs::read_to_string(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let events: Vec<SignedKeyEvent> = serde_json::from_str(&contents)?;
        Ok(Some(Kel::from_events(events, true)?))
    }

    async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
        use std::io::Write;
        let prefix = kel
            .prefix()
            .ok_or_else(|| KelsError::InvalidKel("KEL has no prefix".to_string()))?;
        let path = self.kel_path(prefix);
        let contents = serde_json::to_string_pretty(kel.events())?;
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
    use super::*;
    use crate::SoftwareKeyProvider;
    use crate::builder::KeyEventBuilder;
    use tempfile::TempDir;

    async fn create_test_kel() -> Kel {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        Kel::from_events(vec![icp], true).unwrap()
    }

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
    async fn test_load_nonexistent_returns_none() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let result = store.load("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        store.save(&kel).await.unwrap();

        let loaded = store.load(&prefix).await.unwrap().unwrap();
        assert_eq!(loaded.len(), kel.len());
        assert_eq!(loaded.prefix(), kel.prefix());
    }

    #[tokio::test]
    async fn test_save_creates_json_file() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        store.save(&kel).await.unwrap();

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

        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        store.save(&kel).await.unwrap();

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

        let result = store.load("bad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_isolation_between_prefixes() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let kel1 = create_test_kel().await;
        let kel2 = create_test_kel().await;
        let prefix1 = kel1.prefix().unwrap().to_string();
        let prefix2 = kel2.prefix().unwrap().to_string();

        store.save(&kel1).await.unwrap();
        store.save(&kel2).await.unwrap();

        // Both should be loadable independently
        let loaded1 = store.load(&prefix1).await.unwrap().unwrap();
        let loaded2 = store.load(&prefix2).await.unwrap().unwrap();

        assert_eq!(loaded1.prefix(), kel1.prefix());
        assert_eq!(loaded2.prefix(), kel2.prefix());

        // Delete one shouldn't affect the other
        store.delete(&prefix1).await.unwrap();
        assert!(store.load(&prefix1).await.unwrap().is_none());
        assert!(store.load(&prefix2).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_cache_skips_owner_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        // Set this KEL's prefix as the owner
        store.set_owner_prefix(Some(&prefix));

        // Cache should skip saving because it's the owner's KEL
        store.cache(&kel).await.unwrap();

        // KEL should NOT be saved
        let loaded = store.load(&prefix).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_cache_saves_non_owner_kel() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        // Set a different owner prefix
        store.set_owner_prefix(Some("different_prefix"));

        // Cache should save because it's not the owner's KEL
        store.cache(&kel).await.unwrap();

        // KEL should be saved
        let loaded = store.load(&prefix).await.unwrap();
        assert!(loaded.is_some());
    }
}
