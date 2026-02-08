//! KEL Storage trait - persisting Key Event Logs locally

pub mod file;
pub mod repository;

pub use file::FileKelStore;
pub use repository::RepositoryKelStore;

use async_trait::async_trait;

use crate::{error::KelsError, types::Kel};

/// Trait for persisting KELs. When `owner_prefix` is set, `cache()` protects the owner's
/// authoritative state from being overwritten by server-fetched data.
#[async_trait]
pub trait KelStore: Send + Sync {
    /// Owner's prefix. When set, `cache()` skips saving KELs with this prefix.
    fn owner_prefix(&self) -> Option<String> {
        None
    }

    /// Set/clear owner prefix after enrollment.
    fn set_owner_prefix(&self, _prefix: Option<&str>) {}

    /// Load a KEL by prefix. Returns None if not found. Skip verification on load (verified on save).
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError>;

    /// Save a KEL, overwriting any existing one with the same prefix.
    async fn save(&self, kel: &Kel) -> Result<(), KelsError>;

    /// Delete a KEL by prefix. No-op if not found.
    async fn delete(&self, prefix: &str) -> Result<(), KelsError>;

    /// Cache server-fetched KEL. Skips owner prefix to protect authoritative local state.
    async fn cache(&self, kel: &Kel) -> Result<(), KelsError> {
        if let Some(owner) = self.owner_prefix()
            && kel.prefix() == Some(owner.as_str())
        {
            return Ok(());
        }
        self.save(kel).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use super::*;
    use crate::{builder::KeyEventBuilder, crypto::SoftwareKeyProvider};

    /// In-memory store for testing
    struct MemoryStore {
        kels: RwLock<HashMap<String, Kel>>,
        owner: RwLock<Option<String>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                kels: RwLock::new(HashMap::new()),
                owner: RwLock::new(None),
            }
        }
    }

    #[async_trait]
    impl KelStore for MemoryStore {
        fn owner_prefix(&self) -> Option<String> {
            self.owner.read().ok().and_then(|g| g.clone())
        }

        fn set_owner_prefix(&self, prefix: Option<&str>) {
            if let Ok(mut guard) = self.owner.write() {
                *guard = prefix.map(|s| s.to_string());
            }
        }

        async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
            Ok(self.kels.read().ok().and_then(|g| g.get(prefix).cloned()))
        }

        async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
            if let (Ok(mut guard), Some(prefix)) = (self.kels.write(), kel.prefix()) {
                guard.insert(prefix.to_string(), kel.clone());
            }
            Ok(())
        }

        async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
            if let Ok(mut guard) = self.kels.write() {
                guard.remove(prefix);
            }
            Ok(())
        }
    }

    async fn create_test_kel() -> Kel {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        Kel::from_events(vec![icp], true).unwrap()
    }

    #[tokio::test]
    async fn test_cache_saves_non_owner_kel() {
        let store = MemoryStore::new();
        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        store.cache(&kel).await.unwrap();

        let loaded = store.load(&prefix).await.unwrap();
        assert!(loaded.is_some());
    }

    #[tokio::test]
    async fn test_cache_skips_owner_kel() {
        let store = MemoryStore::new();
        let kel = create_test_kel().await;
        let prefix = kel.prefix().unwrap().to_string();

        // Set owner prefix to match KEL
        store.set_owner_prefix(Some(&prefix));

        // Cache should skip owner's KEL
        store.cache(&kel).await.unwrap();

        // KEL should NOT be saved
        let loaded = store.load(&prefix).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_default_owner_prefix_is_none() {
        let store = MemoryStore::new();
        assert!(store.owner_prefix().is_none());
    }
}
