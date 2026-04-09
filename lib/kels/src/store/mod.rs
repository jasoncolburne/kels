//! Storage traits - persisting Key Event Logs and Self-Addressed Data locally

pub mod file;
pub mod repository;
pub mod sad;

pub use file::FileKelStore;
pub use repository::RepositoryKelStore;
pub use sad::{FileSadStore, InMemorySadStore, SadStore};

use async_trait::async_trait;

use crate::{error::KelsError, types::SignedKeyEvent};

#[cfg(test)]
pub(crate) async fn create_test_events() -> (cesr::Digest256, Vec<SignedKeyEvent>) {
    use cesr::VerificationKeyCode;

    use crate::{builder::KeyEventBuilder, crypto::SoftwareKeyProvider};
    let mut builder = KeyEventBuilder::new(
        SoftwareKeyProvider::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa87),
        None,
    );
    let icp = builder.incept().await.unwrap();
    let prefix = icp.event.prefix;
    (prefix, vec![icp])
}

/// Trait for persisting KELs. When `owner_prefix` is set, `cache()` protects the owner's
/// authoritative state from being overwritten by server-fetched data.
#[async_trait]
pub trait KelStore: Send + Sync {
    /// Owner's prefix. When set, `cache()` skips saving KELs with this prefix.
    fn owner_prefix(&self) -> Option<cesr::Digest256> {
        None
    }

    /// Set/clear owner prefix after enrollment.
    fn set_owner_prefix(&self, _prefix: Option<&cesr::Digest256>) {}

    /// Load a page of events by prefix. Returns `(events, has_more)`.
    /// Callers iterate explicitly via paginated reads.
    async fn load(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;

    /// Load the last `limit` events for a prefix, returned in serial-ascending order.
    /// Used for bounded tail access without loading the entire KEL.
    async fn load_tail(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
    ) -> Result<Vec<SignedKeyEvent>, KelsError>;

    /// Append events for a prefix (merges with any existing events).
    async fn append(
        &self,
        prefix: &cesr::Digest256,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError>;

    /// Overwrite all events for a prefix (truncate + write).
    /// Only intended for dev-tools use cases (e.g., truncation).
    async fn overwrite(
        &self,
        prefix: &cesr::Digest256,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError>;

    /// Cache server-fetched events. Skips owner prefix to protect authoritative local state.
    async fn cache(
        &self,
        prefix: &cesr::Digest256,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError> {
        if let Some(owner) = self.owner_prefix()
            && *prefix == owner
        {
            return Ok(());
        }
        self.append(prefix, events).await
    }
}

/// Adapter that wraps any `&dyn KelStore` as a `PagedKelSink`.
///
/// Delegates `store_page()` to `KelStore::append()`.
pub struct KelStoreSink<'a>(pub &'a (dyn KelStore + Sync));

#[async_trait]
impl crate::types::PagedKelSink for KelStoreSink<'_> {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }
        self.0.append(&events[0].event.prefix, events).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use super::*;

    /// In-memory store for testing
    struct MemoryStore {
        kels: RwLock<HashMap<String, Vec<SignedKeyEvent>>>,
        owner: RwLock<Option<cesr::Digest256>>,
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
        fn owner_prefix(&self) -> Option<cesr::Digest256> {
            self.owner.read().ok().and_then(|g| *g)
        }

        fn set_owner_prefix(&self, prefix: Option<&cesr::Digest256>) {
            if let Ok(mut guard) = self.owner.write() {
                *guard = prefix.cloned();
            }
        }

        async fn load(
            &self,
            prefix: &cesr::Digest256,
            limit: u64,
            offset: u64,
        ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
            let guard = match self.kels.read() {
                Ok(g) => g,
                Err(_) => return Ok((vec![], false)),
            };
            match guard.get(prefix.as_ref()) {
                Some(events) => {
                    let start = offset as usize;
                    if start >= events.len() {
                        return Ok((vec![], false));
                    }
                    let end = (start + limit as usize).min(events.len());
                    let page = events[start..end].to_vec();
                    let has_more = end < events.len();
                    Ok((page, has_more))
                }
                None => Ok((vec![], false)),
            }
        }

        async fn load_tail(
            &self,
            prefix: &cesr::Digest256,
            limit: u64,
        ) -> Result<Vec<SignedKeyEvent>, KelsError> {
            let guard = match self.kels.read() {
                Ok(g) => g,
                Err(_) => return Ok(vec![]),
            };
            match guard.get(prefix.as_ref()) {
                Some(events) => {
                    let start = events.len().saturating_sub(limit as usize);
                    Ok(events[start..].to_vec())
                }
                None => Ok(vec![]),
            }
        }

        async fn append(
            &self,
            prefix: &cesr::Digest256,
            events: &[SignedKeyEvent],
        ) -> Result<(), KelsError> {
            if let Ok(mut guard) = self.kels.write() {
                guard
                    .entry(prefix.to_string())
                    .or_default()
                    .extend(events.iter().cloned());
            }
            Ok(())
        }

        async fn overwrite(
            &self,
            prefix: &cesr::Digest256,
            events: &[SignedKeyEvent],
        ) -> Result<(), KelsError> {
            if let Ok(mut guard) = self.kels.write() {
                guard.insert(prefix.to_string(), events.to_vec());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_cache_saves_non_owner_kel() {
        let store = MemoryStore::new();
        let (prefix, events) = super::create_test_events().await;

        store.cache(&prefix, &events).await.unwrap();

        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(!loaded.is_empty());
    }

    #[tokio::test]
    async fn test_cache_skips_owner_kel() {
        let store = MemoryStore::new();
        let (prefix, events) = super::create_test_events().await;

        // Set owner prefix to match KEL
        store.set_owner_prefix(Some(&prefix));

        // Cache should skip owner's KEL
        store.cache(&prefix, &events).await.unwrap();

        // KEL should NOT be saved
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_default_owner_prefix_is_none() {
        let store = MemoryStore::new();
        assert!(store.owner_prefix().is_none());
    }
}
