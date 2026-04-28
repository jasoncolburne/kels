//! Identity Event Log (IEL) storage.
//!
//! Mirrors `lib/kels/src/store/sad.rs` for the IEL primitive. The trait
//! exposes the operations a builder or page-loader needs:
//! - `store_iel_event` — append an owner-authored IEL event, indexed by
//!   prefix and by SAID.
//! - `load_iel_events` — paginated reads ordered
//!   `(version ASC, kind sort_priority ASC, said ASC)`.
//! - `load_iel_event` — by-SAID lookup (round-12 SE binding resolution will
//!   consume this; convenient for tests now).
//!
//! `InMemoryIdentityStore` is the test-tier in-process implementation.
//! Production storage is the server-side `iel_events` table (Gap 4) — the
//! `IdentityStore` trait is intentionally minimal so a trait object can wrap
//! either.

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{error::KelsError, types::IdentityEvent};

/// Trait for persisting Identity Event Log events.
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Store an owner-authored IEL event. Idempotent: storing the same SAID
    /// twice is a no-op (the index entry is replaced in place).
    async fn store_iel_event(&self, event: &IdentityEvent) -> Result<(), KelsError>;

    /// Load owner-authored IEL events for `prefix`, ordered
    /// `(version ASC, kind sort_priority ASC, said ASC)`. Returns
    /// `(events, has_more)`. Missing prefix returns `(empty, false)` —
    /// callers can use this to detect "chain not yet locally inducted."
    async fn load_iel_events(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError>;

    /// Load a single IEL event by SAID. Returns `None` if not in the store.
    async fn load_iel_event(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<IdentityEvent>, KelsError>;
}

/// In-process IEL store for tests / dev tooling. Holds events in memory by
/// SAID and by prefix; no persistence.
pub struct InMemoryIdentityStore {
    by_said: RwLock<HashMap<cesr::Digest256, IdentityEvent>>,
    by_prefix: RwLock<HashMap<cesr::Digest256, Vec<IdentityEvent>>>,
}

impl InMemoryIdentityStore {
    pub fn new() -> Self {
        Self {
            by_said: RwLock::new(HashMap::new()),
            by_prefix: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityStore for InMemoryIdentityStore {
    async fn store_iel_event(&self, event: &IdentityEvent) -> Result<(), KelsError> {
        {
            let mut by_said = self.by_said.write().await;
            by_said.insert(event.said, event.clone());
        }

        let mut by_prefix = self.by_prefix.write().await;
        let entries = by_prefix.entry(event.prefix).or_default();
        // Idempotent: replace any existing entry with the same SAID.
        if let Some(pos) = entries.iter().position(|e| e.said == event.said) {
            entries[pos] = event.clone();
        } else {
            entries.push(event.clone());
        }
        entries.sort_by(|a, b| {
            a.version
                .cmp(&b.version)
                .then_with(|| a.kind.sort_priority().cmp(&b.kind.sort_priority()))
                .then_with(|| a.said.as_ref().cmp(b.said.as_ref()))
        });
        Ok(())
    }

    async fn load_iel_events(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        let by_prefix = self.by_prefix.read().await;
        let entries = match by_prefix.get(prefix) {
            Some(e) => e.clone(),
            None => return Ok((Vec::new(), false)),
        };
        drop(by_prefix);

        let start = offset as usize;
        if start >= entries.len() {
            return Ok((Vec::new(), false));
        }
        let end_inclusive = start.saturating_add(limit as usize);
        let has_more = end_inclusive < entries.len();
        let end = end_inclusive.min(entries.len());
        Ok((entries[start..end].to_vec(), has_more))
    }

    async fn load_iel_event(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<IdentityEvent>, KelsError> {
        let by_said = self.by_said.read().await;
        Ok(by_said.get(said).cloned())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

    fn fixture_chain() -> (IdentityEvent, IdentityEvent) {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();
        (v0, v1)
    }

    #[tokio::test]
    async fn empty_store_returns_empty_page_for_unknown_prefix() {
        let store = InMemoryIdentityStore::new();
        let bogus = test_digest(b"unknown-prefix");
        let (page, has_more) = store.load_iel_events(&bogus, 10, 0).await.unwrap();
        assert!(page.is_empty());
        assert!(!has_more);
    }

    #[tokio::test]
    async fn store_and_load_round_trip() {
        let store = InMemoryIdentityStore::new();
        let (v0, v1) = fixture_chain();
        store.store_iel_event(&v0).await.unwrap();
        store.store_iel_event(&v1).await.unwrap();

        let (page, has_more) = store.load_iel_events(&v0.prefix, 10, 0).await.unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].said, v0.said);
        assert_eq!(page[1].said, v1.said);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn pagination_advances_offset() {
        let store = InMemoryIdentityStore::new();
        let (v0, v1) = fixture_chain();
        store.store_iel_event(&v0).await.unwrap();
        store.store_iel_event(&v1).await.unwrap();

        let (page0, has_more0) = store.load_iel_events(&v0.prefix, 1, 0).await.unwrap();
        assert_eq!(page0.len(), 1);
        assert_eq!(page0[0].said, v0.said);
        assert!(has_more0);

        let (page1, has_more1) = store.load_iel_events(&v0.prefix, 1, 1).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].said, v1.said);
        assert!(!has_more1);
    }

    #[tokio::test]
    async fn load_by_said_returns_event() {
        let store = InMemoryIdentityStore::new();
        let (v0, _) = fixture_chain();
        store.store_iel_event(&v0).await.unwrap();
        let loaded = store.load_iel_event(&v0.said).await.unwrap();
        assert_eq!(loaded.map(|e| e.said), Some(v0.said));
    }

    #[tokio::test]
    async fn idempotent_store_does_not_duplicate_index() {
        let store = InMemoryIdentityStore::new();
        let (v0, _) = fixture_chain();
        store.store_iel_event(&v0).await.unwrap();
        store.store_iel_event(&v0).await.unwrap();

        let (page, _) = store.load_iel_events(&v0.prefix, 10, 0).await.unwrap();
        assert_eq!(page.len(), 1);
    }
}
