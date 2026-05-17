//! `RepositorySadStore` — `SadStore` impl backed by identity-service
//! repositories.
//!
//! Layer 0 of the identity service's `CascadingSadStore[RepositorySadStore,
//! RemoteSadStore]`. SAD body methods delegate to [`SadObjectRepository`];
//! SEL event methods delegate to [`SelRepository`] (the same table that
//! `Gap 2` introduced for owner-authored SEL events).
//!
//! The trait impl is intentionally thin — every method routes to a
//! repository call. Repositories own the SQL.

use std::sync::Arc;

use async_trait::async_trait;
use verifiable_storage::{ChainedRepository, StorageError};

use kels_core::{
    CascadingSadStore, KelsError, RemoteSadStore, SadEvent, SadStore, SadStoreClient,
};

use crate::repository::{SadObjectEntry, SadObjectRepository, SelRepository};

fn storage_to_kels(err: StorageError) -> KelsError {
    KelsError::StorageError(err.to_string())
}

/// `SadStore` impl over identity-service repositories.
///
/// Constructed with shared handles to the SAD-body cache repository and the
/// SEL-chain repository (both live on `IdentityRepository`).
pub struct RepositorySadStore {
    sad_objects: Arc<SadObjectRepository>,
    sel: Arc<SelRepository>,
}

impl RepositorySadStore {
    pub fn new(sad_objects: Arc<SadObjectRepository>, sel: Arc<SelRepository>) -> Self {
        Self { sad_objects, sel }
    }
}

/// Build the identity service's two-layer cascade.
///
/// Layer 0 is [`RepositorySadStore`] (local Postgres cache + SEL events).
/// Layer 1 is [`RemoteSadStore`] (the federation's sadstore service).
///
/// Reads first-hit-wins with cache-back to layer 0; writes fan out to both.
/// The shape matches `docs/design/infrastructure/federation.md §Per-peer
/// address publication` — local authorship + automatic remote submission.
pub fn build_cascade(
    sad_objects: Arc<SadObjectRepository>,
    sel: Arc<SelRepository>,
    sad_client: SadStoreClient,
) -> CascadingSadStore {
    let local: Arc<dyn SadStore> = Arc::new(RepositorySadStore::new(sad_objects, sel));
    let remote: Arc<dyn SadStore> = Arc::new(RemoteSadStore::new(sad_client));
    CascadingSadStore::new(vec![local, remote])
}

#[async_trait]
impl SadStore for RepositorySadStore {
    async fn store(
        &self,
        said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        let entry =
            SadObjectEntry::create(*said, value.clone()).map_err(storage_to_kels)?;
        self.sad_objects.store(entry).await.map_err(storage_to_kels)
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        let entry = self
            .sad_objects
            .get_by_object_said(said)
            .await
            .map_err(storage_to_kels)?;
        Ok(entry.map(|e| e.object))
    }

    async fn list(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        self.sad_objects
            .list_object_saids(since, limit)
            .await
            .map_err(storage_to_kels)
    }

    async fn delete(&self, said: &cesr::Digest256) -> Result<(), KelsError> {
        self.sad_objects
            .delete_by_object_said(said)
            .await
            .map_err(storage_to_kels)
    }

    async fn store_sel_event(&self, event: &SadEvent) -> Result<(), KelsError> {
        // Idempotent re-insert: a duplicate at the same SAID is already
        // present (same content → same SAID), so the post-condition is met.
        match self.sel.insert(event.clone()).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(storage_to_kels(e)),
        }
    }

    async fn load_sel_events(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), KelsError> {
        let chain = self.sel.fetch_chain(prefix).await.map_err(storage_to_kels)?;
        let total = chain.len();
        let start = offset as usize;
        if start >= total {
            return Ok((Vec::new(), false));
        }
        let end = start.saturating_add(limit as usize).min(total);
        let has_more = end < total;
        Ok((chain[start..end].to_vec(), has_more))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use cesr::test_digest;
    use kels_core::PEER_SERVICES_SEL_TOPIC;
    use serde_json::json;

    use super::*;
    use crate::repository::IdentityRepository;

    /// Build a RepositorySadStore from a fresh IdentityRepository connected to
    /// the shared test harness. Pool is cloned across both wrapped repos, so
    /// they share a single connection pool.
    async fn make_store(repo: &IdentityRepository) -> RepositorySadStore {
        let sad_objects = Arc::new(SadObjectRepository {
            pool: repo.sad_objects.pool.clone(),
        });
        let sel = Arc::new(SelRepository {
            pool: repo.sel.pool.clone(),
        });
        RepositorySadStore::new(sad_objects, sel)
    }

    /// Bring up the shared harness via the helper inside repository.rs's test
    /// module. Tests skip when the harness is unavailable (CI without Docker).
    async fn ensure_repo() -> Option<IdentityRepository> {
        crate::repository::tests::get_harness()
            .await
            .map(|h| async move { h.repo().await })?
            .await
            .into()
    }

    #[tokio::test]
    async fn store_and_load_roundtrips_through_the_trait() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;

        let object_said = test_digest("rss-roundtrip");
        let body = json!({"said": object_said, "label": "rss-roundtrip"});
        store.store(&object_said, &body).await.unwrap();

        let loaded = store.load(&object_said).await.unwrap();
        assert_eq!(loaded, Some(body));
    }

    #[tokio::test]
    async fn load_missing_returns_none() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;
        let result = store.load(&test_digest("rss-missing")).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_round_trip() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;

        let object_said = test_digest("rss-delete");
        let body = json!({"said": object_said, "n": 7});
        store.store(&object_said, &body).await.unwrap();
        store.delete(&object_said).await.unwrap();
        assert_eq!(store.load(&object_said).await.unwrap(), None);
    }

    #[tokio::test]
    async fn sel_event_roundtrip_through_the_trait() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;

        let identity = test_digest("rss-sel-identity");
        let icp = kels_core::SadEvent::icp(identity, PEER_SERVICES_SEL_TOPIC).unwrap();
        store.store_sel_event(&icp).await.unwrap();

        let (events, has_more) = store.load_sel_events(&icp.prefix, 10, 0).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].said, icp.said);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn sel_event_store_is_idempotent_via_duplicate_record() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;

        let identity = test_digest("rss-sel-idempotent");
        let icp = kels_core::SadEvent::icp(identity, PEER_SERVICES_SEL_TOPIC).unwrap();
        store.store_sel_event(&icp).await.unwrap();
        // Re-insert: DuplicateRecord is swallowed by store_sel_event.
        store.store_sel_event(&icp).await.unwrap();
    }

    #[tokio::test]
    async fn load_sel_events_respects_offset_and_limit() {
        let Some(repo) = ensure_repo().await else {
            return;
        };
        let store = make_store(&repo).await;

        let identity = test_digest("rss-sel-paging");
        let icp = kels_core::SadEvent::icp(identity, PEER_SERVICES_SEL_TOPIC).unwrap();
        let upd = kels_core::SadEvent::upd(
            &icp,
            test_digest("iel-evt"),
            test_digest("content"),
        )
        .unwrap();
        let sea = kels_core::SadEvent::sea(&upd, test_digest("iel-evt-2")).unwrap();
        store.store_sel_event(&icp).await.unwrap();
        store.store_sel_event(&upd).await.unwrap();
        store.store_sel_event(&sea).await.unwrap();

        // limit=1, offset=1 → the Upd event; has_more true (Sea is left).
        let (events, has_more) = store.load_sel_events(&icp.prefix, 1, 1).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].said, upd.said);
        assert!(has_more);
    }
}
