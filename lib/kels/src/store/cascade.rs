//! `CascadingSadStore` — chained `SadStore` over an ordered set of layers.
//!
//! The client-side I/O interface that combines local caching with remote
//! submission. Constructed with `Vec<Arc<dyn SadStore>>` ordered cache-first
//! (layer 0 is the closest cache, the last layer is the remote/authoritative
//! tier).
//!
//! **Reads** walk layers in order — first hit wins. On a hit at layer `k > 0`,
//! the value is back-cached into every preceding layer so the next read hits
//! at layer 0. Failures while caching back are logged at debug-level and do
//! not poison the response — the caller gets the data.
//!
//! **Writes** fan out to every layer. The identity-service shape
//! `CascadingSadStore[PostgresSadStore, RemoteSadStore]` means a store
//! caches locally *and* submits to the remote sadstore in one call (the
//! "knows how to cache locally + submit" shape from
//! `docs/design/infrastructure/federation.md`).

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::{error::KelsError, store::sad::SadStore, types::SadEvent};

/// Chained `SadStore` with cache-back on read and fan-out on write.
///
/// Layer ordering is significant: `layers[0]` is the closest cache, the
/// last layer is the remote/authoritative tier. The cascade is empty-safe
/// (a zero-layer cascade always misses on read and no-ops on write) so
/// downstream code can construct one unconditionally and skip the special
/// case.
pub struct CascadingSadStore {
    layers: Vec<Arc<dyn SadStore>>,
}

impl CascadingSadStore {
    pub fn new(layers: Vec<Arc<dyn SadStore>>) -> Self {
        Self { layers }
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}

#[async_trait]
impl SadStore for CascadingSadStore {
    async fn store(
        &self,
        said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        // Write fans out to every layer. The cascade exists to ensure both
        // the local cache and the remote tier see the new SAD; partial
        // writes (e.g. local-only on remote failure) would leave the local
        // tier ahead of the remote in a way that breaks the cache-back
        // invariant on future reads.
        for layer in &self.layers {
            layer.store(said, value).await?;
        }
        Ok(())
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        for (idx, layer) in self.layers.iter().enumerate() {
            if let Some(value) = layer.load(said).await? {
                // Cache-back: populate every preceding layer that missed.
                // Failures here are debug-logged and not propagated — the
                // caller already has the data; a sluggish back-cache must
                // not surface as a read failure.
                for back in &self.layers[..idx] {
                    if let Err(e) = back.store(said, &value).await {
                        debug!(
                            said = %said,
                            error = %e,
                            "cache-back store failed on a preceding cascade layer; \
                             continuing — the caller has the value"
                        );
                    }
                }
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    async fn list(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        // List delegates to the first layer that supports it. Remote layers
        // (RemoteSadStore) error on `list`; local layers (Postgres, file,
        // in-memory) answer naturally. Layer 0 is the closest cache and
        // sees every cached SAD post-fetch, so its view is a sound stand-in
        // for "what does this cascade know about?"
        for layer in &self.layers {
            match layer.list(since, limit).await {
                Ok(result) => return Ok(result),
                // Try the next layer on unsupported, propagate everything else.
                Err(KelsError::StorageError(msg)) if msg.contains("not supported") => continue,
                Err(other) => return Err(other),
            }
        }
        Ok((Vec::new(), false))
    }

    async fn delete(&self, said: &cesr::Digest256) -> Result<(), KelsError> {
        // Best-effort delete across layers. Remote layers reject (lifecycle
        // is managed by availability TTL there); local layers honor it.
        for layer in &self.layers {
            match layer.delete(said).await {
                Ok(()) => {}
                Err(KelsError::StorageError(msg)) if msg.contains("not supported") => continue,
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    async fn store_sel_event(&self, event: &SadEvent) -> Result<(), KelsError> {
        for layer in &self.layers {
            layer.store_sel_event(event).await?;
        }
        Ok(())
    }

    async fn load_sel_events(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), KelsError> {
        // First non-empty response wins. SEL events don't have a generic
        // "back-cache the page" shape (the index lives per-layer and is
        // index-keyed by prefix, not by the page contents); callers that
        // need to materialize remote SELs locally do so via the authoring
        // flow (which fans out via `store_sel_event`) or by storing each
        // returned event with `store_sel_event` themselves.
        for layer in &self.layers {
            let (events, has_more) = layer.load_sel_events(prefix, limit, offset).await?;
            if !events.is_empty() {
                return Ok((events, has_more));
            }
        }
        Ok((Vec::new(), false))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::store::sad::InMemorySadStore;

    fn d(label: &str) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label.as_bytes())
    }

    fn layer() -> Arc<InMemorySadStore> {
        Arc::new(InMemorySadStore::new())
    }

    // ==================== read / write fan-out ====================

    #[tokio::test]
    async fn store_fans_out_to_all_layers() {
        let l0 = layer();
        let l1 = layer();
        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);

        let said = d("fanout");
        let value = json!({"said": said, "n": 1});
        cascade.store(&said, &value).await.unwrap();

        assert_eq!(l0.load(&said).await.unwrap(), Some(value.clone()));
        assert_eq!(l1.load(&said).await.unwrap(), Some(value));
    }

    #[tokio::test]
    async fn load_returns_layer_0_hit() {
        let l0 = layer();
        let l1 = layer();
        let said = d("l0-hit");
        let value = json!({"said": said, "from": "l0"});
        l0.store(&said, &value).await.unwrap();
        // Tamper-evidence test: l1 has a different value at the same SAID,
        // proving the cascade returned l0's hit without consulting l1.
        l1.store(&said, &json!({"said": said, "from": "l1"}))
            .await
            .unwrap();

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);

        let loaded = cascade.load(&said).await.unwrap();
        assert_eq!(loaded, Some(value));
    }

    #[tokio::test]
    async fn load_falls_through_to_later_layer_and_caches_back() {
        let l0 = layer();
        let l1 = layer();
        let said = d("l1-hit");
        let value = json!({"said": said, "from": "l1"});
        l1.store(&said, &value).await.unwrap();
        assert_eq!(l0.load(&said).await.unwrap(), None);

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);

        let loaded = cascade.load(&said).await.unwrap();
        assert_eq!(loaded, Some(value.clone()));

        // The hit at l1 is back-cached to l0.
        assert_eq!(l0.load(&said).await.unwrap(), Some(value));
    }

    #[tokio::test]
    async fn load_three_layers_caches_back_to_all_preceding() {
        let l0 = layer();
        let l1 = layer();
        let l2 = layer();
        let said = d("l2-hit");
        let value = json!({"said": said, "from": "l2"});
        l2.store(&said, &value).await.unwrap();

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
            Arc::clone(&l2) as Arc<dyn SadStore>,
        ]);

        cascade.load(&said).await.unwrap();
        assert_eq!(l0.load(&said).await.unwrap(), Some(value.clone()));
        assert_eq!(l1.load(&said).await.unwrap(), Some(value));
    }

    #[tokio::test]
    async fn load_returns_none_when_no_layer_holds_it() {
        let cascade = CascadingSadStore::new(vec![
            layer() as Arc<dyn SadStore>,
            layer() as Arc<dyn SadStore>,
        ]);
        assert_eq!(cascade.load(&d("never-stored")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn empty_cascade_is_a_noop() {
        let cascade = CascadingSadStore::new(Vec::new());
        cascade
            .store(&d("x"), &json!({"said": d("x")}))
            .await
            .unwrap();
        assert_eq!(cascade.load(&d("x")).await.unwrap(), None);
    }

    // ==================== list / delete unsupported-aware ====================

    #[tokio::test]
    async fn list_skips_layers_that_dont_support_it() {
        // First-layer-supports-it: l0 (in-memory) supports list; cascade
        // returns its result without consulting l1.
        let l0 = layer();
        let l1 = layer();
        l0.store(&d("a"), &json!({"said": d("a")}))
            .await
            .unwrap();
        l0.store(&d("b"), &json!({"said": d("b")}))
            .await
            .unwrap();

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);
        let (saids, has_more) = cascade.list(None, 100).await.unwrap();
        assert_eq!(saids.len(), 2);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn delete_propagates_through_supporting_layers() {
        let l0 = layer();
        let l1 = layer();
        let said = d("delete");
        let value = json!({"said": said});
        l0.store(&said, &value).await.unwrap();
        l1.store(&said, &value).await.unwrap();

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);
        cascade.delete(&said).await.unwrap();
        assert_eq!(l0.load(&said).await.unwrap(), None);
        assert_eq!(l1.load(&said).await.unwrap(), None);
    }

    // ==================== SEL events ====================

    #[tokio::test]
    async fn store_sel_event_fans_out() {
        let l0 = layer();
        let l1 = layer();
        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);

        let identity = d("sel-fanout-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();
        cascade.store_sel_event(&icp).await.unwrap();

        let (l0_events, _) = l0.load_sel_events(&icp.prefix, 10, 0).await.unwrap();
        let (l1_events, _) = l1.load_sel_events(&icp.prefix, 10, 0).await.unwrap();
        assert_eq!(l0_events.len(), 1);
        assert_eq!(l1_events.len(), 1);
        assert_eq!(l0_events[0].said, icp.said);
        assert_eq!(l1_events[0].said, icp.said);
    }

    #[tokio::test]
    async fn load_sel_events_falls_through_to_later_layer() {
        let l0 = layer();
        let l1 = layer();

        let identity = d("sel-fall-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();
        l1.store_sel_event(&icp).await.unwrap();

        let cascade = CascadingSadStore::new(vec![
            Arc::clone(&l0) as Arc<dyn SadStore>,
            Arc::clone(&l1) as Arc<dyn SadStore>,
        ]);

        let (events, _) = cascade.load_sel_events(&icp.prefix, 10, 0).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].said, icp.said);
    }
}
