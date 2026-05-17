//! `RemoteSadStore` — `SadStore` adapter over `SadStoreClient`.
//!
//! Wraps the replicated SADStore service's HTTP client so a remote sadstore
//! can participate in a `CascadingSadStore` as a peer to local impls
//! (Postgres, file, in-memory).

use async_trait::async_trait;

use crate::{
    client::sadstore::SadStoreClient,
    error::KelsError,
    store::sad::SadStore,
    types::{ErrorCode, SadEvent},
};

/// `SadStore` adapter over `SadStoreClient`.
///
/// Forwards trait methods to the remote sadstore service:
///
/// - `store(said, value)` → `POST /api/v1/sad`.
/// - `load(said)` → `POST /api/v1/sad/fetch`.
/// - `store_sel_event(event)` → `POST /api/v1/sad/events`.
/// - `load_sel_events(prefix, ...)` → `POST /api/v1/sad/events/fetch`, sliced
///   client-side to satisfy the `(limit, offset)` shape.
///
/// `list` and `delete` are not supported — the remote `list` endpoint
/// requires a `PeerSigner` (anti-entropy surface, not application-layer),
/// and SAD-body deletion is governed by `availability.ttl`, not a delete
/// API. Both return `KelsError::StorageError(...)` with a directive to use
/// `SadStoreClient` directly when needed.
pub struct RemoteSadStore {
    client: SadStoreClient,
}

impl RemoteSadStore {
    pub fn new(client: SadStoreClient) -> Self {
        Self { client }
    }

    pub fn from_base_url(base_url: &str) -> Result<Self, KelsError> {
        Ok(Self {
            client: SadStoreClient::new(base_url)?,
        })
    }
}

#[async_trait]
impl SadStore for RemoteSadStore {
    async fn store(
        &self,
        _said: &cesr::Digest256,
        value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        // The server is the SAID authority: it re-derives and rejects on
        // mismatch. Calling `post_sad_object` with `value` is sufficient; the
        // caller's claimed SAID matches the body or the upstream submission
        // already failed.
        self.client.post_sad_object(value).await?;
        Ok(())
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        match self.client.get_sad_object(said).await {
            Ok(value) => Ok(Some(value)),
            Err(KelsError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    async fn list(
        &self,
        _since: Option<&cesr::Digest256>,
        _limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        Err(KelsError::StorageError(
            "RemoteSadStore::list is not supported — the remote SAD-listing endpoint requires a \
             PeerSigner (anti-entropy surface); use SadStoreClient::fetch_sad_objects directly"
                .to_string(),
        ))
    }

    async fn delete(&self, _said: &cesr::Digest256) -> Result<(), KelsError> {
        Err(KelsError::StorageError(
            "RemoteSadStore::delete is not supported — SAD lifecycle on the remote sadstore is \
             governed by availability.ttl, not a delete API"
                .to_string(),
        ))
    }

    async fn store_sel_event(&self, event: &SadEvent) -> Result<(), KelsError> {
        match self.client.submit_sel_events(std::slice::from_ref(event)).await {
            Ok(_) => Ok(()),
            // Idempotent: re-submitting an event the remote already holds returns
            // 409. The trait's contract is "store this event"; the post-condition
            // is satisfied either way.
            Err(KelsError::ServerError(_, ErrorCode::Conflict)) => Ok(()),
            Err(other) => Err(other),
        }
    }

    async fn load_sel_events(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), KelsError> {
        // The remote API is cursor-based (`since`), not offset-based. For the
        // cascade hit path (layer-0 cache miss is rare for owner-authored
        // events), fetching the full prefix and slicing is acceptable. If a
        // hot path emerges that needs efficient remote paging, it should call
        // `SadStoreClient::fetch_sel_events` directly with cursor semantics.
        let page = self.client.fetch_sel_events(prefix, None).await?;
        let total = page.events.len();
        let start = offset as usize;
        if start >= total {
            return Ok((Vec::new(), page.has_more));
        }
        let end = start.saturating_add(limit as usize).min(total);
        let has_more = end < total || page.has_more;
        Ok((page.events[start..end].to_vec(), has_more))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::types::SadEventPage;

    fn d(label: &str) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label.as_bytes())
    }

    async fn make_store(base_url: &str) -> RemoteSadStore {
        RemoteSadStore::from_base_url(base_url).expect("client constructs")
    }

    // ==================== store / load ====================

    #[tokio::test]
    async fn store_posts_to_sad_endpoint() {
        let mock = MockServer::start().await;
        // Build a real SAD object via NodeSet (a SelfAddressed type with no
        // additional fields) so the SAID embedded in the body matches what
        // `post_sad_object`'s pre-flight check rederives.
        let nodeset = crate::types::NodeSet::create_sorted(vec![d("a"), d("b")]).unwrap();
        let body = serde_json::to_value(&nodeset).unwrap();
        let response_body = json!({"said": nodeset.said});

        Mock::given(method("POST"))
            .and(path("/api/v1/sad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        store.store(&nodeset.said, &body).await.unwrap();
    }

    #[tokio::test]
    async fn load_returns_some_on_200() {
        let mock = MockServer::start().await;
        let said = d("load-hit");
        let body = json!({"said": said, "field": "value"});

        Mock::given(method("POST"))
            .and(path("/api/v1/sad/fetch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        let loaded = store.load(&said).await.unwrap();
        assert_eq!(loaded, Some(body));
    }

    #[tokio::test]
    async fn load_returns_none_on_404() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sad/fetch"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        let loaded = store.load(&d("missing")).await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn load_propagates_other_errors() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sad/fetch"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        let err = store.load(&d("err")).await.unwrap_err();
        match err {
            KelsError::ServerError(body, _) => assert!(body.contains("boom")),
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    // ==================== list / delete unsupported ====================

    #[tokio::test]
    async fn list_returns_unsupported() {
        let mock = MockServer::start().await;
        let store = make_store(&mock.uri()).await;
        let err = store.list(None, 100).await.unwrap_err();
        match err {
            KelsError::StorageError(msg) => assert!(msg.contains("not supported")),
            other => panic!("expected StorageError(not supported), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_returns_unsupported() {
        let mock = MockServer::start().await;
        let store = make_store(&mock.uri()).await;
        let err = store.delete(&d("x")).await.unwrap_err();
        match err {
            KelsError::StorageError(msg) => assert!(msg.contains("not supported")),
            other => panic!("expected StorageError(not supported), got {other:?}"),
        }
    }

    // ==================== SEL events ====================

    #[tokio::test]
    async fn store_sel_event_posts_to_events_endpoint() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sad/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"applied": true, "divergedAt": null})),
            )
            .mount(&mock)
            .await;

        let identity = d("sel-event-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();

        let store = make_store(&mock.uri()).await;
        store.store_sel_event(&icp).await.unwrap();
    }

    #[tokio::test]
    async fn store_sel_event_treats_409_as_idempotent() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sad/events"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_string("event already exists at this serial"),
            )
            .mount(&mock)
            .await;

        let identity = d("sel-event-dup");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();

        let store = make_store(&mock.uri()).await;
        // 409 maps to ServerError(_, Conflict); the trait contract is "store
        // succeeds if the event is now on the server". Re-submitting an event
        // the server already holds satisfies that, so 409 is silently accepted.
        store.store_sel_event(&icp).await.unwrap();
    }

    #[tokio::test]
    async fn load_sel_events_returns_paged_slice() {
        let mock = MockServer::start().await;

        let identity = d("sel-load-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();
        let upd =
            SadEvent::upd(&icp, d("iel-evt"), d("content")).unwrap();
        let sea = SadEvent::sea(&upd, d("iel-evt-2")).unwrap();
        let page = SadEventPage {
            events: vec![icp.clone(), upd.clone(), sea.clone()],
            has_more: false,
        };

        Mock::given(method("POST"))
            .and(path("/api/v1/sad/events/fetch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&page))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        let (events, has_more) = store.load_sel_events(&icp.prefix, 100, 0).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].said, icp.said);
        assert_eq!(events[2].said, sea.said);
        assert!(!has_more);
    }

    #[tokio::test]
    async fn load_sel_events_respects_offset_and_limit() {
        let mock = MockServer::start().await;

        let identity = d("sel-paging-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();
        let upd =
            SadEvent::upd(&icp, d("iel-evt"), d("content")).unwrap();
        let sea = SadEvent::sea(&upd, d("iel-evt-2")).unwrap();
        let page = SadEventPage {
            events: vec![icp.clone(), upd.clone(), sea.clone()],
            has_more: false,
        };

        Mock::given(method("POST"))
            .and(path("/api/v1/sad/events/fetch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&page))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        // limit=1, offset=1 → exactly the Upd event; has_more true (Sea is left).
        let (events, has_more) = store.load_sel_events(&icp.prefix, 1, 1).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].said, upd.said);
        assert!(has_more);
    }

    #[tokio::test]
    async fn load_sel_events_offset_past_end_is_empty() {
        let mock = MockServer::start().await;

        let identity = d("sel-overshoot-identity");
        let icp = SadEvent::icp(identity, "kels/sel/v1/peer/addresses").unwrap();
        let page = SadEventPage {
            events: vec![icp.clone()],
            has_more: false,
        };

        Mock::given(method("POST"))
            .and(path("/api/v1/sad/events/fetch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&page))
            .mount(&mock)
            .await;

        let store = make_store(&mock.uri()).await;
        let (events, has_more) = store.load_sel_events(&icp.prefix, 10, 99).await.unwrap();
        assert!(events.is_empty());
        assert!(!has_more);
    }
}
