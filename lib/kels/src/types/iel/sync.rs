//! Identity Event Log (IEL) sync helpers.
//!
//! Mirrors `lib/kels/src/types/sad/sync.rs`:
//! - `PagedIelSource` — async cursor over a remote IEL (HTTP, gossip).
//! - `IelPageLoader` — offset-paginated reads over a local store.
//! - `IdentityStorePageLoader` — `IelPageLoader` adapter for `IdentityStore`.
//! - `iel_completed_verification` — owner-local verification via a page loader.
//! - `verify_identity_events` — server-side verification via a `PagedIelSource`.

use std::sync::Arc;

use async_trait::async_trait;

use super::event::IdentityEvent;
use super::verification::{IelVerification, IelVerifier};
use crate::KelsError;
use crate::error::read_error_body;
use crate::store::IdentityStore;
use crate::types::{ErrorCode, IdentityEventPage, IdentityEventPageRequest, PolicyChecker};

// ==================== Source Trait ====================

/// Source of paginated Identity Event Log events. Used by
/// `verify_identity_events` to walk a remote IEL forward without loading the
/// full chain into memory.
///
/// Implementations must return events in
/// `(version ASC, kind sort_priority ASC, said ASC)` order. `since` is an
/// exclusive cursor; `None` means "from the beginning."
#[async_trait]
pub trait PagedIelSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError>;
}

/// Destination for a batch of Identity Event Log events. The HTTP impl posts
/// to the IEL submit endpoint; the local-store impl writes through to an
/// `IdentityStore`. Mirrors `PagedSadSink` for SE.
#[async_trait]
pub trait PagedIelSink: Send + Sync {
    async fn store_page(&self, events: &[IdentityEvent]) -> Result<(), KelsError>;
}

// ==================== Owner-local Page Loader ====================

/// Trait for loading offset-paginated IEL events for a given chain prefix.
///
/// Offset-based parallel of `PagedIelSource`. Mirrors SE's `SelPageLoader`
/// (`lib/kels/src/types/sad/sync.rs`) — implemented by
/// `IdentityStorePageLoader` over a `&dyn IdentityStore`.
#[async_trait]
pub trait IelPageLoader: Send + Sync {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError>;
}

/// `IdentityStore` adapter for `IelPageLoader`.
pub struct IdentityStorePageLoader<'a>(&'a dyn IdentityStore);

impl<'a> IdentityStorePageLoader<'a> {
    pub fn new(store: &'a dyn IdentityStore) -> Self {
        Self(store)
    }
}

#[async_trait]
impl IelPageLoader for IdentityStorePageLoader<'_> {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        self.0.load_iel_events(prefix, limit, offset).await
    }
}

// ==================== HTTP Source ====================

/// HTTP-backed `PagedIelSource`. Mirrors `HttpSadSource`.
pub struct HttpIelSource {
    base_url: String,
    client: reqwest::Client,
}

impl HttpIelSource {
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait]
impl PagedIelSource for HttpIelSource {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        let url = format!("{}/api/v1/iel/events/fetch", self.base_url);
        let body = IdentityEventPageRequest {
            prefix: *prefix,
            since: since.copied(),
            limit: Some(limit),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let page: IdentityEventPage = resp.json().await?;
            Ok((page.events, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok((Vec::new(), false))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

// ==================== HTTP Sink ====================

/// HTTP-backed `PagedIelSink`. POSTs each page to the IEL submit endpoint
/// (`/api/v1/iel/events`). Mirrors `HttpSadSink`.
pub struct HttpIelSink {
    base_url: String,
    client: reqwest::Client,
}

impl HttpIelSink {
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait]
impl PagedIelSink for HttpIelSink {
    async fn store_page(&self, events: &[IdentityEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }
        let url = format!("{}/api/v1/iel/events", self.base_url);
        let resp = self.client.post(&url).json(events).send().await?;

        if resp.status().is_success() {
            // Drain the body to honor `SubmitIdentityEventsResponse`'s `#[must_use]`.
            // Forwarding/sync isn't owner-driven, so the divergence/applied
            // signals aren't actionable here — owner submission goes through
            // `SadStoreClient::submit_identity_events`, which surfaces the response.
            let _ = resp
                .json::<crate::types::SubmitIdentityEventsResponse>()
                .await;
            Ok(())
        } else if resp.status() == reqwest::StatusCode::CONFLICT
            || resp.status() == reqwest::StatusCode::FORBIDDEN
        {
            // Chain already terminal or divergent on remote — gossip pulls are
            // best-effort; skip rather than fail. The submit handler's routing
            // is the authority on what's accepted.
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

/// Forward a remote IEL chain into a local sink, paged. Mirrors
/// `forward_sad_events` but without the divergence-aware held-back logic
/// (IEL has no `Rpr`; the server's submit handler routes each batch — Cnt on
/// divergent goes to contest, non-Cnt batch on divergent gets `ContestRequired`).
pub async fn forward_identity_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    sink: &(dyn PagedIelSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    let mut current_since = since.copied();
    for _ in 0..max_pages {
        let (events, has_more) = source
            .fetch_page(prefix, current_since.as_ref(), page_size)
            .await?;
        if events.is_empty() {
            return Ok(());
        }
        sink.store_page(&events).await?;
        if !has_more {
            return Ok(());
        }
        current_since = events.last().map(|e| e.said);
    }
    Err(KelsError::InvalidIel(format!(
        "IEL forward exceeded max_pages limit ({}) for {}",
        max_pages, prefix,
    )))
}

// ==================== Verification Helpers ====================

/// Verify a full IEL using paginated reads from a local store, returning a
/// trusted owner-local `IelVerification`.
///
/// Mirrors SE's `sel_completed_verification`. Walks pages via
/// `loader.load_page`, runs `IelVerifier::verify_page` per page, and returns
/// the proof-of-verification token. `max_pages` limits resource exhaustion —
/// fails secure if exceeded.
///
/// Returns `KelsError::NotFound(prefix)` when the loader returns no events
/// (chain not yet locally inducted).
pub async fn iel_completed_verification(
    loader: &mut dyn IelPageLoader,
    prefix: &cesr::Digest256,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
) -> Result<IelVerification, KelsError> {
    let mut verifier = IelVerifier::new(Some(prefix), checker);
    let mut offset: u64 = 0;
    let mut exhausted = false;
    let mut saw_any = false;
    let limit = page_size as u64;

    for _ in 0..max_pages {
        let (events, has_more) = loader.load_page(prefix, limit, offset).await?;

        if events.is_empty() {
            exhausted = true;
            break;
        }

        saw_any = true;
        let advanced = events.len() as u64;
        verifier.verify_page(&events).await?;
        offset += advanced;

        if !has_more {
            exhausted = true;
            break;
        }
    }

    if !exhausted {
        return Err(KelsError::InvalidKel(format!(
            "IEL for {} exceeds max_pages limit ({}) — verification incomplete",
            prefix, max_pages,
        )));
    }

    if !saw_any {
        return Err(KelsError::NotFound(prefix.to_string()));
    }

    verifier.finish().await
}

/// Verify an IEL by paging through a `PagedIelSource`. Returns a verification
/// token. Mirrors SE's `verify_sad_events`.
///
/// `max_pages` bounds resource exhaustion; fails secure if exceeded.
pub async fn verify_identity_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
) -> Result<IelVerification, KelsError> {
    let mut verifier = IelVerifier::new(Some(prefix), checker);
    let mut since: Option<cesr::Digest256> = None;
    let mut exhausted = false;
    let mut saw_any = false;

    for _ in 0..max_pages {
        let (events, has_more) = source.fetch_page(prefix, since.as_ref(), page_size).await?;

        if events.is_empty() {
            exhausted = true;
            break;
        }

        saw_any = true;
        verifier.verify_page(&events).await?;

        if !has_more {
            exhausted = true;
            break;
        }

        // Cursor on the last event's SAID (exclusive).
        since = events.last().map(|e| e.said);
    }

    if !exhausted {
        return Err(KelsError::InvalidKel(format!(
            "IEL for {} exceeds max_pages limit ({}) — verification incomplete",
            prefix, max_pages,
        )));
    }

    if !saw_any {
        return Err(KelsError::ServerError(
            format!("IEL {} not found on remote source", prefix),
            ErrorCode::NotFound,
        ));
    }

    verifier.finish().await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::store::InMemoryIdentityStore;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

    /// All-pass policy checker for sync tests (the checker behavior is exhaustively
    /// covered by the verifier tests in `verification.rs`; sync tests focus on
    /// pagination plumbing).
    struct AlwaysPassChecker;

    #[async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn is_anchored(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    fn always_pass() -> Arc<dyn PolicyChecker + Send + Sync> {
        Arc::new(AlwaysPassChecker)
    }

    /// Test source that serves a vector of events in fixed order, paginating
    /// by exclusive `since` SAID.
    struct VecSource {
        events: Vec<IdentityEvent>,
    }

    #[async_trait]
    impl PagedIelSource for VecSource {
        async fn fetch_page(
            &self,
            _prefix: &cesr::Digest256,
            since: Option<&cesr::Digest256>,
            limit: usize,
        ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
            let start = match since {
                None => 0,
                Some(cursor) => self
                    .events
                    .iter()
                    .position(|e| &e.said == cursor)
                    .map(|i| i + 1)
                    .unwrap_or(self.events.len()),
            };
            if start >= self.events.len() {
                return Ok((Vec::new(), false));
            }
            let end = (start + limit).min(self.events.len());
            let page = self.events[start..end].to_vec();
            let has_more = end < self.events.len();
            Ok((page, has_more))
        }
    }

    fn make_chain(len: usize) -> Vec<IdentityEvent> {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let mut events = vec![IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap()];
        for _ in 1..len {
            #[allow(clippy::expect_used)]
            let prev = events.last().expect("non-empty");
            events.push(IdentityEvent::evl(prev, None, None).unwrap());
        }
        events
    }

    #[tokio::test]
    async fn iel_completed_verification_walks_local_store() {
        let store = InMemoryIdentityStore::new();
        let chain = make_chain(3);
        for event in &chain {
            store.store_iel_event(event).await.unwrap();
        }
        let prefix = chain[0].prefix;

        let mut loader = IdentityStorePageLoader::new(&store);
        let v = iel_completed_verification(&mut loader, &prefix, always_pass(), 16, 8)
            .await
            .unwrap();

        assert_eq!(v.current_event().map(|e| e.said), Some(chain[2].said));
        assert!(v.policy_satisfied());
    }

    #[tokio::test]
    async fn iel_completed_verification_paginates_across_pages() {
        let store = InMemoryIdentityStore::new();
        let chain = make_chain(5);
        for event in &chain {
            store.store_iel_event(event).await.unwrap();
        }
        let prefix = chain[0].prefix;

        let mut loader = IdentityStorePageLoader::new(&store);
        // Page size 2 → 3 pages of 2/2/1.
        let v = iel_completed_verification(&mut loader, &prefix, always_pass(), 2, 8)
            .await
            .unwrap();
        assert_eq!(v.current_event().map(|e| e.version), Some(4));
    }

    #[tokio::test]
    async fn iel_completed_verification_not_found_on_empty_store() {
        let store = InMemoryIdentityStore::new();
        let prefix = test_digest(b"unknown");
        let mut loader = IdentityStorePageLoader::new(&store);
        let err = iel_completed_verification(&mut loader, &prefix, always_pass(), 16, 8)
            .await
            .expect_err("expected NotFound");
        assert!(matches!(err, KelsError::NotFound(_)));
    }

    #[tokio::test]
    async fn iel_completed_verification_fails_when_max_pages_exceeded() {
        let store = InMemoryIdentityStore::new();
        let chain = make_chain(5);
        for event in &chain {
            store.store_iel_event(event).await.unwrap();
        }
        let prefix = chain[0].prefix;

        let mut loader = IdentityStorePageLoader::new(&store);
        // Page size 1, max 2 pages → can only see 2 of 5; should fail secure.
        let err = iel_completed_verification(&mut loader, &prefix, always_pass(), 1, 2)
            .await
            .expect_err("expected max_pages failure");
        assert!(
            err.to_string().contains("exceeds max_pages limit"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn verify_identity_events_walks_remote_source() {
        let chain = make_chain(3);
        let prefix = chain[0].prefix;
        let source = VecSource {
            events: chain.clone(),
        };
        let v = verify_identity_events(&prefix, &source, always_pass(), 16, 8)
            .await
            .unwrap();
        assert_eq!(v.current_event().map(|e| e.said), Some(chain[2].said));
    }

    #[tokio::test]
    async fn verify_identity_events_paginates_with_since_cursor() {
        let chain = make_chain(5);
        let prefix = chain[0].prefix;
        let source = VecSource {
            events: chain.clone(),
        };
        let v = verify_identity_events(&prefix, &source, always_pass(), 2, 8)
            .await
            .unwrap();
        assert_eq!(v.current_event().map(|e| e.version), Some(4));
    }

    #[tokio::test]
    async fn verify_identity_events_fails_when_max_pages_exceeded() {
        let chain = make_chain(5);
        let prefix = chain[0].prefix;
        let source = VecSource { events: chain };
        let err = verify_identity_events(&prefix, &source, always_pass(), 1, 2)
            .await
            .expect_err("expected max_pages failure");
        assert!(
            err.to_string().contains("exceeds max_pages limit"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn verify_identity_events_not_found_on_empty_source() {
        let prefix = test_digest(b"unknown");
        let source = VecSource { events: Vec::new() };
        let err = verify_identity_events(&prefix, &source, always_pass(), 16, 8)
            .await
            .expect_err("expected ServerError(NotFound)");
        match err {
            KelsError::ServerError(_, ErrorCode::NotFound) => {}
            other => panic!("unexpected error: {}", other),
        }
    }
}
