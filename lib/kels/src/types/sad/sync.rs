//! Paginated transfer infrastructure for SAD Event Logs
//!
//! Mirrors the KEL `transfer_key_events` pattern: `PagedSadSource` / `PagedSadSink`
//! traits abstract data movement, and `transfer_sad_events` is the core private
//! function that pages through a source, optionally verifies structure, and sends
//! to a sink.
//!
//! For owner-local hydration over a `SadStore` (no server round-trip), use
//! `SelPageLoader` + `SadStorePageLoader` + `sel_completed_verification` —
//! parallels KEL's `PageLoader` / `KelStorePageLoader` / `completed_verification`
//! at `lib/kels/src/types/kel/sync.rs`.
//!
//! Public functions:
//! - `verify_sad_events` — structural + policy verification via `PolicyChecker`
//! - `forward_sad_events` — forward without verification, supports delta via `since`
//! - `sel_completed_verification` — owner-local verification via `SelPageLoader`

use std::sync::Arc;

use async_trait::async_trait;

use super::super::error::ErrorCode;
use super::event::{SadEvent, SadEventPage, SelVerification};
use super::verification::SelVerifier;
use crate::store::SadStore;
use crate::types::PolicyChecker;
use crate::{KelsError, error::read_error_body};

// ==================== Source / Sink Traits ====================

/// Source of paginated SAD events (e.g., HTTP client).
///
/// Implementations must return events in `version ASC, said ASC` order.
#[async_trait]
pub trait PagedSadSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<SadEvent>, bool), KelsError>;

    /// Fetch the tail of a chain — the last `limit` events ordered by
    /// `(version ASC, said ASC)`.
    ///
    /// Used by `SadEventBuilder::repair`'s adversary-extension walk-back as
    /// a single round-trip alternative to forward-paginating the whole chain.
    /// Default implementation returns `Unsupported` so legacy sources don't
    /// silently degrade — callers that need tail fetch should depend on a
    /// source that overrides this. `HttpSadSource` provides the production
    /// implementation; test mocks override as needed.
    async fn fetch_tail(
        &self,
        _prefix: &cesr::Digest256,
        _limit: usize,
    ) -> Result<Vec<SadEvent>, KelsError> {
        Err(KelsError::OfflineMode(
            "PagedSadSource::fetch_tail not implemented by this source".into(),
        ))
    }
}

/// Destination for SAD events (e.g., local SADStore).
#[async_trait]
pub trait PagedSadSink: Send + Sync {
    async fn store_page(&self, events: &[SadEvent]) -> Result<(), KelsError>;
}

// ==================== Owner-local Page Loader ====================

/// Trait for loading offset-paginated SAD events for a given chain prefix.
///
/// The offset-based parallel of `PagedSadSource` (which is cursor/`since`-based
/// for HTTP transfer). Mirrors KEL's `PageLoader`
/// (`lib/kels/src/types/kel/sync.rs`) — implemented by `SadStorePageLoader`
/// over a `&dyn SadStore`, or by transaction wrappers that read under
/// advisory locks.
#[async_trait]
pub trait SelPageLoader: Send + Sync {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), KelsError>;
}

/// `SadStore` adapter for `SelPageLoader` — wraps a shared reference to a
/// `SadStore`. Pairs with the trait's `load_sel_events` method, which is
/// populated by `store_sel_event` calls during `SadEventBuilder::flush`.
///
/// Mirrors KEL's `KelStorePageLoader` (`lib/kels/src/types/kel/sync.rs`).
pub struct SadStorePageLoader<'a>(&'a dyn SadStore);

impl<'a> SadStorePageLoader<'a> {
    pub fn new(store: &'a dyn SadStore) -> Self {
        Self(store)
    }
}

#[async_trait]
impl SelPageLoader for SadStorePageLoader<'_> {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), KelsError> {
        self.0.load_sel_events(prefix, limit, offset).await
    }
}

/// Verify a full SEL using paginated reads from a local store, returning a
/// trusted owner-local `SelVerification`.
///
/// Mirrors KEL's `completed_verification` (`lib/kels/src/types/kel/sync.rs`).
/// Walks pages via `loader.load_page`, runs `SelVerifier::verify_page` per
/// page, and returns the proof-of-verification token. `max_pages` limits
/// resource exhaustion — fails secure if exceeded.
///
/// **Owner-local invariant.** Loader-fed pages contain only owner-authored
/// events (the `store_sel_event` writers populate the prefix index, the
/// repair flow does not). The resulting `SelVerification` reflects owner's
/// view; server state is consulted at action time, not here.
pub async fn sel_completed_verification(
    loader: &mut dyn SelPageLoader,
    prefix: &cesr::Digest256,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
) -> Result<SelVerification, KelsError> {
    let mut verifier = SelVerifier::new(Some(prefix), checker);
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

    // Fail secure: if we ran out of pages before exhausting the source,
    // return an error rather than a partial SelVerification.
    if !exhausted {
        return Err(KelsError::InvalidKel(format!(
            "SEL for {} exceeds max_pages limit ({}) — verification incomplete",
            prefix, max_pages,
        )));
    }

    if !saw_any {
        return Err(KelsError::NotFound(prefix.to_string()));
    }

    verifier.finish().await
}

// ==================== Sink Implementations ====================

/// No-op sink that discards events. Used for verify-only flows.
struct NoOpSadSink;

#[async_trait]
impl PagedSadSink for NoOpSadSink {
    async fn store_page(&self, _events: &[SadEvent]) -> Result<(), KelsError> {
        Ok(())
    }
}

// ==================== HTTP Source / Sink ====================

/// HTTP-based source of paginated SAD events.
pub struct HttpSadSource {
    base_url: String,
    client: reqwest::Client,
}

impl HttpSadSource {
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
impl PagedSadSource for HttpSadSource {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<SadEvent>, bool), KelsError> {
        let url = format!("{}/api/v1/sad/events/fetch", self.base_url);
        let body = crate::SadEventPageRequest {
            prefix: *prefix,
            since: since.copied(),
            limit: Some(limit),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let page: SadEventPage = resp.json().await?;
            Ok((page.events, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok((Vec::new(), false))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    async fn fetch_tail(
        &self,
        prefix: &cesr::Digest256,
        limit: usize,
    ) -> Result<Vec<SadEvent>, KelsError> {
        let url = format!("{}/api/v1/sad/events/tail", self.base_url);
        let body = crate::SadEventTailRequest {
            prefix: *prefix,
            limit: Some(limit),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let page: SadEventPage = resp.json().await?;
            Ok(page.events)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(Vec::new())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

/// HTTP-based sink that submits SAD events to a SADStore service.
pub struct HttpSadSink {
    base_url: String,
    client: reqwest::Client,
}

impl HttpSadSink {
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
impl PagedSadSink for HttpSadSink {
    async fn store_page(&self, events: &[SadEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/v1/sad/events", self.base_url);
        let resp = self.client.post(&url).json(events).send().await?;

        if resp.status().is_success() {
            // Drain the body to honor `SubmitSadEventsResponse`'s `#[must_use]`.
            // Forwarding/sync isn't owner-driven, so the divergence/applied
            // signals aren't actionable here — owner submission goes through
            // `SadStoreClient::submit_sad_events`, which surfaces the response.
            let _ = resp.json::<crate::SubmitSadEventsResponse>().await;
            Ok(())
        } else if resp.status() == reqwest::StatusCode::CONFLICT {
            // Chain already divergent on remote — that's fine, skip
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

// ==================== Core Transfer Function ====================

/// Page through a SAD Event Log from source to sink, optionally verifying.
///
/// Mirrors the KEL `transfer_key_events` pattern: uses a held-back event
/// strategy to detect divergence at page boundaries. When divergence is
/// found (two events at the same version), switches to collection mode,
/// accumulates all remaining events, then submits them via
/// `send_divergent_sad_events` in an order the remote can accept.
async fn transfer_sad_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    mut verifier: Option<&mut SelVerifier>,
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    if verifier.is_some() && since.is_some() {
        return Err(KelsError::InvalidKel(
            "Cannot use since with verification — verifier must see the full chain".to_string(),
        ));
    }

    let mut since: Option<cesr::Digest256> = since.cloned();
    let mut held_back: Option<SadEvent> = None;
    let mut divergence_found = false;
    let mut pre_divergence: Vec<SadEvent> = Vec::new();
    let mut post_divergence: Vec<SadEvent> = Vec::new();

    for _ in 0..max_pages {
        let (fetched, has_more) = source.fetch_page(prefix, since.as_ref(), page_size).await?;

        // Prepend held-back event from previous page
        let mut events = if let Some(held) = held_back.take() {
            let mut v = vec![held];
            v.extend(fetched);
            v
        } else {
            fetched
        };

        if events.is_empty() {
            break;
        }

        if divergence_found {
            // Collection mode: accumulate post-divergence events
            if let Some(ref mut v) = verifier {
                v.verify_page(&events).await?;
            }
            since = events.last().map(|e| e.said);
            post_divergence.extend(events);
        } else {
            // Phase 1: scan for divergence
            if has_more || events.len() > page_size {
                held_back = events.pop();
            }

            if events.is_empty() {
                if !has_more {
                    break;
                }
                continue;
            }

            if let Some(ref mut v) = verifier {
                v.verify_page(&events).await?;
            }

            // Detect divergence: two consecutive events at the same version
            let mut divergence_idx: Option<usize> = None;
            for i in 1..events.len() {
                if events[i].version == events[i - 1].version {
                    divergence_idx = Some(i - 1);
                    break;
                }
            }

            if let Some(div_idx) = divergence_idx {
                let div_version = events[div_idx].version;
                let same_version_count = events.iter().filter(|e| e.version == div_version).count();
                if same_version_count > 2 {
                    return Err(KelsError::InvalidKel(format!(
                        "Generation at version {} has {} events, max 2 allowed",
                        div_version, same_version_count
                    )));
                }

                divergence_found = true;
                pre_divergence = events[..div_idx].to_vec();
                post_divergence = events[div_idx..].to_vec();

                if let Some(held) = held_back.take() {
                    if let Some(ref mut v) = verifier {
                        v.verify_page(std::slice::from_ref(&held)).await?;
                    }
                    since = Some(held.said);
                    post_divergence.push(held);
                } else {
                    since = post_divergence.last().map(|e| e.said);
                }
            } else {
                // No divergence on this page
                sink.store_page(&events).await?;
                since = events.last().map(|e| e.said);
            }
        }

        if !has_more {
            break;
        }

        if let Some(ref held) = held_back {
            since = Some(held.said);
        }
    }

    // Process final held-back event
    if let Some(held) = held_back {
        if divergence_found {
            post_divergence.push(held);
        } else {
            if let Some(ref mut v) = verifier {
                v.verify_page(std::slice::from_ref(&held)).await?;
            }
            sink.store_page(std::slice::from_ref(&held)).await?;
        }
    }

    if !divergence_found {
        return Ok(());
    }

    send_divergent_sad_events(sink, &pre_divergence, post_divergence, page_size).await
}

/// Separate post-divergence events into two branches by tracing `previous`
/// events, then send to the sink in an order the remote can accept.
///
/// Event chains have no recovery/contest — divergent chains just freeze.
/// Strategy:
///   1. Pre-divergence + longer branch (paged, non-divergent appends)
///   2. Fork event from shorter branch (creates divergence on remote)
async fn send_divergent_sad_events(
    sink: &(dyn PagedSadSink + Sync),
    pre_divergence: &[SadEvent],
    post_divergence: Vec<SadEvent>,
    page_size: usize,
) -> Result<(), KelsError> {
    if post_divergence.len() < 2 {
        return Err(KelsError::InvalidKel(
            "Divergent chain must have at least 2 events at divergence point".to_string(),
        ));
    }

    // Trace previous events to separate into two branches
    let mut chain_a_saids = std::collections::HashSet::new();
    let mut chain_b_saids = std::collections::HashSet::new();
    chain_a_saids.insert(post_divergence[0].said);
    chain_b_saids.insert(post_divergence[1].said);

    for event in &post_divergence[2..] {
        if let Some(ref prev) = event.previous {
            if chain_a_saids.contains(prev) {
                chain_a_saids.insert(event.said);
            } else if chain_b_saids.contains(prev) {
                chain_b_saids.insert(event.said);
            }
        }
    }

    let mut chain_a: Vec<SadEvent> = Vec::new();
    let mut chain_b: Vec<SadEvent> = Vec::new();
    for event in post_divergence {
        if chain_a_saids.contains(&event.said) {
            chain_a.push(event);
        } else {
            chain_b.push(event);
        }
    }

    // Longer chain first as non-divergent appends, then fork event from shorter
    let (longer, shorter) = if chain_a.len() >= chain_b.len() {
        (chain_a, chain_b)
    } else {
        (chain_b, chain_a)
    };

    // Pre-divergence + longer chain (non-divergent appends)
    let mut non_divergent = pre_divergence.to_vec();
    non_divergent.extend(longer);
    for chunk in non_divergent.chunks(page_size) {
        sink.store_page(chunk).await?;
    }

    // Fork event from shorter chain (creates divergence).
    // The shorter branch is always exactly one event — the batch truncation
    // invariant prevents extensions past divergence.
    if let Some(fork) = shorter.first() {
        sink.store_page(std::slice::from_ref(fork)).await?;
    }

    Ok(())
}

// ==================== Public API ====================

/// Verify a SAD Event Log by paging through a source. Returns a verification token.
///
/// Structural + policy verification. Verifies SAID, prefix, topic, chain linkage,
/// and write_policy authorization via the provided `PolicyChecker`.
pub async fn verify_sad_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
) -> Result<SelVerification, KelsError> {
    let mut verifier = SelVerifier::new(Some(prefix), checker);
    transfer_sad_events(
        prefix,
        source,
        &NoOpSadSink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;

    verifier.finish().await
}

/// Forward SAD events from source to sink without verification. Supports delta via `since`.
pub async fn forward_sad_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    transfer_sad_events(prefix, source, sink, None, page_size, max_pages, since).await
}

#[cfg(test)]
#[allow(clippy::panic)]
// The single test here stages a divergent chain to exercise
// page-boundary divergence detection. `SadEventBuilder` is single-actor
// and refuses divergent state by design, so the fixture is hand-built.
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    /// In-memory paginated-only source that serves events in pages,
    /// simulating page-boundary splits for divergence-detection tests.
    /// Does not implement `fetch_tail` — for repair-walk-back tests that
    /// need it, see `RepairTestSadSource` in `lib/kels/src/sad_builder.rs`.
    struct PagedVecSadSource {
        events: Vec<SadEvent>,
        page_size: usize,
    }

    #[async_trait]
    impl PagedSadSource for PagedVecSadSource {
        async fn fetch_page(
            &self,
            _prefix: &cesr::Digest256,
            since: Option<&cesr::Digest256>,
            limit: usize,
        ) -> Result<(Vec<SadEvent>, bool), KelsError> {
            let limit = limit.min(self.page_size);
            let start = if let Some(since_said) = since {
                self.events
                    .iter()
                    .position(|e| e.said == *since_said)
                    .map(|i| i + 1)
                    .unwrap_or(0)
            } else {
                0
            };
            let end = (start + limit).min(self.events.len());
            let page = self.events[start..end].to_vec();
            let has_more = end < self.events.len();
            Ok((page, has_more))
        }
    }

    /// Collecting sink that records all stored pages.
    struct CollectingSink {
        pages: tokio::sync::Mutex<Vec<Vec<SadEvent>>>,
    }

    impl CollectingSink {
        fn new() -> Self {
            Self {
                pages: tokio::sync::Mutex::new(Vec::new()),
            }
        }

        async fn all_events(&self) -> Vec<SadEvent> {
            self.pages.lock().await.iter().flatten().cloned().collect()
        }
    }

    #[async_trait]
    impl PagedSadSink for CollectingSink {
        async fn store_page(&self, events: &[SadEvent]) -> Result<(), KelsError> {
            self.pages.lock().await.push(events.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_divergence_detection_at_page_boundary() {
        let wp = test_digest(b"write-policy");
        let gp = test_digest(b"governance-policy");

        // Build a chain: v0 (declares governance_policy), v1, then two events at v2 (divergence)
        let v0 = SadEvent::icp("kels/test", wp, Some(gp)).unwrap();
        let v1 = SadEvent::upd(&v0, test_digest(b"content1")).unwrap();

        // Two conflicting v2 events (same previous = v1.said)
        let v2_a = SadEvent::upd(&v1, test_digest(b"content2a")).unwrap();
        let v2_b = SadEvent::upd(&v1, test_digest(b"content2b")).unwrap();

        let prefix = v0.prefix;

        // page_size=2: page 1 = [v0, v1], page 2 = [v2_a, v2_b]
        // Divergence is within page 2 — no boundary split.
        // Now test page_size=3: page 1 = [v0, v1, v2_a], held-back = v2_a,
        // page 2 starts with v2_b which has same version → divergence at boundary.
        let source = PagedVecSadSource {
            events: vec![v0, v1, v2_a.clone(), v2_b.clone()],
            page_size: 3,
        };
        let sink = CollectingSink::new();

        forward_sad_events(&prefix, &source, &sink, 3, 100, None)
            .await
            .unwrap();

        let stored = sink.all_events().await;

        // All 4 events should be forwarded (pre-divergence + both branches)
        assert_eq!(
            stored.len(),
            4,
            "Expected 4 events (including both divergent), got {}",
            stored.len()
        );

        // Both v2 events present
        let saids: std::collections::HashSet<_> = stored.iter().map(|e| e.said).collect();
        assert!(
            saids.contains(&v2_a.said),
            "v2_a missing from forwarded events"
        );
        assert!(
            saids.contains(&v2_b.said),
            "v2_b missing from forwarded events"
        );
    }
}
