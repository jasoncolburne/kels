//! Identity Event Log (IEL) sync helpers.
//!
//! Mirrors `lib/kels/src/types/sad/sync.rs`:
//! - `PagedIelSource` — async cursor over a remote IEL (HTTP, gossip).
//! - `IelPageLoader` — offset-paginated reads over a local store.
//! - `IdentityStorePageLoader` — `IelPageLoader` adapter for `IdentityStore`.
//! - `iel_completed_verification` — owner-local verification via a page loader.
//! - `verify_identity_events` — server-side verification via a `PagedIelSource`.

use std::{collections::BTreeSet, sync::Arc};

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

    /// Said-form fetch: identifies the IEL by the SAID of any event on it,
    /// returns a page of that chain. Per #167, the verifier uses this when
    /// it holds an IEL event SAID without prior identity context (e.g.,
    /// resolving `custody.write`). Same ordering and pagination semantics
    /// as `fetch_page`; the server resolves the prefix internally.
    ///
    /// Default impl errors with `OfflineMode` — sources that can't serve
    /// said-form lookups (e.g., test fixtures keyed by prefix) opt out.
    async fn fetch_page_by_event_said(
        &self,
        _event_said: &cesr::Digest256,
        _since: Option<&cesr::Digest256>,
        _limit: usize,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        Err(KelsError::OfflineMode(
            "PagedIelSource does not support said-form fetch".into(),
        ))
    }
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
        let body = IdentityEventPageRequest {
            prefix: Some(*prefix),
            since: since.copied(),
            limit: Some(limit),
            ..Default::default()
        };
        self.fetch_with_request(body).await
    }

    async fn fetch_page_by_event_said(
        &self,
        event_said: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        let body = IdentityEventPageRequest {
            said: Some(*event_said),
            since: since.copied(),
            limit: Some(limit),
            ..Default::default()
        };
        self.fetch_with_request(body).await
    }
}

impl HttpIelSource {
    async fn fetch_with_request(
        &self,
        body: IdentityEventPageRequest,
    ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
        let url = format!("{}/api/v1/iel/events/fetch", self.base_url);
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

        let status = resp.status();
        if status.is_success() {
            // Drain the body to honor `SubmitIdentityEventsResponse`'s `#[must_use]`.
            // Forwarding/sync isn't owner-driven, so the
            // divergence/applied/terminal signals aren't actionable here —
            // owner submission goes through
            // `SadStoreClient::submit_identity_events`, which surfaces the
            // response. The 200-OK terminal-state-skip path (#147
            // follow-up) lands here too: a gossip-race-
            // already-terminal remote returns 200 with `terminal: Some(_)`
            // instead of 4xx, so the sink reads it as idempotent success.
            let _ = resp
                .json::<crate::types::SubmitIdentityEventsResponse>()
                .await;
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            // 409 = genuine client-vs-state conflict (e.g., sealed-fork
            // rejection from `save_batch`). 403 = real failure
            // (`policy_satisfied=false`, divergent-rejection); the
            // gossip-race-already-terminal idempotent case now flows
            // through 200 OK + `terminal: Some(_)`, so the previous
            // FORBIDDEN→Ok silent-skip is gone.
            let code = if status == reqwest::StatusCode::CONFLICT {
                ErrorCode::Conflict
            } else {
                ErrorCode::InternalError
            };
            Err(KelsError::ServerError(text, code))
        }
    }
}

/// Separate post-divergence IEL events into the two branches by tracing
/// forward from each fork event, then send them to the sink in an order
/// the remote will accept under its routing rules.
///
/// Mirrors KEL's `send_divergent_events` (`lib/kels/src/types/kel/sync.rs:517`)
/// adapted for IEL semantics: IEL has no `Rpr`, so the only legitimate
/// divergence resolver is `Cnt`. Two cases:
///
/// **Contested** (a `Cnt` exists on either branch): pre-divergence events
/// plus the non-`Cnt` chain go as paged appends; the `Cnt` chain goes as
/// a single atomic batch (so the receiver's submit handler routes it via
/// the `is_contest` path with the correct branch). The Cnt-chain must fit
/// in one page — exceeding the bound indicates DB tampering.
///
/// **Unrecovered** (no terminal in either branch — defensive only; in
/// production the IEL submit handler rejects non-`Cnt` events on
/// divergent chains with `ContestRequired`): longer chain goes as paged
/// appends, then the fork event from the shorter chain establishes
/// divergence at the receiver. Mirrors KEL's unrecovered-divergence path.
async fn send_divergent_iel_events(
    sink: &(dyn PagedIelSink + Sync),
    pre_divergence: &[IdentityEvent],
    post_divergence: Vec<IdentityEvent>,
    page_size: usize,
) -> Result<(), KelsError> {
    if post_divergence.len() < 2 {
        return Err(KelsError::InvalidIel(
            "Divergent IEL must have at least 2 events at divergence point".to_string(),
        ));
    }

    // Partition: trace forward from each fork event. Mirror KEL's
    // chain-partition loop at lib/kels/src/types/kel/sync.rs:546-570.
    let mut chain_a_saids = std::collections::HashSet::new();
    let mut chain_b_saids = std::collections::HashSet::new();
    chain_a_saids.insert(post_divergence[0].said);
    chain_b_saids.insert(post_divergence[1].said);

    for event in &post_divergence[2..] {
        if let Some(prev) = event.previous.as_ref() {
            if chain_a_saids.contains(prev) {
                chain_a_saids.insert(event.said);
            } else if chain_b_saids.contains(prev) {
                chain_b_saids.insert(event.said);
            }
        }
    }

    let mut chain_a: Vec<IdentityEvent> = Vec::new();
    let mut chain_b: Vec<IdentityEvent> = Vec::new();
    for event in post_divergence {
        if chain_a_saids.contains(&event.said) {
            chain_a.push(event);
        } else {
            chain_b.push(event);
        }
    }

    let chain_a_has_cnt = chain_a.iter().any(|e| e.kind.is_contest());
    let chain_b_has_cnt = chain_b.iter().any(|e| e.kind.is_contest());

    if chain_a_has_cnt || chain_b_has_cnt {
        // Contested case: send pre-divergence + non-cnt chain as paged
        // appends, then cnt-chain as atomic single-page batch.
        let (non_cnt_chain, cnt_chain) = if chain_a_has_cnt {
            (chain_b, chain_a)
        } else {
            (chain_a, chain_b)
        };

        let mut non_divergent = pre_divergence.to_vec();
        non_divergent.extend(non_cnt_chain);
        for chunk in non_divergent.chunks(page_size) {
            sink.store_page(chunk).await?;
        }

        // The cnt-chain must fit in one page — under #147 routing,
        // post-Cnt extension on the cnt branch is structurally rare
        // (handler rejects further events on contested chains via the
        // terminal-state gate), so a long cnt-chain indicates corrupted
        // source state.
        if cnt_chain.len() > crate::MINIMUM_PAGE_SIZE {
            return Err(KelsError::InvalidIel(format!(
                "Contest chain exceeds page bound ({} > {}) — possible DB tampering",
                cnt_chain.len(),
                crate::MINIMUM_PAGE_SIZE,
            )));
        }
        // Best-effort: the receiver may already be contested on this
        // chain (gossip race). The submit handler's terminal-state gate
        // returns 200 OK with `terminal: Some(Contested)` for that case
        // (#147 follow-up), so the sink reads it as
        // idempotent success. Errors here are reserved for genuine
        // failures (now propagating uniformly via `ErrorCode::Conflict`
        // for 409 and `ErrorCode::InternalError` for 5xx).
        sink.store_page(&cnt_chain).await?;
    } else {
        // Unrecovered (defensive): production routing prevents this
        // state. If the source produces it anyway, send the longer
        // chain as paged appends, then the fork event from the shorter
        // chain establishes divergence at the receiver.
        let (longer, shorter) = if chain_a.len() >= chain_b.len() {
            (chain_a, chain_b)
        } else {
            (chain_b, chain_a)
        };

        let mut non_divergent = pre_divergence.to_vec();
        non_divergent.extend(longer);
        for chunk in non_divergent.chunks(page_size) {
            sink.store_page(chunk).await?;
        }

        if let Some(fork) = shorter.first() {
            sink.store_page(std::slice::from_ref(fork)).await?;
        }
    }

    Ok(())
}

/// Page through an IEL from `source` to `sink`, detecting divergence at
/// page boundaries. When divergence is found, switches to collection
/// mode, accumulates remaining events, and submits them via
/// [`send_divergent_iel_events`] in an order the remote can accept.
///
/// Mirrors SE's `transfer_sad_events` (`lib/kels/src/types/sad/sync.rs`).
/// Uses the held-back-event strategy: holds the last event of each page
/// (when `has_more`) so a same-version overlap with the next page's
/// first event is detectable.
async fn transfer_identity_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    sink: &(dyn PagedIelSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    let mut current_since = since.copied();
    let mut held_back: Option<IdentityEvent> = None;
    let mut divergence_found = false;
    let mut pre_divergence: Vec<IdentityEvent> = Vec::new();
    let mut post_divergence: Vec<IdentityEvent> = Vec::new();

    for _ in 0..max_pages {
        let (fetched, has_more) = source
            .fetch_page(prefix, current_since.as_ref(), page_size)
            .await?;

        // Prepend held-back event from the previous page so a same-version
        // overlap at the page boundary is visible.
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
            // Collection mode: accumulate post-divergence events in
            // canonical chain order; defer the actual sink writes to
            // `send_divergent_iel_events` once we have the full picture.
            current_since = events.last().map(|e| e.said);
            post_divergence.extend(events);
        } else {
            // Phase 1: scan for divergence on this page.
            if has_more || events.len() > page_size {
                held_back = events.pop();
            }

            if events.is_empty() {
                if !has_more {
                    break;
                }
                continue;
            }

            // Detect divergence: two consecutive events at the same version
            // in canonical sort order indicate a fork.
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
                    return Err(KelsError::InvalidIel(format!(
                        "IEL generation at version {} has {} events, max 2 allowed",
                        div_version, same_version_count
                    )));
                }

                divergence_found = true;
                pre_divergence = events[..div_idx].to_vec();
                post_divergence = events[div_idx..].to_vec();

                if let Some(held) = held_back.take() {
                    current_since = Some(held.said);
                    post_divergence.push(held);
                } else {
                    current_since = post_divergence.last().map(|e| e.said);
                }
            } else {
                // No divergence on this page — straight passthrough.
                sink.store_page(&events).await?;
                current_since = events.last().map(|e| e.said);
            }
        }

        if !has_more {
            break;
        }

        if let Some(ref held) = held_back {
            current_since = Some(held.said);
        }
    }

    // Final held-back event handling — same shape as SE's transfer.
    if let Some(held) = held_back {
        if divergence_found {
            post_divergence.push(held);
        } else {
            sink.store_page(std::slice::from_ref(&held)).await?;
        }
    }

    if !divergence_found {
        return Ok(());
    }

    send_divergent_iel_events(sink, &pre_divergence, post_divergence, page_size).await
}

/// Forward a remote IEL chain into a local sink, paged. Detects divergence
/// at page boundaries and uses [`send_divergent_iel_events`] to partition
/// the post-divergence events into batches the receiver's submit handler
/// will accept under its routing rules. Mirrors `forward_sad_events`.
pub async fn forward_identity_events(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    sink: &(dyn PagedIelSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    transfer_identity_events(prefix, source, sink, page_size, max_pages, since).await
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
    iel_completed_verification_with_queried(
        loader,
        prefix,
        checker,
        page_size,
        max_pages,
        BTreeSet::new(),
    )
    .await
}

/// `iel_completed_verification` plus caller-bounded SAID querying. The
/// queried set is registered on the `IelVerifier` before the walk so the
/// resulting token's `is_said_satisfied` answers correctly. Mirrors
/// `KelVerifier::check_anchors` integrated with the verification helper.
///
/// #147 follow-up: shared entry point for resolver impls
/// ([`AnchoredIelResolver::is_satisfied`](crate::AnchoredIelResolver),
/// the in-process `RepositoryIelResolver`) so the page-walk + verifier
/// construction lives in one place.
pub async fn iel_completed_verification_with_queried(
    loader: &mut dyn IelPageLoader,
    prefix: &cesr::Digest256,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
    queried_saids: BTreeSet<cesr::Digest256>,
) -> Result<IelVerification, KelsError> {
    let mut verifier = IelVerifier::new(Some(prefix), checker);
    if !queried_saids.is_empty() {
        verifier.check_satisfied(queried_saids);
    }
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
    verify_identity_events_with_queried(
        prefix,
        source,
        checker,
        page_size,
        max_pages,
        BTreeSet::new(),
    )
    .await
}

/// `verify_identity_events` plus caller-bounded SAID querying. Registers
/// `queried_saids` on the `IelVerifier` before the walk so the resulting
/// token's `is_said_satisfied` answers correctly.
///
/// #147 follow-up: shared entry point for `AnchoredIelResolver`
/// (HTTP source) and any other `PagedIelSource` consumer that needs the
/// queried/satisfied surface.
pub async fn verify_identity_events_with_queried(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
    queried_saids: BTreeSet<cesr::Digest256>,
) -> Result<IelVerification, KelsError> {
    verify_identity_events_inner(
        prefix,
        source,
        checker,
        page_size,
        max_pages,
        queried_saids,
        |_| {},
    )
    .await
}

/// Verify an IEL with a per-page callback that fires after each page passes
/// verification. Mirrors `verify_key_events_with` for the IEL primitive.
///
/// The callback receives `&[IdentityEvent]` for each page batch in the
/// canonical sort order delivered by the source. Used by the CLI's
/// `kels iel get` to stream events while the verifier walks the chain.
pub async fn verify_identity_events_with<F>(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
    on_page: F,
) -> Result<IelVerification, KelsError>
where
    F: FnMut(&[IdentityEvent]) + Send,
{
    verify_identity_events_inner(
        prefix,
        source,
        checker,
        page_size,
        max_pages,
        BTreeSet::new(),
        on_page,
    )
    .await
}

async fn verify_identity_events_inner<F>(
    prefix: &cesr::Digest256,
    source: &(dyn PagedIelSource + Sync),
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
    queried_saids: BTreeSet<cesr::Digest256>,
    mut on_page: F,
) -> Result<IelVerification, KelsError>
where
    F: FnMut(&[IdentityEvent]) + Send,
{
    let mut verifier = IelVerifier::new(Some(prefix), checker);
    if !queried_saids.is_empty() {
        verifier.check_satisfied(queried_saids);
    }
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
        on_page(&events);

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

    /// Wire-level mapping contract: a 409 from the IEL submit endpoint
    /// surfaces as `KelsError::ServerError(_, ErrorCode::Conflict)`,
    /// not `InternalError`. Mirrors the SE-side test in
    /// `lib/kels/src/types/sad/sync.rs` — #147 follow-up dropped
    /// both 409 and 403 silent-skips (replaced by 200-with-`terminal`
    /// for the gossip-race-already-terminal case).
    /// Owner-side and gossip-relay callers now both see `Conflict`
    /// for genuine `save_batch` conflicts.
    #[tokio::test]
    async fn http_iel_sink_409_maps_to_conflict_error_code() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/iel/events"))
            .respond_with(ResponseTemplate::new(409).set_body_string(
                "Cannot fork at version 2 — sealed by governance evaluation at version 3",
            ))
            .mount(&mock_server)
            .await;

        let sink = HttpIelSink::new(&mock_server.uri()).expect("sink");
        let chain = make_chain(1);
        let result = sink.store_page(&chain).await;
        match result {
            Err(KelsError::ServerError(body, ErrorCode::Conflict)) => {
                assert!(
                    body.contains("Cannot fork"),
                    "body should preserve server message, got: {body}"
                );
            }
            other => panic!("expected ServerError(_, Conflict), got {other:?}"),
        }
    }

    /// 500 from IEL submit (server-internal integrity, e.g.
    /// `KelsError::ChainVerificationFailed` from
    /// `verify_existing_iel_chain`) maps to
    /// `ServerError(_, ErrorCode::InternalError)` with the variant's
    /// Display prefix preserved in the body.
    #[tokio::test]
    async fn http_iel_sink_500_with_chain_verification_body_maps_to_internal_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/iel/events"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("Chain verification failed: invalid said in stored event"),
            )
            .mount(&mock_server)
            .await;

        let sink = HttpIelSink::new(&mock_server.uri()).expect("sink");
        let chain = make_chain(1);
        let result = sink.store_page(&chain).await;
        match result {
            Err(KelsError::ServerError(body, ErrorCode::InternalError)) => {
                assert!(
                    body.starts_with("Chain verification failed:"),
                    "body should preserve `ChainVerificationFailed` Display prefix, got: {body}"
                );
            }
            other => panic!("expected ServerError(_, InternalError), got {other:?}"),
        }
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

    // ==================== #147 follow-up: page partitioning ====================

    /// Collecting sink — records every page passed to `store_page` so tests
    /// can assert the exact partitioning sequence.
    struct CollectingSink {
        pages: tokio::sync::Mutex<Vec<Vec<IdentityEvent>>>,
    }

    impl CollectingSink {
        fn new() -> Self {
            Self {
                pages: tokio::sync::Mutex::new(Vec::new()),
            }
        }

        async fn pages(&self) -> Vec<Vec<IdentityEvent>> {
            self.pages.lock().await.clone()
        }
    }

    #[async_trait]
    impl PagedIelSink for CollectingSink {
        async fn store_page(&self, events: &[IdentityEvent]) -> Result<(), KelsError> {
            self.pages.lock().await.push(events.to_vec());
            Ok(())
        }
    }

    /// Build a contested-divergent IEL chain in canonical sort order and
    /// confirm `forward_identity_events` partitions it into:
    ///   1. pre-divergence + non-cnt chain (paged appends)
    ///   2. cnt-chain (atomic single-page batch)
    ///
    /// Mirrors KEL's `send_divergent_events` contested case at
    /// `lib/kels/src/types/kel/sync.rs:572-610`.
    #[tokio::test]
    async fn forward_partitions_contested_divergent_iel_into_non_cnt_then_cnt_chain() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let icp = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let prefix = icp.prefix;

        // Two competing v=1 events: one Evl, one Cnt. Cnt creates the
        // divergence (post-Evl Cnt would have higher version).
        let evl_a = IdentityEvent::evl(&icp, None, None).unwrap();
        let cnt_b = IdentityEvent::cnt(&icp).unwrap();

        // Canonical sort order: at v=1 Evl (kind=1) sorts before Cnt
        // (kind=2). Source serves them in canonical order.
        let chain = vec![icp.clone(), evl_a.clone(), cnt_b.clone()];
        let source = VecSource {
            events: chain.clone(),
        };
        let sink = CollectingSink::new();

        forward_identity_events(&prefix, &source, &sink, 16, 8, None)
            .await
            .expect("forward succeeds on contested divergent IEL");

        let pages = sink.pages().await;
        // Expect at least two pages: the non-cnt chain (Icp + Evl) and the
        // cnt chain (Cnt). The exact paging count depends on `page_size`
        // but the partition shape is fixed.
        let sent_events: Vec<IdentityEvent> = pages.iter().flatten().cloned().collect();

        // Non-cnt chain comes first: should include Icp and Evl, in that
        // order, before the Cnt page.
        let cnt_page_idx = pages
            .iter()
            .position(|page| page.iter().any(|e| e.kind.is_contest()))
            .expect("cnt page present");
        let non_cnt_pages = &pages[..cnt_page_idx];
        let cnt_page = &pages[cnt_page_idx];

        // Pre-divergence + non-cnt chain (Evl branch): should contain Icp
        // and Evl, no Cnt.
        let non_cnt_events: Vec<IdentityEvent> = non_cnt_pages.iter().flatten().cloned().collect();
        assert!(non_cnt_events.iter().any(|e| e.said == icp.said));
        assert!(non_cnt_events.iter().any(|e| e.said == evl_a.said));
        assert!(non_cnt_events.iter().all(|e| !e.kind.is_contest()));

        // Cnt page: contains the Cnt event, sent atomically.
        assert_eq!(cnt_page.len(), 1);
        assert_eq!(cnt_page[0].said, cnt_b.said);

        // Sanity: every event in the source ends up sent exactly once.
        assert_eq!(sent_events.len(), chain.len());
        for source_event in &chain {
            assert!(
                sent_events.iter().any(|e| e.said == source_event.said),
                "event {} not in sink output",
                source_event.said
            );
        }
    }

    /// Linear (non-divergent) IEL forward: same single-page passthrough as
    /// before — `forward_identity_events` returns Ok without invoking the
    /// divergence path. Pinned to confirm the wrapper doesn't perturb the
    /// happy path.
    #[tokio::test]
    async fn forward_linear_iel_passes_chain_through_unchanged() {
        let chain = make_chain(3);
        let prefix = chain[0].prefix;
        let source = VecSource {
            events: chain.clone(),
        };
        let sink = CollectingSink::new();

        forward_identity_events(&prefix, &source, &sink, 16, 8, None)
            .await
            .expect("forward succeeds on linear IEL");

        let sent: Vec<IdentityEvent> = sink.pages().await.into_iter().flatten().collect();
        assert_eq!(sent.len(), chain.len());
        for (i, e) in sent.iter().enumerate() {
            assert_eq!(e.said, chain[i].said, "event {i} mismatch");
        }
    }

    /// Unrecovered divergent IEL — no Cnt on either branch (defensive
    /// case; production routing rejects this state with `ContestRequired`).
    /// Send order: longer chain as paged appends, then fork event from
    /// shorter chain establishes divergence at the receiver. Mirrors
    /// KEL's unrecovered-divergence path.
    #[tokio::test]
    async fn forward_unrecovered_divergent_iel_sends_longer_chain_then_fork_event() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let icp = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let prefix = icp.prefix;

        // Two competing Evls at v=1. Use distinct auth_policy SAIDs to
        // produce different branch-tip SAIDs (Evl constructors derive
        // SAIDs from event content).
        let auth_a = test_digest(b"auth-a");
        let auth_b = test_digest(b"auth-b");
        let evl_a = IdentityEvent::evl(&icp, Some(auth_a), None).unwrap();
        let evl_b = IdentityEvent::evl(&icp, Some(auth_b), None).unwrap();
        // Add a v=2 Evl extending one of them so that branch is "longer".
        // Pick canonically-first branch by SAID for determinism.
        let (longer_v1, shorter_v1) = if evl_a.said.as_ref() < evl_b.said.as_ref() {
            (evl_a.clone(), evl_b.clone())
        } else {
            (evl_b.clone(), evl_a.clone())
        };
        let evl_v2 = IdentityEvent::evl(&longer_v1, None, None).unwrap();

        // Canonical sort: Icp@0, then v=1 Evls (by said), then v=2 Evl.
        let chain = vec![
            icp.clone(),
            longer_v1.clone(),
            shorter_v1.clone(),
            evl_v2.clone(),
        ];
        let source = VecSource {
            events: chain.clone(),
        };
        let sink = CollectingSink::new();

        forward_identity_events(&prefix, &source, &sink, 16, 8, None)
            .await
            .expect("forward succeeds on unrecovered divergent IEL");

        let pages = sink.pages().await;

        // Partition: longer chain (Icp + longer_v1 + evl_v2) must come
        // before the fork event (shorter_v1).
        let fork_page_idx = pages
            .iter()
            .position(|page| page.iter().any(|e| e.said == shorter_v1.said))
            .expect("fork event page present");
        let pre_fork_events: Vec<IdentityEvent> =
            pages[..fork_page_idx].iter().flatten().cloned().collect();
        assert!(pre_fork_events.iter().any(|e| e.said == icp.said));
        assert!(pre_fork_events.iter().any(|e| e.said == longer_v1.said));
        assert!(pre_fork_events.iter().any(|e| e.said == evl_v2.said));
        assert!(!pre_fork_events.iter().any(|e| e.said == shorter_v1.said));

        // Fork event page is a single-event batch.
        assert_eq!(pages[fork_page_idx].len(), 1);
        assert_eq!(pages[fork_page_idx][0].said, shorter_v1.said);
    }

    /// Multi-page contested-divergent partitioning: pre-divergence + non-cnt
    /// chain spans multiple pages. Each chunk is sent as a paged append, the
    /// cnt-chain as an atomic single-page batch at the end.
    #[tokio::test]
    async fn forward_partitions_contested_divergent_iel_with_multi_page_non_cnt_chain() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let icp = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let prefix = icp.prefix;

        // Linear pre-divergence chain: Icp@0, Evl@1, Evl@2, Evl@3, Evl@4.
        // Then divergence at v=5: an Evl on the linear branch + a Cnt
        // creating divergence by extending v=4.
        let mut linear = vec![icp.clone()];
        for _ in 1..=4 {
            #[allow(clippy::expect_used)]
            let prev = linear.last().expect("non-empty");
            linear.push(IdentityEvent::evl(prev, None, None).unwrap());
        }
        let evl_v5 = IdentityEvent::evl(linear.last().unwrap(), None, None).unwrap();
        let cnt_v5 = IdentityEvent::cnt(linear.last().unwrap()).unwrap();
        // Canonical sort at v=5: Evl (kind=1) before Cnt (kind=2).
        let mut chain = linear.clone();
        chain.push(evl_v5.clone());
        chain.push(cnt_v5.clone());

        let source = VecSource {
            events: chain.clone(),
        };
        let sink = CollectingSink::new();

        // page_size=2 forces multiple pages over the pre-divergence + non-cnt
        // chain (Icp..Evl_v4 + Evl_v5 = 6 events at 2 per page = 3 pages).
        forward_identity_events(&prefix, &source, &sink, 2, 16, None)
            .await
            .expect("multi-page partitioning succeeds");

        let pages = sink.pages().await;
        // Cnt page comes last, atomically (1 event).
        let cnt_page = pages.last().expect("at least one page");
        assert_eq!(cnt_page.len(), 1, "cnt-chain page is atomic");
        assert!(cnt_page.iter().any(|e| e.kind.is_contest()));

        // Non-cnt chunks: collect everything before the cnt page; should
        // span ≥2 pages and contain Icp, Evls v=1..=5 (non-cnt branch).
        let non_cnt_pages = &pages[..pages.len() - 1];
        assert!(
            non_cnt_pages.len() >= 2,
            "non-cnt chain spans multiple pages"
        );
        let non_cnt_events: Vec<IdentityEvent> = non_cnt_pages.iter().flatten().cloned().collect();
        assert!(non_cnt_events.iter().all(|e| !e.kind.is_contest()));
        assert!(non_cnt_events.iter().any(|e| e.said == evl_v5.said));
        // The Cnt itself is on its own page; pre-divergence events plus
        // non-cnt branch should total 6 events.
        assert_eq!(non_cnt_events.len(), 6);
    }

    /// Divergence detection across a page boundary: the held-back-event
    /// strategy in `transfer_identity_events` must surface a same-version
    /// overlap that's split between two pages. Construct a chain where
    /// the divergence-creating event lands as the FIRST event of page 2,
    /// with its same-version sibling at the END of page 1.
    #[tokio::test]
    async fn forward_detects_divergence_at_page_boundary_via_held_back_event() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let icp = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let prefix = icp.prefix;

        // Linear v=0..=2, then divergence at v=3 between Evl@v3 and Cnt@v3.
        // We want Evl@v3 to land at page-end and Cnt@v3 at page-start.
        // With page_size=4 and chain length 5 (Icp + Evl@1 + Evl@2 + Evl@v3 +
        // Cnt@v3), page 1 = first 4 events (Icp, Evl@1, Evl@2, Evl@v3),
        // page 2 = [Cnt@v3]. The divergence-creating Cnt is on page 2.
        let evl_v1 = IdentityEvent::evl(&icp, None, None).unwrap();
        let evl_v2 = IdentityEvent::evl(&evl_v1, None, None).unwrap();
        let evl_v3 = IdentityEvent::evl(&evl_v2, None, None).unwrap();
        let cnt_v3 = IdentityEvent::cnt(&evl_v2).unwrap();
        let chain = vec![
            icp.clone(),
            evl_v1.clone(),
            evl_v2.clone(),
            evl_v3.clone(),
            cnt_v3.clone(),
        ];

        let source = VecSource {
            events: chain.clone(),
        };
        let sink = CollectingSink::new();

        // page_size=4 → page 1 = Icp..Evl@v3, page 2 = [Cnt@v3]. The held-back
        // event from page 1 (Evl@v3) prepends to page 2's contents to make
        // the same-version overlap visible to the divergence detector.
        forward_identity_events(&prefix, &source, &sink, 4, 8, None)
            .await
            .expect("page-boundary divergence detection succeeds");

        let pages = sink.pages().await;
        // Verify the contested partition shape: non-cnt chain (Icp + Evls)
        // sent first, Cnt sent atomically last.
        let last = pages.last().expect("at least one page");
        assert_eq!(last.len(), 1);
        assert!(last[0].kind.is_contest());
        assert_eq!(last[0].said, cnt_v3.said);

        // Total events sent equals chain length.
        let sent_count: usize = pages.iter().map(Vec::len).sum();
        assert_eq!(sent_count, chain.len());
    }
}
