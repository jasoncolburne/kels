//! KEL sync infrastructure — paged sources, sinks, and transfer functions.
//!
//! `PagedKelSource` / `PagedKelSink` / `transfer_key_events` provide divergence-aware
//! streaming of events from a source through a verifier into a destination.

use std::{
    collections::{HashMap, HashSet},
    slice,
};

use async_trait::async_trait;
use cesr::VerificationKey;
use tracing::warn;

use super::event::SignedKeyEvent;
use super::verification::{KelVerification, KelVerifier, truncate_incomplete_generation};
use crate::error::KelsError;
use crate::store::KelStore;

/// Trait for loading pages of signed key events. Implemented by `KelStore`
/// and by transaction wrappers that read under advisory locks.
#[async_trait]
pub trait PageLoader: Send + Sync {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;
}

/// `KelStore` adapter for `PageLoader` — wraps a shared reference.
pub struct StorePageLoader<'a>(&'a dyn KelStore);

impl<'a> StorePageLoader<'a> {
    pub fn new(store: &'a dyn KelStore) -> Self {
        Self(store)
    }
}

#[async_trait]
impl PageLoader for StorePageLoader<'_> {
    async fn load_page(
        &mut self,
        prefix: &cesr::Digest,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.0.load(prefix, limit, offset).await
    }
}

/// Adapts a `KelStore` (offset-based) into a `PagedKelSource` (SAID-based).
///
/// Resolves `since` SAIDs by scanning for the matching event.
///
/// **Warning:** `fetch_page` with `since` loads the entire KEL into memory (O(N))
/// to find the offset of the `since` SAID. Only suitable for dev-tools and CLI
/// usage, not production workloads.
pub struct StoreKelSource<'a>(&'a dyn KelStore);

impl<'a> StoreKelSource<'a> {
    pub fn new(store: &'a dyn KelStore) -> Self {
        Self(store)
    }
}

#[async_trait]
impl PagedKelSource for StoreKelSource<'_> {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest,
        since: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        if let Some(said) = since {
            // Scan to find the offset of the `since` SAID
            let (all, _) = self.0.load(prefix, crate::LOAD_ALL, 0).await?;
            let offset = all
                .iter()
                .position(|e| &e.event.said == said)
                .ok_or_else(|| KelsError::NotFound(prefix.to_string()))?;
            let start = offset + 1;
            let end = (start + limit).min(all.len());
            let has_more = end < all.len();
            Ok((all[start..end].to_vec(), has_more))
        } else {
            self.0.load(prefix, limit as u64, 0).await
        }
    }
}

/// Verify a full KEL using paginated reads, returning a trusted `KelVerification`.
///
/// Pages through the loader with `KelVerifier` and returns the proof-of-verification
/// token. `max_pages` limits resource exhaustion from enormous KELs — fails secure
/// if exceeded.
///
/// `anchor_saids` optionally registers SAIDs to check for anchoring during the walk.
/// Results are available via `KelVerification::anchored_saids()` / `anchors_all_saids()`.
///
/// Use `StorePageLoader` to wrap a `&dyn KelStore`, or implement `PageLoader` on a
/// locked transaction wrapper to read under advisory lock.
pub async fn completed_verification(
    loader: &mut dyn PageLoader,
    prefix: &cesr::Digest,
    page_size: usize,
    max_pages: usize,
    anchor_saids: impl IntoIterator<Item = cesr::Digest>,
) -> Result<KelVerification, KelsError> {
    let mut verifier = KelVerifier::new(prefix);
    verifier.check_anchors(anchor_saids);
    let mut offset: u64 = 0;
    let mut exhausted = false;
    let limit = page_size as u64;

    for _ in 0..max_pages {
        let (mut events, has_more) = loader.load_page(prefix, limit, offset).await?;

        if events.is_empty() {
            exhausted = true;
            break;
        }

        // Ensure complete generations at page boundary
        let truncated = if has_more {
            truncate_incomplete_generation(&mut events)
        } else {
            0
        };

        let advanced = events.len() as u64;
        verifier.verify_page(&events)?;
        offset += advanced;

        // Break if the source is exhausted, or if truncation removed all events
        // (every event belonged to an incomplete final generation) — continuing
        // would loop forever since the offset can't advance.
        if !has_more || (truncated > 0 && advanced == 0) {
            exhausted = true;
            break;
        }
    }

    // Fail secure: if we ran out of pages before exhausting the source,
    // return an error rather than a partial KelVerification.
    if !exhausted {
        return Err(KelsError::InvalidKel(format!(
            "KEL for {} exceeds max_pages limit ({}) — verification incomplete",
            prefix, max_pages,
        )));
    }

    verifier.into_verification()
}

// ==================== Sync Abstraction ====================

/// Source of paginated signed key events (e.g., HTTP client, local DB).
///
/// Implementations must return events in `serial ASC, kind sort_priority ASC, said ASC`
/// order. The `bool` return value indicates whether more pages are available (`has_more`).
/// Pages should contain complete generations (all events at a given serial together),
/// though `transfer_key_events` tolerates split generations via its held-back event strategy.
#[async_trait]
pub trait PagedKelSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest,
        since: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;
}

/// Destination for signed key events (e.g., local DB).
#[async_trait]
pub trait PagedKelSink: Send + Sync {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError>;
}

// ==================== HTTP Source/Sink Implementations ====================

/// HTTP-based source of paginated signed key events.
///
/// Works with any KELS-compatible HTTP endpoint. The path template may contain
/// `{prefix}` which is replaced with the actual prefix on each request.
///
/// Used by `verify_key_events`, `collect_key_events`, `forward_key_events`, and
/// `resolve_key_events` to abstract over different service endpoints.
pub struct HttpKelSource {
    base_url: String,
    /// Path template, e.g. "/api/v1/kels/kel/{prefix}" or "/api/v1/identity/kel"
    path: String,
    client: reqwest::Client,
}

impl HttpKelSource {
    pub fn new(base_url: &str, path: &str) -> Result<Self, KelsError> {
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            path: path.to_string(),
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}

#[async_trait]
impl PagedKelSource for HttpKelSource {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest,
        since: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        let path = self.path.replace("{prefix}", prefix.as_ref());
        let mut url = format!("{}{}?limit={}", self.base_url, path, limit);
        if let Some(since_said) = since {
            url.push_str(&format!("&since={}", since_said));
        }

        let resp = self.client.get(&url).send().await.map_err(|e| {
            KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
        })?;

        if resp.status().is_success() {
            let page: super::event::SignedKeyEventPage = resp.json().await.map_err(|e| {
                KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
            })?;
            Ok((page.events, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let err: crate::types::ErrorResponse = resp.json().await.map_err(|e| {
                KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
            })?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }
}

/// Sink that discards events — used for verify-only flows.
pub(crate) struct NoOpSink;

#[async_trait]
impl PagedKelSink for NoOpSink {
    async fn store_page(&self, _events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        Ok(())
    }
}

/// Sink that collects events into a `Vec` — used for resolve flows.
///
/// **WARNING:** This entity collects events in an unbounded loop, use with care.
#[cfg(any(test, feature = "dev-tools"))]
pub(crate) struct CollectSink {
    events: tokio::sync::Mutex<Vec<SignedKeyEvent>>,
}

#[cfg(any(test, feature = "dev-tools"))]
impl Default for CollectSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "dev-tools"))]
impl CollectSink {
    pub fn new() -> Self {
        Self {
            events: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    pub async fn into_events(self) -> Vec<SignedKeyEvent> {
        self.events.into_inner()
    }
}

#[cfg(any(test, feature = "dev-tools"))]
#[async_trait]
impl PagedKelSink for CollectSink {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        self.events.lock().await.extend_from_slice(events);
        Ok(())
    }
}

/// HTTP-based sink that submits events to a KELS service.
pub struct HttpKelSink {
    base_url: String,
    /// Path, e.g. "/api/v1/kels/events"
    path: String,
    client: reqwest::Client,
}

impl HttpKelSink {
    pub fn new(base_url: &str, path: &str) -> Result<Self, KelsError> {
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            path: path.to_string(),
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}

#[async_trait]
impl PagedKelSink for HttpKelSink {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        let url = format!("{}{}", self.base_url, self.path);

        let resp = self
            .client
            .post(&url)
            .json(events)
            .send()
            .await
            .map_err(|e| {
                KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
            })?;

        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == reqwest::StatusCode::GONE {
            let err: crate::types::ErrorResponse = resp.json().await.map_err(|e| {
                KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
            })?;
            Err(KelsError::ContestedKel(err.error))
        } else {
            let err: crate::types::ErrorResponse = resp.json().await.map_err(|e| {
                KelsError::ServerError(e.to_string(), crate::types::ErrorCode::InternalError)
            })?;
            if err.code == crate::types::ErrorCode::ContestRequired {
                Err(KelsError::ContestRequired)
            } else {
                Err(KelsError::ServerError(err.error, err.code))
            }
        }
    }
}

// ==================== Transfer Functions ====================

/// Core transfer function: pages through source, optionally verifies, sends to sink.
///
/// Handles divergence-aware ordering. On divergence, all post-divergence events
/// are collected in memory (bounded: max 2 × page_size + 2 events, since each
/// branch is limited to page_size by the submission limit, plus rec+rot). Events
/// are then separated into owner and adversary chains and submitted in the correct
/// order so the remote merge engine can process them:
///
/// 1. Pre-divergence events (paged normally)
/// 2. Longer chain (paged normally as non-divergent appends)
/// 3. Single fork event from shorter chain + rec(+rot) (atomic batch: creates
///    divergence and resolves it in one submission)
///
/// For unrecovered divergence (no rec), the recovery-revealing branch is deferred
/// so the non-revealing branch establishes divergence first.
async fn transfer_key_events(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    sink: &(dyn PagedKelSink + Sync),
    mut verifier: Option<&mut KelVerifier>,
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest>,
) -> Result<(), KelsError> {
    if verifier.is_some() && since.is_some() {
        return Err(KelsError::InvalidKel(
            "Cannot use since with verification — verifier must see the full chain".to_string(),
        ));
    }

    let mut since: Option<cesr::Digest> = since.cloned();
    // Hold back the last event when has_more is true. If the next page's
    // first event has the same serial, we've found a divergent pair. If not,
    // it's just a normal event and we process it with the next batch.
    let mut held_back: Option<SignedKeyEvent> = None;
    // When divergence is detected, we switch to collection mode and accumulate
    // all remaining events before submitting them in the correct order.
    let mut divergence_found = false;
    let mut pre_divergence: Vec<SignedKeyEvent> = Vec::new();
    let mut post_divergence: Vec<SignedKeyEvent> = Vec::new();

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
                v.verify_page(&events)?;
            }
            since = events.last().map(|e| e.event.said.clone());
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
                v.verify_page(&events)?;
            }

            let mut divergence_idx: Option<usize> = None;
            for i in 1..events.len() {
                if events[i].event.serial == events[i - 1].event.serial {
                    divergence_idx = Some(i - 1);
                    break;
                }
            }

            if let Some(div_idx) = divergence_idx {
                let div_serial = events[div_idx].event.serial;
                let same_serial_count = events
                    .iter()
                    .filter(|e| e.event.serial == div_serial)
                    .count();
                if same_serial_count > 2 {
                    return Err(KelsError::InvalidKel(format!(
                        "Generation at serial {} has {} events, max 2 allowed",
                        div_serial, same_serial_count
                    )));
                }

                divergence_found = true;
                pre_divergence = events[..div_idx].to_vec();
                post_divergence = events[div_idx..].to_vec();

                // Include held-back event in post-divergence collection and
                // advance since cursor past it to avoid double-fetching.
                if let Some(held) = held_back.take() {
                    since = Some(held.event.said.clone());
                    post_divergence.push(held);
                } else {
                    since = post_divergence.last().map(|e| e.event.said.clone());
                }
            } else {
                // No divergence on this page
                sink.store_page(&events).await?;
                since = events.last().map(|e| e.event.said.clone());
            }
        }

        if !has_more {
            break;
        }

        if let Some(ref held) = held_back {
            since = Some(held.event.said.clone());
        }
    }

    // Process final held-back event
    if let Some(held) = held_back {
        if divergence_found {
            post_divergence.push(held);
        } else {
            if let Some(ref mut v) = verifier {
                v.verify_page(slice::from_ref(&held))?;
            }
            sink.store_page(slice::from_ref(&held)).await?;
        }
    }

    if !divergence_found {
        return Ok(());
    }

    // Submit divergent events in the correct order
    send_divergent_events(sink, &pre_divergence, post_divergence, page_size).await
}

/// Separate post-divergence events into owner and adversary chains, then send
/// to the sink in an order compatible with the remote merge engine.
///
/// For recovered divergence:
///   1. Pre-divergence + longer chain (paged, non-divergent appends)
///   2. Single fork event from shorter chain (creates divergence)
///   3. rec(+rot) (resolves divergence)
///
/// For unrecovered divergence:
///   1. Pre-divergence + non-revealing chain (paged, non-divergent appends)
///   2. Revealing chain (creates divergence; warn on failure)
async fn send_divergent_events(
    sink: &(dyn PagedKelSink + Sync),
    pre_divergence: &[SignedKeyEvent],
    post_divergence: Vec<SignedKeyEvent>,
    page_size: usize,
) -> Result<(), KelsError> {
    if post_divergence.len() < 2 {
        return Err(KelsError::InvalidKel(
            "Divergent KEL must have at least 2 events at divergence point".to_string(),
        ));
    }

    // With synchronous archival, a divergent KEL should only contain cnt
    // (contested) or no terminal events (unrecovered, awaiting owner action).
    // A divergent KEL with rec but no cnt indicates possible DB tampering —
    // recovery archives adversary events atomically, so both branches should
    // never coexist with a rec in the live tables. Refuse to propagate.
    let has_contest = post_divergence.iter().any(|e| e.event.is_contest());
    let has_recovery = post_divergence.iter().any(|e| e.event.is_recover());

    if has_recovery && !has_contest {
        return Err(KelsError::InvalidKel(
            "Divergent KEL contains rec without cnt — possible DB tampering \
             (recovery archival is synchronous)"
                .to_string(),
        ));
    }

    // Unrecovered or contested divergence.
    // Build two chains by tracing forward from each fork event.
    let mut chain_a_saids = HashSet::new();
    let mut chain_b_saids = HashSet::new();
    chain_a_saids.insert(post_divergence[0].event.said.clone());
    chain_b_saids.insert(post_divergence[1].event.said.clone());

    for evt in &post_divergence[2..] {
        if let Some(prev) = evt.event.previous.as_ref() {
            if chain_a_saids.contains(prev) {
                chain_a_saids.insert(evt.event.said.clone());
            } else if chain_b_saids.contains(prev) {
                chain_b_saids.insert(evt.event.said.clone());
            }
        }
    }

    let mut chain_a: Vec<SignedKeyEvent> = Vec::new();
    let mut chain_b: Vec<SignedKeyEvent> = Vec::new();
    for evt in post_divergence {
        if chain_a_saids.contains(&evt.event.said) {
            chain_a.push(evt);
        } else {
            chain_b.push(evt);
        }
    }

    if has_contest {
        // Contested: partition by which chain has cnt, not by length.
        // Send non-cnt chain first as paged appends (may exceed one page if
        // the adversary extended with multiple ROR cycles before detection),
        // then cnt chain as atomic batch (bounded to one page by proactive
        // ROR invariant).
        let chain_a_has_cnt = chain_a.iter().any(|e| e.event.is_contest());
        let (non_cnt_chain, cnt_chain) = if chain_a_has_cnt {
            (chain_b, chain_a)
        } else {
            (chain_a, chain_b)
        };

        // Step 1: pre-divergence + non-cnt chain (non-divergent appends)
        let mut non_divergent = pre_divergence.to_vec();
        non_divergent.extend(non_cnt_chain);
        for chunk in non_divergent.chunks(page_size) {
            sink.store_page(chunk).await?;
        }

        // Step 2: cnt chain as atomic batch (creates divergence + contest).
        // The cnt chain must fit in one page (proactive ROR invariant). If it
        // doesn't, the DB has been tampered with — refuse to propagate.
        if cnt_chain.len() > crate::MINIMUM_PAGE_SIZE {
            return Err(KelsError::InvalidKel(format!(
                "Contest chain exceeds page bound ({} > {}) — possible DB tampering",
                cnt_chain.len(),
                crate::MINIMUM_PAGE_SIZE,
            )));
        }
        match sink.store_page(&cnt_chain).await {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    "Contest chain submission failed \
                     (KEL may already be divergent): {e}"
                );
            }
        }
    } else {
        // Unrecovered: longer chain first as non-divergent appends, then
        // just the fork event from the shorter chain to establish divergence.
        let (longer, shorter) = if chain_a.len() > chain_b.len() {
            (chain_a, chain_b)
        } else if chain_b.len() > chain_a.len() {
            (chain_b, chain_a)
        } else if chain_b.iter().any(|e| e.event.reveals_recovery_key()) {
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

        // Fork event from shorter chain (creates divergence)
        if let Some(fork) = shorter.first() {
            match sink.store_page(slice::from_ref(fork)).await {
                Ok(()) => {}
                Err(e) => {
                    warn!(
                        "Deferred branch submission failed \
                         (KEL may already be divergent): {e}"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Verify-only: pages through source, verifies, returns `KelVerification`.
pub async fn verify_key_events(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    verifier: KelVerifier,
    page_size: usize,
    max_pages: usize,
) -> Result<KelVerification, KelsError> {
    let sink = NoOpSink;
    let mut verifier = verifier;
    transfer_key_events(
        prefix,
        source,
        &sink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;
    verifier.into_verification()
}

/// Verify-only with establishment key collection: pages through source, verifies,
/// returns `KelVerification` plus collected establishment keys.
///
/// The verifier must have been constructed with `with_establishment_key_collection`.
pub async fn verify_key_events_collecting_establishment_keys(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    verifier: KelVerifier,
    page_size: usize,
    max_pages: usize,
) -> Result<(KelVerification, HashMap<u64, VerificationKey>), KelsError> {
    let sink = NoOpSink;
    let mut verifier = verifier;
    transfer_key_events(
        prefix,
        source,
        &sink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;
    verifier.into_verification_with_keys()
}

/// Verify with callback: pages through source, verifies, calls `on_page` with each
/// batch of verified events, then returns `KelVerification`.
///
/// The callback receives `&[SignedKeyEvent]` for each batch. Batches may be smaller
/// than `page_size` due to divergence handling. Completion is signaled by the function
/// returning.
pub async fn verify_key_events_with<F>(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    verifier: KelVerifier,
    page_size: usize,
    max_pages: usize,
    on_page: F,
) -> Result<KelVerification, KelsError>
where
    F: FnMut(&[SignedKeyEvent]) + Send,
{
    let sink = CallbackSink(std::sync::Mutex::new(on_page));
    let mut verifier = verifier;
    transfer_key_events(
        prefix,
        source,
        &sink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;
    verifier.into_verification()
}

/// Sink that invokes a callback for each batch of events.
struct CallbackSink<F: FnMut(&[SignedKeyEvent]) + Send>(std::sync::Mutex<F>);

#[async_trait]
impl<F: FnMut(&[SignedKeyEvent]) + Send> PagedKelSink for CallbackSink<F> {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        if let Ok(mut f) = self.0.lock() {
            (f)(events);
        }
        Ok(())
    }
}

/// Forward without verification: pages through source, sends to sink.
///
/// `since` optionally starts the transfer from a specific SAID cursor (delta fetch).
pub async fn forward_key_events(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    sink: &(dyn PagedKelSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest>,
) -> Result<(), KelsError> {
    transfer_key_events(prefix, source, sink, None, page_size, max_pages, since).await
}

/// Resolve: pages through source, collects events (no verification).
///
/// `since` optionally starts the transfer from a specific SAID cursor (delta fetch).
///
/// **WARNING:** This is an unbounded call, and should be used with care.
#[cfg(any(test, feature = "dev-tools"))]
pub async fn resolve_key_events(
    prefix: &cesr::Digest,
    source: &(dyn PagedKelSource + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest>,
) -> Result<Vec<SignedKeyEvent>, KelsError> {
    let sink = CollectSink::new();
    transfer_key_events(prefix, source, &sink, None, page_size, max_pages, since).await?;
    Ok(sink.into_events().await)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        iter,
        sync::RwLock,
    };

    use async_trait::async_trait;
    use cesr::{Digest, Matter, SigningKey, VerificationKeyCode};
    use verifiable_storage::Chained;

    use super::super::verification::*;
    use super::*;
    use crate::{builder::KeyEventBuilder, crypto::SoftwareKeyProvider, store::KelStore};

    /// Helper to clone all keys from a builder's key provider
    fn clone_keys(
        builder: &KeyEventBuilder<SoftwareKeyProvider>,
    ) -> (SigningKey, SigningKey, SigningKey) {
        let software = builder.key_provider();
        (
            software.current_private_key().unwrap().clone(),
            software.next_private_key().unwrap().clone(),
            software.recovery_private_key().unwrap().clone(),
        )
    }

    /// Create a valid CESR anchor digest from a test label
    fn anchor(label: &str) -> cesr::Digest {
        Digest::blake3_256(label.as_bytes())
    }

    /// Create a SoftwareKeyProvider with random algorithm selection.
    /// Recovery algorithm is always >= signing algorithm strength.
    fn random_provider() -> SoftwareKeyProvider {
        use rand::Rng;
        let mut rng = rand::rng();
        let algorithms = [
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::MlDsa65,
            VerificationKeyCode::MlDsa87,
        ];
        let signing_idx = rng.random_range(0..algorithms.len());
        let recovery_idx = rng.random_range(signing_idx..algorithms.len());
        SoftwareKeyProvider::new(algorithms[signing_idx], algorithms[recovery_idx])
    }

    /// Sort events the way the DB would: serial ASC, kind sort_priority ASC, said ASC
    fn sort_events(events: &mut [SignedKeyEvent]) {
        events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(
                    a.event
                        .kind
                        .sort_priority()
                        .cmp(&b.event.kind.sort_priority()),
                )
                .then(a.event.said.cmp(&b.event.said))
        });
    }

    /// Verify events with KelVerifier and return KelVerification
    fn verify(events: &[SignedKeyEvent]) -> KelVerification {
        let prefix = &events[0].event.prefix;
        let mut verifier = KelVerifier::new(prefix);
        verifier.verify_page(events).unwrap();
        verifier.into_verification().unwrap()
    }

    /// Verify events with anchor checking and return KelVerification
    fn verify_with_anchors(
        events: &[SignedKeyEvent],
        anchors: impl IntoIterator<Item = cesr::Digest>,
    ) -> KelVerification {
        let prefix = &events[0].event.prefix;
        let mut verifier = KelVerifier::new(prefix);
        verifier.check_anchors(anchors);
        verifier.verify_page(events).unwrap();
        verifier.into_verification().unwrap()
    }

    /// In-memory store for testing
    struct MemoryStore {
        kels: RwLock<HashMap<String, Vec<SignedKeyEvent>>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                kels: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl KelStore for MemoryStore {
        async fn load(
            &self,
            prefix: &cesr::Digest,
            limit: u64,
            offset: u64,
        ) -> Result<(Vec<SignedKeyEvent>, bool), crate::error::KelsError> {
            let guard = self.kels.read().unwrap();
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
            prefix: &cesr::Digest,
            limit: u64,
        ) -> Result<Vec<SignedKeyEvent>, crate::error::KelsError> {
            let guard = self.kels.read().unwrap();
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
            prefix: &cesr::Digest,
            events: &[SignedKeyEvent],
        ) -> Result<(), crate::error::KelsError> {
            self.kels
                .write()
                .unwrap()
                .entry(prefix.to_string())
                .or_default()
                .extend(events.iter().cloned());
            Ok(())
        }

        async fn overwrite(
            &self,
            prefix: &cesr::Digest,
            events: &[SignedKeyEvent],
        ) -> Result<(), crate::error::KelsError> {
            self.kels
                .write()
                .unwrap()
                .insert(prefix.to_string(), events.to_vec());
            Ok(())
        }


    }

    #[tokio::test]
    async fn test_large_kel_paginated_verification() {
        // Build a KEL that spans 3 pages. The builder auto-inserts ror events
        // to maintain proactive recovery compliance, so we request enough ixn
        // events to exceed 2 full pages worth of total events.
        let page_size = crate::page_size();
        let target_events = 2 * page_size + 1;
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();

        // Keep adding ixn until we have enough events (including auto-rors)
        while builder.pending_events().len() < target_events {
            builder
                .interact(&Digest::blake3_256(
                    format!("anchor-{}", builder.pending_events().len()).as_bytes(),
                ))
                .await
                .unwrap();
        }

        let events = builder.pending_events().to_vec();
        let prefix = events[0].event.prefix.clone();
        assert!(events.len() >= target_events);

        // Save to MemoryStore
        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        // Verify — spans 3+ pages
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            page_size,
            100,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(!kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert!(!kel_verification.is_contested());
        assert!(!kel_verification.is_decommissioned());
        assert!(kel_verification.current_public_key().is_some());
        assert!(kel_verification.is_proactive_ror_compliant());

        // Tip should be the last event
        assert_eq!(kel_verification.branch_tips().len(), 1);
        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            events.last().unwrap().event.said
        );
    }

    #[tokio::test]
    async fn test_large_kel_with_early_divergence() {
        // Build a long KEL (spanning 2+ pages), then inject a divergent event
        // at serial 2. The builder auto-inserts rors for compliance.
        let page_size = crate::page_size();
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        builder1.incept().await.unwrap();
        builder1
            .interact(&Digest::blake3_256(b"anchor-1"))
            .await
            .unwrap();

        // Duplicate builder after icp+ixn1 (adversary has same keys)
        let mut builder2 = builder1.clone();

        // Owner continues building a long chain (2+ pages worth)
        while builder1.pending_events().len() < 2 * page_size + 1 {
            builder1
                .interact(&Digest::blake3_256(
                    format!("anchor-{}", builder1.pending_events().len()).as_bytes(),
                ))
                .await
                .unwrap();
        }

        let owner_events = builder1.pending_events().to_vec();
        let prefix = owner_events[0].event.prefix.clone();

        // Adversary injects one event at serial 2 (divergence)
        let adversary_ixn = builder2
            .interact(&Digest::blake3_256(b"adversary-anchor"))
            .await
            .unwrap();
        assert_eq!(adversary_ixn.event.serial, 2);

        // Combined events: owner chain + adversary event at serial 2
        let mut all_events = owner_events;
        all_events.push(adversary_ixn.clone());
        sort_events(&mut all_events);

        // Save to store
        let store = MemoryStore::new();
        store.overwrite(&prefix, &all_events).await.unwrap();

        // Verify with paginated reads — should detect divergence
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            page_size,
            100,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(2));
        assert_eq!(kel_verification.branch_tips().len(), 2);
    }

    #[tokio::test]
    async fn test_completed_verification_with_anchor_checking() {
        let target_anchor = cesr::Digest::blake3_256(b"target-anchor");
        let missing_anchor = cesr::Digest::blake3_256(b"missing-anchor");

        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let ixn = builder.interact(&target_anchor).await.unwrap();

        let store = MemoryStore::new();
        store.overwrite(&prefix, &[icp, ixn]).await.unwrap();

        // Check for an anchor that exists
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            100,
            iter::once(target_anchor.clone()),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_said_anchored(&target_anchor));
        assert!(kel_verification.anchors_all_saids());

        // Check for an anchor that doesn't exist
        let kel_verification2 = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            100,
            iter::once(missing_anchor.clone()),
        )
        .await
        .unwrap();

        assert!(!kel_verification2.is_said_anchored(&missing_anchor));
        assert!(!kel_verification2.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_max_pages_limit_fails_secure() {
        // Build a KEL larger than max_pages * page_size
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let mut events = vec![icp];
        for i in 0..20 {
            let ixn = builder
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()))
                .await
                .unwrap();
            events.push(ixn);
        }

        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        // Page size 5, max 2 pages = 10 events max, but we have 21
        let result = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            5,
            2,
            iter::empty(),
        )
        .await;

        // Should fail secure — incomplete verification returns an error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("max_pages limit"),
            "Error should mention max_pages limit, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_truncate_incomplete_generation_basic() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let ixn1 = builder1.interact(&Digest::blake3_256(b"a1")).await.unwrap();

        // Create adversary builder with same keys, reset to icp state
        let mut builder2 = KeyEventBuilder::with_events(
            builder1.key_provider().clone(),
            None,
            None,
            vec![icp.clone()],
        );
        let ixn2 = builder2.interact(&Digest::blake3_256(b"a2")).await.unwrap();

        // Two events at serial 1, simulating divergence
        // If a page ends with only one of them, truncate should remove it
        let mut events = [icp, ixn1.clone(), ixn2.clone()].to_vec();
        sort_events(&mut events);

        // Simulate page that has icp + first divergent event but not second
        let mut partial_page = events[..2].to_vec();
        let truncated = truncate_incomplete_generation(&mut partial_page);

        // Should truncate the lone serial-1 event since serial-0 has 1 event
        // but serial-1 should have 2 — we only have 1 of them
        // Actually: second-to-last serial (0) has 1 event, last serial (1) has 1 event
        // 1 == 1, so no truncation. This is correct — we can't know there should be 2
        // without seeing the second event.
        assert_eq!(truncated, 0);
    }

    // ==================== compute_rotation_hash ====================

    #[test]
    fn test_compute_rotation_hash() {
        let (public_key, _) = cesr::generate_secp256r1().unwrap();
        let hash = compute_rotation_hash(&public_key);
        assert_eq!(hash.as_ref().len(), 44);

        let hash2 = compute_rotation_hash(&public_key);
        assert_eq!(hash, hash2);
    }

    // ==================== Builder / Event Creation ====================

    #[tokio::test]
    async fn test_incept() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);

        let icp = builder.incept().await.unwrap();

        assert!(icp.event.is_inception());
        assert!(icp.event.previous.is_none());
        assert!(icp.event.public_key.is_some());
        assert!(icp.event.rotation_hash.is_some());

        let public_key = builder.current_public_key().await.unwrap();
        assert!(
            public_key
                .verify(
                    icp.event.said.qb64().as_bytes(),
                    &icp.signatures[0].signature
                )
                .is_ok()
        );

        assert_eq!(builder.prefix(), Some(&icp.event.prefix));
    }

    #[tokio::test]
    async fn test_interact() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);

        let icp = builder.incept().await.unwrap();

        let a = anchor("credential");
        let ixn = builder.interact(&a).await.unwrap();

        assert!(ixn.event.is_interaction());
        assert_ne!(ixn.event.said, icp.event.said);
        assert_eq!(ixn.event.prefix, icp.event.prefix);
        assert_eq!(ixn.event.previous, Some(icp.event.said.clone()));
        assert_eq!(ixn.event.anchor, Some(a));
        assert!(ixn.event.public_key.is_none());
        assert!(ixn.event.rotation_hash.is_none());
    }

    #[tokio::test]
    async fn test_rotate() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);

        let icp = builder.incept().await.unwrap();
        let original_public_key = builder.current_public_key().await.unwrap();

        let rot = builder.rotate().await.unwrap();

        assert!(rot.event.is_rotation());
        assert_ne!(rot.event.said, icp.event.said);
        assert_eq!(rot.event.prefix, icp.event.prefix);
        assert_eq!(rot.event.previous, Some(icp.event.said.clone()));
        assert!(rot.event.public_key.is_some());
        assert!(rot.event.rotation_hash.is_some());

        let new_public_key = builder.current_public_key().await.unwrap();
        assert_ne!(original_public_key.qb64(), new_public_key.qb64());

        let rotation_hash = icp.event.rotation_hash.unwrap();
        let expected_hash = compute_rotation_hash(&new_public_key);
        assert_eq!(rotation_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_interact_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let result = builder.interact(&anchor("some_anchor")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rotate_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let result = builder.rotate().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_said_verification() {
        use verifiable_storage::SelfAddressed;

        let mut builder = KeyEventBuilder::new(random_provider(), None);

        let icp = builder.incept().await.unwrap();
        assert!(icp.event.verify_prefix().is_ok());

        let ixn = builder.interact(&anchor("test")).await.unwrap();
        assert!(ixn.event.verify_said().is_ok());
    }

    #[tokio::test]
    async fn test_with_events() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            vec![icp.clone()],
        );

        let ixn = builder2.interact(&anchor("test")).await.unwrap();
        assert_eq!(ixn.event.prefix, icp.event.prefix);
        assert_eq!(ixn.event.previous, Some(icp.event.said.clone()));
    }

    #[tokio::test]
    async fn test_rotation_after_interactions() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        builder.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder);
        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            builder.pending_events().to_vec(),
        );

        assert_eq!(builder2.last_event().unwrap().said, ixn2.event.said);
        assert_eq!(
            builder2.last_establishment_event().unwrap().said,
            icp.event.said
        );

        let rot = builder2.rotate().await.unwrap();
        assert_eq!(rot.event.previous, Some(ixn2.event.said.clone()));
    }

    #[tokio::test]
    async fn test_json_roundtrip() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();

        let json = serde_json::to_string(&icp).unwrap();
        let deserialized: SignedKeyEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.event.said, icp.event.said);
        assert_eq!(deserialized.event.prefix, icp.event.prefix);

        let kel_verification = verify(&[deserialized]);
        assert!(!kel_verification.is_empty());
    }

    // ==================== KelVerifier — basic verification ====================

    #[tokio::test]
    async fn test_verify_basic_kel() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        let ixn = builder.interact(&anchor("test")).await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(!kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert!(!kel_verification.is_contested());
        assert!(!kel_verification.is_decommissioned());
        assert!(kel_verification.current_public_key().is_some());
        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            ixn.event.said
        );
    }

    #[tokio::test]
    async fn test_verify_with_rotation() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        builder.interact(&anchor("a1")).await.unwrap();
        let rot = builder.rotate().await.unwrap();
        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let kel_verification = verify(builder.pending_events());

        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            ixn2.event.said
        );
        assert_eq!(
            kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .said,
            rot.event.said
        );

        let rot_key = rot.event.public_key.as_ref().unwrap();
        let icp_key = icp.event.public_key.as_ref().unwrap();
        assert_ne!(kel_verification.current_public_key().unwrap(), icp_key);
        assert_eq!(kel_verification.current_public_key().unwrap(), rot_key);
    }

    // ==================== KelVerifier — divergence detection ====================

    #[tokio::test]
    async fn test_divergence_two_way() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        assert_ne!(ixn1.event.said, ixn2.event.said);

        let mut events = vec![icp, ixn1, ixn2];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(1));
        assert_eq!(kel_verification.branch_tips().len(), 2);
    }

    #[tokio::test]
    async fn test_three_events_at_same_serial_rejected() {
        // The DB can never have 3 events at the same serial — handle_overlap_submission
        // only inserts one divergent event. The verifier must reject this as invalid.
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let prefix_digest = icp.event.prefix.clone();
        let mut builder2 = builder1.clone();
        let mut builder3 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();
        let ixn3 = builder3.interact(&anchor("a3")).await.unwrap();

        let mut events = vec![icp, ixn1, ixn2, ixn3];
        sort_events(&mut events);

        let mut verifier = KelVerifier::new(&prefix_digest);
        let result = verifier.verify_page(&events);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max 2 allowed"));
    }

    #[tokio::test]
    async fn test_second_divergence_after_existing_rejected() {
        // Once a KEL is divergent, only 1 event per generation is allowed.
        // A second divergence (2 events at a serial after the divergence point) is invalid.
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let prefix_digest = icp.event.prefix.clone();
        let mut builder2 = builder1.clone();

        // Diverge at serial 1
        let ixn1a = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn1b = builder2.interact(&anchor("a2")).await.unwrap();

        // Both continue at serial 2 (invalid — after divergence, only 1 event per generation)
        let ixn2a = builder1.interact(&anchor("a3")).await.unwrap();
        let ixn2b = builder2.interact(&anchor("a4")).await.unwrap();

        let mut events = vec![icp, ixn1a, ixn1b, ixn2a, ixn2b];
        sort_events(&mut events);

        let mut verifier = KelVerifier::new(&prefix_digest);
        let result = verifier.verify_page(&events);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("after divergence"));
    }

    #[tokio::test]
    async fn test_divergent_kel_has_no_single_public_key() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = vec![icp, ixn1, ixn2];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.current_public_key().is_none());
        assert!(kel_verification.last_establishment_event().is_none());
    }

    #[tokio::test]
    async fn test_adversary_rotation_detection() {
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let owner_ixn = owner.interact(&anchor("owner")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&owner);

        let mut adversary = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            vec![icp.clone()],
        );
        let adversary_rot = adversary.rotate().await.unwrap();

        let mut events = vec![icp, owner_ixn.clone(), adversary_rot.clone()];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(1));

        let tips = kel_verification.branch_tips();
        assert_eq!(tips.len(), 2);
        let tip_saids: HashSet<_> = tips.iter().map(|t| &t.tip.event.said).collect();
        assert!(tip_saids.contains(&owner_ixn.event.said));
        assert!(tip_saids.contains(&adversary_rot.event.said));
    }

    // ==================== KelVerifier — decommission / contest ====================

    #[tokio::test]
    async fn test_decommissioned_kel() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(kel_verification.is_decommissioned());
        assert!(!kel_verification.is_contested());
    }

    #[tokio::test]
    async fn test_contested_kel() {
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();

        let mut adversary = owner.clone();

        let ror = adversary.rotate_recovery().await.unwrap();
        let cnt = owner.contest().await.unwrap();

        let mut events = vec![icp, ror, cnt];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_contested());
        assert!(kel_verification.is_decommissioned());
    }

    #[tokio::test]
    async fn test_non_contested_kel_with_ror() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();

        let mut adversary = builder.clone();
        let ror = adversary.rotate_recovery().await.unwrap();

        let mut events = vec![icp, ror];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(!kel_verification.is_contested());
        assert!(!kel_verification.is_decommissioned());
    }

    // ==================== KelVerifier — anchor checking ====================

    #[tokio::test]
    async fn test_anchor_found() {
        let a = anchor("my-anchor");
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.interact(&a).await.unwrap();

        let kel_verification = verify_with_anchors(builder.pending_events(), [a.clone()]);
        assert!(kel_verification.is_said_anchored(&a));
        assert!(kel_verification.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_anchor_not_found() {
        let a = anchor("my-anchor");
        let missing = anchor("missing");
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.interact(&a).await.unwrap();

        let kel_verification = verify_with_anchors(builder.pending_events(), [missing.clone()]);
        assert!(!kel_verification.is_said_anchored(&missing));
        assert!(!kel_verification.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_anchor_no_interactions() {
        let missing = anchor("anything");
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();

        let kel_verification = verify_with_anchors(builder.pending_events(), [missing.clone()]);
        assert!(!kel_verification.is_said_anchored(&missing));
    }

    #[tokio::test]
    async fn test_anchor_before_divergence() {
        let a_pre = anchor("pre-divergence");
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        owner.interact(&a_pre).await.unwrap();

        let mut adversary = owner.clone();

        owner.interact(&anchor("owner-gen2")).await.unwrap();
        let adversary_ixn2 = adversary.interact(&anchor("adv-gen2")).await.unwrap();

        let mut events = owner.pending_events().to_vec();
        events.push(adversary_ixn2);
        sort_events(&mut events);

        let kel_verification = verify_with_anchors(&events, [a_pre.clone()]);
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(2));
        assert!(kel_verification.is_said_anchored(&a_pre));
    }

    #[tokio::test]
    async fn test_anchors_on_divergent_branches_excluded() {
        // Anchors on divergent branches must NOT be trusted — an adversary could
        // forge anchors on their branch. Both owner and adversary anchors at the
        // divergence serial are excluded (fail secure). Pre-divergence anchors
        // remain trusted.
        let a_pre = anchor("pre-divergence");
        let a_owner = anchor("owner");
        let a_adv = anchor("adversary");
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        owner.interact(&a_pre).await.unwrap();
        let mut adversary = owner.clone();

        owner.interact(&a_owner).await.unwrap();
        let adversary_ixn = adversary.interact(&a_adv).await.unwrap();

        let mut events = owner.pending_events().to_vec();
        events.push(adversary_ixn);
        sort_events(&mut events);

        let kel_verification =
            verify_with_anchors(&events, [a_pre.clone(), a_owner.clone(), a_adv.clone()]);
        assert!(kel_verification.is_divergent());
        // Pre-divergence anchor is trusted
        assert!(kel_verification.is_said_anchored(&a_pre));
        // Neither anchor at the divergence serial should be trusted
        assert!(!kel_verification.is_said_anchored(&a_owner));
        assert!(!kel_verification.is_said_anchored(&a_adv));
        assert!(!kel_verification.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_anchors_after_divergence_excluded_multi_serial() {
        // Regression: anchors at serials beyond diverged_at_serial are also excluded.
        // Chain: icp(0), ixn(1, pre-anchor), diverge at 2, owner extends to 3 with anchor.
        let a_pre = anchor("before");
        let a_post = anchor("after");
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        owner.interact(&a_pre).await.unwrap(); // serial 1
        let mut adversary = owner.clone();

        // serial 2: divergence
        owner.interact(&anchor("filler")).await.unwrap();
        let adv_ixn = adversary.interact(&anchor("adv-filler")).await.unwrap();

        // serial 3: owner extends with the anchor we care about
        owner.interact(&a_post).await.unwrap();

        let mut events = owner.pending_events().to_vec();
        events.push(adv_ixn);
        sort_events(&mut events);

        let kel_verification = verify_with_anchors(&events, [a_pre.clone(), a_post.clone()]);
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(2));
        // Pre-divergence anchor is trusted
        assert!(kel_verification.is_said_anchored(&a_pre));
        // Post-divergence anchor (even from owner) is NOT trusted
        assert!(!kel_verification.is_said_anchored(&a_post));
    }

    #[tokio::test]
    async fn test_max_pages_exact_boundary_succeeds() {
        // Boundary: KEL fits exactly within max_pages * page_size — should succeed.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let mut events = vec![icp];
        for i in 0..9 {
            let ixn = builder
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()))
                .await
                .unwrap();
            events.push(ixn);
        }

        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        // Page size 5, max 2 pages = 10 events, we have exactly 10
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            5,
            2,
            iter::empty(),
        )
        .await
        .unwrap();

        assert_eq!(kel_verification.branch_tips()[0].tip.event.serial, 9);
    }

    #[tokio::test]
    async fn test_max_pages_one_over_boundary_fails() {
        // One event over max_pages * page_size — should fail secure.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let mut events = vec![icp];
        for i in 0..10 {
            let ixn = builder
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()))
                .await
                .unwrap();
            events.push(ixn);
        }

        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        // Page size 5, max 2 pages = 10 events, we have 11
        let result = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            5,
            2,
            iter::empty(),
        )
        .await;

        assert!(result.is_err());
    }

    // ==================== KelVerifier — effective SAID ====================

    #[tokio::test]
    async fn test_effective_tail_said_non_divergent() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        let ixn = builder.interact(&anchor("test")).await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert_eq!(
            kel_verification.effective_tail_said(),
            Some(ixn.event.said.clone())
        );
    }

    #[tokio::test]
    async fn test_effective_tail_said_divergent() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = vec![icp, ixn1.clone(), ixn2.clone()];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        let effective = kel_verification.effective_tail_said().unwrap();

        assert_ne!(effective, ixn1.event.said);
        assert_ne!(effective, ixn2.event.said);

        let kel_verification2 = verify(&events);
        assert_eq!(
            kel_verification.effective_tail_said(),
            kel_verification2.effective_tail_said()
        );
    }

    // ==================== KelVerifier — recovery events ====================

    #[tokio::test]
    async fn test_verify_recovery_event() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.recover(false).await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(!kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert!(
            kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .is_recover()
        );
    }

    #[tokio::test]
    async fn test_verify_rotate_recovery() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.rotate_recovery().await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(!kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert!(
            kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .reveals_recovery_key()
        );
    }

    // ==================== KelVerifier — resume from Verification ====================

    #[tokio::test]
    async fn test_resume_extends_verification() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        let ixn1 = builder.interact(&anchor("a1")).await.unwrap();

        let kel_verification = verify(&builder.pending_events()[..2]);
        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            ixn1.event.said
        );

        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let mut verifier =
            KelVerifier::resume(kel_verification.prefix(), &kel_verification).unwrap();
        verifier.verify_page(slice::from_ref(&ixn2)).unwrap();
        let kel_verification2 = verifier.into_verification().unwrap();

        assert_eq!(
            kel_verification2.branch_tips()[0].tip.event.said,
            ixn2.event.said
        );
    }

    // ==================== KelVerifier — from_branch_tip ====================

    #[tokio::test]
    async fn test_from_branch_tip_verifies_extension() {
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        let owner_ixn = owner.interact(&anchor("owner")).await.unwrap();
        let _adv_ixn = adversary.interact(&anchor("adv")).await.unwrap();

        let tip = BranchTip {
            tip: owner_ixn.clone(),
            establishment_tip: icp.clone(),
        };

        let owner_ixn2 = owner.interact(&anchor("owner2")).await.unwrap();

        let mut verifier = KelVerifier::from_branch_tip(&icp.event.prefix, &tip, 0).unwrap();
        verifier.verify_page(slice::from_ref(&owner_ixn2)).unwrap();
        let kel_verification = verifier.into_verification().unwrap();

        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            owner_ixn2.event.said
        );
    }

    // ==================== Builder — divergent state ====================

    #[tokio::test]
    async fn test_builder_with_divergent_events() {
        let mut builder1 = KeyEventBuilder::new(random_provider(), None);
        let icp = builder1.incept().await.unwrap();
        builder1.interact(&anchor("a1")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            vec![icp.clone()],
        );
        builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = builder1.pending_events().to_vec();
        events.extend(builder2.pending_events().iter().cloned());
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_divergent());

        let builder3 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            events,
        );
        assert_eq!(builder3.confirmed_count(), 3);
        assert_eq!(builder3.pending_events().len(), 0);
    }

    // ==================== Comprehensive verification scenarios ====================
    //
    // Exercises the full verification stack: multi-page pagination,
    // divergence at page boundaries, recovery, contest, decommission,
    // anchor checking across pages, resume/incremental verification,
    // delegated inception, sync abstraction, and truncation safety.

    // ---- Multi-page linear KEL with rotations ----

    #[tokio::test]
    async fn test_multi_page_kel_with_rotations() {
        // Build a 40-event KEL that spans 2 pages (page_size=32), with
        // rotations interspersed. Verifies that key state transitions are
        // tracked correctly across page boundaries.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        for i in 0..39 {
            if i % 10 == 9 {
                builder.rotate().await.unwrap();
            } else {
                builder
                    .interact(&anchor(&format!("evt-{}", i)))
                    .await
                    .unwrap();
            }
        }

        let events = builder.pending_events().to_vec();
        assert_eq!(events.len(), 40);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            10,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(!kel_verification.is_divergent());
        assert!(!kel_verification.is_contested());
        assert!(!kel_verification.is_decommissioned());
        assert_eq!(kel_verification.branch_tips().len(), 1);
        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            events.last().unwrap().event.said
        );

        // Last establishment event should be the last rotation (at serial 60)
        let last_est = kel_verification.last_establishment_event().unwrap();
        assert!(last_est.event.is_rotation());

        // Key should differ from inception key
        assert_ne!(
            kel_verification.current_public_key().unwrap(),
            icp.event.public_key.as_ref().unwrap()
        );
    }

    // ---- Anchor checking across page boundary ----

    #[tokio::test]
    async fn test_anchor_checking_across_pages() {
        // Place an anchor in the first page and another in the second page.
        // Verify both are found with completed_verification.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let early_anchor = anchor("early-target");
        let late_anchor = anchor("late-target");

        // First page: events 0..31
        for i in 0..30 {
            if i == 10 {
                builder.interact(&early_anchor).await.unwrap();
            } else {
                builder
                    .interact(&anchor(&format!("filler-{}", i)))
                    .await
                    .unwrap();
            }
        }
        // Second page: events 32+
        for i in 0..8 {
            if i == 4 {
                builder.interact(&late_anchor).await.unwrap();
            } else {
                builder
                    .interact(&anchor(&format!("filler2-{}", i)))
                    .await
                    .unwrap();
            }
        }

        let events = builder.pending_events().to_vec();
        assert!(events.len() > 32);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &events).await.unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            10,
            vec![early_anchor.clone(), late_anchor.clone()],
        )
        .await
        .unwrap();

        assert!(kel_verification.is_said_anchored(&early_anchor));
        assert!(kel_verification.is_said_anchored(&late_anchor));
        assert!(kel_verification.anchors_all_saids());
    }

    // ---- Divergence entirely on second page ----

    #[tokio::test]
    async fn test_divergence_starts_on_second_page() {
        // Owner fills exactly one page, then both owner and adversary add
        // events at the next serial — divergence falls entirely on page 2.
        let page_size = crate::page_size();
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        let prefix = owner.pending_events()[0].event.prefix.clone();

        // Fill first page (page_size events including icp)
        while owner.pending_events().len() < page_size {
            owner
                .interact(&anchor(&format!("o-{}", owner.pending_events().len())))
                .await
                .unwrap();
        }
        let mut adversary = owner.clone();

        // Both add an event at the next serial (page 2)
        let owner_ixn = owner.interact(&anchor("owner-page2")).await.unwrap();
        let adv_ixn = adversary.interact(&anchor("adv-page2")).await.unwrap();
        assert_eq!(owner_ixn.event.serial, adv_ixn.event.serial);

        let diverge_serial = owner_ixn.event.serial;
        let mut all_events = owner.pending_events().to_vec();
        all_events.push(adv_ixn);
        sort_events(&mut all_events);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &all_events).await.unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            page_size,
            10,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(diverge_serial));
        assert_eq!(kel_verification.branch_tips().len(), 2);
        assert!(kel_verification.current_public_key().is_none());
    }

    // ---- Long owner chain with early adversary injection ----

    #[tokio::test]
    async fn test_long_owner_chain_with_early_adversary() {
        // Owner builds a long chain (2+ pages). Adversary branches after icp.
        // Tests multi-page divergent verification where one branch is much
        // longer. The short adversary branch should be carried forward.
        let page_size = crate::page_size();
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        let prefix = owner.pending_events()[0].event.prefix.clone();
        let mut adversary = owner.clone();

        // Owner builds long chain (2+ pages including auto-rors)
        while owner.pending_events().len() < 2 * page_size {
            owner
                .interact(&anchor(&format!("owner-{}", owner.pending_events().len())))
                .await
                .unwrap();
        }
        let owner_tip = owner.pending_events().last().unwrap().clone();

        // Adversary injects one event at serial 1
        let adv_ixn = adversary.interact(&anchor("adversary-1")).await.unwrap();
        assert_eq!(adv_ixn.event.serial, 1);

        let mut all_events = owner.pending_events().to_vec();
        all_events.push(adv_ixn.clone());
        sort_events(&mut all_events);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &all_events).await.unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            10,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(1));
        assert_eq!(kel_verification.branch_tips().len(), 2);

        let tip_saids: HashSet<_> = kel_verification
            .branch_tips()
            .iter()
            .map(|t| &t.tip.event.said)
            .collect();
        assert!(tip_saids.contains(&owner_tip.event.said));
        assert!(tip_saids.contains(&adv_ixn.event.said));
    }

    // ---- Divergence with rotations on both branches ----

    #[tokio::test]
    async fn test_divergent_branches_with_rotations() {
        // Owner continues with rotation after divergence.
        // Adversary branch is a single event (the DB invariant).
        // Verifier tracks independent crypto state per branch.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        // Owner branch: ixn @ 1, rot @ 2, ixn @ 3
        owner.interact(&anchor("owner-1")).await.unwrap();
        let owner_rot = owner.rotate().await.unwrap();
        let owner_tip = owner.interact(&anchor("owner-3")).await.unwrap();

        // Adversary branch: single event at serial 1 (shorter branch invariant)
        let adv_ixn = adversary.interact(&anchor("adv-1")).await.unwrap();

        let mut events = owner.pending_events().to_vec();
        events.push(adv_ixn.clone());
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(1));
        assert_eq!(kel_verification.branch_tips().len(), 2);

        // Owner branch tip should have the rotation as establishment tip
        for tip in kel_verification.branch_tips() {
            if tip.tip.event.said == owner_tip.event.said {
                assert_eq!(
                    tip.establishment_tip.event.said, owner_rot.event.said,
                    "Owner branch should reference owner's rotation"
                );
            } else {
                assert_eq!(tip.tip.event.said, adv_ixn.event.said);
                // Adversary's establishment tip is the inception (no rotation on that branch)
            }
        }
    }

    // ---- Recovery after divergence ----

    #[tokio::test]
    async fn test_recovery_after_divergence() {
        // Owner incepts, adversary branches, owner recovers.
        // After recovery, the KEL should be non-divergent.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&owner);
        let mut adversary = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            vec![icp.clone()],
        );

        let owner_ixn = owner.interact(&anchor("owner-1")).await.unwrap();
        let adv_ixn = adversary.interact(&anchor("adv-1")).await.unwrap();

        // Verify pre-recovery divergence
        let mut divergent_events = vec![icp.clone(), owner_ixn.clone(), adv_ixn.clone()];
        sort_events(&mut divergent_events);
        let kel_verification = verify(&divergent_events);
        assert!(kel_verification.is_divergent());

        // Owner recovers
        let rec = owner.recover(false).await.unwrap();
        assert!(rec.event.is_recover());
        assert!(rec.event.reveals_recovery_key());

        // Verify owner chain including recovery is valid
        let owner_kel_verification = verify(owner.pending_events());
        assert!(!owner_kel_verification.is_divergent());
        assert!(
            owner_kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .is_recover()
        );
    }

    // ---- Contest permanently freezes a divergent KEL ----

    #[tokio::test]
    async fn test_contest_freezes_kel() {
        // Adversary reveals recovery key via rotate_recovery.
        // Owner contests. The contested KEL is permanently frozen.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        let owner_ixn = owner.interact(&anchor("owner")).await.unwrap();
        let adv_ror = adversary.rotate_recovery().await.unwrap();

        // Contest
        let cnt = owner.contest().await.unwrap();
        assert!(cnt.event.is_contest());
        assert!(cnt.event.reveals_recovery_key());

        // Combine all events
        let mut events = vec![icp, owner_ixn, adv_ror, cnt.clone()];
        sort_events(&mut events);

        let kel_verification = verify(&events);
        assert!(kel_verification.is_contested());
        assert!(kel_verification.is_decommissioned());
        assert!(kel_verification.is_divergent());

        // Contest event should appear in a branch tip
        let has_cnt = kel_verification
            .branch_tips()
            .iter()
            .any(|t| t.tip.event.said == cnt.event.said);
        assert!(has_cnt);
    }

    // ---- Decommission ends the KEL ----

    #[tokio::test]
    async fn test_decommission_then_no_more_events() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.interact(&anchor("data")).await.unwrap();
        builder.decommission().await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(kel_verification.is_decommissioned());
        assert!(!kel_verification.is_contested());
        assert!(!kel_verification.is_divergent());

        // Builder should refuse further events
        assert!(builder.interact(&anchor("rejected")).await.is_err());
    }

    // ---- Resume incremental verification across pages ----

    #[tokio::test]
    async fn test_resume_across_multiple_increments() {
        // Simulate three incremental verifications: page 1, page 2, page 3.
        // Each time resume from the previous Verification and verify the next batch.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();

        // Build 30 events total
        for i in 0..29 {
            builder
                .interact(&anchor(&format!("inc-{}", i)))
                .await
                .unwrap();
        }
        let events = builder.pending_events().to_vec();
        assert_eq!(events.len(), 30);

        // Verify first 10
        let kel_verification1 = verify(&events[..10]);
        assert_eq!(kel_verification1.branch_tips()[0].tip.event.serial, 9);

        // Resume and verify next 10
        let prefix_digest = kel_verification1.prefix().clone();
        let mut v2 = KelVerifier::resume(&prefix_digest, &kel_verification1).unwrap();
        v2.verify_page(&events[10..20]).unwrap();
        let kel_verification2 = v2.into_verification().unwrap();
        assert_eq!(kel_verification2.branch_tips()[0].tip.event.serial, 19);

        // Resume and verify last 10
        let mut v3 = KelVerifier::resume(&prefix_digest, &kel_verification2).unwrap();
        v3.verify_page(&events[20..30]).unwrap();
        let kel_verification3 = v3.into_verification().unwrap();
        assert_eq!(kel_verification3.branch_tips()[0].tip.event.serial, 29);

        // Final tip should match
        assert_eq!(
            kel_verification3.branch_tips()[0].tip.event.said,
            events.last().unwrap().event.said
        );
    }

    // ---- Resume preserves divergence state ----

    #[tokio::test]
    async fn test_resume_preserves_divergence() {
        // Diverge at serial 1, then resume and verify the continuing branch extends.
        // The shorter branch is exactly 1 event (DB invariant).
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        let owner_ixn1 = owner.interact(&anchor("o1")).await.unwrap();
        let adv_ixn1 = adversary.interact(&anchor("a1")).await.unwrap();

        let mut page1 = vec![icp, owner_ixn1, adv_ixn1];
        sort_events(&mut page1);
        let kel_verification1 = verify(&page1);
        assert!(kel_verification1.is_divergent());
        assert_eq!(kel_verification1.diverged_at_serial(), Some(1));

        // Only the continuing branch extends (1 event per generation after divergence)
        let owner_ixn2 = owner.interact(&anchor("o2")).await.unwrap();
        let page2 = vec![owner_ixn2.clone()];

        let prefix_digest = kel_verification1.prefix().clone();
        let mut v2 = KelVerifier::resume(&prefix_digest, &kel_verification1).unwrap();
        v2.verify_page(&page2).unwrap();
        let kel_verification2 = v2.into_verification().unwrap();

        assert!(kel_verification2.is_divergent());
        assert_eq!(kel_verification2.diverged_at_serial(), Some(1));
        assert_eq!(kel_verification2.branch_tips().len(), 2);
        // Owner branch advanced to serial 2, adversary stays at serial 1
        let tip_serials: HashSet<_> = kel_verification2
            .branch_tips()
            .iter()
            .map(|t| t.tip.event.serial)
            .collect();
        assert!(tip_serials.contains(&1));
        assert!(tip_serials.contains(&2));
    }

    // ---- Delegated inception verification ----

    #[tokio::test]
    async fn test_delegated_inception_verifies() {
        let delegating_prefix = anchor("delegating");
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let dip = builder.incept_delegated(&delegating_prefix).await.unwrap();

        assert!(dip.event.is_delegated_inception());
        assert_eq!(
            dip.event.delegating_prefix.as_ref(),
            Some(&delegating_prefix)
        );

        let ixn = builder.interact(&anchor("delegated-data")).await.unwrap();

        let kel_verification = verify(builder.pending_events());
        assert!(!kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert_eq!(
            kel_verification.branch_tips()[0].tip.event.said,
            ixn.event.said
        );
    }

    // ---- Effective SAID determinism ----

    #[tokio::test]
    async fn test_effective_said_is_deterministic_across_orderings() {
        // Two divergent branches produce the same effective SAID regardless
        // of which order they appear internally.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        let ixn_a = owner.interact(&anchor("a")).await.unwrap();
        let ixn_b = adversary.interact(&anchor("b")).await.unwrap();

        // Order 1: a then b
        let mut events1 = vec![icp.clone(), ixn_a.clone(), ixn_b.clone()];
        sort_events(&mut events1);
        let kel_verification1 = verify(&events1);

        // Verify it's not just the tip SAID
        let effective = kel_verification1.effective_tail_said().unwrap();
        assert_ne!(effective, ixn_a.event.said);
        assert_ne!(effective, ixn_b.event.said);

        // Verify determinism: same events, same result
        let kel_verification2 = verify(&events1);
        assert_eq!(
            kel_verification1.effective_tail_said(),
            kel_verification2.effective_tail_said(),
            "Effective SAID must be deterministic"
        );
    }

    // ---- Truncation of incomplete generation ----

    #[tokio::test]
    async fn test_truncate_splits_divergent_generation_correctly() {
        // Truncation compares last_count vs second_last_count. For it to
        // detect an incomplete generation, the divergence must extend over
        // multiple serials so the second-to-last serial establishes the
        // expected width.
        //
        // Setup: 2-way divergence at serial 1 that extends to serial 2.
        // Events: [icp@0, a1@1, b1@1, a2@2, b2@2] = 5 events
        // Simulate page ending at 4 events: [icp@0, a1@1, b1@1, a2@2]
        // Serial 2 has 1 event but serial 1 has 2 → 1 < 2 → truncation
        // removes the lone serial-2 event. Remaining page still has the
        // complete divergent generation at serial 1.
        let mut b1 = KeyEventBuilder::new(random_provider(), None);
        b1.incept().await.unwrap();
        let mut b2 = b1.clone();

        b1.interact(&anchor("b1-s1")).await.unwrap();
        b2.interact(&anchor("b2-s1")).await.unwrap();
        b1.interact(&anchor("b1-s2")).await.unwrap();
        b2.interact(&anchor("b2-s2")).await.unwrap();

        let mut all = b1.pending_events().to_vec();
        all.extend(b2.pending_events()[1..].iter().cloned());
        sort_events(&mut all);
        // [icp@0, a1@1, b1@1, a2@2, b2@2]
        assert_eq!(all.len(), 5);

        // Simulate page ending with 4 events: icp + 2 at serial 1 + 1 at serial 2
        let mut partial = all[..4].to_vec();
        let truncated = truncate_incomplete_generation(&mut partial);
        assert_eq!(
            truncated, 1,
            "Should remove the 1 incomplete serial-2 event"
        );
        assert_eq!(partial.len(), 3, "icp + both serial-1 events should remain");
        assert_eq!(partial.last().unwrap().event.serial, 1);
    }

    #[tokio::test]
    async fn test_truncate_no_op_on_complete_generation() {
        // A complete generation should not be truncated.
        let mut b1 = KeyEventBuilder::new(random_provider(), None);
        let icp = b1.incept().await.unwrap();
        let mut b2 = b1.clone();

        let ixn1 = b1.interact(&anchor("x1")).await.unwrap();
        let ixn2 = b2.interact(&anchor("x2")).await.unwrap();

        let mut all = vec![icp, ixn1, ixn2];
        sort_events(&mut all);

        // Both serial-1 events present: 2 at serial 1, 1 at serial 0
        // last_count (2) >= second_last_count (1), no truncation
        let truncated = truncate_incomplete_generation(&mut all);
        assert_eq!(truncated, 0);
        assert_eq!(all.len(), 3);
    }

    // ---- Paginated divergence with truncation ----

    #[tokio::test]
    async fn test_paginated_divergence_spanning_page_boundary() {
        // 2-way divergence at serial 5 with the divergent pair landing at the
        // boundary between pages. Page size chosen so page 1 ends with the
        // two divergent events, and page 2 starts with the continuing branch.
        //
        // 5 linear events (serials 0-4), then 2-way divergence at serial 5.
        // Owner continues for serials 6-7, adversary has just 1 event at serial 5.
        // Total: 5 + 1 (adv) + 3 (owner serials 5,6,7) = 9 events.
        // Sorted: 5 linear + 2 at serial 5 + 1 at serial 6 + 1 at serial 7 = 9.
        //
        // Page size 7: first page = serials 0-4 (5 events) + serial 5 (2 events) = 7.
        // Truncation: serial 5 has 2 events, no incomplete generation. Full page.
        // Page 2: serials 6-7 (2 events).
        let mut b1 = KeyEventBuilder::new(random_provider(), None);
        let icp = b1.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        // 4 linear events (serials 1-4)
        for i in 0..4 {
            b1.interact(&anchor(&format!("pre-{}", i))).await.unwrap();
        }

        // Clone at serial 4 for adversary
        let mut b2 = b1.clone();

        // Owner continues for 3 serials (5, 6, 7)
        for i in 0..3 {
            b1.interact(&anchor(&format!("b1-{}", i))).await.unwrap();
        }

        // Adversary has just 1 event at serial 5 (shorter branch invariant)
        b2.interact(&anchor("b2-0")).await.unwrap();

        let mut all_events = b1.pending_events().to_vec();
        all_events.push(b2.pending_events()[5].clone());
        sort_events(&mut all_events);
        // 5 linear + 2 at serial 5 + 1 at serial 6 + 1 at serial 7 = 9
        assert_eq!(all_events.len(), 9);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &all_events).await.unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            7,
            10,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.diverged_at_serial(), Some(5));
        assert_eq!(kel_verification.branch_tips().len(), 2);
        // Owner branch tip at serial 7, adversary at serial 5
        let tip_serials: HashSet<_> = kel_verification
            .branch_tips()
            .iter()
            .map(|t| t.tip.event.serial)
            .collect();
        assert!(tip_serials.contains(&5));
        assert!(tip_serials.contains(&7));
    }

    // ---- Full lifecycle: incept → interact → rotate → diverge → recover ----

    #[tokio::test]
    async fn test_full_lifecycle() {
        // Full lifecycle test: incept, interact, rotate, adversary branches,
        // verify divergence, owner recovers, verify recovery.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        // Normal operations
        owner.interact(&anchor("data-1")).await.unwrap();
        owner.interact(&anchor("data-2")).await.unwrap();
        let rot = owner.rotate().await.unwrap();
        owner.interact(&anchor("data-3")).await.unwrap();

        // Adversary branches after rotation (has post-rotation keys).
        // Clone at current state, then both add events at the same serial.
        let (ck, nk, rk) = clone_keys(&owner);
        let mut adversary = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(ck, nk, rk),
            None,
            None,
            owner.pending_events().to_vec(),
        );
        let owner_ixn2 = owner.interact(&anchor("data-4")).await.unwrap();
        let adv_ixn = adversary.interact(&anchor("adversary")).await.unwrap();
        assert_eq!(owner_ixn2.event.serial, adv_ixn.event.serial);

        // Store divergent state
        let mut all_events = owner.pending_events().to_vec();
        all_events.push(adv_ixn.clone());
        sort_events(&mut all_events);

        let store = MemoryStore::new();
        store.overwrite(&prefix, &all_events).await.unwrap();

        // Verify divergence
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            crate::page_size(),
            10,
            iter::empty(),
        )
        .await
        .unwrap();
        assert!(kel_verification.is_divergent());
        assert_eq!(kel_verification.branch_tips().len(), 2);

        // Owner recovers
        let rec = owner.recover(false).await.unwrap();
        assert!(rec.event.is_recover());

        // Verify the owner's chain after recovery is clean
        let recovered_kel_verification = verify(owner.pending_events());
        assert!(!recovered_kel_verification.is_divergent());
        assert!(
            recovered_kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .is_recover()
        );

        // The recovery event should be signed by the new key
        let rec_key = rec.event.public_key.as_ref().unwrap();
        assert_ne!(rec_key, rot.event.public_key.as_ref().unwrap());
    }

    // ---- from_branch_tip used for recovery verification ----

    #[tokio::test]
    async fn test_from_branch_tip_for_recovery_path() {
        // Simulate the submit handler's recovery verification path:
        // verify a divergent KEL, pick the owner branch tip, then verify
        // recovery events against that specific branch.
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        owner.interact(&anchor("owner")).await.unwrap();
        let _adv_ixn = adversary.interact(&anchor("adv")).await.unwrap();

        // Owner continues and recovers
        let owner_ixn2 = owner.interact(&anchor("owner2")).await.unwrap();
        let rec = owner.recover(false).await.unwrap();

        // Construct a branch tip for the owner's pre-recovery state
        let owner_tip = BranchTip {
            tip: owner_ixn2.clone(),
            establishment_tip: icp.clone(),
        };

        // Verify recovery event against owner branch
        let mut verifier = KelVerifier::from_branch_tip(&icp.event.prefix, &owner_tip, 0).unwrap();
        verifier.verify_page(slice::from_ref(&rec)).unwrap();
        let kel_verification = verifier.into_verification().unwrap();

        assert!(!kel_verification.is_divergent());
        assert!(
            kel_verification
                .last_establishment_event()
                .unwrap()
                .event
                .is_recover()
        );
    }

    // ---- Verification SAID is content-addressable ----

    #[tokio::test]
    async fn test_verification_said_is_content_addressable() {
        // Two independent verifications of the same events must produce
        // the same Verification SAID.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.interact(&anchor("a")).await.unwrap();
        builder.rotate().await.unwrap();

        let events = builder.pending_events().to_vec();
        let kel_verification1 = verify(&events);
        let kel_verification2 = verify(&events);

        assert_eq!(kel_verification1.said(), kel_verification2.said());
    }

    // ---- Empty KEL produces empty Verification ----

    #[tokio::test]
    async fn test_empty_kel_verification() {
        let store = MemoryStore::new();
        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &Digest::blake3_256(b"nonexistent_prefix"),
            crate::page_size(),
            10,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(kel_verification.is_empty());
        assert!(!kel_verification.is_divergent());
        assert!(!kel_verification.is_contested());
        assert!(kel_verification.current_public_key().is_none());
        assert!(kel_verification.effective_tail_said().is_none());
    }

    // ---- Rotate recovery (ror) verification ----

    #[tokio::test]
    async fn test_rotate_recovery_changes_recovery_key() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let ror = builder.rotate_recovery().await.unwrap();

        assert!(ror.event.reveals_recovery_key());
        assert!(ror.event.recovery_key.is_some());
        assert!(ror.event.recovery_hash.is_some());

        // Verify the forward commitment: inception's recovery_hash should
        // match hash of the recovery key revealed in ror
        let icp_recovery_hash = icp.event.recovery_hash.as_ref().unwrap();
        let ror_recovery_key = ror.event.recovery_key.as_ref().unwrap();
        assert_eq!(
            *icp_recovery_hash,
            compute_rotation_hash(ror_recovery_key),
            "Recovery key revealed in ror must match inception's recovery_hash commitment"
        );

        let kel_verification = verify(builder.pending_events());
        assert!(!kel_verification.is_divergent());
        assert!(!kel_verification.is_contested());
    }

    // ---- Verification rejects wrong prefix ----

    #[tokio::test]
    async fn test_rejects_wrong_prefix() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();

        let mut verifier = KelVerifier::new(&anchor("wrong_prefix"));
        let result = verifier.verify_page(builder.pending_events());
        assert!(result.is_err());
    }

    // ---- Verification rejects non-sequential serials ----

    #[tokio::test]
    async fn test_rejects_serial_gap() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        builder.incept().await.unwrap();
        builder.interact(&anchor("a")).await.unwrap();
        builder.interact(&anchor("b")).await.unwrap();

        let events = builder.pending_events().to_vec();
        // Skip serial 1, feed serial 0 then serial 2
        let prefix_digest = events[0].event.prefix.clone();
        let mut verifier = KelVerifier::new(&prefix_digest);
        verifier.verify_page(slice::from_ref(&events[0])).unwrap();
        let result = verifier.verify_page(slice::from_ref(&events[2]));
        assert!(result.is_err());
    }

    // ---- Small page sizes force many pages ----

    #[tokio::test]
    async fn test_tiny_page_size_verifies_correctly() {
        // Use page_size=3 to force many page loads. This stress-tests the
        // pagination loop in completed_verification.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        for i in 0..29 {
            builder
                .interact(&anchor(&format!("tiny-{}", i)))
                .await
                .unwrap();
        }

        let store = MemoryStore::new();
        store
            .overwrite(&prefix, builder.pending_events())
            .await
            .unwrap();

        let kel_verification = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            3, // very small pages
            100,
            iter::empty(),
        )
        .await
        .unwrap();

        assert!(!kel_verification.is_divergent());
        assert_eq!(kel_verification.branch_tips()[0].tip.event.serial, 29);
    }

    // ---- Multi-page with anchor checking and resume combined ----

    // ==================== PagedKelSource mock for transfer tests ====================

    /// In-memory PagedKelSource that serves events with since-based pagination.
    struct MemoryKelSource {
        events: Vec<SignedKeyEvent>,
    }

    impl MemoryKelSource {
        fn new(events: Vec<SignedKeyEvent>) -> Self {
            Self { events }
        }
    }

    impl MemoryKelSource {
        /// Compute effective SAID matching the real serving layer:
        /// single tip → its SAID, contested → hash("contested:{prefix}"),
        /// divergent → hash("divergent:{prefix}").
        fn effective_said(&self) -> Option<cesr::Digest> {
            if self.events.is_empty() {
                return None;
            }
            let prefix = &self.events[0].event.prefix;
            let referenced: std::collections::HashSet<&cesr::Digest> = self
                .events
                .iter()
                .filter_map(|e| e.event.previous.as_ref())
                .collect();
            let tips: Vec<&SignedKeyEvent> = self
                .events
                .iter()
                .filter(|e| !referenced.contains(&e.event.said))
                .collect();
            match tips.len() {
                0 => None,
                1 => Some(tips[0].event.said.clone()),
                _ => {
                    if tips.iter().any(|e| e.event.is_contest()) {
                        Some(crate::hash_effective_said(&format!("contested:{}", prefix)))
                    } else {
                        Some(crate::hash_effective_said(&format!("divergent:{}", prefix)))
                    }
                }
            }
        }
    }

    #[async_trait]
    impl PagedKelSource for MemoryKelSource {
        async fn fetch_page(
            &self,
            _prefix: &cesr::Digest,
            since: Option<&cesr::Digest>,
            limit: usize,
        ) -> Result<(Vec<SignedKeyEvent>, bool), crate::error::KelsError> {
            let start = match since {
                Some(said) => {
                    if let Some(i) = self.events.iter().position(|e| &e.event.said == said) {
                        i + 1
                    } else if self.effective_said().as_ref() == Some(said) {
                        // Composite SAID matches effective — caller is in sync
                        return Ok((vec![], false));
                    } else {
                        return Err(crate::error::KelsError::NotFound(said.to_string()));
                    }
                }
                None => 0,
            };
            if start >= self.events.len() {
                return Ok((vec![], false));
            }
            let end = (start + limit).min(self.events.len());
            let has_more = end < self.events.len();
            Ok((self.events[start..end].to_vec(), has_more))
        }
    }

    // ==================== transfer_key_events tests ====================

    #[tokio::test]
    async fn test_verify_key_events_linear() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        builder.interact(&anchor("a1")).await.unwrap();
        builder.interact(&anchor("a2")).await.unwrap();

        let source = MemoryKelSource::new(builder.pending_events().to_vec());
        let kel_verification = verify_key_events(
            &prefix,
            &source,
            KelVerifier::new(&prefix),
            2, // small page size to force pagination
            100,
        )
        .await
        .unwrap();

        assert_eq!(kel_verification.branch_tips().len(), 1);
        assert_eq!(kel_verification.branch_tips()[0].tip.event.serial, 2);
        assert!(!kel_verification.is_divergent());
    }

    #[tokio::test]
    async fn test_resolve_key_events_linear() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        builder.interact(&anchor("a1")).await.unwrap();

        let source = MemoryKelSource::new(builder.pending_events().to_vec());
        let events = resolve_key_events(&prefix, &source, 100, 100, None)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_forward_key_events_linear() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        builder.interact(&anchor("a1")).await.unwrap();

        let source = MemoryKelSource::new(builder.pending_events().to_vec());
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, 100, 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;
        assert_eq!(collected.len(), 2);
    }

    #[tokio::test]
    async fn test_transfer_key_events_divergent() {
        // Owner: icp, o1, o2, o3, o4, o5
        // Adversary: a1 at serial 2 (diverges from o1)
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let o1 = owner.interact(&anchor("o1")).await.unwrap();

        // Clone builder for adversary after serial 1
        let mut adversary = owner.clone();
        let a1 = adversary.interact(&anchor("adversary")).await.unwrap();
        assert_eq!(a1.event.serial, 2);

        // Owner continues
        owner.interact(&anchor("o2")).await.unwrap();
        owner.interact(&anchor("o3")).await.unwrap();
        owner.interact(&anchor("o4")).await.unwrap();
        owner.interact(&anchor("o5")).await.unwrap();

        // Combine and sort (DB ordering: serial ASC, kind sort_priority ASC, said ASC)
        let mut all_events = owner.pending_events().to_vec();
        all_events.push(a1.clone());
        sort_events(&mut all_events);

        let source = MemoryKelSource::new(all_events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, 100, 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;
        // Owner: icp(0) + o1(1) + o2(2) + o3(3) + o4(4) + o5(5) = 6, plus a1 = 7
        assert_eq!(collected.len(), 7);
        // Deferred event (adversary) should be last
        assert_eq!(collected.last().unwrap().event.said, a1.event.said);
        // First events should be the continuing branch
        assert_eq!(collected[0].event.said, icp.event.said);
        assert_eq!(collected[1].event.said, o1.event.said);
    }

    #[tokio::test]
    async fn test_transfer_key_events_divergent_page_boundary() {
        // Test divergence at the end of a page boundary
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        owner.interact(&anchor("o1")).await.unwrap();

        let mut adversary = owner.clone();
        let a1 = adversary.interact(&anchor("adversary")).await.unwrap();

        // Owner continues
        owner.interact(&anchor("o2")).await.unwrap();
        owner.interact(&anchor("o3")).await.unwrap();

        let mut all_events = owner.pending_events().to_vec();
        all_events.push(a1.clone());
        sort_events(&mut all_events);

        // Use page_size=3 so divergence (serial 2, two events) falls at page boundary
        // Page 1: icp(0), o1(1), first_of_serial_2 — divergence at end of page
        let source = MemoryKelSource::new(all_events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, 3, 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;
        assert_eq!(collected.len(), 5); // icp(0) + o1(1) + o2(2) + o3(3) + a1(2) = 5
        // Deferred event should be last
        assert_eq!(collected.last().unwrap().event.said, a1.event.said);
    }

    #[tokio::test]
    async fn test_transfer_key_events_no_verifier() {
        // Structural divergence detection works without crypto verification
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        owner.interact(&anchor("o1")).await.unwrap();

        let mut adversary = owner.clone();
        let a1 = adversary.interact(&anchor("adversary")).await.unwrap();
        owner.interact(&anchor("o2")).await.unwrap();

        let mut all_events = owner.pending_events().to_vec();
        all_events.push(a1.clone());
        sort_events(&mut all_events);

        // resolve_key_events uses no verifier
        let source = MemoryKelSource::new(all_events);
        let events = resolve_key_events(&prefix, &source, 100, 100, None)
            .await
            .unwrap();

        assert_eq!(events.len(), 4); // icp(0) + o1(1) + o2(2) + a1(2) = 4
        // Both serial-2 events present, one deferred to last position
        let last_two_saids: Vec<&cesr::Digest> =
            events[2..].iter().map(|e| &e.event.said).collect();
        assert!(last_two_saids.contains(&&a1.event.said));
    }

    // ==================== Divergent Transfer: Exhaustive Cases ====================
    //
    // These tests cover every combination of owner/adversary chain length and
    // recovery type. The transfer must submit events in an order the remote
    // merge engine can process:
    //   Recovered:   pre-div + longer chain (non-div) → shorter fork → rec(+rot)
    //   Unrecovered: pre-div + longer chain (non-div) → shorter fork (warn on fail)
    //   Contested:   pre-div + non-revealing chain → revealing fork (warn on fail)

    /// Helper: build a divergent KEL with configurable chain lengths and recovery.
    /// Returns (all_events_sorted, owner_rec_rot_saids, adversary_fork_said).
    async fn build_divergent_kel(
        owner_event_count: usize,
        adversary_event_count: usize,
        recovery: &str, // "none", "rec", "rec+rot", "cnt"
    ) -> (
        Vec<SignedKeyEvent>,
        cesr::Digest,         // prefix
        Vec<cesr::Digest>,    // owner chain SAIDs (includes rec/rot if present)
        Option<cesr::Digest>, // adversary fork SAID
    ) {
        let mut owner = KeyEventBuilder::new(random_provider(), None);
        let icp = owner.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        // Pre-divergence event
        owner.interact(&anchor("shared")).await.unwrap();

        // Clone for adversary at this point
        let (ck, nk, rk) = clone_keys(&owner);
        let mut adversary = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(ck, nk, rk),
            None,
            None,
            owner.pending_events().to_vec(),
        );

        // Owner events after fork point
        let mut owner_saids = Vec::new();
        for i in 0..owner_event_count {
            let evt = owner
                .interact(&anchor(&format!("owner-{i}")))
                .await
                .unwrap();
            owner_saids.push(evt.event.said.clone());
        }

        // Adversary events after fork point
        let mut adversary_events = Vec::new();
        for i in 0..adversary_event_count {
            let evt = if i == 0 && recovery == "cnt" {
                // For contest: adversary reveals recovery key via ror
                adversary.rotate_recovery().await.unwrap()
            } else {
                adversary
                    .interact(&anchor(&format!("adv-{i}")))
                    .await
                    .unwrap()
            };
            adversary_events.push(evt);
        }
        let adversary_fork_said = adversary_events.first().map(|e| e.event.said.clone());

        // Recovery
        match recovery {
            "rec" => {
                let rec = owner.recover(false).await.unwrap();
                owner_saids.push(rec.event.said.clone());
            }
            "rec+rot" => {
                let rot = owner.recover(true).await.unwrap();
                // recover(true) returns the rot, but both rec+rot are in pending_events
                let pending = owner.pending_events();
                // rec is second-to-last, rot is last
                let rec_said = pending[pending.len() - 2].event.said.clone();
                owner_saids.push(rec_said);
                owner_saids.push(rot.event.said.clone());
            }
            "cnt" => {
                let cnt = owner.contest().await.unwrap();
                owner_saids.push(cnt.event.said.clone());
            }
            _ => {} // "none"
        }

        // Combine and sort
        let mut all_events = owner.pending_events().to_vec();
        all_events.extend(adversary_events);
        sort_events(&mut all_events);

        (all_events, prefix, owner_saids, adversary_fork_said)
    }

    /// Helper: verify transfer output ordering for unrecovered/contested KELs.
    /// Shorter fork should be last.
    fn verify_transfer_ordering(
        collected: &[SignedKeyEvent],
        owner_saids: &[cesr::Digest],
        adversary_fork_said: Option<&cesr::Digest>,
        owner_event_count: usize,
        adversary_event_count: usize,
    ) {
        // Shorter chain's fork should be last
        if owner_event_count > adversary_event_count {
            assert_eq!(
                collected.last().unwrap().event.said,
                *adversary_fork_said.unwrap(),
                "Expected adversary fork last (shorter chain)"
            );
        } else if adversary_event_count > owner_event_count {
            assert!(
                owner_saids.contains(&collected.last().unwrap().event.said),
                "Expected owner fork last (shorter chain)"
            );
        }
        // Equal length: either could be last, just check all present
    }

    // Case 1: Owner:1, Adversary:1, rec — divergent KEL with rec is rejected
    // (synchronous archival means this state indicates DB tampering)
    #[tokio::test]
    async fn test_transfer_divergent_case1_owner1_adv1_rec() {
        let (events, prefix, _owner_saids, _adv_fork) = build_divergent_kel(1, 1, "rec").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err(), "Divergent KEL with rec should be rejected");
    }

    // Case 2: Owner:1, Adversary:1, rec+rot — same rejection
    #[tokio::test]
    async fn test_transfer_divergent_case2_owner1_adv1_rec_rot() {
        let (events, prefix, _owner_saids, _adv_fork) = build_divergent_kel(1, 1, "rec+rot").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err(), "Divergent KEL with rec should be rejected");
    }

    // Cases 3-6: Various owner/adversary chain lengths with rec/rec+rot — all rejected
    #[tokio::test]
    async fn test_transfer_divergent_case3_owner1_adv_n_rec() {
        let (events, prefix, _, _) = build_divergent_kel(1, 30, "rec").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transfer_divergent_case4_owner1_adv_n_rec_rot() {
        let (events, prefix, _, _) = build_divergent_kel(1, 30, "rec+rot").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transfer_divergent_case5_owner_n_adv1_rec() {
        let (events, prefix, _, _) = build_divergent_kel(30, 1, "rec").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transfer_divergent_case6_owner_n_adv1_rec_rot() {
        let (events, prefix, _, _) = build_divergent_kel(30, 1, "rec+rot").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    // Case 7: Owner:N, Adversary:N (both large), rec
    #[tokio::test]
    async fn test_transfer_divergent_case7_owner_n_adv_n_rec() {
        let (events, prefix, _, _) = build_divergent_kel(15, 30, "rec").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    // Case 8: Owner:N, Adversary:N (both large), rec+rot — rejected
    #[tokio::test]
    async fn test_transfer_divergent_case8_owner_n_adv_n_rec_rot() {
        let (events, prefix, _, _) = build_divergent_kel(15, 30, "rec+rot").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result =
            forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None).await;
        assert!(result.is_err());
    }

    // Case 9: Unrecovered divergence (owner longer)
    #[tokio::test]
    async fn test_transfer_divergent_case9_unrecovered() {
        let (events, prefix, owner_saids, adv_fork) = build_divergent_kel(5, 1, "none").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;
        verify_transfer_ordering(&collected, &owner_saids, adv_fork.as_ref(), 5, 1);
    }

    // Case 10: Contested KEL (adversary reveals recovery key, owner contests)
    #[tokio::test]
    async fn test_transfer_divergent_case10_contested() {
        let (events, prefix, owner_saids, adv_fork) = build_divergent_kel(1, 1, "cnt").await;
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;
        verify_transfer_ordering(&collected, &owner_saids, adv_fork.as_ref(), 1, 1);
    }

    // Regression: contested KEL must transfer the cnt event, not just the fork
    #[tokio::test]
    async fn test_transfer_contested_includes_cnt() {
        // Owner has events after fork + cnt. The cnt must arrive at the sink.
        let (events, prefix, _, _) = build_divergent_kel(3, 1, "cnt").await;

        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;

        // The cnt event MUST be present in the collected events
        let has_cnt = collected.iter().any(|e| e.event.is_contest());
        assert!(
            has_cnt,
            "cnt event missing from transfer — remote would not know KEL is contested"
        );
    }

    // Regression: contested KEL with longer adversary chain must transfer cnt
    #[tokio::test]
    async fn test_transfer_contested_longer_adversary_includes_cnt() {
        // Adversary has the longer chain (ror + ixns). Owner has ixn + cnt.
        // The owner's chain is shorter, so only the fork event is sent.
        // The cnt must still reach the sink.
        let (events, prefix, _, _) = build_divergent_kel(1, 3, "cnt").await;

        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        forward_key_events(&prefix, &source, &sink, crate::page_size(), 100, None)
            .await
            .unwrap();

        let collected = sink.into_events().await;

        let has_cnt = collected.iter().any(|e| e.event.is_contest());
        assert!(
            has_cnt,
            "cnt event missing from transfer — remote would not know KEL is contested"
        );
    }

    // Case 3b/4b: Multi-page adversary chain with small page_size
    #[tokio::test]
    async fn test_transfer_divergent_multi_page_adversary() {
        let (events, prefix, _, _) = build_divergent_kel(1, 20, "rec").await;

        // Use page_size=8 to force multiple pages during collection
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result = forward_key_events(&prefix, &source, &sink, 8, 100, None).await;
        assert!(result.is_err(), "Divergent KEL with rec should be rejected");
    }

    // Case 5b/6b: Multi-page owner chain with small page_size — same rejection
    #[tokio::test]
    async fn test_transfer_divergent_multi_page_owner() {
        let (events, prefix, _, _) = build_divergent_kel(20, 1, "rec+rot").await;

        // Use page_size=8 to force multiple pages during collection
        let source = MemoryKelSource::new(events);
        let sink = CollectSink::new();
        let result = forward_key_events(&prefix, &source, &sink, 8, 100, None).await;
        assert!(
            result.is_err(),
            "Divergent KEL with rec+rot should be rejected"
        );
    }

    #[tokio::test]
    async fn test_transfer_key_events_max_pages() {
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        for i in 0..10 {
            builder.interact(&anchor(&format!("a{}", i))).await.unwrap();
        }

        // Only allow 2 pages of 3 events — should get 6 events, not all 11
        let source = MemoryKelSource::new(builder.pending_events().to_vec());
        let events = resolve_key_events(&prefix, &source, 3, 2, None)
            .await
            .unwrap();

        assert_eq!(events.len(), 6);
    }

    #[tokio::test]
    async fn test_paginated_anchor_check_then_resume() {
        // Phase 1: verify a KEL via completed_verification with anchor checking.
        // Phase 2: add more events with new anchors, resume, verify new anchors.
        let mut builder = KeyEventBuilder::new(random_provider(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let anchor1 = anchor("phase1-anchor");
        builder.interact(&anchor1).await.unwrap();
        for i in 0..8 {
            builder
                .interact(&anchor(&format!("pad-{}", i)))
                .await
                .unwrap();
        }

        let store = MemoryStore::new();
        store
            .overwrite(&prefix, builder.pending_events())
            .await
            .unwrap();

        // Phase 1: verify with anchor check
        let kel_verification1 = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            5,
            100,
            vec![anchor1.clone()],
        )
        .await
        .unwrap();
        assert!(kel_verification1.is_said_anchored(&anchor1));
        assert_eq!(kel_verification1.branch_tips()[0].tip.event.serial, 9);

        // Phase 2: add more events with a new anchor
        let anchor2 = anchor("phase2-anchor");
        builder.interact(&anchor2).await.unwrap();
        for i in 0..4 {
            builder
                .interact(&anchor(&format!("pad2-{}", i)))
                .await
                .unwrap();
        }

        // Resume from kel_verification1 and check new anchor
        let new_events = &builder.pending_events()[10..]; // events after kel_verification1
        let mut verifier =
            KelVerifier::resume(kel_verification1.prefix(), &kel_verification1).unwrap();
        verifier.check_anchors(vec![anchor2.clone()]);
        verifier.verify_page(new_events).unwrap();
        let kel_verification2 = verifier.into_verification().unwrap();

        assert!(kel_verification2.is_said_anchored(&anchor2));
        assert_eq!(kel_verification2.branch_tips()[0].tip.event.serial, 14);
    }
}
