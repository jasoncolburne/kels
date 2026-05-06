//! Bootstrap merge-sync helper.
//!
//! Replaces the per-prefix existence-check storm in bootstrap preload with a
//! sort-merge against the local listing. Both local and remote listings are
//! returned in canonical sort order (`prefix ASC` for chains, `sad_said ASC`
//! for SAD objects); cursor-paginated; both sides paged through cooperatively.
//!
//! Memory bound: `page_size × 2 + queue_max`. The merge holds at most one
//! page from each side plus the in-flight enqueue buffer; nothing scales with
//! federation cardinality.
//!
//! Wrap-fill correction: the listing endpoints implement circular pagination
//! for AE — when the natural end of the listing is reached and a cursor was
//! supplied, the page tail is filled with `lte(cursor)` entries (front of
//! list). Bootstrap doesn't want those; the merge filters them by tracking
//! `max_yielded_so_far` and dropping entries `<= max_yielded` on the last
//! page (where `next_cursor.is_none()`).
//!
//! Algorithm:
//!
//! 1. Open a paginated stream from each side.
//! 2. Walk both heads pairwise:
//!    - `remote == local` → both have it; advance both.
//!    - `remote < local`  → enqueue `remote` (missing locally); advance remote.
//!    - `remote > local`  → advance local (local has something remote doesn't;
//!      bootstrap doesn't reach back for it — out-of-scope).
//! 3. Either side exhausts → drain the other (remote-only tails get
//!    enqueued; local-only tails are skipped).
//! 4. Queue at `queue_max` → drain by syncing with bounded concurrency,
//!    then continue the merge.

use std::collections::VecDeque;
use std::future::Future;

use futures::stream::{self, StreamExt};

/// One page of keys plus the cursor for the next page.
///
/// `next_cursor.is_none()` signals the listing has reached the end (the
/// circular wrap may have padded the page with already-seen entries — those
/// get filtered downstream against `max_yielded_so_far`).
pub struct KeyPage<K> {
    pub keys: Vec<K>,
    pub next_cursor: Option<K>,
}

/// Paginated, sorted stream of keys with wrap-fill filtering.
///
/// The `fetch` callback drives pagination: given the previous page's
/// `next_cursor` (or `None` for the first page), it returns the next
/// `KeyPage`. The stream tracks the highest key yielded so far and drops any
/// page entry `<= max_yielded` — the wrap-around fill the listing endpoint
/// emits on its last page would otherwise re-yield front-of-list entries.
pub struct SortedKeyStream<K, F, Fut, E>
where
    K: Ord + Clone,
    F: FnMut(Option<K>) -> Fut,
    Fut: Future<Output = Result<KeyPage<K>, E>>,
{
    fetch: F,
    cursor: Option<K>,
    buffer: VecDeque<K>,
    max_yielded: Option<K>,
    end_reached: bool,
}

impl<K, F, Fut, E> SortedKeyStream<K, F, Fut, E>
where
    K: Ord + Clone,
    F: FnMut(Option<K>) -> Fut,
    Fut: Future<Output = Result<KeyPage<K>, E>>,
{
    pub fn new(fetch: F) -> Self {
        Self {
            fetch,
            cursor: None,
            buffer: VecDeque::new(),
            max_yielded: None,
            end_reached: false,
        }
    }

    /// Refill the buffer from the next page if empty and not at end.
    /// Filters wrap-fill entries (`<= max_yielded`) so the merge sees a
    /// strictly-monotonic sequence.
    async fn refill(&mut self) -> Result<(), E> {
        if !self.buffer.is_empty() || self.end_reached {
            return Ok(());
        }
        let page = (self.fetch)(self.cursor.clone()).await?;
        for k in page.keys {
            if let Some(max) = &self.max_yielded
                && k <= *max
            {
                continue;
            }
            self.buffer.push_back(k);
        }
        self.cursor = page.next_cursor.clone();
        if page.next_cursor.is_none() {
            self.end_reached = true;
        }
        Ok(())
    }

    /// Peek at the head without consuming. Drives pagination as needed.
    pub async fn peek(&mut self) -> Result<Option<&K>, E> {
        self.refill().await?;
        Ok(self.buffer.front())
    }

    /// Consume the head. Drives pagination as needed.
    pub async fn pop(&mut self) -> Result<Option<K>, E> {
        self.refill().await?;
        let k = self.buffer.pop_front();
        if let Some(ref k) = k {
            self.max_yielded = Some(k.clone());
        }
        Ok(k)
    }
}

/// Drive a sort-merge between a remote and local key stream, syncing the
/// keys present in remote but missing locally.
///
/// `sync_one` handles the per-key sync (HTTP fetch + post). The driver
/// enqueues missing keys and drains the queue when it reaches `queue_max`,
/// running `sync_one` over the drained batch with bounded concurrency
/// (`concurrency`). Returns `(synced_count, sync_failures)` where
/// `sync_failures` are individual `sync_one` errors aggregated rather than
/// halting the whole pass — the existing bootstrap pattern soft-fails per-
/// prefix and lets gossip + AE backstop.
///
/// Stream-level errors (listing pagination failures) DO halt; those signal
/// the source peer is unreachable for this primitive and the caller should
/// fall through to the next ready peer.
pub async fn merge_sync<K, RemFut, LocFut, SyncFut, SyncFn, FRem, FLoc, ER, EL>(
    mut remote: SortedKeyStream<K, FRem, RemFut, ER>,
    mut local: SortedKeyStream<K, FLoc, LocFut, EL>,
    queue_max: usize,
    concurrency: usize,
    sync_one: SyncFn,
) -> Result<MergeStats, MergeError<ER, EL>>
where
    K: Ord + Clone + Send + 'static,
    FRem: FnMut(Option<K>) -> RemFut,
    FLoc: FnMut(Option<K>) -> LocFut,
    RemFut: Future<Output = Result<KeyPage<K>, ER>>,
    LocFut: Future<Output = Result<KeyPage<K>, EL>>,
    SyncFn: Fn(K) -> SyncFut + Clone,
    SyncFut: Future<Output = bool> + Send,
    ER: std::fmt::Debug + std::fmt::Display,
    EL: std::fmt::Debug + std::fmt::Display,
{
    let mut queue: Vec<K> = Vec::with_capacity(queue_max);
    let mut stats = MergeStats::default();

    loop {
        // Compare heads. Peek into temporaries; if either side is empty,
        // dispatch by what's left.
        let order = match (
            remote.peek().await.map_err(MergeError::Remote)?.cloned(),
            local.peek().await.map_err(MergeError::Local)?.cloned(),
        ) {
            (None, _) => break, // remote exhausted; done
            (Some(_), None) => {
                // local exhausted — every remaining remote key is missing
                while let Some(k) = remote.pop().await.map_err(MergeError::Remote)? {
                    queue.push(k);
                    if queue.len() >= queue_max {
                        let drained = std::mem::replace(&mut queue, Vec::with_capacity(queue_max));
                        drain_queue(drained, concurrency, sync_one.clone(), &mut stats).await;
                    }
                }
                break;
            }
            (Some(r), Some(l)) => r.cmp(&l),
        };

        match order {
            std::cmp::Ordering::Equal => {
                remote.pop().await.map_err(MergeError::Remote)?;
                local.pop().await.map_err(MergeError::Local)?;
            }
            std::cmp::Ordering::Less => {
                if let Some(k) = remote.pop().await.map_err(MergeError::Remote)? {
                    queue.push(k);
                    if queue.len() >= queue_max {
                        let drained = std::mem::replace(&mut queue, Vec::with_capacity(queue_max));
                        drain_queue(drained, concurrency, sync_one.clone(), &mut stats).await;
                    }
                }
            }
            std::cmp::Ordering::Greater => {
                local.pop().await.map_err(MergeError::Local)?;
            }
        }
    }

    if !queue.is_empty() {
        drain_queue(queue, concurrency, sync_one, &mut stats).await;
    }

    Ok(stats)
}

async fn drain_queue<K, SyncFn, SyncFut>(
    keys: Vec<K>,
    concurrency: usize,
    sync_one: SyncFn,
    stats: &mut MergeStats,
) where
    K: Send + 'static,
    SyncFn: Fn(K) -> SyncFut + Clone,
    SyncFut: Future<Output = bool> + Send,
{
    let attempted = keys.len();
    let succeeded: usize = stream::iter(keys)
        .map(|k| {
            let f = sync_one.clone();
            async move { if f(k).await { 1usize } else { 0usize } }
        })
        .buffer_unordered(concurrency)
        .fold(0usize, |acc, n| async move { acc + n })
        .await;
    stats.synced += succeeded;
    stats.failed += attempted - succeeded;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MergeStats {
    /// Number of remote-only keys that synced successfully.
    pub synced: usize,
    /// Number of remote-only keys whose sync failed (gossip + AE backstop).
    pub failed: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum MergeError<ER, EL>
where
    ER: std::fmt::Debug + std::fmt::Display,
    EL: std::fmt::Debug + std::fmt::Display,
{
    #[error("remote listing pagination failed: {0}")]
    Remote(ER),
    #[error("local listing pagination failed: {0}")]
    Local(EL),
}
