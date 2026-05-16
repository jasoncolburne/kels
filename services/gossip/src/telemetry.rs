//! Lightweight in-flight counter telemetry for local sadstore HTTP calls.
//!
//! Bootstrap merge-sync and the gossip-event handler both POST/GET against
//! the local sadstore. When the local PG pool exhausts (default 16 conns),
//! requests queue at the sqlx side and time out at the http_client side —
//! the loss is visible but the *source* of the load isn't. This module
//! provides RAII-tracked counters that emit on each call boundary so we can
//! correlate inflight depth with sadstore pool depth at the same wall-clock
//! time.
//!
//! Logged at `target = "kels_gossip::inflight"` at `debug` level. Pair with
//! the sadstore-side `kels_sadstore::pool` and `kels_sadstore::handlers`
//! traces.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tracing::debug;

/// Cloneable handle to an atomic in-flight counter labelled by source
/// (e.g. "gossip", "bootstrap-kel", "bootstrap-sad-objects").
#[derive(Clone)]
pub struct LocalInflight {
    counter: Arc<AtomicUsize>,
    source: &'static str,
}

impl LocalInflight {
    pub fn new(source: &'static str) -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
            source,
        }
    }

    /// Increment the counter and return a guard that decrements on drop.
    /// Logs entry and exit at debug level.
    pub fn enter(&self, op: &'static str) -> InflightGuard {
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        debug!(
            target: "kels_gossip::inflight",
            source = self.source,
            op,
            inflight = n,
            "local sadstore call start",
        );
        InflightGuard {
            counter: self.counter.clone(),
            source: self.source,
            op,
            start: Instant::now(),
        }
    }
}

pub struct InflightGuard {
    counter: Arc<AtomicUsize>,
    source: &'static str,
    op: &'static str,
    start: Instant,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let n = self.counter.fetch_sub(1, Ordering::Relaxed) - 1;
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        debug!(
            target: "kels_gossip::inflight",
            source = self.source,
            op = self.op,
            inflight = n,
            elapsed_ms,
            "local sadstore call done",
        );
    }
}
