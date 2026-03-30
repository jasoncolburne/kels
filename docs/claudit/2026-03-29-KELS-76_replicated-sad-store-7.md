# Branch Audit: KELS-76_replicated-sad-store (Round 7) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: ~13,400 lines across 99 files. Replicated SADStore service, SAD gossip sync, SAD anti-entropy, CLI extensions, integration/E2E tests. All 28 findings from rounds 1-6 are resolved. This round focuses on residual issues after those fixes.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 1    | 0        |
| Low      | 2    | 0        |

---

## Medium Priority

### 1. `ensure_bucket()` catches all `head_bucket` errors as "bucket not found"

**File:** `services/kels-sadstore/src/object_store.rs:55-72`

`ensure_bucket()` uses `Err(_)` to catch all `head_bucket()` failures, then unconditionally attempts `create_bucket()`. If `head_bucket` fails for a transient reason (network timeout, DNS blip, auth token expiry), the code assumes the bucket doesn't exist and tries to create it. MinIO returns `BucketAlreadyOwnedByYou` on duplicate creation, which propagates as `"Failed to create bucket: ..."` — masking the real cause (transient error on HEAD).

This only runs once at startup and is fail-secure (service won't start on error), but the confusing error message makes operator debugging harder.

**Suggested fix:** Check whether the `head_bucket` error is a 404 specifically (using the existing `is_not_found()` helper pattern from `get()`) before falling through to bucket creation. Return the original error for non-404 failures.

---

## Low Priority

### 2. Bootstrap `preload_sad_objects` silently skips individual object failures

**File:** `services/kels-gossip/src/bootstrap.rs:193-206`

Within the per-object loop, `sad_object_exists()` errors are silently `continue`d (line 198), and `get_sad_object()`/`put_sad_object()` errors are absorbed by the `if let Ok(...) && .is_ok()` chain (lines 202-204). No logging occurs for individual object failures.

The outer page-level loop correctly logs and breaks on `fetch_sad_objects` failures (lines 187-190), but individual object-level errors within a successfully fetched page are invisible. If a transient error affects 50% of objects in a page, the operator sees "SAD object preload complete: 50 objects synced" with no indication that 50 others failed.

Anti-entropy will eventually catch missed objects, so this isn't a data-loss risk, but it makes bootstrap completeness hard to diagnose.

**Suggested fix:** Add `debug!` or `warn!` logging for individual object failures before `continue`/skip.

### 3. Integration test import ordering

**File:** `services/kels-sadstore/tests/integration_tests.rs:9-20`

`std` (line 12) and `tokio` (line 19) imports are interleaved with external crates (`ctor`, `kels`, `reqwest`, `testcontainers`) instead of being grouped first per CLAUDE.md convention. Should be: Group 1 (`std`, `tokio`), blank line, Group 2 (external crates), blank line, Group 3 (local).

**Suggested fix:** Reorder to place `std` and `tokio` imports first, followed by external crates.

---

## Positive Observations

- **Comprehensive validation in `submit_sad_records`.** Nine validation steps before storage — IP rate limiting, prefix consistency, SAID integrity, bounded establishment serial collection, KEL verification, signature verification, prefix derivation — with early returns and dedup-aware rate limit accrual. Matches the KEL `submit_events` handler quality.

- **Clean transfer infrastructure.** `PagedSadSource`/`PagedSadSink` with `transfer_sad_records`, `forward_sad_records`, and `verify_sad_records` cleanly mirrors the KEL pattern. Two-pass verification stays O(page_size) in memory while collecting establishment serials between passes.

- **Thorough chain integrity in `save_with_verified_signature`.** Advisory locking, divergence detection, v0 determinism enforcement, previous SAID linkage, kel_prefix/kind consistency, sequential version checks, and prefix derivation — all within a single transaction. Repair path (`truncate_and_replace`) includes `windows(2)` internal chain linkage verification.

- **Three-phase bidirectional anti-entropy with exponential backoff.** Phase 1 (targeted stale repair), Phase 2 (random chain sampling with wrap-around cursor and push+pull), Phase 3 (object set comparison). Shared `drain_due_stale_entries` and `encode/decode_stale_value` infrastructure between KEL and SAD paths avoids code duplication.

- **Feedback loop prevention with cache key cleanup on failure.** SAD gossip handlers pre-insert feedback-prevention cache keys, and remove them on forward failure — preventing the 60-second "dead window" that would block gossip re-delivery of that chain.

- **FK cascade deletes across all services.** Every signature table has `ON DELETE CASCADE`. No manual cleanup code needed for archive, repair, or truncation paths. Consistent across all five services.
