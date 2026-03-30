# Branch Audit: KELS-76_replicated-sad-store (Round 6) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: ~13,300 lines across 98 files. Replicated SADStore service, SAD gossip sync, SAD anti-entropy, CLI extensions, integration/E2E tests. All 24 findings from rounds 1-5 are resolved. This round focuses on residual issues after those fixes.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. SAD anti-entropy loop recreates `SadStoreClient` (and its reqwest connection pool) on every iteration~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:1321-1327`

~~The SAD anti-entropy loop creates a new `SadStoreClient` inside the loop body on every cycle. Each `SadStoreClient::new()` constructs a fresh `reqwest::Client` with its own connection pool. By contrast, the KEL anti-entropy loop at line 983 creates its `KelsClient` once before the loop and reuses it across all iterations.~~

**Resolution:** Moved `local_client` creation above the `loop` block, matching the KEL anti-entropy pattern.

---

## Low Priority

### ~~2. `DefaultBodyLimit` (5 MiB) is 5x larger than the application-level `max_sad_object_size` (1 MiB)~~ — RESOLVED

**File:** `services/kels-sadstore/src/server.rs:71`

~~The Axum `DefaultBodyLimit::max(5 * 1024 * 1024)` allows the framework to buffer up to 5 MiB before the handler's size check at `handlers.rs:322` rejects anything over 1 MiB (the default `SADSTORE_MAX_OBJECT_SIZE`). This means 4 MiB of wasted bandwidth and memory for every oversized request before rejection.~~

**Resolution:** `DefaultBodyLimit` now derives from `max_sad_object_size() + 4096`, keeping both limits in sync.

### ~~3. Gossip `handle_sad_chain_announcement` pre-inserts feedback-prevention cache key before forwarding — not removed on failure~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:406-461`

~~The cache key `sad-record:{chain_prefix}:{remote_said}` is inserted at line 409 before the forward attempt. If forwarding fails (line 447-461), the cache entry persists for 60 seconds (`RECENTLY_STORED_TTL`). During that window, if the same chain/SAID pair is re-announced via gossip, `run_sad_redis_subscriber` would skip it as "recently stored." This temporarily blocks gossip-driven sync for that chain.~~

**Resolution:** Cache key is now removed on forward failure.

### ~~4. `get_stored_chain` over-fetches by `page_size()` rows when `since` cursor is used~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs:368-375`

~~When a `since` cursor is provided, the query adds `page_size()` (default 64) extra rows to `fetch_limit` to account for records at the cursor position that will be skipped. In practice, at most one or two extra rows exist at the cursor version (the cursor record itself plus divergent duplicates), so fetching `page_size()` extra is overly generous.~~

**Resolution:** Fetch limit now uses `limit + 2` (cursor record + at most one divergent fork). Added a tamper-detection check: if more than 2 records are skipped at the cursor version, the function returns an error indicating possible DB tampering, since legitimate divergence can only produce one extra record at one version.

---

## Positive Observations

- **Consistent verification-invariant adherence.** The serving/consuming/resolving classification is applied consistently across the new SADStore code — gossip sync uses forwarding (serving), CLI verification returns tokens (consuming), anti-entropy uses effective SAID comparison (resolving). This is a clean application of the pattern from CLAUDE.md.

- **Two-pass O(page_size) verification design.** `verify_sad_records` in `sad_transfer.rs` avoids holding the full chain in memory by splitting into structural verification (pass 1) and signature verification (pass 2), collecting only establishment serials between passes. This mirrors the KEL verification architecture well.

- **Robust chain repair with full audit trail.** `truncate_and_replace` archives displaced records and signatures into separate tables with a first-class `SadChainRepair` entity linking them. This allows forensic investigation of repairs and is a thoughtful design decision for a security-focused system.

- **Rate limiting at multiple levels.** The combination of per-IP token bucket, per-chain-prefix daily limits, and nonce deduplication provides defense-in-depth against abuse, with configurable thresholds via environment variables and automatic reaping to prevent unbounded map growth.

- **SAD anti-entropy mirrors KEL anti-entropy structure.** The Phase 1 (targeted stale prefixes) + Phase 2 (random sampling) pattern with exponential backoff and max retry limits is cleanly replicated for SAD chains and extended with Phase 3 for object comparison. The code reuses shared infrastructure (`drain_due_stale_entries`, `encode/decode_stale_value`) rather than duplicating it.

- **Multi-page repair correctness.** The `HttpSadSink` with `?repair=true` correctly handles multi-page chains — each page's `truncate_and_replace` uses its first record's version as `from_version`, so pages 2+ append without disturbing page 1's insertions. This subtle interaction works because the advisory lock serializes concurrent access and the predecessor check validates chain continuity across pages.
