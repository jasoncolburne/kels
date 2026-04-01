# Branch Audit: KELS-76_replicated-sad-store (Round 5) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: ~10,685 lines diff, 77 files changed. Full review of SAD transfer infrastructure, gossip sync/anti-entropy, SADStore handlers/repository, and client code. All 22 findings from rounds 1-4 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 4        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. `unwrap_or_default()` on reqwest client builders silently drops timeouts~~ — RESOLVED

**Files:**
- `lib/kels/src/client/sadstore.rs`
- `lib/kels/src/types/sad_transfer.rs` (`HttpSadSource::new`, `HttpSadSink::build`)
- `lib/kels/src/client/kels.rs` (`KelsClient::with_path_prefix`, `with_timeout`)
- `lib/kels/src/types/verifier.rs` (`HttpKelSource::new`, `HttpKelSink::new`)
- Plus all other client constructors across the codebase

~~If `reqwest::Client::builder().build()` fails, `unwrap_or_default()` silently falls back to `reqwest::Client::default()` which has no timeouts. Per the project's "no security fallbacks" convention, this should fail loudly.~~

**Resolution:** All HTTP client constructors across both KEL and SAD infrastructure now return `Result<Self, KelsError>` and use `?` to propagate `reqwest::Error` (which maps to `KelsError::HttpError` via the existing `From` impl). Call sites updated to propagate with `?`. `HttpSadSink` constructors deduplicated via shared `build()` method (also resolves finding #6).

---

## Medium Priority

### ~~2. KEL gossip feedback loop prevention breaks for divergent KELs~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~The `recently_stored` cache key used `{prefix}:{effective_said}`, but the Redis `kel_updates` message contains the actual event SAID. For divergent KELs the effective SAID is synthetic, causing a key mismatch and redundant gossip re-broadcasts.~~

**Resolution:** The KELS `submit_events` handler now always publishes the effective SAID (computed via `compute_prefix_effective_said`) rather than the submitted event's tip SAID. For non-divergent KELs these are the same; for divergent KELs the effective SAID is the synthetic hash. The gossip handler's cache key `{prefix}:{effective_said}` now matches the Redis payload exactly.

### ~~3. SAD repair gossip feedback loop — cache key mismatch on `:repair` suffix~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~The handler inserted `sad-record:{prefix}:{said}` but the subscriber constructed `sad-record:{prefix}:{said}:repair` for repair events, causing a mismatch.~~

**Resolution:** The SADStore handler now publishes the effective SAID (computed via `effective_said()`) rather than the last stored record's SAID. The gossip subscriber strips the `:repair` suffix before constructing the cache key, so both `{prefix}:{effective_said}` and `{prefix}:{effective_said}:repair` match the handler's cache key `sad-record:{prefix}:{effective_said}`.

### ~~4. `local_saids` cache in `SyncHandler` grows unbounded~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~`local_saids` HashMap grew indefinitely with every unique prefix handled, unlike `peer_fetch_counts` which had a periodic reaper.~~

**Resolution:** Added `handler.local_saids.clear()` to the existing 300-second reap interval in the sync event loop. Values are re-fetched on cache miss, so clearing is safe — it just causes a DB round-trip on the next access.

### ~~5. `SadChainVerifier` doesn't call `verify_prefix()` on v0 records~~ — RESOLVED

**File:** `lib/kels/src/types/sad_transfer.rs`

~~The client-side `SadChainVerifier::verify_page()` checked SAID integrity and prefix consistency but didn't verify prefix derivation on the v0 inception record.~~

**Resolution:** Added `record.verify_prefix()?` when `self.expected_version == 0` in `verify_page()`. Added `Chained` trait import to bring `verify_prefix()` into scope. Client-side verification now matches the server-side check.

---

## Low Priority

### ~~6. `HttpSadSink::new()` and `new_repair()` duplicate client construction~~ — RESOLVED

**File:** `lib/kels/src/types/sad_transfer.rs`

~~Both constructors built identical `reqwest::Client` instances with the same timeout configuration.~~

**Resolution:** Extracted shared `HttpSadSink::build(base_url, repair)` method. `new()` and `new_repair()` delegate to it. Resolved as part of finding #1.

### ~~7. Import style issues in files touched by this branch~~ — RESOLVED

**Files:**
- `services/kels-gossip/src/hsm_signer.rs` — two `use gossip::` statements
- `services/kels-registry/src/handlers.rs` — two `use kels::` blocks
- `services/kels-registry/src/server.rs` — two `use kels::` statements

**Resolution:** Merged into single nested `use` blocks per the import convention.

---

## Positive Observations

- **Three-phase SAD anti-entropy with exponential backoff.** Phase 1 (targeted stale repair), Phase 2 (random sampling with wrap-around cursor), Phase 3 (object set comparison). The backoff prevents tight retry loops on persistent failures, and phase 2 rediscovers entries dropped after max retries. Clean, well-structured approach.

- **Comprehensive chain integrity in `save_with_verified_signature`.** Advisory locking, divergence detection, v0 determinism enforcement, previous SAID linkage, kel_prefix/kind consistency, sequential version checks, and prefix derivation verification — all within a single transaction. Belt-and-suspenders correctness.

- **Two-pass verification stays O(page_size) in memory.** Pass 1 streams through records for structural verification and serial collection (with `NoOpSink`), then pass 2 streams again for signature verification with collected KEL keys. No full-chain accumulation needed.

- **Repair propagation via gossip with `:repair` flag.** Divergent chains auto-repair across the federation without manual per-node intervention. The `SadGossipMessage::Chain { repair: bool }` design keeps the protocol clean.

- **`SadRecordVerification` proof token pattern.** `pub(crate)` constructor prevents fabrication, matching the `KelVerification` pattern. Consistent type-level security enforcement across both subsystems.

- **Bidirectional anti-entropy in both KEL and SAD paths.** Random sampling pushes local-only state to peers and pulls remote-only state. Wrapping cursor ensures unbiased sampling across the prefix/object keyspace.
