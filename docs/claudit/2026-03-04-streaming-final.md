# Branch Audit: Streaming Verification (Final) — 2026-03-04

Automated audit of `kels-52_paginate-kels-requests` branch changes vs `main`. Scope: full `git diff main` (~22K lines). Focus: correctness, security, performance, and API design.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High | 2 | 0 |
| Medium | 8 | 0 |
| Low | 6 | 0 |

---

## High Priority

### 1. Raft `apply()` holds state machine mutex across async I/O

**File:** `services/kels-registry/src/federation/state_machine.rs`

The `apply()` method holds `self.inner.lock().await` while performing `verify_member_anchoring_from_repo(...).await` calls and the `SyncMemberKel` fetch block (which makes HTTP requests via `kels::forward_key_events`). This blocks all Raft state reads (including `is_member()` checks, peer list access) during potentially slow I/O. If a member KEL HTTP fetch is slow or times out, the entire state machine is blocked.

Consider moving the `SyncMemberKel` fetch outside the lock scope — spawn as a background task after releasing the lock, or restructure so the lock is only held for pure state mutation.

### 2. `max_verification_pages()` reads environment variable on every call

**File:** `lib/kels/src/lib.rs:113-127`

`max_verification_pages()` calls `env::var("KELS_MAX_VERIFICATION_PAGES")` on every invocation. It is called in `merge_events` (on every event submission) and in multiple scan/trace methods in `merge.rs`, potentially 5+ times per merge operation. While `env::var` is not extremely expensive, it involves a syscall and heap allocation per call.

Consider caching with `std::sync::OnceLock` or `std::sync::LazyLock`, since changing the value mid-process would be unexpected.

---

## Medium Priority

### 3. Three-way divergence heuristic is overly broad

**File:** `services/kels-gossip/src/sync.rs`

The old code checked `local_kel.find_divergence().is_some()` to detect three-way divergence. The new code uses `if local_said.is_some()` — this is true for *any* existing local KEL, not just divergent ones. A `Failed` merge result with a non-divergent local KEL could have other causes (network errors, validation failures), and the new heuristic would incorrectly `record_seen_said`, suppressing retries.

This is a resolving operation, so wrong guesses either cause an unnecessary retry or skip one sync cycle — not a security issue — but it could cause stale data to persist longer than necessary.

### 4. Batch endpoint error propagation — one bad prefix fails entire batch

**File:** `services/kels/src/handlers.rs`

In the batch endpoint's delta path, if a `since` SAID is not found, the code falls back to a full fetch. If the prefix itself doesn't exist, the full fetch produces `EventNotFound` which propagates via `?`. Individual task errors are collected and re-propagated, so one bad entry fails the entire batch request.

### 5. `fetch_events_delta` only fetches one page

**File:** `services/kels-gossip/src/sync.rs:776-799`

This function calls `fetch_key_events` (single page) rather than a paginated loop. For KELs with more than 512 events, the delta fetch returns only the first page. Used in the anti-entropy push path (`sync_prefix`). Since anti-entropy runs periodically and this is a resolving operation, incomplete data triggers another round of sync — not a correctness issue, but inefficient for large KELs.

### 6. `cmd_dev_truncate` ignores `_has_more` flag — silent single-page limit

**File:** `clients/kels-cli/src/main.rs:797-799`

The `_has_more` return value is explicitly discarded. If a local KEL has more than 512 events, `cmd_dev_truncate` only sees the first 512. If the user requests truncation to 600 events, the function would report "KEL already has 512 events, nothing to truncate" — which is wrong.

This is dev-tools only. Either paginate to load all events, or document the 512-event limitation for truncation.

### 7. `get_signed_history_since` limit+2 arithmetic is correct but fragile

**File:** `lib/kels-derive/src/lib.rs:226-245`

The method fetches `limit + 2` events (one for the since event to be retained then filtered, one for has_more detection). The arithmetic works because at most one event is filtered out by `retain` and at most one extra is the has_more sentinel. The edge case where the since SAID is not found (scalar subquery returns NULL, `serial >= NULL` evaluates to false) correctly returns an empty result.

No bug, but the two-event slack reasoning should be documented inline more thoroughly.

### 8. `SyncMemberKel` Raft entry is a trigger — no data consistency guarantee

**File:** `services/kels-registry/src/federation/state_machine.rs`

The new pattern changes from "KEL data replicated in Raft" to "Raft replicates a trigger, each node fetches independently." Different nodes may fetch at different times with different member KEL state in their local PostgreSQL. If a vote anchoring verification runs on one node before the latest KEL events have been fetched, it could fail.

The fail-secure behavior (anchoring verification fails if KEL not available) is correct. This is an architectural trade-off (decoupling data from consensus) that trades consistency for scalability.

### 9. Snapshot restore no longer validates member KELs

**File:** `services/kels-registry/src/federation/state_machine.rs`

The old code verified all member KELs during snapshot restore and removed invalid ones. The new code removes member KELs from snapshots entirely (they're in PostgreSQL now). There's no equivalent validation of PostgreSQL-backed member KELs on startup. Member KELs in PostgreSQL are verified on each read via `completed_verification` in `verify_member_anchoring_from_repo`, so invalid data can't be *consumed* unsafely, but corrupt data would cause verification failures until re-synced.

### 10. `merge_events` re-verifies entire KEL on every submission

**File:** `lib/kels/src/merge.rs:340-350`

Every call to `merge_events` runs `completed_verification` over the entire existing KEL. For large KELs (e.g., 100K events), this involves reading and cryptographically verifying all existing events before processing the new submission. This is the correct application of the verification invariant ("We cannot cache Verification tokens because the DB cannot be trusted") and is bounded by `max_verification_pages * MAX_EVENTS_PER_KEL_QUERY` (default 262K events). Documented design trade-off, not a bug.

---

## Low Priority

### 11. `fetch_all_events` shell function has no max-page guard

**File:** `clients/test/scripts/lib/test-common.sh:113-146`

The `fetch_all_events` function loops indefinitely with `while true` and no iteration limit. If a server returns `hasMore: true` with no progress (e.g., buggy response where the last SAID doesn't advance), this function loops forever. The Rust-side functions all have `max_pages` guards for this reason.

In practice, test scripts run against known-good servers with finite KELs, but this diverges from the bounded pagination principle.

### 12. `federation_sync_member_kel` accepts raw JSON body

**File:** `services/kels-registry/src/handlers.rs`

`Json(body): Json<serde_json::Value>` then `body["prefix"].as_str()` — uses untyped JSON parsing instead of a proper request struct. Inconsistent with the rest of the codebase which uses typed request bodies. Not a bug, but reduces type safety and documentation.

### 13. Identity admin tool paginated KEL fetch has no page bound

**File:** `services/kels-registry/src/bin/kels-registry-admin.rs`

The loop fetching pages in `show_identity_status` has no `max_pages` bound — it continues until `!page.has_more`. A malicious or buggy identity service could keep returning `has_more: true` forever. Low concern since this is an admin CLI tool, not a production service path, and the identity service is trusted (same deployment).

### 14. `ContestRequired` match arm is unreachable in submit handler

**File:** `services/kels/src/handlers.rs`

The `KelMergeResult::ContestRequired` match arm is defensive dead code — `save_with_merge` returns `Err(KelsError::ContestRequired)` which is caught by the `.map_err()` block above before reaching the match. Not a bug; the current approach (returning the same error) is safe as defense-in-depth.

### 15. Import style inconsistency in `sync.rs`

**File:** `services/kels-registry/src/federation/sync.rs`

`use std::sync::Arc;` and `use std::time::Duration;` are on separate lines rather than nested: `use std::{sync::Arc, time::Duration};` as required by CLAUDE.md import style.

### 16. Bench tool Makefile parameters increased without rationale

**File:** `Makefile:157`

Concurrency increased from 40 to 60, duration from 3s to 5s. Likely justified by the additional benchmark sizes (1, 8, 32, 64, 128, 256, 512 events vs. previous 1, 8, 32, 128), but no comment explains the motivation.

---

## Positive Observations

- **Verification invariant enforcement is rigorous:** `Verification` has private fields and can only be constructed through `KelVerifier::into_verification()`. The type system makes invalid states unrepresentable. All consuming paths use `completed_verification` to produce proper tokens. Comments consistently annotate operations as "Serving", "Consuming", or "Resolving".
- **Deterministic ordering is consistently maintained:** All paginated queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` via `EventKind::sort_priority_mapping()`. No hardcoded event kind strings appear anywhere.
- **Streaming verifier architecture is well-designed:** `KelVerifier` tracks per-branch cryptographic state incrementally without holding the full event chain in memory. The `transfer_key_events` held-back event strategy handles split-generation detection across page boundaries. `truncate_incomplete_generation` limitations are explicitly documented.
- **Comprehensive test suite:** ~3600+ lines of verifier tests covering linear verification, multi-page pagination, divergence at page boundaries, recovery, contest, decommission, resume/incremental verification, anchor checking across pages, truncation edge cases, and full lifecycle tests. Integration tests cover asymmetric KEL sizes (1537 vs 513 events), divergence creation, and overlapping submissions.
- **Submit handler simplified dramatically:** `save_with_merge` (generated derive macro) encapsulates all merge/verification/advisory-lock logic. The handler is now a thin orchestrator with early rejection before lock acquisition.
- **Clean `serve_kel_page` serving path:** All services that serve KELs use the same since-resolution and pagination logic, eliminating inconsistencies. Composite SAID fallback for divergent KELs cleanly handles the "client has divergent state" case.
- **Signed KEL-update notifications are well-designed:** The new `identity_kel_updated` endpoint uses signed requests with timestamp validation, nonce deduplication, and rate limiting. Signing happens *before* rotation (when the key is still valid), verification happens against cached pre-rotation KEL.
- **Fail-secure behavior is consistent:** `completed_verification` returns an error rather than a partial `Verification` when `max_pages` is reached. Divergent anchors are excluded (adversary may have forged them). `identity_kel_updated` returns 503 when MemberKelRepository is empty rather than accepting an unverifiable notification.
- **Client-side caching removal simplifies architecture:** Server-side Redis caching with pub/sub invalidation replaces the complex `KelCache`/`RedisKelCache` system, avoiding cache coherence issues.
- **Consistent pagination adoption across all clients and tests:** Every raw `curl` call replaced with paginated fetching. Test scripts use `fetch_all_events()`, CLI uses `collect_key_events()` / `resolve_key_events()`, bench tool uses `benchmark_key_events()` / `resolve_key_events()`.
- **Action-oriented error naming:** `RecoveryProtected` -> `ContestRequired`, `Rejected` -> `RecoverRequired` — carried consistently across Rust, FFI, Swift, shell tests, and documentation.
- **Member KEL decoupling from Raft improves scalability:** Removing potentially large `HashMap<String, Kel>` from Raft snapshots improves snapshot size and serialization time. Each node independently fetches and verifies, which is architecturally cleaner.
