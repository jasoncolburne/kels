# Branch Audit: KELS-71_bound-archival (Round 1) — 2026-03-22

Async recovery archival: 33 files changed, ~2424 diff lines (+1347/-306). Replaces synchronous adversary archival with background task, adds RecoveryRecord state machine, serve filter, recovery table to all services.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 3        |
| Low      | 0    | 3        |

All 7 findings resolved.

---

## High Priority

### ~~1. `find_adversary_tip_all_adversary` may miss true tip for long adversary chains~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:455-483`

~~The query fetches only `page_size()` events (32) from `diverged_at` sorted by serial DESC. If the adversary chain exceeds 32 events (possible over multiple days despite the 64/day rate limit), the true highest-serial adversary event may not be on this page. The function would return the wrong tip, and archival would start from the wrong position — potentially leaving adversary events unarchived.~~

**Resolution:** Changed to `LIMIT 3` — the owner has at most rec + rot above the adversary tip, so 3 rows always finds it regardless of chain length.

---

## Medium Priority

### ~~2. `query_active_recoveries` fetches all recovery records then filters in Rust~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:109-131`

~~The query fetches every record from the recovery table (including terminal `Recovered` records) sorted by `(kel_prefix, version DESC)`, then deduplicates and filters in memory. For a system with many past recoveries, this loads unnecessary data on every cycle.~~

**Resolution:** Added `Query::ne()` shorthand to verifiable-storage query builder. `query_active_recoveries` now filters `.ne("state", "recovered")` at the SQL level.

### ~~3. `std::collections::HashSet` used inline in function body~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:119`

~~Per CLAUDE.md: "Never import inline within function bodies, unless inside a feature-gated block." `std::collections::HashSet` is constructed inline rather than imported at the top of the file.~~

**Resolution:** `HashSet` added to top-level `use std::collections::{HashMap, HashSet};` import.

### ~~4. Tip query in `archive_one_page` does not filter by prefix~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:224-226`

~~The tip event is fetched by SAID only (`.eq("said", tip_said)`), without a prefix filter. While SAIDs should be globally unique (Blake3 hashes), defense-in-depth would add `.eq("prefix", &current.kel_prefix)` to prevent any theoretical cross-prefix issue.~~

**Resolution:** Added `.eq("prefix", &current.kel_prefix)` to the tip query.

---

## Low Priority

### ~~5. Import style: `std` imports not nested~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:11-12`

~~Per CLAUDE.md convention, `std` imports should be nested in a single `use` statement.~~

**Resolution:** Combined into `use std::{collections::{HashMap, HashSet}, time::Duration};`.

### ~~6. No integration test for audit endpoint returning actual recovery records~~ — RESOLVED

**File:** `services/kels/tests/integration_tests.rs:495-507`

~~The test `test_get_kel_with_audit` only checks that the audit endpoint returns empty for a simple KEL. There's no test that performs a recovery and then verifies the audit endpoint returns the expected `RecoveryRecord` entries.~~

**Resolution:** Expanded `test_recovery_from_divergence` to verify the audit endpoint returns a `RecoveryRecord` with correct fields (state, diverged_at, kel_prefix, version, said, prefix, rec_previous) and that the archived events endpoint returns empty before archival runs.

### ~~7. `process_all_recoveries` may log-flood on persistent failures~~ — RESOLVED

**File:** `lib/kels/src/recovery.rs:94-106`

~~If processing a specific recovery record fails persistently (e.g., corrupted record), it logs a warning every cycle indefinitely. No backoff or suppression.~~

**Resolution:** Accepted as intended behavior. Persistent failures indicate corruption or misconfiguration that operators should investigate immediately. The warning-per-cycle pattern ensures visibility. Log aggregation/alerting handles deduplication at the ops layer.

---

## Positive Observations

- **Immutable audit trail via chained records.** Each `RecoveryRecord` state transition creates a new version with a `previous` pointer, forming a tamper-evident chain. Records are never deleted or mutated — terminal `Recovered` records serve as permanent audit trail.

- **Backward chain walk for adversary identification.** Using `previous` pointer traversal in memory after a batch fetch deterministically identifies adversary events without explicit tagging. The owner's rec/rot at the same serial is naturally excluded since it's on a different `previous` chain.

- **Fail-secure recovery-in-progress rejection.** Blocking all submissions during active recovery (merge.rs:310-312) prevents the async window from being exploitable. The adversary cannot inject additional events while archival is in progress.

- **Consistent advisory lock discipline.** Every background task state transition acquires the advisory lock and re-reads the record under lock before proceeding, preventing TOCTOU races between concurrent merge operations and the background task.

- **Clean cfg-gated cache invalidation.** The `recovery_archival_loop_with_cache` variant is redis-gated, keeping the recovery module independent of Redis while still providing cache invalidation where available. No trait objects or unnecessary abstractions.

- **Generic `RecoveryConfig` enables clean reuse.** The table name configuration struct allows the same recovery loop to work across all four services (kels, kels-registry, kels-gossip, identity) with different table names, without code duplication.
