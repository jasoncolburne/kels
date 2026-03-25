# Branch Audit: KELS-71_bound-archival (Round 6) — 2026-03-25

Synchronous bounded archival, reconciliation proof, `send_divergent_events` gossip ordering, proactive ror enforcement, contest chain-rebuild, 10-scenario reconciliation test suite: 53 files changed, ~5836 diff lines (+3542/-693). Focus on fresh review of entire diff surface for new findings not covered in rounds 1-5.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 5        |
| Medium   | 0    | 13       |
| Low      | 0    | 14       |

All 24 findings from rounds 1-5 remain resolved. 2 new findings this round, both resolved.

---

## High Priority

### ~~1. `find_adversary_tip_all_adversary` may miss true tip for long adversary chains~~ — RESOLVED (Round 1)

**Resolution:** Replaced with bounded synchronous archival in merge transaction. No longer applicable.

### ~~2. `collect_all_adversary_saids` fetch limit used `page_size()` instead of `MINIMUM_PAGE_SIZE`~~ — RESOLVED (Round 2)

**Resolution:** Changed to `crate::MINIMUM_PAGE_SIZE as u64 * 2`.

### ~~3. Contest recovery-revealing check uses `cnt_serial` instead of `diverged_at`~~ — RESOLVED (Round 3)

**Resolution:** Changed to `non_contest_recovery_revealed_since(diverged_at)`.

### ~~4. `check_contest_required` false negative when adversary chain extends past divergence point~~ — RETRACTED (Round 4)

**Resolution:** False positive — divergence invariants guarantee correctness.

### ~~5. `find_missing_owner_events` loads entire local KEL into memory~~ — RESOLVED (Round 4)

**Resolution:** Added `load_tail` to `KelStore` trait, bounded by `MINIMUM_PAGE_SIZE`.

---

## Medium Priority

### ~~6. `std::collections::HashSet` used inline in function body~~ — RESOLVED (Round 1)

### ~~7. `collect_adversary_chain_saids` forward walk silently breaks on unexpected children~~ — RESOLVED (Round 2)

### ~~8. `sig_saids` variable name in `archive_adversary_events` could be ambiguous~~ — RESOLVED (Round 2)

### ~~9. `verify_chain_before_serial` in `handle_divergent_submission` is redundant (async artifact)~~ — RESOLVED (Round 3)

### ~~10. `from_branch_tip` verifier initializes proactive ror counter to 0~~ — RESOLVED (Round 3)

### ~~11. `handle_overlap_submission` contest path doesn't verify post-merge divergence~~ — RESOLVED (Round 4)

### ~~12. `find_missing_owner_events` loads entire local KEL into memory~~ — RESOLVED (Round 4)

### ~~4 (R1). Tip query in `archive_one_page` does not filter by prefix~~ — RESOLVED (Round 1)

### ~~3 (R1). `query_active_recoveries` fetches all recovery records then filters in Rust~~ — RESOLVED (Round 1)

### ~~13 (R5). `send_divergent_events` unrecovered/contested chain partition silently assigns orphaned events to chain B~~ — RETRACTED (Round 5)

### ~~22 (R5). `FileKelStore::owner_tail_path` is dead code~~ — RESOLVED (Round 5)

### ~~23 (R5). `collect_adversary_chain_saids` filters `is_recover()` unnecessarily~~ — RESOLVED (Round 5)

### ~~24. `FileKelStore::load_tail` uses O(n) ring buffer with `remove(0)`~~ — RESOLVED

**File:** `lib/kels/src/store/file.rs:112-116`

~~The `load_tail` implementation collects the last `limit` lines using a `Vec` with `ring.remove(0)` to evict the oldest entry. `Vec::remove(0)` is O(n) per call, making the full scan O(n × limit) where n is the total number of lines. For long KELs on disk, this could be noticeable.~~

**Resolution:** Changed from `Vec` with `remove(0)` to `VecDeque` with `pop_front()` (O(1) amortized).

---

## Low Priority

### ~~14 (R1). Import style: `std` imports not nested~~ — RESOLVED (Round 1)

### ~~15 (R1). No integration test for audit endpoint returning actual recovery records~~ — RESOLVED (Round 1)

### ~~16 (R1). `process_all_recoveries` may log-flood on persistent failures~~ — RESOLVED (Round 1)

### ~~17 (R2). `RecoveryRecord` module doc comment is slightly stale~~ — RESOLVED (Round 2)

### ~~18 (R2). `test-reconciliation.sh` scenarios don't verify archived events endpoint~~ — RESOLVED (Round 2)

### ~~19 (R3). Backward/forward walk bounds use `page_size()` instead of `MINIMUM_PAGE_SIZE`~~ — RESOLVED (Round 3)

### ~~20 (R4). `RecoveryRecord` missing `owner_first_serial` in integration test assertions~~ — RESOLVED (Round 4)

### ~~21 (R4). Duplicate rate-limit helper functions across services~~ — RESOLVED (Round 4)

### ~~22 (R5). `FileKelStore::owner_tail_path` is dead code~~ — RESOLVED (Round 5)

### ~~23 (R5). `collect_adversary_chain_saids` filters `is_recover()` unnecessarily~~ — RESOLVED (Round 5)

### ~~25. `merge.rs` import style: `std::iter` imported separately from `std::collections`~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:8-9`

~~Per CLAUDE.md, `std` imports should be nested in a single `use std::{ ... }` block.~~

**Resolution:** Combined into `use std::{collections::{HashMap, HashSet}, iter};`.

---

## Positive Observations

- **Merge engine architecture is clean and well-separated.** The routing hierarchy (`handle_normal_append` → `handle_full_path` → `handle_divergent_submission`/`handle_overlap_submission`) correctly isolates the common path (fast, no dedup or divergence checks) from the rare complex paths. Each method has clear preconditions documented in comments.

- **`MergeTransaction` encapsulates all DB operations cleanly.** Table names, query helpers, insert/delete/archive operations, and the main merge logic are all co-located. The `PageLoader` trait impl allows `completed_verification` to read directly through the transaction, maintaining advisory lock protection during the full verify-then-write cycle.

- **Proactive ror tracking is comprehensive across all entry points.** `KelVerifier` tracks per-branch `events_since_last_revealing`, `into_verification()` derives the global conservative maximum, `merge_events` enforces compliance on every submission path, and `KeyEventBuilder::needs_proactive_ror()` auto-inserts `ror` on the client side. The three-layer enforcement ensures the security bound holds even with misbehaving clients.

- **`send_divergent_events` correctly handles all divergence geometries.** The recovered path (owner/adversary chain separation, longer-first ordering, atomic rec+rot submission) and the unrecovered/contested path (forward-trace chain-building, terminal event detection) both produce correct submission sequences. The contest path sending the full shorter chain ensures the remote merge engine receives a verifiable batch.

- **Defense-in-depth validation patterns are consistent.** `verify_divergent_at` post-insertion check, `find_adversary_event` serial-count invariant validation, `collect_adversary_chain_saids` failing secure on unexpected children, and `completed_verification` fail-secure on max_pages exhaustion all follow the same pattern: verify postconditions, don't trust the DB, fail loudly.

- **Archive table design using `LIKE ... INCLUDING ALL` is elegant.** The archive schema mirrors the live tables exactly, keeping query paths identical. Combined with `RecoveryRecord` audit trail, the full picture is reconstructable by joining live + archived tables.
