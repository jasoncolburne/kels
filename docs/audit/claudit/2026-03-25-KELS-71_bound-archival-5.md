# Branch Audit: KELS-71_bound-archival (Round 5) — 2026-03-25

Synchronous bounded archival, reconciliation proof, `send_divergent_events` gossip ordering, proactive ror enforcement, contest chain-rebuild, 10-scenario reconciliation test suite: 50 files changed, ~5542 diff lines (+3296/-682). Focus on fresh review of entire diff surface for new findings not covered in rounds 1-4.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 5        |
| Medium   | 0    | 11       |
| Low      | 0    | 12       |

All 21 findings from rounds 1-4 remain resolved. 3 new findings this round (2 retracted as false positives, 1 resolved).

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

**Resolution:** Added `verify_divergent_at(diverged_at)`.

### ~~12. `find_missing_owner_events` loads entire local KEL into memory~~ — RESOLVED (Round 4)

### ~~4 (R1). Tip query in `archive_one_page` does not filter by prefix~~ — RESOLVED (Round 1)

### ~~3 (R1). `query_active_recoveries` fetches all recovery records then filters in Rust~~ — RESOLVED (Round 1)

### ~~13. `send_divergent_events` unrecovered/contested chain partition silently assigns orphaned events to chain B~~ — RETRACTED

**File:** `lib/kels/src/types/verifier.rs:1292-1315`

~~Initially flagged because the partition loop uses `else` (not `else if chain_b_saids.contains(...)`) when assigning events to chains. Concern was that an event whose `previous` wasn't traced into either chain would silently land in chain B.~~

~~On deeper analysis, this cannot happen: events are sorted by serial, so parents at serial N are always processed before children at serial N+1. The forward-tracing loop seeds both chains at the fork serial, then processes every subsequent serial in order. An event's `previous` can only miss both sets if its parent isn't in `post_divergence` at all — meaning a broken chain, which the verifier would have already rejected.~~

**Resolution:** False positive — sorted serial ordering guarantees the forward-tracing always assigns every event to the correct chain.

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

### ~~22. `FileKelStore::owner_tail_path` is dead code~~ — RESOLVED

**File:** `lib/kels/src/store/file.rs:43-45`

~~`owner_tail_path()` constructs a path for `{prefix}.owner_tail` files, but no code in the current branch writes these files. The method is only referenced in `delete()` to clean up potentially stale files from a previous design iteration. The `kels-ffi` crate also references `.owner_tail` in its deletion logic.~~

**Resolution:** Removed `owner_tail_path()` method, the cleanup in `delete()`, and the `.owner_tail` reference in `kels-ffi`.

### ~~23. `collect_adversary_chain_saids` filters `is_recover()` unnecessarily~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:419-421`

~~The forward walk from the adversary event filtered children with `!e.is_recover()`. The filter was a no-op: archival runs before insertion (line 897 vs 900), so the owner's rec is not in the DB. The owner's rec also chains from the owner's branch, not the adversary's. And `check_contest_required` already verified no recovery-revealing events exist, all within the same advisory-locked transaction — the view cannot change.~~

**Resolution:** Removed the unnecessary filter. The `children` vec is now used directly. Error message updated from "Multiple non-rec children" to "Multiple children".

---

## Positive Observations

- **`verify_divergent_at` is a clean defense-in-depth pattern.** Rather than relying on complex logical arguments about why the contest batch must create divergence, the post-insertion check directly queries the DB to confirm the post-condition. This makes the code more robust against future refactoring and easier to reason about.

- **Proactive ror tracking is end-to-end correct.** The per-branch `events_since_last_revealing` counter in `BranchState`, combined with the conservative max-across-branches derivation in `into_verification()`, ensures the security bound holds through resumption, divergence, and recovery paths. The three-layer enforcement (verifier tracking, merge enforcement, builder auto-insertion) provides comprehensive coverage.

- **`load_signed_history_tail` is well-designed for bounded access.** The single `ORDER BY serial DESC LIMIT N` + reverse pattern avoids loading the entire KEL and works correctly with the DB's deterministic ordering. The `KelStore` trait addition is clean and all implementations (file, repository, memory test stores) are consistent.

- **The merge transaction architecture is sound.** `MergeTransaction` wraps table names and a transaction executor, keeping all merge logic in one place. The advisory lock + full re-verification on every submission pattern is simple and correct. The routing logic (`handle_normal_append` → `handle_full_path` → `handle_divergent_submission`/`handle_overlap_submission`) clearly separates the common case from the complex paths.

- **Test coverage for the contest regression bugs is targeted and thorough.** `test_contest_on_divergent_kel_with_cnt_serial_above_diverged_at` and `test_contest_creates_divergence_on_linear_kel` directly exercise the specific failure modes from round 3, with clear comments explaining the bug and why each assertion matters.

- **`RecoveryRecord` is the right level of abstraction.** A single immutable audit record per recovery, written atomically in the merge transaction. The fields (`recovery_serial`, `diverged_at`, `rec_previous`, `owner_first_serial`) capture exactly what's needed to reconstruct the recovery context without duplicating event data.
