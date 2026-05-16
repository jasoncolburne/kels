# Branch Audit: KELS-71_bound-archival (Round 3) — 2026-03-25

Synchronous bounded archival, reconciliation proof, `send_divergent_events` gossip ordering, proactive ror enforcement, contest chain-rebuild: 45 files changed, ~4550 diff lines (+2601/-613). Focus on artifacts from async→synchronous transition per user request.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 3        |
| Medium   | 0    | 7        |
| Low      | 0    | 6        |

All 12 findings from rounds 1-2 remain resolved. 4 new findings, all resolved this round.

---

## High Priority

### ~~1. `find_adversary_tip_all_adversary` may miss true tip for long adversary chains~~ — RESOLVED (Round 1)

**Resolution:** Replaced with bounded synchronous archival in merge transaction. No longer applicable.

### ~~2. `collect_all_adversary_saids` fetch limit used `page_size()` instead of `MINIMUM_PAGE_SIZE`~~ — RESOLVED (Round 2)

**Resolution:** Changed to `crate::MINIMUM_PAGE_SIZE as u64 * 2`.

### ~~3. Contest recovery-revealing check uses `cnt_serial` instead of `diverged_at`~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:743`

~~In `handle_divergent_submission`, the contest path checked `non_contest_recovery_revealed_since(cnt_serial)`. When the owner's chain extended past the fork (e.g., owner has ixn at serial 3, adversary submits ror at serial 3 creating divergence, owner contests at serial 4), the scan from `cnt_serial=4` missed the adversary's ror at serial 3.~~

**Resolution:** Changed to `non_contest_recovery_revealed_since(diverged_at)`, matching `handle_overlap_submission`'s equivalent check. Regression test `test_contest_on_divergent_kel_with_cnt_serial_above_diverged_at` covers this scenario. Also added `test_contest_creates_divergence_on_linear_kel` for the overlap path where cnt itself creates divergence.

---

## Medium Priority

### ~~4. Tip query in `archive_one_page` does not filter by prefix~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — `archive_one_page` removed.

### ~~5. `std::collections::HashSet` used inline in function body~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — recovery.rs rewritten.

### ~~6. `collect_adversary_chain_saids` forward walk silently breaks on unexpected children~~ — RESOLVED (Round 2)

**Resolution:** Changed `_ => break` to return a `StorageError`.

### ~~7. `sig_saids` variable name in `archive_adversary_events` could be ambiguous~~ — RESOLVED (Round 2)

**Resolution:** Accepted as-is.

### ~~3 (R1). `query_active_recoveries` fetches all recovery records then filters in Rust~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — async recovery task removed entirely.

### ~~8. `verify_chain_before_serial` in `handle_divergent_submission` is redundant (async artifact)~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:806-807`

~~In `handle_divergent_submission`'s recovery path, `verify_chain_before_serial` re-verified from serial 0 to `first_serial` — redundant with `completed_verification` at the top of `merge_events`. Leftover from the async recovery design.~~

**Resolution:** Removed `verify_chain_before_serial` call and the now-unused method.

### ~~9. `from_branch_tip` verifier initializes proactive ror counter to 0~~ — RESOLVED

**File:** `lib/kels/src/types/verifier.rs:152-153`

~~`KelVerifier::from_branch_tip` initialized `events_since_last_revealing: 0` regardless of how many non-revealing events existed on the branch. The `from_branch_tip` verifier is used in divergence/recovery/contest paths, allowing a malicious client to bypass the proactive ror limit.~~

**Resolution:** Added per-branch `events_since_last_revealing` counter to `BranchState`. The counter is tracked per-branch through `verify_chain_event`, and `into_verification` derives the global value as the max across all branches (most conservative). `from_branch_tip` now accepts the count as a parameter; callers pass `kel_verification.events_since_last_revealing()`.

---

## Low Priority

### ~~8 (R1). Import style: `std` imports not nested~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable.

### ~~9 (R1). No integration test for audit endpoint returning actual recovery records~~ — RESOLVED (Round 1)

**Resolution:** Integration tests expanded.

### ~~10 (R1). `process_all_recoveries` may log-flood on persistent failures~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — async recovery loop removed.

### ~~11 (R2). `RecoveryRecord` module doc comment is slightly stale~~ — RESOLVED (Round 2)

**Resolution:** False positive.

### ~~12 (R2). `test-reconciliation.sh` scenarios don't verify archived events endpoint~~ — RESOLVED (Round 2)

**Resolution:** Added `wait_for_archived_convergence` helper and assertions.

### ~~13. Backward/forward walk bounds use `page_size()` instead of `MINIMUM_PAGE_SIZE`~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:339, 385`

~~`collect_all_adversary_saids` and `collect_adversary_chain_saids` use `crate::page_size()` as the iteration bound for their backward and forward walks. The proactive ror invariant guarantees the chain fits within `MINIMUM_PAGE_SIZE` events. Using `page_size()` (operator-configurable, always ≥ `MINIMUM_PAGE_SIZE`) is functionally correct but inconsistent with line 360 which explicitly uses `MINIMUM_PAGE_SIZE` for the fetch query.~~

**Resolution:** Changed both loop bounds to `crate::MINIMUM_PAGE_SIZE`.

---

## Positive Observations

- **Clean async→synchronous transition.** The removal of the async recovery task (RecoveryConfig, RecoveryState state machine, background loop, recovery module) is thorough. No stale async references remain in the codebase. The synchronous in-merge archival is architecturally simpler and eliminates an entire class of TOCTOU races.

- **`send_divergent_events` rewrite is well-structured.** The new three-phase submission strategy (longer chain as non-divergent appends → fork event → rec/rot resolution) correctly maps divergent source state into the sequence the remote merge engine expects. The contest path correctly builds chains by forward-tracing from fork events and sends the shorter chain atomically.

- **Proactive ror enforcement is end-to-end.** `KelVerifier` tracks `events_since_last_revealing` through the full verification, `merge_events` checks compliance on every submission path, and `KeyEventBuilder::needs_proactive_ror()` auto-inserts `ror` on the client side. This three-layer enforcement ensures the security bound holds even with misbehaving clients.

- **`find_missing_owner_events` in builder is a sound design.** The contest path now handles the case where the adversary's recovery archived the owner's events by probing the server backward from the owner's tail. This ensures the contest batch includes all events needed for verifiability.

- **Archive table design is clean.** Using `CREATE TABLE ... (LIKE ... INCLUDING ALL)` for archive tables mirrors the live schema exactly, keeping the archive query paths identical. The `RecoveryRecord` provides provenance linking archived events to the recovery that created them.

- **Comprehensive test coverage.** The 10-scenario reconciliation test suite, expanded integration tests (recovery audit, archived events, dual-signature validation), and the verifier unit tests covering proactive ror, anchor checking, and divergent KEL verification provide strong regression protection.
