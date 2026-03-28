# Branch Audit: KELS-71_bound-archival (Round 2) — 2026-03-25

Synchronous bounded archival, reconciliation proof, 10-scenario reconciliation test suite: 45 files changed, ~4507 diff lines (+2558/-613). Replaces async recovery task with synchronous in-merge archival, adds `RecoveryRecord` audit trail, archive tables, `send_divergent_events` gossip ordering, comprehensive reconciliation tests.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 5        |
| Low      | 0    | 5        |

All 7 findings from round 1 remain resolved. 3 new open findings.

---

## High Priority

### ~~1. `find_adversary_tip_all_adversary` may miss true tip for long adversary chains~~ — RESOLVED (Round 1)

**Resolution:** Replaced with bounded synchronous archival in merge transaction. No longer applicable.

### ~~2. `collect_all_adversary_saids` fetch limit used `page_size()` instead of `MINIMUM_PAGE_SIZE`~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:360`

~~The query fetched events from `diverged_at` onward with `limit(crate::page_size() as u64 * 2)`. While safe due to the `MINIMUM_PAGE_SIZE` clamp, the intent was to use the security bound (`MINIMUM_PAGE_SIZE`), not the operator-configurable page size.~~

**Resolution:** Changed to `crate::MINIMUM_PAGE_SIZE as u64 * 2`, making the bound explicit and independent of operator configuration.

---

## Medium Priority

### ~~3. `query_active_recoveries` fetches all recovery records then filters in Rust~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — async recovery task removed entirely.

### ~~4. Tip query in `archive_one_page` does not filter by prefix~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — `archive_one_page` removed.

### ~~5. `std::collections::HashSet` used inline in function body~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — recovery.rs rewritten.

### ~~6. `collect_adversary_chain_saids` forward walk silently breaks on unexpected children~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:400-404`

~~The forward walk from the adversary event silently broke (`_ => break`) when >1 non-rec child existed at the same `previous`. While unreachable via normal merge engine invariants, a tampered DB could inject an extra event that bypasses the divergence-serial check in `find_adversary_event`, causing the walk to stop early and leave adversary events unarchived — a fail-open on tampered data.~~

**Resolution:** Changed `_ => break` to return a `StorageError` indicating possible DB tampering. Fails secure instead of silently stopping.

### ~~7. `sig_saids` variable name in `archive_adversary_events` could be ambiguous~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:285-289`

~~The variable `sig_saids` collects signature record SAIDs (primary keys) for deletion, which could be misread as event SAIDs.~~

**Resolution:** Accepted as-is. The values are SAIDs (of signature records), used 3 lines later in `Delete::<EventSignature>` which makes the context clear. No rename needed.

---

## Low Priority

### ~~8. Import style: `std` imports not nested~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — recovery.rs rewritten with correct imports.

### ~~9. No integration test for audit endpoint returning actual recovery records~~ — RESOLVED (Round 1)

**Resolution:** Integration tests expanded in `services/kels/tests/integration_tests.rs`.

### ~~10. `process_all_recoveries` may log-flood on persistent failures~~ — RESOLVED (Round 1)

**Resolution:** No longer applicable — async recovery loop removed.

### ~~11. `RecoveryRecord` module doc comment is slightly stale~~ — RESOLVED

**File:** `lib/kels/src/types/recovery.rs:1-5`

~~Flagged as potentially stale, but on review the module doc and struct doc both accurately describe the current synchronous design.~~

**Resolution:** False positive — docs are correct as-is.

### ~~12. `test-reconciliation.sh` scenarios don't verify archived events endpoint~~ — RESOLVED

**File:** `clients/test/scripts/test-reconciliation.sh`

~~No scenarios asserted on the archived events endpoint after recovery.~~

**Resolution:** Added `wait_for_archived_convergence` helper and assertions in scenarios 1-3: scenario 1 expects 1 archived event (ixn), scenario 2 expects 1 (ixn), scenario 3 expects 3 (rot,ixn,ixn). Assertions verify all three nodes converge on the expected archived event count.

---

## Positive Observations

- **Synchronous archival eliminates entire class of race conditions.** Moving archival from an async background task into the merge transaction removes TOCTOU windows, eliminates the need for recovery state machine transitions (Detected → Archiving → Recovered), and guarantees atomic recovery: either the adversary is fully archived and the `RecoveryRecord` written, or nothing changes.

- **Clean separation of archival strategies by owner position.** `collect_all_adversary_saids` (owner has no events at divergence) and `collect_adversary_chain_saids` (owner has events) handle the two fundamentally different recovery geometries with distinct, correct algorithms rather than a fragile unified approach.

- **`send_divergent_events` ordering in `transfer_key_events` is well-designed.** The three-phase send (longer chain as non-divergent appends → fork event → rec/rot) correctly maps divergent source state into the sequence the remote merge engine expects. The contest path correctly builds chains by forward-tracing from fork events and sends the shorter chain atomically with `cnt`.

- **Exhaustive reconciliation proof document.** `docs/design/reconciliation.md` systematically covers all KEL state × submission type combinations and source → sink gossip sync scenarios. The state matrix format makes it easy to verify completeness.

- **Comprehensive reconciliation test suite.** 10 scenarios covering recovered KEL propagation, post-recovery events, adversary rotation chains, contested KEL propagation (both shorter and longer chain), contest during active archival, double recovery rejection, effective SAID convergence, and submission rejection on contested/decommissioned KELs. Good use of helper functions for convergence waiting and KEL hash comparison.

- **Bounded archival is provably correct.** The proactive ROR invariant (`MAX_NON_REVEALING_EVENTS = 62`) ensures the adversary chain never exceeds one page. Combined with synchronous archival, this means recovery completes in a single transaction with no background coordination.
