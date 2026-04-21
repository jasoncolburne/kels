# Branch Audit: KELS-129_builder-prep (Round 2) — 2026-04-20

Focused review of SadPointerKind integration, verification logic, and handler changes. Round 1 had 6 findings, all resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

## High Priority

### ~~1. Est sets `records_since_checkpoint = 0` instead of 1 — regression from old code~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:247-248`

~~The Est branch in `flush_generation` returns `(record.checkpoint_policy, 0)`, meaning the Est record itself is not counted toward the checkpoint bound. The design doc (`docs/design/sad-pointers.md:42`) explicitly states: "Est counts as a non-checkpoint record toward this bound."~~

~~The old code handled declarations via the non-checkpoint path, which computed `count = branch.records_since_checkpoint + 1`, correctly counting the declaring record. The new kind-based refactor lost this +1.~~

**Resolution:** Changed `(record.checkpoint_policy, 0)` to `(record.checkpoint_policy, 1)`. Updated `test_checkpoint_overdue_at_64` to expect rejection at v64 (1 Est + 62 Upd = 63 non-checkpoint) instead of v65.

---

## Positive Observations

- **Clean dedup-before-repair unification.** Moving dedup before repair detection into a shared code path (instead of duplicating across repair/normal branches) eliminates the class of bugs where repair and normal paths diverge in their handling of historical records. The comment at line 1249 clearly documents why.
- **Establishment seal as a separate concept from checkpoint seal.** The `establishment_version` prevents repair from truncating the policy foundation (v0 or Est at v1), while `last_checkpoint_version` seals verified history. Having both is more precise than a single seal.
- **`validate_structure()` runs before chain-state reasoning.** The early call at line 139-143 in `flush_generation` means the match on `record.kind` at line 234 can use `unreachable!()` for Icp (since validate_structure already rejected Icp at v1+), which simplifies the chain-state logic.
- **Repair auto-detection from record kind is strictly better than query parameter.** The `?repair=true` flag was a separate authorization channel from the records themselves. Now the intent (repair) is embedded in the signed, content-addressed record — an attacker can't trigger repair by adding a query parameter to a normal submission.
- **Thorough test coverage for kind-specific invariants.** Tests cover Est-at-v2-rejected, Est-when-v0-had-cp-rejected, Upd-without-cp-rejected, Rpr-with-cp-rejected, and Rpr-evaluates-checkpoint. Each tests a distinct constraint, not redundant copies.
- **`build_replacement` in repair_tests.rs correctly uses Rpr for first record and Upd for subsequent.** This matches the real-world repair flow where only the first replacement record carries the Rpr signal.
