# Branch Audit: KELS-129_builder-prep (Round 1) — 2026-04-20

Part 1: topic namespace rework (mechanical string replacements). Part 2: SadPointerKind enum, is_checkpoint removal, ?repair=true removal. 38 files changed, ~2900 diff lines.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

---

## High Priority

### ~~1. Repair checkpoint check uses full `records` instead of `new_records`~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1350-1352`

~~The checkpoint-at-divergence-point check uses `records.iter()` (all submitted records including historical duplicates) instead of `new_records.iter()` (post-dedup genuinely new records). A gossip full-chain replay of a previously-repaired chain could satisfy this check with historical Evl/Rpr records that were already deduplicated out, even if the genuinely new batch contains no checkpoint record.~~

**Resolution:** Changed `records.iter()` to `new_records.iter()`. Also moved `check_prefix_rate_limit` to after dedup, using `new_records.len()` instead of `records.len()`.

### ~~2. Repair path rate limit count uses `records.len()` instead of `new_records.len()`~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1409`

~~The repair path sets `new_record_count = records.len() as u32`, counting all submitted records (including historical duplicates). The normal path correctly gets the count from `save_batch()` result. The comment at line 1491 says "Accrue only actual new records to prefix rate limit" — this line contradicts that intent.~~

**Resolution:** Changed to `new_record_count = new_records.len() as u32`.

---

## Medium Priority

### ~~3. Import ordering violation in verification.rs~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:7-8`

~~Per AGENTS.md, local imports should be sorted: `crate::` before `super::`. Currently `super::pointer` comes before `crate::KelsError`.~~

**Resolution:** `rustfmt` orders `super::` before `crate::` — this is the correct Rust convention. The AGENTS.md example only shows `crate::` imports. Verified `rustfmt` is authoritative; no reordering needed.

---

## Low Priority

### ~~4. Missing test: checkpoint policy evaluation failure on Evl/Rpr~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:267-272`

~~The checkpoint policy evaluation failure path (hard error, aborts verification) is never exercised in tests. All Evl/Rpr tests use `AlwaysPassChecker`.~~

**Resolution:** Added `test_checkpoint_policy_evaluation_failure` using `RejectingChecker`. Verifies error contains "checkpoint policy not satisfied".

### ~~5. Missing test: Icp content forbid rule~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:202`

~~`validate_structure()` forbids `content` on Icp records, but there is no explicit test for this constraint in the `validate_structure` test suite in `mod.rs`.~~

**Resolution:** Added `test_validate_structure_sad_icp_forbids_content` in `mod.rs`.

### ~~6. Missing test: Icp previous forbid rule~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:201`

~~`validate_structure()` forbids `previous` on Icp records, but there is no explicit test for this constraint.~~

**Resolution:** Added `test_validate_structure_sad_icp_forbids_previous` in `mod.rs`. Prefixed with `sad_` to avoid collision with existing KeyEvent test of the same name.

---

## Positive Observations

- **Clean dedup-before-repair restructuring.** Moving dedup ahead of repair detection prevents historical Rpr records in gossip replays from falsely triggering repair. The separation of concerns (SAID existence check vs chain-state reasoning) is well-placed.
- **validate_structure() / verifier split is well-designed.** Record-level invariants live in `validate_structure()`, chain-state reasoning lives in the verifier, with no duplication between the two. The verifier calls `validate_structure()` first and then trusts its results.
- **Establishment version as an immutable seal.** Tracking establishment_version separately from last_checkpoint_version prevents repair from truncating the policy foundation. This is a security improvement over the previous design.
- **Rpr carries checkpoint semantics implicitly.** Using `evaluates_checkpoint()` to share the Evl/Rpr code path avoids duplication while keeping repair semantically distinct. The forbid-checkpoint_policy-on-Rpr constraint forces repair and policy evolution to be separate operations, which simplifies reasoning.
- **Thorough removal of repair query parameter.** The `?repair=true` plumbing was removed from handler, client library, gossip sync, CLI, and test scripts in a single pass. No orphaned code paths remain.
- **Design doc updated in the same PR.** The sad-pointers.md doc reflects the landed design, not a future plan. The "Future: Record Kinds" section was replaced with the actual implementation.
