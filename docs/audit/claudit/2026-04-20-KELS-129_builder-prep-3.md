# Branch Audit: KELS-129_builder-prep (Round 3) — 2026-04-20

Deep review of identity_chain integration, test data validity with new kind field, and handler repair path correctness. Prior rounds: 7 findings, all resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. `identity_chain::advance` doesn't clear `checkpoint_policy`~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:73-77`

~~The `advance` function clones the tip record, sets `kind: Upd`, clears `content` and `custody`, and updates `write_policy` — but does not clear `checkpoint_policy`. If the tip is an `Est` (which requires `checkpoint_policy`) or an `Evl` (which may carry updated `checkpoint_policy`), the resulting Upd record retains `checkpoint_policy`. This violates `validate_structure()` which forbids `checkpoint_policy` on Upd records (`pointer.rs:223`).~~

**Resolution:** Added `pointer.checkpoint_policy = None;` after the other field clears.

---

## Low Priority

### ~~2. `build_chain` in repair_tests.rs doesn't set kind on v1+ records~~ — RESOLVED

**File:** `services/sadstore/tests/repair_tests.rs:156-162`

~~The `build_chain` helper creates v0 with `SadPointerKind::Icp` (correct), but the loop for v1+ records just sets `content` and calls `increment()` without changing `kind`. All v1+ records inherit `Icp` from the clone, which would fail `validate_structure` (Icp requires version 0). Not a correctness issue since repair tests exercise repository-level truncation/archival and bypass the verifier, but the test data is structurally invalid.~~

**Resolution:** Set `pointer.kind = kels_core::SadPointerKind::Upd;` before the loop.

### ~~3. sync.rs forwarding test doesn't set kind on v1+ records~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:473-484`

~~`test_divergence_detection_at_page_boundary` creates v0 with `SadPointerKind::Icp`, then clones and increments for v1, v2_a, v2_b without changing `kind`. All inherit Icp. The forward path intentionally skips verification so the test passes, but the data is structurally invalid per `validate_structure`.~~

**Resolution:** Set `v1.kind = SadPointerKind::Upd;` before increment. v2_a and v2_b inherit Upd from v1's clone.

---

## Positive Observations

- **Unified dedup-before-branch-detection is a clear improvement.** Moving dedup before the repair/normal split eliminates the duplicated dedup logic and ensures historical Rpr records don't falsely trigger repair. The comment at line 1249 explains the invariant well.
- **Handler repair ordering is correct.** Checkpoint seal is checked against pre-truncation state (queried before truncate_and_replace), establishment seal is checked against post-truncation verification (comes from the verifier token). Both protect different invariants and need different data sources — the ordering reflects this.
- **`SadPointerKind` enum design is clean.** Helper methods (`evaluates_checkpoint`, `is_repair`, `is_inception`) plus `validate_structure` per-kind field rules create a clear separation between record-level invariants and chain-state logic. The `short_name`/`from_short_name` pair for CLI is a nice touch.
- **`build_replacement` in repair_tests correctly uses Rpr/Upd kinds.** The first record uses Rpr, subsequent use Upd — matching real-world repair semantics. This was a deliberate update, contrasting with `build_chain` which wasn't fully updated.
- **Topic namespace restructuring is thorough.** The `kels/kel/v1/events/` and `kels/sad/v1/pointer/` namespaces cleanly separate KEL events from SAD pointer records. All code, tests, docs, scripts, and constants were updated in a single pass — no orphaned old-format strings remain.
- **Design doc is authoritative and matches implementation.** The Record Kinds section, handler flow description, and repair mechanics in `sad-pointers.md` accurately reflect the landed code. The "typical chain shapes" examples use real kind values.
