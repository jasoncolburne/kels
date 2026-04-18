# Branch Audit: KELS-122_pointer-checkpoints (Round 3) — 2026-04-17

~1170 lines across 17 files. Third review pass focusing on compilation correctness, E2E test compatibility with checkpoint requirement, and transfer logic edge cases. Rounds 1-2 had 12 findings, all resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

## High Priority

### ~~1. `occupied_versions` not declared `mut` — compilation error~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:82,116`

~~`occupied_versions` is declared as `let occupied_versions: HashSet<u64>` (immutable) at line 82, but line 116 calls `occupied_versions.insert(record.version)` which requires `&mut self`. This won't compile — Rust will reject it with "cannot borrow `occupied_versions` as mutable, as it is not declared as mutable."~~

**Resolution:** Changed to `let mut occupied_versions: HashSet<u64>` at line 82.

### ~~2. Scenario 7 submits v0 alone without `checkpoint_policy` — verifier rejects at `finish()`~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:362-392`

~~Scenario 7 (Divergence Detection + Repair) builds a v0 without `checkpointPolicy` or `isCheckpoint` and submits it alone to node-a. The handler calls `verifier.finish()` after processing, and `finish()` enforces the global invariant that at least one branch must have `checkpoint_policy` established. Since v0 has no checkpoint_policy, `finish()` returns `Err("SAD chain has no checkpoint_policy")`, causing the handler to return 400 Bad Request.~~

**Resolution:** v0 now declares `checkpointPolicy` (without `isCheckpoint` — the first declaration is just a declaration, not an evaluated checkpoint). Moved `build_checkpoint_policy` before v0 construction so the policy SAID is available. Since checkpoint_policy changes the prefix (confirmed by `test_v0_with_checkpoint_policy_changes_prefix`), replaced the CLI-computed `DIV_PREFIX` with the actual `D_V0_PREFIX` from `compute_prefix`. The conflicting v1s (which have `isCheckpoint: true`) chain to this v0 and are evaluated against its declared checkpoint_policy.

---

## Positive Observations

- **Round 2 fix for held-back verification is surgically correct.** The single-line addition of `v.verify_page(std::slice::from_ref(&held))` at the divergence transition point closes the bypass without restructuring the control flow. The verification happens before the held record enters `post_divergence`, matching the collection-mode path where fetched records are verified at line 205-206.

- **Within-batch version collision detection (Round 2 fix) is clean.** Adding `occupied_versions.insert(record.version)` after each insert transforms a snapshot-based check into a running set, catching both DB-vs-batch and intra-batch collisions with the same code path. The only remaining issue is the `mut` declaration (finding 1).

- **Divergence test helper `VecSadSource` is a well-designed test double.** It faithfully simulates page boundaries via configurable `page_size`, serves records in order, and correctly implements the `since` cursor. The test at `sync.rs:472-536` exercises the exact page-boundary-split scenario (page_size=3 with 4 records) that would miss divergence without held-back.

- **Shell test Scenario 7 correctly creates conflicting checkpoints on fork records.** Both v1-a and v1-b include `checkpointPolicy` and `isCheckpoint: true`, ensuring both fork branches have the checkpoint policy established. The repair record also includes checkpoint fields, matching the handler's repair-must-checkpoint requirement.

- **The `since` cursor override at `sync.rs:271-273` correctly prioritizes the held-back record.** After page processing, the cursor is set to the held-back record's SAID, ensuring the next fetch starts from after it. This prevents the held-back from being re-fetched while maintaining the invariant that it will be prepended to the next page.
