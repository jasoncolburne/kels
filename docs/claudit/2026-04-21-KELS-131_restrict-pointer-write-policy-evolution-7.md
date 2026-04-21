# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 7) — 2026-04-21

Seventh-pass audit after Round 6 adopted Option (a) on the Est arm (symmetric gating: `establishment_version` and branch `checkpoint_policy` now blocked when the soft write_policy check fails), tightened the defense-in-depth comment block, and updated the `PolicyChecker` trait docstring. Diff shape unchanged (~230+/68- across the same 16 source/test/doc files + 6 prior claudit docs). Round 7 traced the symmetric-gate story across the remaining seam surfaced by R6 — divergent chains where one branch's Est soft-passes and another's soft-fails — and re-read the match arms for anything R1–R6 hadn't covered. One Low on a chain-wide / per-branch state asymmetry around `establishment_version` in the divergent-Est scenario; no Medium or High findings. The audit has converged: seven rounds have produced a coherent, well-tested, well-documented change.

Total resolved across all rounds: 25 (R1: 7, R2: 5, R3: 5, R4: 3, R5: 1, R6: 3, R7: 1 inline; deferred to #126: 2).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 1        |

---

## Low Priority

### ~~1. `establishment_version` is chain-wide but Est-arm gating is per-record — divergent-Est token can be internally inconsistent~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:90,276-282`; `lib/kels/src/types/sad/pointer.rs:344-348` (accessor docstring)

~~`self.establishment_version` is a chain-wide field (not per-branch), set by the Est arm and by the v0-declared-cp path. R6 added the soft-wp gate inside the Est arm:~~

~~```rust
let (new_est_version, new_cp) = if write_policy_satisfied {
    (Some(1), record.checkpoint_policy)
} else {
    (self.establishment_version, branch.checkpoint_policy)
};
self.establishment_version = new_est_version;
```~~

~~The gate freezes `new_cp` per-branch, but once `self.establishment_version` has been advanced to `Some(1)` by any passing Est in the same generation, a divergent soft-failing Est cannot unset it (nor should it — the value is chain-wide).~~

~~Consider a divergent scenario realizable in production: two writers hold the wp endorsement but only one anchored their Est in the KEL. Both submit Est at v1 with different `checkpoint_policy` values:~~

- ~~Branch A (anchored): wp check passes → `self.establishment_version = Some(1)`, `branch.checkpoint_policy = Some(cp_a)`.~~
- ~~Branch B (unanchored): wp check fails → `self.establishment_version` stays `Some(1)` (already set by A), `branch.checkpoint_policy = None` (per-branch gate holds).~~

~~At `finish()`, the `any(|b| b.checkpoint_policy.is_some())` invariant passes (A has cp). Tie-break on `(version, said)` may pick Branch B. The resulting token then has `establishment_version() == Some(1)` alongside a tip branch with no cp.~~

**Resolution (Option a — document the asymmetry):** Chose option (a) over a larger per-branch refactor because the inconsistency is harmless in practice (handler gates on `policy_satisfied() → 403` at submission, and sync-time consumers must already gate on `policy_satisfied()` to trust any accessor on a non-primary branch), and because `handlers.rs:1396`'s repair-floor guard depends on the chain-wide semantic.

- Appended a paragraph to `SadPointerVerification::establishment_version()` at `pointer.rs:346-356` flagging the value as chain-wide and noting the divergent-Est case where it may not match the tie-break winner's branch state. Directs callers that treat the value as branch-scoped to gate on `policy_satisfied()` first.
- Added a comment block at `verification.rs:281-285` on the `self.establishment_version = new_est_version;` assignment explaining the chain-wide intent and cross-referencing the accessor docstring.
- Added `test_divergent_est_soft_fail_does_not_poison_other_branch` (`verification.rs`) that constructs the divergent Est scenario with an `AcceptLegitEstChecker` (accepts wp iff the record carries the legitimate cp). Asserts: `policy_satisfied() == false`, `establishment_version() == Some(1)` (chain-wide, set by branch A), `last_checkpoint_version() == None` (Est doesn't evaluate), `write_policy() == wp1` (Est forbids wp evolution, R6 gate prevents drift). The test also pins the tie-break determinism — whichever branch wins, the chain-wide/per-branch asymmetry is the documented behavior.

---

## Positive Observations

- **The audit has converged.** Seven rounds, 25 findings total (24 resolved inline, 2 deferred to #126, 1 new Low this round). Rounds 1–2 covered the core correctness/security story (seed + gate). Round 3 closed the doc and re-verification loops. Round 4 pinned down divergent-chain and cross-arm symmetry. Rounds 5–6 extended the defense-in-depth gate symmetrically across all three per-record branch-state advances (`tracked_write_policy`, tracked `checkpoint_policy`, `last_checkpoint_version`) and then to the Est-arm's `establishment_version` / branch cp. Round 7 traced the one remaining asymmetry — a chain-wide field that a per-record gate can't fully freeze in divergent scenarios. Each round narrowed the scope; none required reverting prior-round fixes. The shape of the design is stable.

- **The R6 Est-arm fix cleanly composes with R2/R5's Evl/Rpr-arm fixes.** All four per-record per-branch state advances (`tracked_write_policy`, tracked `checkpoint_policy`, `last_checkpoint_version`, per-branch `checkpoint_policy` establishment) now share the same `write_policy_satisfied` gate. The single captured boolean at `verification.rs:237` drives every per-branch advance in the match body. No hidden state, no revisiting — a reader can check the invariant locally.

- **`PolicyChecker` trait docstring now names the state-gating contract.** The R6 update at `verification.rs:14-22` lists all four gated advances by name ("tracked write_policy, tracked checkpoint_policy, establishment version, last checkpoint version"). Future `PolicyChecker` implementors understand that their `satisfies` return value is not just a soft signal — it's load-bearing for branch state.

- **`create()` and `advance()` docstrings cross-reference each other.** R4's `create()` rustdoc now points to `advance()` for the Est-at-v1 precondition; R3's `advance()` rustdoc explains the Upd→Evl tightening and names the precondition. A reader starting at either entry point learns what they need without surprise rejections at submission time.

- **Greenfield discipline was maintained across seven rounds.** No new migration files. The dead index (`sad_pointers_write_policy_topic_version_idx`) was dropped in-place in R1. The `write_policy` column's `NOT NULL → nullable` transition is a single-line change to the original `0001_initial.sql`. The branch's final diff represents the intended final state, not a migration trail.

- **Test taxonomy is complete across the state machine.** Rounds 1–6 added ~13 new tests covering: single-step evolution (pass + soft-fail), multi-step evolution (pass + soft-fail), Evl-pure-checkpoint inheritance, Rpr inheritance, divergent-branch tracked_wp tie-break determinism, the Evl/Rpr-arm defense-in-depth gate (tracked wp, tracked cp, last checkpoint version), and the Est-arm defense-in-depth gate (establishment-and-cp via the "no checkpoint" error path). Every cell of the per-kind require/forbid matrix has at least one test; every branch of every soft-gate conditional has at least one test. The only gap surfaced this round is the divergent-Est scenario named in Finding #1.

- **Cross-crate API semantics stayed stable despite four semantic shifts.** Over seven rounds the following landed without breaking call sites: `write_policy` field became `Option<_>`; `SadPointerVerification::write_policy()` changed meaning (tip field → branch-tracked); `identity_chain::advance()` switched its produced kind (`Upd → Evl`); the `PolicyChecker::satisfies` return value became load-bearing for branch state beyond just `policy_satisfied`. Every external caller absorbed these with at most a single-line change (e.g., `*verification.write_policy()` deref in `identity_chain`). Keeping method names and return types stable meant zero churn at call sites — the hard work was confined to the types module.
