# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 6) — 2026-04-21

Sixth-pass audit after Round 5 surfaced the single Medium "should we gate `last_checkpoint_version` and tracked `checkpoint_policy` advancement on `write_policy_satisfied`?" and recommended picking a posture. The uncommitted change adopts **Option (a)** — symmetric gating: all three branch-state advances in the Evl/Rpr arm (`tracked_write_policy`, tracked `checkpoint_policy`, `last_checkpoint_version`) are now blocked when the soft write_policy check fails. A new test (`test_evl_rejected_wp_does_not_advance_checkpoint_policy`) exercises the cp-advance gate indirectly via a v2 Evl whose hard cp check depends on tracked cp staying at the legitimate value. Round 6 verifies the fix is complete and traces the same gating question through the remaining match arms. One Medium surfaces — the Est arm has an analogous ungated advance that wasn't part of R5's scope. Two Lows on comment-block readability and a trait-docstring tension.

Total resolved across all rounds: 24 (R1: 7, R2: 5, R3: 5, R4: 3, R5: 1, R6: 3 inline; deferred to #126: 2).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. Est arm doesn't gate `establishment_version` / `checkpoint_policy` on `write_policy_satisfied`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:261-280`

~~The R5 fix (Option a) symmetrically gates three state advances in the Evl/Rpr arm. The Est arm has the analogous class of state advance — and it's not gated.~~

~~**Attack scenario (same shape as R5's):** chain at v0 has `tracked_write_policy = wp1` (from Icp), no checkpoint_policy. Adversary crafts `v1 = Est(checkpoint_policy=cp_attacker)`. Soft wp check fails, but `establishment_version = Some(1)` and `branch.checkpoint_policy = Some(cp_attacker)` both advance. Every subsequent Evl/Rpr on this branch is authorized against `cp_attacker`, not a legitimate cp.~~

**Resolution:** Mirrored R5/R6's Option (a) gate on the Est arm:

```rust
SadPointerKind::Est => {
    if branch.checkpoint_policy.is_some() { ... error }
    // Defense-in-depth: skip state advances on soft wp-fail. See R5/R6 audit.
    // records_since_checkpoint = 1 stays unconditional — an unauthorized Est
    // still occupies a slot in the checkpoint window (same as an unauthorized Upd).
    // tracked_write_policy unchanged — Est forbids write_policy (validate_structure).
    let (new_est_version, new_cp) = if write_policy_satisfied {
        (Some(1), record.checkpoint_policy)
    } else {
        (self.establishment_version, branch.checkpoint_policy)
    };
    self.establishment_version = new_est_version;
    (new_cp, 1, branch.tracked_write_policy)
}
```

`records_since_checkpoint = 1` stays unconditional — an unauthorized Est still occupies a slot in the checkpoint window (matches Upd's counter-increment semantic).

Added `test_est_rejected_wp_does_not_establish_checkpoint_policy` (lib/kels/src/types/sad/verification.rs:820-853): v0 Icp(wp1, no cp) → v1 Est(cp=cp_attacker) under a checker that rejects the wp soft check. Asserts that `finish()` rejects with "no checkpoint_policy" — behavioral proof that the Est did not establish cp despite structurally passing the hard checks. The error-path assertion is the cleanest available signal since finish()'s "at least one branch has cp" guard trips precisely when the Est gate blocks establishment.

Collateral fix: `test_advance_rejects_unsatisfied_policy` in `lib/policy/src/identity_chain.rs:297-320` previously relied on a soft-failed v1 Est implicitly establishing cp. Restructured to v0 Icp → v1 Est (soft-passes under the new `RejectAdvanceChecker` which now accepts Est only) → v2 Upd (soft-fails). The test still proves `advance()` rejects when `policy_satisfied()==false`; the chain construction now survives the R6 Est gate. Updated `RejectAdvanceChecker`'s docstring to explain the Est-accept logic.

---

## Low Priority

### ~~2. The defense-in-depth comment block at line 289-299 is a wall of text~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:289-293`

~~After the R5/R6 change, the Evl/Rpr arm carries an 11-line comment before the `if write_policy_satisfied` block, repeating three points: "defense-in-depth", "keep previous values", and "callers bypassing policy_satisfied()".~~

**Resolution:** Tightened to 5 lines covering the rationale without repetition; per-site inline comments on each `if` block carry the detail. Points curious readers at the R5/R6 audit docs for the full trade-off discussion:

```rust
// Defense-in-depth: when the soft write_policy check above failed,
// skip all branch-state advances driven by this record — even those
// authorized by the cp check that just passed. A consumer that bypasses
// policy_satisfied() then sees unchanged seal/policy state for an
// unauthorized record. (See R5/R6 audit for the rationale.)
```

### ~~3. `PolicyChecker` trait docstring says "Called unconditionally" without flagging the subsequent gate~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:14-22`

~~"Called unconditionally" refers to the trait method invocation (always made regardless of whether the Evl proposes a new write_policy) — that's correct. But after R5/R6, the *result* of that call now drives three (now four, after the R6 Est gate) downstream state advances on the branch. A reader of the trait doc can't tell that the result matters for more than just `policy_satisfied`.~~

**Resolution:** Added a clause to the v1+ bullet in the trait docstring flagging the verifier-side state gating, updated to reflect all four gated advances (tracked write_policy, tracked checkpoint_policy, establishment version, last checkpoint version):

```rust
/// - v1+: `satisfies(record, &branch.tracked_write_policy)` — each advance must be authorized
///   by the branch's currently-tracked write_policy (seeded by v0, updated when Evl carries
///   a new write_policy *and* the evolution was authorized). Called unconditionally,
///   whether or not the policy changed. The returned value also gates whether the verifier
///   advances branch-state (tracked write_policy, tracked checkpoint_policy, establishment
///   version, last checkpoint version); a returned `false` freezes all policy-related state
///   on the branch for this record.
```

---

## Positive Observations

- **R5's Option (a) was adopted with a new test, not just a code change.** The new `test_evl_rejected_wp_does_not_advance_checkpoint_policy` is a *behavioral* test of the cp-advance gate — it doesn't introspect branch state, it constructs a v2 whose hard cp check would fail if the v1 wp-soft-fail had leaked cp_attacker into tracked cp. The test shape ("submit a second record whose success depends on the first record's state NOT having advanced") is exactly the right shape for gating tests: it would pass pre-fix with `unwrap` on line 799, and the test is asserting the successful path post-fix. Reading the test is enough to understand what the fix does.

- **`test_evl_evolution_rejected_does_not_advance_tracked_policy` was extended for the R6 scope.** The test now asserts *both* `write_policy() == &wp1` (original R2/R5 assertion) and `last_checkpoint_version() == None` (new R6 assertion, line 749-753) within a single test. This keeps the "Evl soft-fails, nothing advances" behavior pinned to a single unit of test output. Splitting into two tests would have been defensible, but the combined version makes the symmetric-gate story more readable as a single assertion block.

- **The comment at line 289-299 explicitly names "each layer has its own authorization (cp passed its hard check above)".** This preempts the strongest counter-argument to the fix: "cp was independently authorized; why freeze it?" The answer is given inline: "we treat a record that failed any applicable check as untrusted for state-advance purposes." Even though the comment is long (see Low #2), the explicit counter-argument treatment is unusual and valuable — it records the road not taken, so future editors can't roll back the gate without also rolling back the rationale.

- **The fix uses the same `write_policy_satisfied` local captured at line 234, no new plumbing.** Both `last_checkpoint_version` (line 300) and `new_cp` (line 308) now consume the existing boolean. No new fields on `SadBranchState`, no extra async calls, no re-query of the checker. The gate is three additional `if` blocks in one function.

- **The audit process itself converged on a consistency question in R5 and resolved it in R6.** Rounds 1-4 covered correctness/security/docs. R5 surfaced a single belt-and-suspenders asymmetry and made the user pick a posture. R6 confirms the pick and notes the same posture should extend to Est. The pattern — multiple short passes, each narrower than the last, each producing exactly one structural question — is how audits should converge. No fishing for issues; each round found what was genuinely left.

- **Greenfield migration policy held across six rounds.** No new migration files were added for any round's fix. Every schema change (R1 finding #6: dropping `sad_pointers_write_policy_topic_version_idx`; R1 finding #7: adding `#[serde(default)]` to five Option fields) landed in the existing `0001_initial.sql` and `pointer.rs`. The branch's final diff is the intended final state, not a sequence of migrations.
