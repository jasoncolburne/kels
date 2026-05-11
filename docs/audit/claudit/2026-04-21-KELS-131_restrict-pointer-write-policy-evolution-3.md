# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 3) — 2026-04-21

Third-pass audit. Diff unchanged in shape (~228+/68- across 16 files including the two prior claudit docs). Round 3 focused on consumers of the new API (identity_chain's Upd→Evl switch, doc alignment across design files, and test-helper consistency across crates). All five findings resolved inline — three fixes (sadstore.md doc update, closed verification loop in `test_advance_identity_chain`, expanded `advance()` docstring) plus two deferred to #126 (test-helper alignment and explicit-field hygiene) where the upcoming `SadPointerBuilder` retires the hand-built fixtures. Total resolved across all rounds: 17 (7 from Round 1 + 5 from Round 2 + 5 from Round 3).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 4        |

---

## Medium Priority

### ~~1. `docs/design/sadstore.md` not updated alongside the schema change~~ — RESOLVED

**File:** `docs/design/sadstore.md:28,78,90,92`

~~The sibling design doc still documents the old semantics in four places:~~
- ~~Line 28: `write_policy` described as "required" (now optional on Evl, forbidden on Est/Upd/Rpr).~~
- ~~Line 78: repair invariants list "consistent write_policy/topic" — write_policy is no longer invariant across versions (it evolves via Evl).~~
- ~~Line 90: the verification paragraph repeats "consistent write_policy/topic" — same staleness.~~
- ~~Line 92: the `write_policy()` accessor is listed but its semantic shift (tip's field → tracked branch policy) isn't flagged.~~

~~`docs/design/sad-pointers.md` was updated in this PR; `sadstore.md` was missed. Readers following the design-doc cross-references will encounter a contradiction.~~

**Resolution:** Updated all four sites: line 28 now states the per-kind rules with a pointer to `docs/design/sad-pointers.md`; lines 78 and 90 drop `write_policy` from the "consistent" clauses and note that it may evolve via Evl (tracked per-branch by the verifier); line 92 describes `write_policy()` as returning the branch-tracked (effective) policy that reflects Evl evolutions, not the tip's raw field.

---

## Low Priority

### ~~2. `test_advance_identity_chain` doesn't close the verification loop~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:170-192`

~~The test calls `advance(&verification, &policy2)` and asserts the returned `v2` has `kind == Evl`, `write_policy == Some(policy2.said)`, correct prefix/version. But it never feeds `[v0, v1_cp, v2]` back through `SadChainVerifier` to prove:~~
1. ~~The produced v2 actually passes structural + policy verification as a valid next link.~~
2. ~~`verification.write_policy()` after re-verification equals `policy2.said` (i.e., the tracked policy advanced through the Evl path in the verifier, not just in the builder).~~

~~This matters because `advance` now produces an Evl (was Upd), which is evaluated against `checkpoint_policy` — a different code path in the verifier than the old Upd. A regression in the evaluator arm wouldn't be caught by this builder-only test.~~

**Resolution:** Extended `test_advance_identity_chain` to rebuild the v1 Est checkpoint declaration from v0, run `[v0, v1_cp_rebuilt, v2]` through a fresh `SadChainVerifier` with `AlwaysPassChecker`, and assert `reverification.policy_satisfied() == true` and `reverification.write_policy() == &policy2.said`. This proves the produced Evl passes the verifier's `evaluates_checkpoint()` code path end-to-end.

### ~~3. Cross-crate `add_checkpoint_declaration` helpers diverge~~ — DEFERRED to #126

**File:** `lib/kels/src/types/sad/verification.rs:461-467` vs `lib/policy/src/identity_chain.rs:161-167`

~~Two helpers with the same name and purpose behave differently:~~
- ~~`verification.rs:461` mutates the pointer *and* calls `pointer.increment().unwrap()`.~~
- ~~`identity_chain.rs:161` mutates the pointer *without* incrementing; every caller in that file has to remember to call `increment()` themselves (e.g., `test_advance_identity_chain` line 179: `v1_cp.increment().unwrap();`).~~

~~The divergence is invisible at the callsite unless the author reads both definitions.~~

**Resolution:** Deferred to #126. The hand-built test fixtures in both crates will be replaced by `SadPointerBuilder`, which handles kind-specific field enforcement at the type level. Aligning the current helpers is churn for code that's about to be retired.

### ~~4. Evl builder tests implicitly rely on cloned `write_policy = None` from prior Est~~ — DEFERRED to #126

**File:** `lib/kels/src/types/sad/verification.rs:1024-1040,1325-1347`

~~`test_checkpoint_policy_evolution_on_evl_valid` (line 1024) and `test_checkpoint_after_est_accepted` (line 1325) build Evl records without explicitly setting `v.write_policy = None`. They work only because the preceding clone originated from a pointer that already had `write_policy = None` (an Est or Icp-derived state).~~

~~A future editor who rearranges the clone chain silently produces an Evl with a stale write_policy, changing the test's semantics from "pure checkpoint" to "policy evolution."~~

**Resolution:** Deferred to #126. The `SadPointerBuilder` being introduced there handles kind-specific field enforcement (Evl without explicit write_policy defaults to pure checkpoint by construction, not by implicit clone state), making this fragility moot in the migrated tests.

### ~~5. `identity_chain::advance` docstring doesn't flag the Upd→Evl tightening~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:37-45`

~~The docstring describes the invariant "new policy must differ from current write_policy" but doesn't mention the behavior change introduced by this PR: the produced record is now `Evl` (not `Upd`), which means:~~
- ~~The advance is evaluated against the chain's `checkpoint_policy` (higher-threshold bar), not just `write_policy`.~~
- ~~The advance requires `checkpoint_policy` to be established on the branch (via a prior Est or v0 cp declaration) — chains without a checkpoint will fail verification at the advance record, not at `advance()` itself.~~

**Resolution:** Added a two-paragraph block to the `advance` docstring. The first paragraph calls out the `Upd → Evl` switch (flagged as "was `Upd` before #131"), explains that the advance is now evaluated against `checkpoint_policy` (a higher-threshold authorization bar), and notes that policy replacement now requires satisfying both previous write_policy (soft check) and checkpoint_policy (hard check). The second paragraph names the precondition — chain must have `checkpoint_policy` established via a prior `Est` or v0 declaration — and warns that `advance()` itself does not surface the missing-checkpoint error; the verifier does at submission time.

---

## Positive Observations

- **The `AcceptCheckpointRejectWriteChecker` test helper's rustdoc warning (verification.rs:509-516) is textbook defense-in-depth for test infra.** It documents the disambiguation strategy *and* names the failure mode callers must avoid ("don't reuse the same SAID between write_policy and checkpoint_policy"). Few test helpers bother to document their own fragility; this one preempts a category of silent test failures that would otherwise mask real bugs.

- **Multi-step evolution tests (verification.rs:755-834) cover both directions — accept and reject — in the same pattern.** The pair `test_multi_step_write_policy_evolution` + `test_multi_step_evolution_rejected_keeps_seed_policy` is exactly the shape needed to prove the advance-and-check loop: one proves tracked advances through multiple legitimate evolutions (not re-seeded from v0), the other proves the defense-in-depth gate holds across multiple rejected attempts. The in-test comments explicitly call out that the tests are complementary.

- **The deterministic tie-break in `finish()` accounts for divergent chains with differing tracked_write_policy.** Pre-PR, divergent branches at equal version had implementation-defined max_by_key ordering on version alone — harmless when `write_policy` was a record-level field (both branches had the same tip-derived policy). Post-PR, divergent branches can legitimately carry *different* tracked_write_policy values, making deterministic tie-break a correctness requirement for the `write_policy()` accessor. The PR's `max_by` with `(version, said_bytes)` is the minimal correct fix, and the accompanying test (`test_divergent_branches_tracked_write_policy_tiebreak_deterministic`) verifies order-independence directly.

- **`compute_sad_pointer_prefix` now calls `validate_structure()` as a forward-compat guard** (pointer.rs:174-178). The inline comment explains the "future-proof" intent. This costs one validation pass per prefix computation (cheap) and ensures prefix derivation can never silently diverge from the structural rules a verifier would enforce.

- **The `write_policy_satisfied` local variable cleanly threads one boolean from the soft check (line 234) to the advance gate (line 302).** No hidden state, no revisiting of branch state, no re-querying the checker. The defense-in-depth claim ("on soft-fail, keep previous policy") reduces to a three-line if/else with a comment pointing back to the check site. Readers can verify the invariant locally without tracing through other functions.

- **Shell-script migrations kept consistent with the Rust schema.** `clients/test/scripts/load-sad.sh` and `test-sadstore.sh` drop `writePolicy` from Est/Upd/Rpr payloads in lockstep with the Rust-side `forbid` rules. Submission-time validation would have caught drift, but only after runtime; the preemptive script update keeps the test infra from producing rejected payloads.

- **`SadBranchState` field ordering puts `tracked_write_policy` between `tip` and `checkpoint_policy`** (verification.rs:46-58). Grouping the two policy-tracking fields adjacent to each other — both with block comments explaining their seed/update lifecycle — makes the branch state read like a spec of what the verifier is tracking.
