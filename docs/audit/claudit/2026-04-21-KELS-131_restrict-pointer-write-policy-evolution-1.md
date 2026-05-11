# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 1) — 2026-04-21

Restricts `SadPointer.write_policy` to `Icp` (required) and `Evl` (optional). Diff is 229+/67- across 13 files, touching the pointer struct, verifier branch state, identity-chain advance, exchange CLI, service migration, test scripts, and docs.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 4        |

---

## Medium Priority

### ~~1. No test exercises the soft write_policy rejection path on Evl-with-evolution~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:576-618`

~~`test_rejected_write_policy_evolution` was rewritten when Upd-with-policy-change became structurally forbidden. The new test builds an Evl with `write_policy: Some(wp2)` and runs it through `RejectingChecker`, which rejects every `satisfies` call. The verifier first runs the v1+ authorization check against `branch.tracked_write_policy` (line 227–233, soft — sets `policy_satisfied = false`), and then the checkpoint evaluation inside the Evl path (line 274–279, hard error). The hard error short-circuits and is what the test asserts. The soft rejection on the evolving write_policy is never observably exercised — it's masked by the hard checkpoint error.~~

~~Before the change, the soft-reject-on-evolution path had its own dedicated test. Now it has no coverage: `test_rejected_same_write_policy` covers Upd soft-reject but not the Evl-with-evolution-under-unauthorized-writer scenario, which is exactly the attack vector the whole issue is about ("can the previous write_policy authorize evolution?").~~

**Resolution:** Added `AcceptCheckpointRejectWriteChecker` test helper (lib/kels/src/types/sad/verification.rs ~line 494) that distinguishes the two `satisfies` calls by comparing the supplied policy SAID against a configured checkpoint_policy. Added `test_evl_evolution_rejected_by_previous_write_policy_soft_fails` asserting that Evl-with-evolution under an unauthorized writer causes `finish()` to succeed with `policy_satisfied() == false` (soft rejection) and that `tracked_write_policy` still advances to the new policy (authorization is the caller's decision).

### ~~2. No explicit test that Rpr inherits `tracked_write_policy` unchanged~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:265-293`

~~Rpr and Evl share the `kind if kind.evaluates_checkpoint()` arm. The arm computes `new_wp = record.write_policy.unwrap_or(branch.tracked_write_policy)`. For Rpr, `record.write_policy` is always `None` (validate_structure forbids it), so the branch inherits. Correct today, but fragile: anyone who refactors the shared arm to treat Evl and Rpr differently could accidentally break Rpr inheritance, and no test would catch it.~~

**Resolution:** Added `test_rpr_inherits_tracked_write_policy` — v0 Icp with wp1, v1 Rpr, asserts `verification.write_policy() == &wp1`.

### ~~3. Divergent-branch `tracked_write_policy` is not test-covered~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:382-393`

~~Each branch has its own `tracked_write_policy`, so divergent branches can evolve to different policies. `finish()` picks the max-version branch's tracked policy (line 382–388). For divergent chains at equal version, `max_by_key` is implementation-defined which branch wins. None of the divergence tests (`test_divergence_detection_at_page_boundary` in sync.rs, no divergent-branch tests here) exercise this — they all use same-policy forks.~~

**Resolution:** Replaced `max_by_key(|b| b.tip.version)` in `finish()` with a deterministic `max_by` that sorts on `(version ASC, tip.said ASC)` — higher version wins; equal versions break on lexicographically greater SAID bytes. Added `test_divergent_branches_tracked_write_policy_tiebreak_deterministic` that builds two divergent Evl branches with different new write_policies, submits them in both orders, and asserts the same winner both times.

---

## Low Priority

### ~~4. `_kel_prefix` parameter in `build_replacement` is dead~~ — RESOLVED

**File:** `services/sadstore/tests/repair_tests.rs:172-197`

~~The `_kel_prefix` parameter is no longer used after the Rpr write_policy was cleared (the line that computed `kel_digest` from it was removed). The parameter remains in the signature with an underscore prefix purely to avoid touching the four call sites.~~

**Resolution:** Removed the parameter from the signature and updated all four call sites.

### ~~5. Stale comment in `repository.rs::truncate_and_replace`~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:149-152`

~~The comment "write_policy can evolve across versions, so repair records at v3+ may legitimately differ from v0's write_policy" dates from when Upd records carried write_policy. After this PR, repair records (Rpr) can't carry write_policy at all, and only Icp/Evl do. The broader point (no consistency check at repo layer; callers verify via SadChainVerifier) is still accurate, but the example is misleading.~~

**Resolution:** Rephrased the comment to reference the verifier's branch-state tracking: "write_policy evolution is tracked by the verifier's branch state across versions; no consistency check at the repo layer — callers must verify via SadChainVerifier (the handler does this with PolicyChecker after truncate_and_replace)."

### ~~6. `sad_pointers_write_policy_topic_version_idx` is now largely inert~~ — RESOLVED

**File:** `services/sadstore/migrations/0001_initial.sql:19-20`

~~With `write_policy` nullable and only present on Icp / policy-evolving Evl records, this composite index will have NULL for most rows (Est/Upd/Rpr). Postgres excludes NULL from B-tree indexes by default, so the index still works for its lookups but covers far fewer rows than before. If no query actually uses `(write_policy, topic, version DESC)` as a lookup key, the index is dead weight.~~

**Resolution:** Verified no SQL path filters on `write_policy` as an equality predicate (grep for `write_policy\s*=`, `WHERE.*write_policy`, etc. across `services/sadstore/` returned only a Rust-side field assignment in a test). Dropped the index from the migration.

### ~~7. `Option<T>` fields without `#[serde(default)]` may reject absent keys on deserialization~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:130-154`

~~`write_policy`, `previous`, `content`, `custody`, `checkpoint_policy` all use `#[serde(skip_serializing_if = "Option::is_none")]` but not `#[serde(default)]`. serde_json's default behavior for `Option<T>` is to accept missing fields as `None`, but this is a serde_json-specific convenience that doesn't hold for all serde formats. The existing fields follow this pattern, so this isn't a regression — just a latent fragility shared across all Option fields on SadPointer.~~

**Resolution:** Added `default` to all five `Option<T>` fields on `SadPointer` (`previous`, `content`, `custody`, `write_policy`, `checkpoint_policy`) alongside `skip_serializing_if`. No semantic change in JSON; forward-compatible for CBOR/MessagePack. Scope is `SadPointer` only; broader sweep tracked in #119.

---

## Positive Observations

- **Clean separation of concerns with `tracked_write_policy` on `SadBranchState`.** Authorization lookups now use the branch's tracked policy (`branch.tracked_write_policy`), not the tip's field. This matches the already-proven pattern used for `checkpoint_policy` tracking and removes a category of attack surface where the record's claimed policy could be trusted directly. The change is local to `SadBranchState` and flows outward; no caller-side plumbing was needed.

- **`record.write_policy.unwrap_or(branch.tracked_write_policy)` in the Evl/Rpr path is self-documenting.** The expression directly encodes the rule "Some = evolve, None = inherit" without a conditional. Reads like the spec.

- **Layered defense: `.expect` guarded by `validate_structure` invariants.** The v0 Icp tracked_write_policy seed uses `expect("Icp record must have write_policy per validate_structure")` under `#[allow(clippy::expect_used)]`, and `AnchoredPolicyChecker::self_satisfies` uses `ok_or_else` with a descriptive error. Both layers acknowledge that validate_structure is the authoritative invariant, but neither trusts it to the point of UB. This matches the project's "fail secure, not safe" rule.

- **Comprehensive `validate_structure` test additions.** New tests cover every per-kind writePolicy rule: `icp_missing_write_policy_rejected`, `est_forbids_write_policy`, `upd_forbids_write_policy`, `evl_with_write_policy_valid`, `evl_without_write_policy_valid`, `rpr_forbids_write_policy`. The pair-test pattern on Evl (with and without) is exactly right for an optional field — it prevents future regressions where someone accidentally makes Evl require writePolicy.

- **`test_evl_without_write_policy_inherits_tracked` closes the key new behavior loop.** This is the single most important new test: it proves that an Evl pure-checkpoint record does NOT reset `tracked_write_policy`, and that the verification token's `write_policy()` accessor returns the inherited (seed) value. Without this test, the inheritance semantic would be a silent runtime behavior.

- **Design doc "write_policy per kind" section explicitly states the security rationale.** The new paragraph in `docs/design/sad-pointers.md` explains *why* the restriction matters — an adversary satisfying the current write_policy can no longer replace it via a Upd-style record; replacement now requires also satisfying the stricter checkpoint_policy. Future readers (including LLMs) will understand the invariant, not just the code.

- **`SadPointerVerification::write_policy()` semantic change was handled carefully.** The accessor previously returned `&self.tip.write_policy`; it now returns `&self.tracked_write_policy`. This is a subtle change but it's documented inline, and the one external caller (`lib/policy/src/identity_chain.rs:65`) was updated in the same commit to dereference (`*verification.write_policy()`). Keeping the method name and `&Digest256` return type meant zero call-site churn.
