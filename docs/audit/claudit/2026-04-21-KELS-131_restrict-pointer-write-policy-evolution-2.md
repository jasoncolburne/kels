# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 2) — 2026-04-21

Second-pass audit after Round 1's seven findings were resolved. Diff unchanged in scope (229+/67- across 13 source files + tests + docs). Round 2 focused on subtler semantics: how the new verifier state (`tracked_write_policy`, deterministic tie-break, soft-fail advance) interacts with attacker-crafted chains and with existing consumers of the verification token. Total resolved across both rounds: 12 (7 from Round 1 + 5 from Round 2).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 4        |

---

## Medium Priority

### ~~1. `tracked_write_policy` advances even when the previous policy rejected the evolution~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:289-292`

~~Inside the Evl/Rpr match arm:~~

~~```rust
let new_wp = record.write_policy.unwrap_or(branch.tracked_write_policy);
(new_cp, 0, new_wp)
```~~

~~This runs *unconditionally* — including on records where the preceding `checker.satisfies(record, &branch.tracked_write_policy)` check at line 227–233 returned `false`. The soft-failure flag `policy_satisfied = false` is set, but the branch state still advances to `record.write_policy`. Subsequent v2+ records on this branch are then authorized against the attacker's `wp2`, not the legitimate `wp1`.~~

~~The new test `test_evl_evolution_rejected_by_previous_write_policy_soft_fails` explicitly asserts this behavior (`verification.write_policy() == &wp2` after a rejected evolution). The in-test comment frames it as "authorization is the caller's decision" — meaning the handler must gate on `policy_satisfied()` before trusting any verification-token accessor.~~

**Resolution (Option B, defense-in-depth):** The soft write_policy check's result is now captured into a local `write_policy_satisfied` in `flush_generation`. The Evl/Rpr match arm uses it to gate the advance:

```rust
let new_wp = if write_policy_satisfied {
    record.write_policy.unwrap_or(branch.tracked_write_policy)
} else {
    branch.tracked_write_policy
};
```

Rejected evolutions no longer advance `tracked_write_policy`. Subsequent records on the same branch are re-checked against the legitimate previous policy, producing additional soft-failure signals instead of silently flipping to the attacker's policy. The `SadBranchState.tracked_write_policy`, `SadPointerVerification::write_policy()`, and `PolicyChecker` trait docstrings were updated to reflect the stronger semantic ("updated when Evl carries a new write_policy *and* the evolution was authorized"). The test was renamed to `test_evl_evolution_rejected_does_not_advance_tracked_policy` and now asserts `verification.write_policy() == &wp1` (not wp2).

---

## Low Priority

### ~~2. `test_rejected_write_policy_evolution` name no longer matches what it tests~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:632-655`

~~Before this PR, the test used `Upd` with a changed `write_policy` under `RejectingChecker` and asserted `policy_satisfied() == false` — a clean write_policy-rejection test. After the PR, the test uses `Evl` (the only non-Icp kind that may carry write_policy), and `RejectingChecker` rejects *both* the write_policy check (soft, at line 229) *and* the checkpoint_policy check (hard, at line 274). The hard error short-circuits, so the test now asserts `err.to_string().contains("checkpoint policy not satisfied")`.~~

~~The test's name promises a write_policy-rejection assertion; its body tests checkpoint-policy rejection. The clean write_policy-rejection case is covered by the new `test_evl_evolution_rejected_by_previous_write_policy_soft_fails`. Reader confusion is the only cost.~~

**Resolution:** Rewrote the test to use `AcceptCheckpointRejectWriteChecker` — it now cleanly isolates the write_policy rejection path (checkpoint passes, write soft-fails, `finish()` succeeds, `policy_satisfied()` is false, `write_policy()` stays at wp1 per the Fix #1 gate). The name is kept because it now matches what the test asserts.

### ~~3. No test for multi-step write_policy evolution (v0 wp1 → v1 Est → v2 Evl(wp2) → v3 Evl(wp3))~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs` (entire module)

~~`test_evolving_write_policy_authorized` covers one evolution step (v0 → v1 Evl). No test walks the chain through a *second* evolution where the authorization at v3 must be against the already-evolved `wp2`, not the seed `wp1`. The codepath that matters is line 291 (`new_wp = record.write_policy.unwrap_or(branch.tracked_write_policy)`) feeding line 229's `branch.tracked_write_policy` on the *next* generation. A regression that re-seeded from v0 every time would pass the existing tests.~~

**Resolution:** Added `test_multi_step_write_policy_evolution` — chain v0 Icp(wp1) → v1 Est → v2 Evl(wp2) → v3 Evl(wp3) under `AlwaysPassChecker`, asserts `verification.write_policy() == &wp3` (proves each step advances from the previously-tracked value, not from v0's seed). Also added `test_multi_step_evolution_rejected_keeps_seed_policy` — chain v0 Icp(wp1) → v1 Evl(wp2) → v2 Evl(wp3) under `AcceptCheckpointRejectWriteChecker`, asserts `verification.write_policy() == &wp1` (proves the Fix #1 gate propagates through multi-step chains: neither v1 nor v2 advance tracked state when soft-rejected).

### ~~4. `AcceptCheckpointRejectWriteChecker` disambiguates check types by policy-SAID equality~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:501-516`

~~The test helper can't distinguish a write-policy check from a checkpoint-policy check by callsite — it infers intent by comparing the `policy` argument against a stored `checkpoint_policy` SAID. If a test ever set `wp == cp` (two distinct test labels hashed to the same digest, or a test copying a single digest into both fields), both checks would accept, masking the assertion.~~

~~This works today because all tests use distinct `test_digest(b"...")` labels, but the fragility is implicit. A call-count-based or flag-based mock would be more explicit.~~

**Resolution (Option C):** Added a rustdoc warning on the struct naming the disambiguation strategy and explicitly telling callers not to reuse the same SAID between `write_policy` and `checkpoint_policy` in a single test. Tests already use distinct `test_digest(b"...")` labels, so the rule is documented rather than enforced — the warning makes the implicit contract explicit for future authors.

### ~~5. `compute_sad_pointer_prefix` doesn't call `validate_structure`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:162-175`

~~The function constructs an Icp and returns its prefix but never calls `pointer.validate_structure()`. If Icp's structural rules ever change in a way that depends on fields beyond `write_policy` + `topic` (e.g., adding a required field), this function could silently compute prefixes for structurally-invalid inputs. Today the prefix derivation uses only the blanked-SAID template, so validate_structure is redundant — but that coupling is implicit.~~

**Resolution:** Added `pointer.validate_structure().map_err(StorageError::StorageError)?;` after `SadPointer::create`, with an inline comment explaining the future-proofing intent. Uses the existing `StorageError::StorageError(String)` variant (matches the error-mapping convention in this file).

---

## Positive Observations

- **The defense-in-depth pattern in `policy_checker.rs::self_satisfies` is well-executed.** The `ok_or_else` at `lib/policy/src/policy_checker.rs:55-59` treats `record.write_policy.is_none()` as a verification failure with an explicit error message ("validate_structure should have rejected") rather than panicking. This gives a consistent library-level failure mode for a case that's supposedly unreachable — matching the project's "fail secure" stance. The sibling `expect` in `verification.rs:178` chose the panic path for the same invariant; both are defensible, and the dual-style is arguably better than uniform-style because the panic sits closer to the authoritative `validate_structure` call while the error sits at the API boundary.

- **Comment refactor in `repository.rs::truncate_and_replace` is genuinely clearer than the original.** The new comment at `services/sadstore/src/repository.rs:149-152` names the verifier's branch state as the authority and points callers to `SadChainVerifier` + `PolicyChecker` for consistency enforcement. Readers no longer have to reconstruct the invariant from a stale example.

- **`compute_sad_pointer_prefix` preserves its non-Option `cesr::Digest256` signature.** By taking `write_policy: cesr::Digest256` (not `Option<cesr::Digest256>`), the function makes it impossible to compute a prefix without a write_policy — encoding the v0-has-write_policy invariant at the type level. Callers who have `Some(_)` must unwrap first; callers who have `None` can't reach this API at all. Nice use of the type system to mirror the new semantic rule.

- **`SadPointer::validate_structure` now exhaustively covers the write_policy matrix.** Every kind has an explicit `require` or `forbid` for write_policy (Icp: require, Est/Upd/Rpr: forbid, Evl: optional-so-neither). Combined with the new per-kind unit tests in `mod.rs:1422-1598`, the structural rules are both documented and regression-proofed. The symmetric pair pattern on Evl (`test_validate_structure_evl_with_write_policy_valid` + `test_validate_structure_evl_without_write_policy_valid`) is exactly how optional fields should be tested.

- **Shell test scripts were updated in lockstep with the Rust schema.** `load-sad.sh` and `test-sadstore.sh` no longer emit `writePolicy` on Est/Upd/Rpr records. Had they not been updated, the scripts would silently produce invalid records that'd be rejected at submission time — the kind of test-infrastructure drift that's easy to miss. The accompanying comments ("Est forbids writePolicy" etc.) document *why* the field was removed, which will help future maintainers avoid re-adding it.

- **Migration removed the dead `sad_pointers_write_policy_topic_version_idx` rather than leaving it as dead weight.** Round 1 found this index was never read at query time. The fix in-place (greenfield policy) is the minimal correct action. Index definitions tend to accumulate; proactive removal keeps the schema lean.

- **Deterministic tie-break in `finish()` was introduced with a clarifying comment.** The `max_by` at `verification.rs:385-393` documents *why* the tie-break matters ("so `verification.write_policy()` is reproducible across callers") rather than just *what* it does. Divergent-chain determinism is subtle; the comment saves future readers from having to reconstruct the reasoning.
