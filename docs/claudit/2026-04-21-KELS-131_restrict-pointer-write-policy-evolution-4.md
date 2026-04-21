# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 4) — 2026-04-21

Fourth-pass audit after 17 prior findings (7 in R1, 5 in R2, 5 in R3 — 15 resolved + 2 deferred to #126). Diff shape unchanged (~228+/68- across 16 files + 3 claudit docs). Round 4 focused on the remaining soft seams: the `SadPointerVerification::write_policy()` accessor under divergent chains, the asymmetric handling of `write_policy_satisfied` across the Est/Evl/Upd match arms, and the create → Est → advance preconditions on `identity_chain`. Two low-priority documentation findings and one low-priority code clarity finding, all resolved inline. No new high/medium issues surfaced. Total resolved across all rounds: 20 (7 + 5 + 5 + 3 inline; 2 deferred to #126).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 3        |

---

## Low Priority

### ~~1. `SadPointerVerification::write_policy()` docstring doesn't flag divergent-chain semantics~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:311-320`

~~The docstring states:~~
> ~~Seeded by v0 (Icp) and updated whenever an Evl record carries a new write_policy *and* the evolution was authorized by the previous policy.~~

~~For divergent chains this is misleading. Each branch has its own `tracked_write_policy`, and `finish()` picks the winner via `(version ASC, tip.said ASC)` tie-break (`verification.rs:400-408`). The accessor therefore returns the *winning branch's* tracked policy — not a chain-wide value. Two divergent branches may legitimately carry different tracked policies (tested in `test_divergent_branches_tracked_write_policy_tiebreak_deterministic`), and the accessor silently exposes only one.~~

~~In practice this is low-risk: divergent chains are already frozen at the handler layer (`save_batch` returns `DivergenceCreated`) and submission callers gate on `policy_satisfied()`. But a future consumer reading the docstring alone might assume the value covers the whole chain.~~

**Resolution:** Appended a paragraph to the `write_policy()` rustdoc explaining that for divergent chains the accessor reflects only the tie-break winner's branch (higher version wins; equal versions break on lexicographically greater SAID), and directing callers that depend on chain-wide invariants to detect divergence via `effective_said` first.

### ~~2. `identity_chain::create()` doesn't document the Est-at-v1 precondition for `advance()`~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:17-35`

~~Round 3 added a two-paragraph block to `advance()`'s docstring flagging the `checkpoint_policy` precondition. `create()`'s docstring still reads as if an identity chain is usable after just `create()` — but the minimal working flow is actually `create → Est(checkpoint_policy) at v1 → advance`. Without the Est, `advance()` produces an Evl that the verifier rejects at submission.~~

~~The `create()` function itself doesn't need to change (identity chains may legitimately stay at v0 if the author never needs to rotate). But the docstring should cross-reference the `advance()` precondition so readers building identity chains from scratch don't discover the gap at submission time.~~

**Resolution:** Appended a paragraph to `create()`'s rustdoc explaining that rotation via `advance()` requires an `Est` record at v1 declaring `checkpoint_policy`, noting the failure mode (verifier rejects at submission) and cross-referencing `advance()` for the higher-threshold authorization rules.

### ~~3. Est/Upd match arms don't explain why `write_policy_satisfied` isn't consulted~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:261-321`

~~The Evl/Rpr arm at line 302-306 has a clear comment:~~

~~```rust
// Defense-in-depth: only advance tracked_write_policy when the
// soft write_policy check above passed...
let new_wp = if write_policy_satisfied {
    record.write_policy.unwrap_or(branch.tracked_write_policy)
} else {
    branch.tracked_write_policy
};
```~~

~~The Est arm (line 270) and Upd arm (line 320) both unconditionally pass `branch.tracked_write_policy` through — no gate. This is correct (Est and Upd both forbid `write_policy`, so there's nothing to evolve), but the asymmetry is invisible to a reader tracing through the match. A future editor who adds `write_policy` to Upd (hypothetically) could miss the defense-in-depth gate the Evl/Rpr arm carries.~~

**Resolution:** Added one-line inline comments to both the Est arm (line 270) and the Upd arm (line 321): `// tracked_write_policy unchanged — {Est,Upd} forbids write_policy (validate_structure)`. The asymmetry with the Evl/Rpr arm is now self-documenting at each callsite.

---

## Positive Observations

- **The R1-R3 findings form a coherent defense-in-depth story.** R1 introduced `tracked_write_policy` and the deterministic tie-break. R2 closed the soft-fail-advance attack vector ("Option B" gate). R3 closed the doc and test-loop gaps. Each round's resolution didn't just patch the symptom — it promoted a behavior the verifier was already half-tracking into a first-class invariant. The `SadPointer` module now reads as if the per-kind write_policy matrix had always been the design, not a retrofit.

- **`AnchoredPolicyChecker::self_satisfies` at `lib/policy/src/policy_checker.rs:54-70` handles the structurally-unreachable `None` case with an explicit error rather than a panic.** The message ("validate_structure should have rejected") names the invariant and the layer that enforces it, so a future developer seeing this error knows where the bug actually is. Most codebases would either unwrap (panic) or match-ignore (silently pass) — this one uses the error channel to surface the invariant violation, matching the project's "fail secure" posture.

- **The `write_policy_satisfied` boolean threads cleanly through `flush_generation` without leaking into fields or requiring a re-query.** R2's resolution could have re-queried the checker inside the Evl/Rpr arm (simpler but duplicative) or threaded the result via a mutable `SadBranchState` field (more plumbing, harder to audit). The chosen path — a single local variable captured at the check site and consumed at the advance site — is the minimum viable threading and the easiest to prove correct on a code read.

- **Greenfield discipline was maintained: the migration dropped the dead `sad_pointers_write_policy_topic_version_idx` in-place rather than adding a new migration.** R1's finding #6 could have been deferred ("we'll clean up later"), but the fix lands in the original `0001_initial.sql`. This keeps the migration history lean and matches the project's greenfield policy (AGENTS.md: "Greenfield — edit migrations in place, no new migration files").

- **The test taxonomy is now genuinely complete for the write_policy state machine.** After four rounds, the new test suite covers: single-step evolution (authorized + rejected), multi-step evolution (authorized + rejected), inheritance through Evl-pure-checkpoint and Rpr, divergent-branch tie-break determinism, and cross-crate re-verification through `identity_chain::advance`. Every branch of the `new_wp = if write_policy_satisfied` gate and every cell of the per-kind require/forbid matrix has at least one test pinning it down.

- **Cross-crate API semantics stayed stable despite a non-trivial type change.** `SadPointerVerification::write_policy()` changed its *meaning* (tip field → branch-tracked) but not its *signature* (`&cesr::Digest256`). The only external caller (`identity_chain.rs:76`) absorbed the change with a single `*` deref. Changing a widely-used accessor's semantics without breaking its signature is a routine cause of silent bugs; the resolution here — rename the internal field, keep the method name and return type — was the correct tradeoff given the tight blast radius (one external caller).
