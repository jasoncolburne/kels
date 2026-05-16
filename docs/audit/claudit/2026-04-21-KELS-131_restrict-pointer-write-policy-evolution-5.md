# Branch Audit: KELS-131_restrict-pointer-write-policy-evolution (Round 5) — 2026-04-21

Fifth-pass audit. Diff unchanged in shape (~228+/68- across the 16 source/test/doc files + 4 prior claudit docs). Rounds 1-4 closed 20 findings (15 inline, 2 deferred to #126, 3 from R4 inline). Round 5 focused on the symmetry of the R2 defense-in-depth gate across all branch-state advances driven by a soft-rejected record: tracked_write_policy (gated), tracked checkpoint_policy (not gated), and last_checkpoint_version (not gated). One Medium surfaces; nothing else surfaced after re-tracing the verifier and handler paths.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 0        |

---

## Medium Priority

### ~~1. Branch `checkpoint_policy` and `last_checkpoint_version` still advance when a record soft-fails the write_policy check~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:282-308`

~~Round 2 added the defense-in-depth gate that *blocks* `tracked_write_policy` advancement when the soft wp check fails on an Evl/Rpr record. The same match arm has two other side effects that are not similarly gated:~~

1. ~~`self.last_checkpoint_version = ...` (line 290-293) is updated unconditionally whenever the hard cp check passes.~~
2. ~~`new_cp = record.checkpoint_policy.or(Some(*tracked))` (line 296) then becomes the branch's new `checkpoint_policy` unconditionally.~~

~~Scenario: a chain at v0 has `tracked_write_policy = wp1`, `checkpoint_policy = cp1`. An adversary who has compromised `cp1` endorsers but *not* `wp1` endorsers crafts `v1 = Evl(write_policy=Some(wp_attacker), checkpoint_policy=Some(cp_attacker))`. In the verifier:~~

- ~~Soft wp check: `satisfies(v1, wp1)` → `false` (attacker can't satisfy wp1). `policy_satisfied = false`, `write_policy_satisfied = false`.~~
- ~~Hard cp check: `satisfies(v1, cp1)` → `true` (attacker compromised cp1). No hard error.~~
- ~~`tracked_write_policy` stays at `wp1` (Round 2 gate holds).~~
- ~~`last_checkpoint_version` advances to `Some(1)`.~~
- ~~Branch `checkpoint_policy` advances to `cp_attacker`.~~

~~In practice the handler short-circuits this via `if !verification.policy_satisfied() { return FORBIDDEN }` (both normal and repair paths in `services/sadstore/src/handlers.rs:1390,1449`), so the corrupt branch state never persists through a single submission. The exposure is purely the "belt-and-suspenders" case R2 was designed to protect against — a consumer that forgets to gate on `policy_satisfied()`.~~

~~The Round 2 rationale ("gives consumers multiple soft signals instead of relying on a single `policy_satisfied` flag being checked") applies symmetrically here.~~

**Resolution (Option a — symmetric gating):** Both `last_checkpoint_version` and `new_cp` in the Evl/Rpr arm are now gated on `write_policy_satisfied`, mirroring the R2 gate on `tracked_write_policy`:

```rust
if write_policy_satisfied {
    self.last_checkpoint_version = Some(match self.last_checkpoint_version {
        Some(existing) => existing.min(record.version),
        None => record.version,
    });
}

let new_cp = if write_policy_satisfied {
    record.checkpoint_policy.or(Some(*tracked))
} else {
    Some(*tracked)
};
```

The comment block above these gates records the rationale ("each layer has its own authorization (cp passed its hard check above), but we treat a record that failed any applicable check as untrusted for state-advance purposes") so future editors see why the cp-advance is deliberately coupled to the wp check. Added `test_evl_rejected_wp_does_not_advance_checkpoint_policy` that proves the cp-advance gate holds by submitting a v2 Evl whose hard cp check would fail if the v1 wp-soft-fail had leaked `cp_attacker` into tracked cp. Extended `test_evl_evolution_rejected_does_not_advance_tracked_policy` to also assert `last_checkpoint_version() == None` after the soft-failed Evl.

---

## Positive Observations

- **The audit has converged.** After four prior rounds touching correctness, security, API design, tests, and docs, Round 5 surfaced exactly one finding — and that finding is a consistency question, not a bug. The change is ready for review by this bar: no high-priority issues remain open across five passes, all medium/low priorities have been addressed or deferred to scoped follow-ups (#119, #126).

- **The R2 `write_policy_satisfied` boolean is well-placed for the R5 suggestion if adopted.** The local variable is already captured at line 234 and consumed at line 303. Extending the gate to the cp advancement and `last_checkpoint_version` update is a local, readable change — the boolean doesn't need to be re-derived or threaded through a new field.

- **Handler-layer gate on `policy_satisfied()` is consistent across both submission paths.** `services/sadstore/src/handlers.rs:1390` (repair path) and `:1449` (normal path) both early-return 403 before `save_batch` runs. This is the primary enforcement layer; the verifier's defense-in-depth gates are additional signals, not primary controls. The symmetry of the primary gate across both paths means the R5 finding is about soft-signal consistency, not about an exploitable hole.

- **The prior rounds' fixes compose cleanly.** R1's `tracked_write_policy` introduction, R2's defense-in-depth gate, R3's doc alignment and cross-crate verification, and R4's doc clarifications each build on the prior rounds without requiring rework. The final shape of `SadBranchState` and `flush_generation` reads as a coherent design, not a sequence of patches.

- **Test taxonomy covers both the advance-and-reject loops exhaustively.** `test_multi_step_write_policy_evolution` (advance) and `test_multi_step_evolution_rejected_keeps_seed_policy` (reject) together pin down that the R2 gate propagates through multi-step chains. The divergent tie-break test (`test_divergent_branches_tracked_write_policy_tiebreak_deterministic`) closes the divergent-branch arm. No surface of the new state machine is untested.

- **The `Option<Digest256>` migration on `SadPointer.write_policy` didn't introduce asymmetric deserialization risk.** All five `Option` fields now carry both `skip_serializing_if` and `default` (R1 Finding #7), so records without `writePolicy` deserialize cleanly on Est/Upd/Rpr and records with it deserialize cleanly on Icp/Evl. No format-specific failure mode remains between JSON, CBOR, and MessagePack.
