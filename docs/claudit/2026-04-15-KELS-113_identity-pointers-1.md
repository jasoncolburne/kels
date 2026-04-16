# Branch Audit: KELS-113_identity-pointers (Round 1) — 2026-04-15

Branch `KELS-113_identity-pointers` vs `main`: ~665 insertions, 115 deletions across 14 files. Adds `PolicyChecker` trait, evolving write_policy on `SadChainVerifier`, identity chain module, `AnchoredPolicyChecker`, server-side verify-then-extend enforcement, exchange layer policy migration, and `read_policy` removal.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. Verify-then-extend bypassed for repair submissions~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1183-1266`

~~The verify-then-extend block runs unconditionally before `save_batch` / `truncate_and_replace`. For `?repair=true` submissions, the verifier re-verifies the existing (potentially divergent) chain from scratch, then appends the repair records. But a divergent chain has >1 record at the same version — the verifier's `flush_generation` allows max 2 records per generation, so divergent chains should verify structurally. However, the repair records themselves are replacement records intended to truncate the chain at a specific version. The verifier sees: existing chain (divergent) + repair records that start at `from_version`. The repair records' `previous` field won't match a branch tip if the chain is divergent and the repair starts at the divergence point.~~

**Resolution:** Restructured to a single-transaction pattern with advisory lock. The handler now begins a transaction, acquires an advisory lock on the chain prefix, then branches:

- **Normal path:** verify existing + new records through `SadChainVerifier`, check `policy_satisfied()`, then `save_batch_in()` — all within the transaction. Rollback on any failure.
- **Repair path:** `truncate_and_replace_in()` first (archival + truncation + insert, within the same transaction), then verify the entire post-repair chain from scratch. If policy check fails, rollback undoes the truncation.

New `_in` variants (`save_batch_in`, `truncate_and_replace_in`, `get_stored_in`) accept an external transaction. The advisory lock eliminates TOCTOU between verification and write. Divergence is impossible at the database level.

---

## Medium Priority

### ~~2. Performance: full chain re-verification on every pointer submission~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1205-1241`

~~Every pointer submission re-verifies the entire existing chain from scratch (paging through all records) before accepting new records. For long chains (thousands of records), this means every single-record append reads the entire chain from the database and calls `evaluate_anchored_policy` on every record via the `PolicyChecker`. Each checker call resolves a policy and queries KELs for anchoring — potentially N HTTP calls for an N-record chain.~~

**Resolution:** Accepted — the pattern is correct and matches the KEL merge engine.

### ~~3. `sync.rs` module doc comment is stale~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:9`

~~The module doc comment says "structural verify (no signatures with anchoring model)" but `verify_sad_pointer` now does policy verification via `PolicyChecker` (which calls `evaluate_anchored_policy`). The "no signatures" description is misleading for the new behavior.~~

**Resolution:** Updated comment to "structural + policy verification via `PolicyChecker`".

### ~~4. `pointer.rs` doc comment on `SadPointer` is stale~~ — RESOLVED

**File:** `lib/kels/src/types/sad/pointer.rs:8-10`

~~The doc comment says "Chains are keyed by `(write_policy SAID, topic)`" which implies write_policy is fixed per chain. With evolving write_policy, the keying is really `(v0_write_policy SAID, topic)` for prefix derivation, but subsequent records can have different write_policies. This could confuse readers.~~

**Resolution:** Updated to clarify that chain prefix is derived from v0's write_policy + topic, and that write_policy can evolve across versions.

---

## Low Priority

### ~~5. Duplicate `AlwaysPassChecker` mock across test files~~ — RESOLVED

**Files:** `lib/kels/src/types/sad/verification.rs:295-304`, `lib/policy/src/identity_chain.rs:95-104`

~~Both test modules define identical `AlwaysPassChecker` structs with the same `PolicyChecker` implementation. If a third file needs it, that's three copies.~~

**Resolution:** Accepted — two copies is manageable. If a third appears, extract to a shared test utility.

### ~~6. `exchange_write_policy` uses `threshold(1, [endorse(...)])` in issue text but `endorse(...)` in code~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:17`

~~The issue's migration path section says "Create policy `threshold(1, [endorse(kel_prefix)])` — semantically equivalent" but the implementation uses the simpler `endorse(prefix)` form. Both are semantically equivalent (single endorser), but the discrepancy between the issue description and the implementation could cause confusion during review.~~

**Resolution:** `endorse(prefix)` is simpler and correct. No change needed — issue text is illustrative, not prescriptive.

---

## Positive Observations

- **`finish()` returns `SadPointerVerification` directly.** This is better than the plan's original design of a separate `policy_satisfied()` method on the verifier — it ensures the flag is only accessible after `flush_generation` runs, preventing a class of timing bugs. It also matches the existing verification token pattern.

- **Policy satisfaction is recorded, not errored.** The verifier records `policy_satisfied = false` instead of returning an error on policy failure. This separates structural integrity (errors) from authorization (flags), letting callers decide the response. The server returns 403, clients can log — clean separation of concerns.

- **`AnchoredPolicyChecker` is a single canonical implementation.** Both `lib/policy` and `services/sadstore` use the same struct. No duplication of the `evaluate_anchored_policy` call pattern across the codebase.

- **Identity chain `advance()` requires a verification token.** This prevents building on an unverified chain — the type system enforces the verify-then-advance invariant. Matches the KEL pattern where operations require a `Verification` token.

- **Clean import structure in new files.** Both `identity_chain.rs` and `policy_checker.rs` follow the three-group import convention (std, external, local) with correct sorting. The `lib.rs` re-exports use `pub(crate)` for modules and selective `pub use` for the public API.

- **Shell script policy construction is correct.** `load-sad.sh` correctly constructs the policy JSON with the `said` placeholder, computes the SAID via `compute_said`, and uploads it before using the SAID as `writePolicy`. The SAID computation matches the Rust `Policy::build` derivation because both use the same Blake3-of-JSON-with-placeholder approach.
