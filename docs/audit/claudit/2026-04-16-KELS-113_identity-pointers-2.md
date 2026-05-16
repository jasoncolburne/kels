# Branch Audit: KELS-113_identity-pointers (Round 2) — 2026-04-16

Branch `KELS-113_identity-pointers` vs `main`: ~1010 insertions, 173 deletions across 18 files. Focus on correctness of repair path with evolving write_policy, API design of verification tokens, and code duplication in new repository methods.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 1        |

Prior rounds: 6 findings, all resolved.

---

## High Priority

### ~~1. `truncate_and_replace` v0 write_policy check rejects valid repairs with evolved write_policy~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:88-103`

~~The repair path checks `records[0].write_policy` against the existing chain's v0 `write_policy`. Before this branch, write_policy was constant across the chain (enforced by the removed "All records must have the same write_policy" check in `handlers.rs`), so this was always true. Now that write_policy can evolve, a repair starting at e.g. v3 will have `records[0].write_policy` set to the evolved policy at v3, which differs from v0's write_policy. The check fails, blocking legitimate repairs on any chain where write_policy has evolved.~~

**Resolution:** Removed the stale v0 write_policy check. The handler's post-repair full chain re-verification via `SadChainVerifier` + `PolicyChecker` catches unauthorized policy changes. Added a doc comment noting callers must verify policy satisfaction independently.

---

## Medium Priority

### ~~2. `advance()` doesn't check `policy_satisfied()` on the verification token~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:41-73`

~~`advance()` accepts a `SadPointerVerification` token but doesn't check `verification.policy_satisfied()`. The token now carries both structural verification and policy authorization status — having a token no longer proves authorization. A caller could verify a chain where policy failed (getting `policy_satisfied = false`) and use that token to build the next record.~~

**Resolution:** Added `policy_satisfied()` check at the top of `advance()`. Returns `PolicyError::InvalidPolicy` if the chain has unauthorized records. Added `test_advance_rejects_unsatisfied_policy` test with `RejectAdvanceChecker`.

### ~~3. `get_stored` and `get_stored_in` have ~60 lines of duplicated pagination logic~~ — RESOLVED

**Files:** `services/sadstore/src/repository.rs:216-278` and `services/sadstore/src/repository.rs:283-343`

~~The two methods are nearly identical — same cursor lookup, same query construction, same `since_position` filtering, same integrity check, same truncation. The only difference is the executor (`self.pool` vs `tx`). A bug fix to the pagination/cursor logic in one must be manually replicated to the other.~~

**Resolution:** `get_stored` now delegates to `get_stored_in` via an implicit transaction. `QueryExecutor` and `TransactionExecutor` have incompatible signatures (`&self` vs `&mut self`), so a single generic helper wasn't possible. Delegation through a transaction is the cleanest deduplication — Postgres reads are in implicit transactions anyway, so the overhead is minimal.

---

## Low Priority

### ~~4. Exchange CLI re-uploads policy on every key rotation~~ — RESOLVED

**Files:** `clients/cli/src/commands/exchange.rs:183-186`

~~`cmd_exchange_rotate_key` builds and uploads the same policy to sadstore on every invocation. Since the policy expression is deterministic (`endorse(prefix)`), the policy SAID never changes — every upload is a duplicate that sadstore handles idempotently.~~

**Resolution:** Accepted — SADStore handles idempotently. The redundancy is harmless and avoids an extra existence check round-trip.

---

## Positive Observations

- **Single-transaction verify-then-extend pattern.** The handler's transactional flow (advisory lock -> verify existing + new -> write -> commit/rollback) eliminates the TOCTOU window that round 1 flagged. The repair path also correctly re-verifies the entire post-truncation chain within the same transaction.

- **Clean separation of structural vs. authorization errors.** The verifier records `policy_satisfied = false` without returning an error, keeping structural failures (bad SAID, wrong prefix) as hard errors and authorization as a flag. The handler maps this cleanly to 403 vs 400/409.

- **Comprehensive test coverage for policy checker behavior.** The new tests (`RejectingChecker`, `RejectInceptionChecker`, evolving write_policy scenarios) cover the important edge cases — rejected inception, rejected advance, and the distinction between unchanged and evolved write_policy.

- **`AnchoredPolicyChecker` avoids code duplication across service boundaries.** A single implementation in `lib/policy` is used by both the handler and the library's identity chain module, preventing divergent policy evaluation logic.

- **Shell script anchoring is correct and thorough.** `load-sad.sh` anchors every version's SAID in the KEL before submission, matching the real authorization flow. This means the test script actually exercises the full policy evaluation path.
