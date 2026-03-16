# Branch Audit: Credentials (Round 8) — 2026-03-16

Eighth-pass audit of `credentials` branch changes vs `main`. Scope: full `lib/kels-creds` crate (~4.7K lines across 12 source files) plus changes to `lib/kels` and `clients/kels-cli`. Diff: ~7.3K lines across 32 files. Focus: atomic issuance refactor (`create`/`issue` merge), json_api surface reduction, security invariant enforcement.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 1    | 0        |
| Low      | 1    | 0        |

All 49 findings from rounds 1–7 remain resolved.

---

## Medium Priority

### 1. Doc comment overstates construction restriction

**File:** `lib/kels-creds/src/credential.rs:54`

The struct doc says "The only public way to create a credential is `Credential::issue()`" but all fields on `Credential<T>` are `pub`, allowing struct literal construction or manual `Deserialize` from arbitrary JSON. The security invariant (can't *anchor* uninspected content) holds regardless — `issue()` takes expanded types by value, not `&self`, so the type system prevents issuing compacted credentials. But the doc claim is technically incorrect and could mislead auditors into thinking construction is gated.

**Suggested fix:** Change "The only public way to create a credential" to "The only public way to issue a credential" (or "create and anchor"). The distinction between construction (for verification/disclosure of received credentials) and issuance (anchoring in a KEL) is the actual security boundary.

---

## Low Priority

### 2. No explicit test demonstrating the closed attack vector

**File:** `lib/kels-creds/src/credential.rs`

The round 8 refactor eliminated the vulnerability where a compacted credential could be issued via the old `cred.issue(&schema, &mut builder)` API. The new `Credential::issue()` takes expanded types directly, making this impossible by construction. However, there is no test that explicitly documents this closed attack vector — e.g., a comment in the test suite noting why the old `test_verify_schema_validation_compacted` test no longer issues the compacted credential, or a doc-test showing the type system prevents it.

**Suggested fix:** Add a brief comment in the test suite (e.g., near `test_verify_schema_validation_compacted`) explaining that the test previously issued a compacted credential to test schema validation, and that the API now prevents this by taking expanded types directly. This documents the security decision for future auditors.

---

## Positive Observations

- **Atomic issuance is a material security improvement.** Merging `create()` and `issue()` into a single `issue()` that takes expanded types by value eliminates an entire class of attacks (signing uninspected compacted content). The type system enforces the invariant at compile time — no runtime checks needed.
- **The `build()` / `issue()` split is clean.** `build()` as `pub(crate)` gives tests and the json_api access to credential construction without exposing it publicly. `issue()` is the only public entry point for issuance. The separation is the minimum needed.
- **json_api surface reduction is well-motivated.** Removing `create()` from the JSON API eliminates the impedance mismatch of passing `KeyEventBuilder` through a string-based interface. Keeping `parse_edges`/`parse_rules` as public exports prepares for FFI without dead code.
- **The disclosure.rs clippy fixes (let-chain collapse, `?` operator)** follow the project's stated preference for collapsing nested conditionals and are strictly improvements.
- **Test coverage remains comprehensive after the refactor.** All integration tests (issuance, revocation, irrevocable, expiration, schema validation at both expanded/compacted levels, two-level chains, three-level chains) now use the atomic `issue()` path. The `test_verify_schema_validation_compacted` test was correctly rewritten to issue via expanded form and verify the compacted form — testing the same thing without the vulnerability.
- **The design doc update accurately reflects the new API.** The issuance flow section now documents the security rationale, the atomic operation, and the absence of `create()` from the JSON API.
