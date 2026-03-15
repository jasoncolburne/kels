# Branch Audit: Credentials (Round 5) — 2026-03-14

Fifth-pass audit of `credentials` branch changes vs `main`. Scope: full `lib/kels-creds` crate (~3.5K lines across 12 source files). Focuses on correctness and usability issues not covered in rounds 1–4.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 4        |

---

## Medium Priority

### ~~1. `SchemaConstraint::Required(false)` is a silent no-op~~ — RESOLVED

**File:** `lib/kels-creds/src/schema.rs`

`SchemaConstraint` was removed entirely. Schema fields now use a simple `optional: bool` on `SchemaField`, eliminating the ambiguous `Required(false)` variant.

---

## Low Priority

### ~~2. `expand_all` performs unnecessary store lookups for non-SAID CESR strings~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs`

`expand_all_bounded` was removed. Schema-aware expansion (`expand_with_schema`) now only expands fields explicitly marked `compactable: true` in the schema, eliminating blind lookups on non-SAID CESR strings like issuer/subject prefixes.

### ~~3. All modules are `pub` instead of `pub(crate)`~~ — RESOLVED

**File:** `lib/kels-creds/src/lib.rs`

All modules changed to `pub(crate)`. Public API is now exclusively through `pub use` re-exports. Dead code surfaced by the change (`expand_field`, `navigate_to_parent`, and their tests) was removed.

### ~~4. `max_pages` for KEL verification is hardcoded to 1024~~ — RESOLVED

**File:** `lib/kels-creds/src/verification.rs`

Now uses `max_verification_pages()` from the `kels` crate (defaults to 512, configurable via `KELS_MAX_VERIFICATION_PAGES` env var).

### ~~5. `compact()` is called redundantly across `create`, `issue`, and `store`~~ — WONTFIX

**Files:** `lib/kels-creds/src/credential.rs`

`issue` and `store` are convenience methods. Optimizing them to accept a pre-computed SAID would collapse them into the raw KELS API, defeating their purpose. The redundant compaction is cheap deterministic CPU work, not I/O.

---

## Positive Observations

- **All 37 findings from rounds 1–4 are resolved.** The codebase is in good shape after four iterations.
- **SAID integrity is verified at two levels.** `verify_credential` checks both the expanded SAID (data integrity) and the compacted SAID (KEL anchoring). This dual-check design is sound and well-implemented.
- **KEL errors are soft failures.** `verify_credential` returns `Ok(CredentialVerification)` with `kel_error` populated rather than `Err(...)`, allowing partial verification results. `is_valid()` aggregates all checks. This is a good API design for graduated trust decisions.
- **The `Compactable<T>` untagged enum correctly handles the `serde_json::Value` case.** With `Said(String)` listed first, `#[serde(untagged)]` tries string deserialization first, so SAID strings deserialize as `Said` and objects as `Expanded`. This works correctly for all current usage patterns.
- **Schema validation is thorough and well-bounded.** All recursive validation paths (schema fields, claims, edges, rules) use `MAX_RECURSION_DEPTH`. The closed-schema model (reject unknown fields) is appropriate for verifiable credentials.
- **Edge and rule label validation is consistent.** Both `Edges` and `Rules` reject `"said"` as a label at three points: `new_validated()`, `TryFrom<Raw*>` (deserialization), and schema-level validation. This defense-in-depth prevents `#[serde(flatten)]` collision.
- **The disclosure DSL is clean and well-tested.** The parse/apply split, left-to-right token application starting from compacted form, and the compact-always-children-first invariant produce correct results for all tested scenarios.
- **Test coverage is excellent.** Integration tests with real `KeyEventBuilder` and `FileKelStore` cover issuance, non-issuance, revocation, irrevocable credentials, expiration, schema validation, and three-level credential chains with edge verification.
