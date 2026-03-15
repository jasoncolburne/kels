# Branch Audit: Credentials (Round 5) — 2026-03-14

Fifth-pass audit of `credentials` branch changes vs `main`. Scope: full `lib/kels-creds` crate (~3.5K lines across 12 source files). Focuses on correctness and usability issues not covered in rounds 1–4.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 1    | 0        |
| Low      | 4    | 0        |

---

## Medium Priority

### 1. `SchemaConstraint::Required(false)` is a silent no-op

**File:** `lib/kels-creds/src/schema.rs:370-383`

`SchemaConstraint` is an untagged enum with variants `Required(bool)` and `Value(String)`. In edge validation, `Required(true)` means "field must be present" and `Value(v)` means "field must equal v". But `Required(false)` falls through to the `_ => {}` wildcard and has no effect — it's identical to omitting the constraint entirely.

A schema author writing `"issuer": false` might expect it to mean "issuer must NOT be present", but it silently does nothing. There's no way to express "field must be absent" in the current schema constraint model.

**Suggested fix:** Either:
- Document that `false` is equivalent to omitting the field (no constraint).
- Make `Required(false)` mean "must be absent" and add a validation check.
- Remove `Required(bool)` in favor of just `Required` (unit variant) and `Value(String)`, since `false` has no use. This would reject `false` at the deserialization level.

---

## Low Priority

### 2. `expand_all` performs unnecessary store lookups for non-SAID CESR strings

**File:** `lib/kels-creds/src/compaction.rs:130-172`

`expand_all_bounded` looks up any string value passing `could_be_said()` (44-char, starts with `E`, URL-safe base64) in the SAD store, exempting only `key == "said"`. Fields like `issuer` and `subject` contain CESR-encoded prefixes that match this format, triggering store lookups that always return empty (prefixes aren't stored as chunk keys). No incorrect behavior results — the fields are left unchanged — but each 44-char CESR string incurs a wasted store round-trip.

### 3. All modules are `pub` instead of `pub(crate)`

**File:** `lib/kels-creds/src/lib.rs:6-16`

All 10 modules are declared `pub mod`, but the public API is defined through `pub use` re-exports at lines 18–30. This means downstream consumers can also access internal helpers via paths like `kels_creds::schema::validate_schema` or `kels_creds::compaction::compact`. Functions like `validate_schema`, `validate_claims`, `validate_edges`, `validate_rules`, `validate_expiration`, and `validate_credential_report` are correctly marked `pub(crate)`, but the module visibility exposes them anyway.

Per prior feedback on encapsulation: modules that only export items through re-exports should be `pub(crate)`.

### 4. `max_pages` for KEL verification is hardcoded to 1024

**File:** `lib/kels-creds/src/verification.rs:149-156`

```rust
verify_key_events(
    &credential.issuer,
    source,
    verifier,
    MAX_EVENTS_PER_KEL_QUERY,
    1024,  // hardcoded
)
```

This limits verification to 512 × 1024 = 524K events. While sufficient for most use cases, very long-lived KELs could exceed this. The value isn't configurable and isn't documented.

### 5. `compact()` is called redundantly across `create`, `issue`, and `store`

**Files:** `lib/kels-creds/src/credential.rs:115, 132, 147-158`

- `Credential::create` calls `compact()` during the compact/expand SAID derivation cycle (line 115).
- `Credential::issue` calls `compact()` to get the SAID for KEL anchoring (line 132).
- `Credential::store` calls `compact()` to get chunks for the SAD store (line 147).

Each call re-serializes to JSON and re-runs `compact_value_bounded`. A typical flow of `create → issue → store` performs three full compactions. Since compaction is deterministic and the credential is immutable after creation, the compacted SAID and chunks from `create` could be cached or returned for reuse.

The `create` method already returns the compacted SAID, which `issue` and `store` could accept as a parameter to avoid recomputation.

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
