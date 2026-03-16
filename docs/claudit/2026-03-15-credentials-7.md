# Branch Audit: Credentials (Round 7) — 2026-03-15

Seventh-pass audit of `credentials` branch changes vs `main`. Scope: full `lib/kels-creds` crate (~4.7K lines across 12 source files) plus changes to `lib/kels` and `clients/kels-cli`. Diff: ~7.2K lines across 30 files. Focus: edge cases in schema-aware operations, verification completeness, API surface consistency.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

All 45 findings from rounds 1–6 remain resolved.

---

## Medium Priority

### ~~1. `resolve_schema_fields_at_path` does not handle array segments~~ — RESOLVED

**File:** `lib/kels-creds/src/disclosure.rs:175-199`

~~`resolve_schema_fields_at_path` navigates the schema tree by looking up each path segment in the `fields` map of the current `SchemaField::Object`. It does not handle the case where a segment's field is `SchemaFieldType::Array` — if the path crosses through an array-typed field (e.g., `items.0.name`), `field.fields` is `None` for arrays (array schemas use `field.items` instead), so the function returns `None` and schema-aware recursive expansion silently falls back to no expansion.~~

**Resolution:** `resolve_schema_fields_at_path` now resolves child fields from either `field.fields` (Object) or `field.items.fields` (Array element schema), using `or_else` to try both. A test (`test_apply_disclosure_expand_recursive_through_array`) verifies that `ExpandRecursive` correctly traverses through array-typed fields and expands nested compactable objects within array elements.

### ~~2. Disclosure constructs fake schemas for sub-tree operations~~ — RESOLVED

**Files:** `lib/kels-creds/src/disclosure.rs:153-160,244-252`, `lib/kels-creds/src/compaction.rs:18-35,135-157`

~~`compact_at_path` and the `ExpandRecursive` handler constructed temporary `Schema { said: String::new(), ... }` objects to pass to `compact_with_schema`/`expand_with_schema` when operating on sub-trees. While currently correct (SAIDs are derived from object content, not schema metadata), this pattern would break if those functions ever validated the schema itself.~~

**Resolution:** Added `compact_with_fields` and `expand_with_fields` functions that take `&BTreeMap<String, SchemaField>` directly instead of `&Schema`. The existing `compact_with_schema`/`expand_with_schema` are now thin wrappers. Disclosure uses the `_fields` variants for sub-tree operations, eliminating all fake schema construction.

---

## Low Priority

### ~~3. `json_api::create` sorts claims keys but typed `Credential::create` does not~~ — RESOLVED

**File:** `lib/kels-creds/src/json_api.rs:65-70`

~~`json_api::create` manually sorted claims keys before building the `serde_json::Value`, but the typed `Credential::create` did not. The two paths could produce different SAIDs for the same logical claims.~~

**Resolution:** Removed the manual key sorting from `json_api::create`. Field order is determined by schema order (via `preserve_order` on `serde_json`), not by sorting — both API paths now behave identically. Removed the `test_create_claims_field_order_independent` test whose premise (order-independent SAIDs) was based on the sorting behavior.

### ~~4. `validate_schema` not exported~~ — RESOLVED

**Files:** `lib/kels-creds/src/schema.rs:240`, `lib/kels-creds/src/lib.rs:24-27`

~~`validate_schema` was `pub(crate)` and not re-exported. External consumers could create schemas but not independently validate them before use in credential creation.~~

**Resolution:** Changed `validate_schema` from `pub(crate)` to `pub` and added it to the `pub use schema::{...}` re-exports in `lib.rs`.

---

## Positive Observations

- **All 45 findings from rounds 1–6 are resolved.** The codebase has been through thorough iterative refinement across seven audit rounds.
- **Schema-aware compaction/expansion is architecturally clean.** Walking the schema alongside the value ensures only intended fields are compacted, and the batch-fetch pattern in `expand_object_with_schema` avoids N+1 store lookups. The separation of concerns between compaction (schema-driven field selection) and SAID derivation (content-based hashing) is well-maintained.
- **Edge verification is comprehensive.** The `verify_edges` function enforces issuer constraints, schema constraints, delegation constraints (dip inception + delegating prefix anchoring), and recursively verifies the full edge credential chain with proper depth bounding.
- **The `delegating_prefix` plumbing through `KelVerifier` is complete.** Captured during `dip` inception (verifier.rs:428), preserved through `resume` (verifier.rs:172), `from_branch_tip` (verifier.rs:139), and `into_verification` (verifier.rs:249). All existing callers pass `None` appropriately when delegation is not relevant.
- **The disclosure DSL is well-tested and robust.** Parser tests cover all token variants, normalization, and error cases. Apply tests cover full expansion, selective expansion, expand-then-compact roundtrips, nested recursive disclosure, and non-compactable object traversal.
- **Test coverage is excellent.** Integration tests with real `KeyEventBuilder` and `FileKelStore` cover issuance, non-issuance, revocation, irrevocable credentials, expiration, schema validation at both expanded and compacted levels, two-level credential chains, and three-level credential chains with recursive edge verification.
