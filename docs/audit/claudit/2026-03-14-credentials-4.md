# Branch Audit: Credentials (Round 4) — 2026-03-14

Fourth-pass audit of `credentials` branch changes vs `main`. Scope: full `git diff main` (~5.5K lines across 24 files). Focuses on issues not covered in rounds 1–3.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. Schema validation has no depth limit (DoS via deeply nested schema)~~ — RESOLVED

**Files:** `lib/kels-creds/src/schema.rs:109-157, 279-414`

~~`validate_schema_fields` and `validate_field` recurse through `SchemaField::Object` and `SchemaField::Array` without any depth bound. Compaction and expansion are bounded by `MAX_RECURSION_DEPTH = 32`, but schema validation is not. A maliciously crafted schema with thousands of nested `Object` or `Array` layers would cause stack overflow during `validate_schema()` or `validate_claims()`.~~

**Resolution:** Added `remaining_depth` parameter to `validate_schema_fields`, `validate_schema_array_fields`, `validate_object_fields`, and `validate_field`. All use `MAX_RECURSION_DEPTH` (formerly `MAX_EXPANSION_DEPTH`) as the starting depth. Two tests added: one for schema validation depth and one for claims validation depth.

As part of this fix, the three depth-limit constants (`MAX_EXPANSION_DEPTH`, `MAX_COMPACTION_DEPTH`, `MAX_CREDENTIAL_DEPTH`) were consolidated into a single `MAX_RECURSION_DEPTH = 32` in `compaction.rs`, used by all recursive operations (compaction, expansion, schema validation, claims validation). `MAX_COMPACTION_DEPTH` remains in `verifiable-storage` as the upstream default (not used by kels-creds).

### ~~2. `json_api::create` duplicates expiry/schema validation with `Credential::create`~~ — RESOLVED

**Files:** `lib/kels-creds/src/json_api.rs:61-132`, `lib/kels-creds/src/credential.rs:110-133`

~~`json_api::create()` validates the schema, claims, edges, rules, and expiration, then manually builds a `serde_json::Value` credential. `Credential::create()` performs the same validations. Since `json_api::create` doesn't call `Credential::create` (it builds a `Value` directly), the two paths must be kept in sync manually. If a validation rule is added to `Credential::create` but not `json_api::create` (or vice versa), the paths diverge.~~

**Resolution:** Extracted `validate_credential()` in `schema.rs` — a single `pub(crate)` function that validates schema, claims, edges, rules, and expiration. Both `Credential::create` and `json_api::create` now call it. Validation functions are `pub(crate)` (not exported); consumers use `verify_credential` / `Credential::verify()` for trust decisions. Verification logic moved to `verification.rs` with a public `verify_credential` function.

---

## Low Priority

### ~~3. `compact_children` name is misleading~~ — RESOLVED

**File:** `lib/kels-creds/src/disclosure.rs:200-215`

~~`compact_children` fully compacts the value (including root) to a SAID string, then retrieves the root object from the accumulator and replaces `value` with it. The result is the root object with all children compacted to SAIDs, but the root itself is expanded. The function name suggests it only compacts children, which is what it does, but the implementation roundtrips through full compaction — if the value has no `said` field, this would fail silently or error. A comment clarifying the intent would help.~~

**Resolution:** Added doc comment explaining the roundtrip mechanism: full compaction then restore from accumulator.

### ~~4. `revocation.rs` doc comment does not mention domain separation~~ — RESOLVED

**File:** `lib/kels-creds/src/revocation.rs:3-4`

~~The doc comment says `revocation_hash = Blake3(credential_said.as_bytes()).qb64()` but the implementation uses `Blake3(b"kels/revocation:" || credential_said.as_bytes())`. The comment is stale from before domain separation was added.~~

**Resolution:** Updated doc comment to show the domain-separated formula.

### ~~5. `store_credentials` clones each input value~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs:33-44`

~~`store_credentials` takes `&[serde_json::Value]` but immediately clones each value (line 39: `let mut value = value.clone()`). Since `compact` mutates in place, the clone is necessary, but the function could take `Vec<serde_json::Value>` by value to let callers avoid the clone when they don't need the originals.~~

**Resolution:** Changed signature from `&[serde_json::Value]` to `Vec<serde_json::Value>`, compacting in place without cloning.

---

## Positive Observations

- **All 32 findings from rounds 1–3 are resolved.** The codebase reflects thorough iteration on every prior audit item.
- **Unified depth constant.** `MAX_RECURSION_DEPTH = 32` is now the single depth limit for compaction, expansion, schema validation, and claims validation. No more juggling `MAX_EXPANSION_DEPTH`, `MAX_COMPACTION_DEPTH`, and `MAX_CREDENTIAL_DEPTH`.
- **Integration tests are solid.** Seven integration tests with real `KeyEventBuilder` and `FileKelStore` cover issuance, non-issuance, revocation, irrevocable credentials, expiration, and schema validation at both expanded and compacted levels.
- **`delegating_prefix` plumbing through `KelVerifier` is complete and correct.** The field is captured during `dip` inception (verifier.rs:428), preserved through `resume` (verifier.rs:172), `from_branch_tip` (verifier.rs:139), and `into_verification` (verifier.rs:249), and exposed via accessor. All existing callers pass `None` appropriately.
- **`KelVerification` is now `SelfAddressed`.** The verification token itself has a SAID and includes `delegating_prefix`, making it a complete proof of verification state.
- **Clippy lints remain strict.** `unwrap_used`, `expect_used`, `panic`, and `unwrap_in_result` are denied outside tests across the crate.
- **`deny.toml` is properly configured.** License allowlist is sensible, git sources are restricted to `github = ["jasoncolburne"]`, and advisory database is checked.
- **`preserve_order` on `serde_json` is correctly enabled** in `Cargo.toml`, ensuring deterministic SAID derivation from `serde_json::Map`.
- **Verification checks both expanded and compacted SAIDs.** `Credential::verify()` recomputes the expanded SAID for data integrity and the compacted SAID for KEL anchoring — both must be consistent.
- **Batch expansion via `get_chunks` is consistently used.** The two-pass pattern (collect candidates, batch fetch, expand) in `expand_all_bounded` avoids N+1 store lookups.
- **The disclosure DSL is well-tested.** Parser tests cover all token variants, normalization (`*` → `.*`), error cases (empty segments, bare `-`), and the apply tests cover full expansion, selective expansion, expand-then-compact roundtrips, and nested recursive disclosure.
