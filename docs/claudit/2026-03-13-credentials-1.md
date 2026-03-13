# Branch Audit: Credentials — 2026-03-13

Automated audit of `credentials` branch changes vs `main`. Scope: full `git diff main` (~3.8K lines). Focus: correctness, security, performance, and API design.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 3        |
| Low      | 0    | 4        |

---

## High Priority

### ~~1. No cycle detection in credential graph traversal~~ — RESOLVED

**Files:** `lib/kels-creds/src/verification.rs`

~~Both `collect_anchors` and `verify_credential` recurse through edge credentials without tracking visited SAIDs. A malicious or buggy credential graph with circular edge references (credential A edges to B, B edges to A) would cause infinite recursion and stack overflow.~~

**Resolution:** `collect_anchors` now takes a `visited: HashSet<String>` parameter. Each credential SAID is inserted before traversal; if the SAID is already present, a `VerificationError("circular edge reference detected")` is returned.

### ~~2. No depth limit on recursive operations~~ — RESOLVED

**Files:** `lib/kels-creds/src/compaction.rs`, `lib/kels-creds/src/verification.rs`

~~All recursive traversals (`expand_all`, `collect_anchors`, `verify_credential`) have no depth bound. A deeply nested credential graph or deeply nested SelfAddressed JSON structure could exhaust the stack. Even without cycles, a linear chain of 1000+ edge credentials would be problematic.~~

**Resolution:** Added `MAX_EXPANSION_DEPTH = 32` for `expand_all` (via internal `expand_all_bounded`) and `MAX_CREDENTIAL_DEPTH = 32` for `collect_anchors` and `build_verification`. All recursive functions decrement a `remaining_depth` counter and error at 0.

---

## Medium Priority

### ~~3. Non-recursive `compact_at_path` produces incorrect SAID for partially-expanded objects~~ — RESOLVED

**File:** `lib/kels-creds/src/disclosure.rs`

~~When `recursive=false`, `compact_at_path` calls `compute_said_from_value(child)` on the current state of the child, which may have some nested children expanded and others compacted. The SAID is computed over this mixed state, which differs from the canonical SAID (computed over the fully-compacted form). The resulting SAID won't match what the credential expects.~~

**Resolution:** `compact_at_path` now always calls `compact_value` (which compacts children depth-first before the parent), regardless of the `Compact` vs `CompactRecursive` token variant. The `recursive` parameter was removed since both variants produce the same result at the target field level. The `Compact` and `CompactRecursive` token variants are now merged in the match arm. A test was added verifying that non-recursive expand of `claims` then `claims.address` leaves a deeper `included` object (which has a `said`) as a compacted string.

### ~~4. Batch KEL verification not reused for edge credentials~~ — RESOLVED

**File:** `lib/kels-creds/src/verification.rs`

~~Phase 1-2 collects all credential anchors and batch-verifies KELs per issuer. But at line 262, `verify_credential(edge_said, ...)` is called recursively for each edge, which triggers an entirely new phase 1-2 for the edge credential's graph. The initial batch verification is wasted for edges — the recursive call doesn't reuse those results.~~

**Resolution:** `build_verification` now recurses into itself for edge credentials, passing the shared `kel_verifications` map through. Each issuer's KEL is verified exactly once in phase 2, and the results are reused for all edge credential checks. The `kel_store` parameter was removed from `build_verification` since it's no longer needed (KEL verification only happens in phase 2).

### ~~5. `expand_all` expands any string value that resolves in the SADStore~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs`

~~`expand_all` looks up every string value (except `"said"` keys) in the SADStore and replaces it if found. If the store contains an entry whose key happens to match a regular string field value, that field would be incorrectly expanded.~~

**Resolution:** Added `could_be_said()` check before store lookups — verifies the string is exactly 44 characters of URL-safe base64 (`[A-Za-z0-9\-_]`). Strings that can't be CESR SAIDs are skipped entirely, providing both defense-in-depth and a performance improvement.

---

## Low Priority

### ~~6. Unused `blake3` direct dependency~~ — RESOLVED

**File:** `lib/kels-creds/Cargo.toml`

~~`blake3 = "1.5"` is listed as a dependency but never imported or used directly in any source file. The revocation hash uses `cesr::Digest::blake3_256` which has its own blake3 dependency.~~

**Resolution:** Removed the unused `blake3` dependency from `Cargo.toml`.

### ~~7. Schema validation allows extra fields in claims~~ — RESOLVED

**File:** `lib/kels-creds/src/schema.rs`

~~`validate_claims` checks that all schema-defined fields exist in claims with correct types, but does not reject extra fields present in claims that are not in the schema. Whether this is intentional (open schema) or a gap (closed schema) is ambiguous.~~

**Resolution:** Implemented closed schema validation. `said` is a reserved field name that cannot appear in schema definitions (enforced by `validate_schema`). For compactable objects, `said` is implicitly required when expanded and the object can appear as a SAID string when compacted. Non-compactable objects reject `said` (caught by the extra-fields check). `validate_object_fields` enforces: all schema fields present and correctly typed, `said` required on compactable objects, and no extra fields beyond what the schema defines (plus `said` for compactable objects).

### ~~8. `InMemorySADStore` uses `Mutex` instead of `RwLock`~~ — RESOLVED

**File:** `lib/kels-creds/src/store.rs`

~~Read operations (`get_chunks`) are serialized unnecessarily behind a `Mutex`.~~

**Resolution:** Switched to `RwLock`. `store_chunks` uses `.write()`, `get_chunks` uses `.read()`, allowing concurrent reads.

### ~~9. `KelStore` import change in kels-cli~~ — RESOLVED

**File:** `clients/kels-cli/src/main.rs:11`

~~`KelStore` was moved from the non-cfg-gated import to the `#[cfg(feature = "dev-tools")]` import. This means `KelStore` is only available when the `dev-tools` feature is enabled. If any non-dev-tools code path uses `KelStore`, this would break compilation without the feature flag.~~

**Resolution:** Verified intentional. `KelStore` and `EventKind` are only used in `#[cfg(feature = "dev-tools")]` code paths. The crate compiles cleanly without the feature flag.

---

## Positive Observations

- **SAID-as-canonical-form invariant is well-designed:** The compaction model where every SAID is computed over the fully-compacted form of its children creates a Merkle-like tree where each node is independently verifiable. This is cryptographically sound.
- **Disclosure DSL is clean and FFI-friendly:** Using a plain string expression (`const char*`) for the disclosure path avoids structured types crossing the FFI boundary. The grammar is simple enough to be unambiguous.
- **Revocation via KEL anchoring is elegant:** No separate revocation registry — just anchor `Blake3(credential_said)` in the issuer's KEL. The `irrevocable` flag is covered by the credential's SAID, preventing post-hoc claims of irrevocability.
- **`Compactable<T>` untagged serde ordering is correct:** `Said(String)` comes first, so JSON strings deserialize as SAIDs and objects try to deserialize as `T`. Since `T: Claims` requires `SelfAddressed` (a struct), there's no ambiguity.
- **Reserved label validation on Edges/Rules:** Both `Edges::new_validated` and `Rules::new_validated` reject `"said"` as a label, preventing collision with the `#[serde(flatten)]` SAID field. This is a subtle correctness concern handled well.
- **`KelVerification::delegating_prefix()` accessor is properly wired:** The new field flows through `KelVerifier` inception processing, is preserved across `from_verification` reconstruction, and propagates through `into_verification`. The `#[crate_new]` derive handles the constructor update.
- **Type-level compaction via `Compactable<T>`** solves the generic claims problem elegantly — you can't swap a generic `T` for a `String` at the type level without an enum wrapper, and `#[serde(untagged)]` makes serialization transparent.
- **KERI comparison document** (`docs/keri-comparison.md`) is thorough and honest about KELS's tradeoffs vs KERI's design choices, covering security properties, post-quantum considerations, and deployment models.
- **Clippy lints are strict:** `unwrap_used`, `expect_used`, `panic`, and `unwrap_in_result` are all denied outside of tests, enforcing proper error handling.
