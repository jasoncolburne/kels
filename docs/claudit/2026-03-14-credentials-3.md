# Branch Audit: Credentials (Round 3) — 2026-03-14

Third-pass audit of `credentials` branch changes vs `main`. Scope: full `git diff main` (~5K lines across 22 files). Focuses on issues not covered in rounds 1 and 2.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 3        |
| Low      | 0    | 3        |

---

## High Priority

### 1. `KelVerifier::from_branch_tip` doesn't preserve `delegating_prefix` — RESOLVED

**File:** `lib/kels/src/types/verifier.rs:124-145`

**Correction:** The original finding incorrectly identified `resume` as the problem. `resume` (line 168) correctly preserves `delegating_prefix` via `kel_verification.delegating_prefix().map(String::from)`. The actual gap was in `from_branch_tip` (line 135), which hardcoded `delegating_prefix: None`.

**Resolution:** Added `delegating_prefix: Option<String>` parameter to `from_branch_tip`. Existing callers in `merge.rs` and tests pass `None` (correct — they verify chain extension, not delegation). Callers that need delegation verification can now pass the appropriate value.

---

## Medium Priority

### 2. Public API should be JSON-in/JSON-out with separate storage — RESOLVED

**Resolution:** The `json_api` module now provides four JSON-boundary functions (`create`, `store`, `verify`, `disclose`). `Credential::create` no longer takes a store parameter; storage is explicit via `Credential::store()` or `json_api::store()`. `verify` takes credential JSON directly — no SAD store needed. The typed `Credential<T>` API remains public for Rust consumers. `impl SelfAddressed for serde_json::Value` in `verifiable-storage` enables `Credential<serde_json::Value>` for the JSON API path, eliminating parallel verification logic. The `verification.rs` module was removed; `CredentialVerification` and `Credential::verify()` now live in `credential.rs`.

### 3. `collect_anchors` double-fetches delegation edge credentials — RESOLVED

**Resolution:** The `collect_anchors` function and the edge-traversal verification logic were removed during the verification rewrite. Verification now operates on the credential as presented, without fetching edges from a SAD store.

### 4. `Compact` and `CompactRecursive` disclosure tokens are functionally identical — RESOLVED

**Resolution:** This is by design — bottom-up compaction is inherently recursive (must compact children to derive the parent SAID). Both tokens correctly delegate to `compact_at_path`. The distinction serves as documentation of intent in disclosure statements rather than behavioral difference.

---

## Low Priority

### 5. Schema validation silently skipped when either schema or claims is compacted — RESOLVED

**Resolution:** Replaced `schema_valid: Option<bool>` with `schema_validation: SchemaValidationResult` enum (`Valid`, `Invalid`, `NotValidated`). Callers now see an explicit `not-validated` in JSON output when schema/claims are compacted, distinguishing it clearly from `valid` and `invalid`. No silent skipping.

### 6. No integration tests for `Credential::verify` with actual KEL and store data — RESOLVED

**File:** `lib/kels-creds/src/credential.rs`

**Resolution:** Added 7 integration tests using `KeyEventBuilder<SoftwareKeyProvider>` with `FileKelStore` injected via `with_dependencies`. Tests cover: issued credential, unissued credential, revoked credential, irrevocable credential ignoring revocation hash, non-expired credential, schema validation on expanded credentials, and schema validation on compacted credentials. Added `Credential::issue()` method that compacts to the anchored SAID and calls `builder.interact()`, simplifying the issuance pattern. Verification now checks both expanded SAID integrity (data consistency) and compacted SAID (KEL anchoring).

### 7. `CredentialSchema` doesn't derive `PartialEq` — RESOLVED

**File:** `lib/kels-creds/src/schema.rs:54`

**Resolution:** Added `PartialEq` to `CredentialSchema`'s derive list, consistent with other types in the crate.

---

## Positive Observations

- **All round 1 and round 2 findings are resolved:** The codebase shows thorough follow-through on every prior audit item.
- **`delegating_prefix` plumbing through `KelVerifier` and `KelVerification` is complete:** Captured during inception, forwarded via `from_verification`, `resume`, and `from_branch_tip`, and exposed via accessor.
- **Credential issuance validation is comprehensive:** `Credential::create` validates schema structure, claims conformance, edge constraints, rule constraints, and expiration consistency before deriving SAIDs.
- **Compaction depth bounds are consistently applied:** Every call to `compact_value_bounded` and `expand_all_bounded` passes explicit depth limits. No unbounded recursion remains.
- **Domain-separated revocation hash is clean:** `Blake3(b"kels/revocation:" || said)` with CESR encoding.
- **Disclosure DSL is well-designed:** The token grammar is simple, the parser is robust (rejects empty segments, normalizes `*` → `.*`), and the apply function chains operations left-to-right.
- **`Compactable<T>` untagged serde with `Said(String)` first:** Correct ordering prevents deserialization ambiguity.
- **clippy deny lints for unwrap/expect/panic in non-test code:** Prevents accidental panics in library code.
- **Unified verification path:** `Credential::verify()` is the single implementation; the JSON API uses `Credential<serde_json::Value>` via `SelfAddressed` impl on `Value`, avoiding parallel logic.
- **Dual SAID verification in `verify()`:** Checks expanded SAID integrity (data hasn't been tampered with) and compacted SAID (used for KEL anchoring and revocation). Both must be consistent.
- **`Credential::issue()` encapsulates the anchoring pattern:** Compacts to the canonical SAID and anchors via the builder, preventing callers from accidentally anchoring the wrong SAID.
