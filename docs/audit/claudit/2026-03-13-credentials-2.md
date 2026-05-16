# Branch Audit: Credentials (Round 2) — 2026-03-13

Second-pass audit of `credentials` branch changes vs `main`. Scope: full `git diff main` (~4.2K lines across 20 files). Focuses on issues not covered in the first audit round.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 6        |
| Low      | 0    | 9        |

---

## High Priority

### ~~1. `validate_schema` and `validate_claims` are never called during credential creation~~ — RESOLVED

**Files:** `lib/kels-creds/src/credential.rs:66-96`, `lib/kels-creds/src/schema.rs:40-42`

~~`Credential::create()` derives SAIDs and compacts, but never validates the schema or claims. A caller can create a schema with `said` as a field name or create a credential where claims don't match the schema at all.~~

**Resolution:** `Credential::create()` now calls `validate_schema(&schema)` and `validate_claims(&schema, &serde_json::to_value(&claims)?)` before deriving SAIDs. Schema and claims validation is mandatory at issuance time.

### ~~1a. `Credential::create` copied the compacted SAID onto the expanded credential~~ — RESOLVED

**File:** `lib/kels-creds/src/credential.rs:95`

`Credential::create` set `credential.said = compacted.said` — putting the compacted form's SAID on the expanded credential. This violates the self-addressing invariant: every form's `said` must match a SAID derived over that form's own content. The expanded and compacted forms have different content and therefore different SAIDs.

**Resolution:** `compact()` now returns `(expanded_said, compacted_said, chunks)`. The expanded credential gets the SAID derived over the expanded content. The compacted SAID is returned separately for KEL anchoring. Tests updated to verify the two SAIDs differ.

---

## Medium Priority

### ~~2. Direct deserialization of `Edges`/`Rules` bypasses reserved label validation~~ — RESOLVED

**Files:** `lib/kels-creds/src/edge.rs:22-28`, `lib/kels-creds/src/rule.rs:16-22`

~~`Edges` and `Rules` use `#[serde(flatten)]` on a `BTreeMap<String, Edge/Rule>` alongside a `said: String` field. The `validate_labels` check (rejecting `"said"` as a label) only runs in `new_validated()`, not during `serde_json::from_str::<Edges>(...)`. Any code path that deserializes `Edges` or `Rules` from untrusted JSON without going through `new_validated` bypasses the reserved label guard.~~

**Resolution:** Both `Edges` and `Rules` now use custom `Deserialize` impls via `RawEdges`/`RawRules` intermediaries with `TryFrom` conversion that calls `validate_labels` during deserialization. Tests verify the guard rejects reserved labels on both the `TryFrom` and `new_validated` paths.

### ~~3. Silent KEL verification failure masks integrity issues~~ — RESOLVED

**File:** `lib/kels-creds/src/verification.rs:105-117`

~~When `verify_key_events` fails (corrupted KEL, invalid signatures), the error is silently swallowed. The credential is reported as `is_issued: false, is_revoked: false`. The caller cannot distinguish "issuer has no KEL" from "issuer's KEL is cryptographically invalid." This fails secure (credential is not trusted) but obscures potentially serious integrity problems.~~

**Resolution:** Added `kel_error: Option<KelsError>` field to `CredentialVerification`. KEL verification failures are now captured per-issuer and surfaced on each credential whose issuer had a failure. Uses typed `KelsError` rather than strings for programmatic error handling.

### ~~4. `compact` and `expand_all` are not inverse operations at the root level~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs:23-29, 95-100`

~~After `compact(&mut value)`, `value` is a SAID string. Calling `expand_all(&mut value, store)` on that string does nothing — `expand_all` only processes objects and arrays, not root-level strings. The caller must manually look up the root SAID in the store before calling `expand_all`. Handled correctly in `apply_disclosure` but undocumented.~~

**Resolution:** `expand_all` now handles root-level SAID strings — if the value is a string that could be a SAID, it looks it up in the store, replaces the value, and recurses. `compact` and `expand_all` are now true inverses.

### ~~5. `SchemaField::Float` validation rejects integer literals~~ — RESOLVED

**File:** `lib/kels-creds/src/schema.rs:159-163`

~~`value.is_f64()` returns `false` for JSON integers in serde_json — `42` is stored as `i64`, not `f64`. So a schema field typed `Float` rejects `{"score": 42}` but accepts `{"score": 42.0}`. These are semantically identical in JSON but serde_json distinguishes them internally.~~

**Resolution:** Float validation now accepts `is_f64() || is_i64() || is_u64()`, so integer literals pass validation for float-typed fields.

### ~~6. `compact_value` (upstream) has no depth bound~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs:27` (calls into `verifiable-storage`)

~~`expand_all` is depth-bounded (`MAX_EXPANSION_DEPTH = 32`), but `compact_value` from verifiable-storage uses unbounded recursion. A sufficiently deep JSON input could cause a stack overflow during compaction.~~

**Resolution:** Added `compact_value_bounded` and `MAX_COMPACTION_DEPTH` to verifiable-storage. All kels-creds call sites now use `compact_value_bounded` with their own depth constants (`MAX_EXPANSION_DEPTH` or `remaining_depth` when already recursing), so upstream changes to the default cannot alter our behavior.

### ~~7. `expand_at_path` does not verify SAID integrity on expansion~~ — NOT A CONCERN

**File:** `lib/kels-creds/src/disclosure.rs:153-158`

~~When expanding at a path, the code fetches from the SAD store by SAID and inserts the result without verifying that the returned value's computed SAID matches the key.~~

Not a concern. SAID integrity is verified during credential verification (`build_verification` compacts to canonical form and checks the SAID). Disclosure is a data-shaping operation — consumers must verify credentials before trusting them regardless.

---

## Low Priority

### ~~8. Design doc `SchemaField::Object` is outdated~~ — RESOLVED

**File:** `docs/design/kels-creds.md:63-72`

~~The design doc shows `Object(BTreeMap<String, SchemaField>)` but the implementation now uses `Object { fields, compactable }`. The design doc also doesn't mention closed-schema validation, `validate_schema()`, the `said` reserved field name rule, `MAX_EXPANSION_DEPTH`, or `MAX_CREDENTIAL_DEPTH`.~~

**Resolution:** Complete rewrite of the design doc to match the current implementation. Updated: `SchemaField::Object` with `compactable`, `CredentialSchema` with `expires`/`edges`/`rules`, `SchemaEdge`/`SchemaRule` types, `Credential` with `expires_at`, `CredentialVerification` with `is_expired`/`kel_error`, `camelCase` serialization, `FromStr` impls, depth bounds, deserialization guards, domain-separated revocation hash, batch expansion, SAID recomputation on expansion, full delegation verification, and all four validation functions.

### ~~9. `Credential::create` returns the SAID redundantly~~ — NOT A CONCERN

**File:** `lib/kels-creds/src/credential.rs:97`

Not redundant. The canonical SAID is derived from the compacted form. The expanded credential cannot produce it without re-compacting. The separate SAID return is the only way to get it directly.

### ~~10. `could_be_said()` is broader than necessary~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs:14-18`

~~Matches any 44-character URL-safe base64 string. CESR SAIDs have specific prefix characters (e.g., `E` for Blake3-256). A tighter check would reduce false-positive store lookups. Currently harmless — store misses return `None`.~~

**Resolution:** `could_be_said()` now requires the `E` prefix (Blake3-256 digest code) in addition to length and character checks.

### ~~11. `expand_all` makes sequential store lookups instead of batching~~ — RESOLVED

**File:** `lib/kels-creds/src/compaction.rs:120-130`

~~Each candidate SAID triggers an individual `get_chunk()` call. The `SADStore` trait already exposes `get_chunks()` for batch retrieval. A two-pass approach (collect, batch-fetch, expand) would be more efficient for network-backed stores.~~

**Resolution:** `expand_all_bounded` now uses a two-pass approach for both objects and arrays: pass 1 collects all candidate SAIDs, batch-fetches via `get_chunks()`, then pass 2 expands and recurses.

### ~~12. `std::sync::RwLock` in async context~~ — RESOLVED

**File:** `lib/kels-creds/src/store.rs:2, 34-36`

~~`InMemorySADStore` uses `std::sync::RwLock` inside an `async_trait`. Currently safe (no `.await` while lock held) but fragile for future changes. Acceptable for tests/CLI.~~

**Resolution:** Switched to `tokio::sync::RwLock`. Added `tokio` (sync feature) as a regular dependency.

### ~~13. `Edges::new_validated` assumes inner edges already have SAIDs derived~~ — RESOLVED

**File:** `lib/kels-creds/src/edge.rs:44-52`

~~`new_validated()` calls `derive_said()` on itself but trusts that each `Edge` in the map already has its SAID derived. Same pattern in `Rules::new_validated()`.~~

**Resolution:** Both `Edges::new_validated` and `Rules::new_validated` now call `derive_said()` on each inner item before deriving the container's SAID.

### ~~14. Delegation verification result is not surfaced to callers~~ — RESOLVED

**File:** `lib/kels-creds/src/verification.rs:347-362`

~~The delegation check verifies `KelVerification.delegating_prefix()` matches, but per CLAUDE.md "Delegation trust is NOT verified by the KELS service." The `delegating_prefix()` returns whatever was in the `dip` event, which is unverified by KELS. The `CredentialVerification` struct has no field indicating delegation trust was claimed-not-verified, so callers cannot distinguish verified from unverified delegation.~~

**Resolution:** Delegation is now fully verified in `kels-creds`. The delegating prefix's KEL is verified and checked for anchoring of the delegated prefix. Three checks: (1) the delegated KEL's `dip` claims the expected delegating prefix, (2) the delegating KEL is cryptographically verified, (3) the delegating KEL actually anchors the delegated prefix. While KELS the service doesn't verify delegation, `kels-creds` credential verification now does.

### ~~15. `compact_at_path` silently no-ops on objects without `said`~~ — RESOLVED

**File:** `lib/kels-creds/src/disclosure.rs:182-186`

~~If the object at the target path has no `"said"` field, `compact_at_path` silently does nothing. For a security-sensitive disclosure API, failing explicitly would be more consistent with the fail-secure principle.~~

**Resolution:** `compact_at_path` now returns `InvalidDisclosure` error when the target is not a compactable object (missing `said` field). Already-compacted strings are allowed through.

### ~~16. Revocation hash has no explicit domain separation~~ — RESOLVED

**File:** `lib/kels-creds/src/revocation.rs:5-7`

~~The revocation hash was `Blake3(credential_said.as_bytes())` with no domain separation.~~

**Resolution:** Now uses `Blake3(b"kels/revocation:" || credential_said.as_bytes())` for explicit domain separation.

---

## Positive Observations

- **All findings from round 1 are resolved:** Cycle detection, depth limits, batch KEL verification reuse, correct canonical SAIDs in `compact_at_path`, `could_be_said` filter, `blake3` dep removal, `RwLock` upgrade, closed schema validation, and CLI import gating are all addressed.
- **Closed schema validation is thorough:** The `said` reserved field name check, compactable/non-compactable object enforcement, and extra-field rejection work correctly together.
- **Verification graph traversal is well-bounded:** Cycle detection via `visited` set + depth limits via `remaining_depth` counter on both `collect_anchors` and `build_verification`. Batch KEL verification shared across the entire credential graph.
- **Test coverage is comprehensive:** Each module has focused unit tests covering happy paths, error cases, and edge conditions. The disclosure DSL tests cover all token variants and composition.
- **Reserved label validation on Edges/Rules:** Both `Edges::new_validated` and `Rules::new_validated` reject `"said"` as a label, preventing collision with the `#[serde(flatten)]` SAID field.
- **`Compactable<T>` untagged serde ordering is correct:** `Said(String)` first ensures JSON strings deserialize as SAIDs and objects as `T`. No ambiguity since `T: Claims` is always a struct.
- **`serde_json` `preserve_order` feature enabled:** Ensures deterministic serialization order for SAID computation.
