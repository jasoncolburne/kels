# Branch Audit: KELS-87_consolidate-sad-stores (Round 1) — 2026-04-09

Consolidates two SADStore traits into one, moves InMemorySadStore to kels-core, converts all SAID parameters to cesr::Digest256. 13 files changed, ~650 lines delta.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 2    | 1        |

---

## Medium Priority

### ~~1. Import ordering violations in touched files~~ — RESOLVED

**File:** `lib/creds/src/compaction.rs:1-11`, `lib/creds/src/credential.rs:1-22`, `lib/ffi/src/credential.rs:1-10`

~~Per CLAUDE.md, imports should be in three groups: (1) system/core, (2) external crates, (3) local. Several files mix external crate groups.~~

**Resolution:** Merged all external crate imports into single group 2 blocks in all three files. Also removed orphaned `use cesr::Matter` inline imports from credential.rs test blocks that were no longer needed after the `Digest256` return type change.

### ~~2. `Credential::build` still returns `String` for compacted SAID~~ — RESOLVED

**File:** `lib/creds/src/credential.rs:130-154`

~~`Credential::build()` returns `(Self, String)` where the String is the compacted SAID, then immediately parsed back into a `Digest256`.~~

**Resolution:** Changed `build()` to return `(Self, cesr::Digest256)`. Updated `test_credential()`, `credential_for_prefix()`, and all test callers. Removed unnecessary `from_qb64` parse calls in tests. `json_api::build()` kept as `(String, String)` since it's the JSON/FFI boundary — it calls `.to_string()` on the returned `Digest256`.

---

## Low Priority

### 3. Unused `cesr::Matter` import in disclosure.rs

**File:** `lib/creds/src/disclosure.rs:1`

`use cesr::Matter;` is imported but the only usage of `cesr::Digest256` in this file is via `from_qb64()` (which is on the `Matter` trait). However, `from_qb64` is the only `Matter` method used — if the `Matter` import is needed, it's fine, but worth confirming clippy didn't flag it (it didn't because it's used through the trait method).

**Suggested fix:** No action needed — the import is required for `from_qb64`. This is a non-issue on closer inspection.

### ~~4. `compact_single_node` calls `said.to_string()` twice~~ — RESOLVED

**File:** `lib/creds/src/compaction.rs:47-58`

~~`said.to_string()` is called twice, allocating a new String each time.~~

**Resolution:** Extracted `let said_str = said.to_string();` and reused it for both the object insert and the replacement value.

### 5. FFI disclose function parses JSON chunks into String keys then converts to Digest256

**File:** `lib/ffi/src/credential.rs:273-293`

The FFI `kels_disclose` deserializes JSON into `HashMap<String, Value>` then converts each key to `Digest256`. This is correct and necessary since JSON keys are always strings, but the intermediate `string_chunks` HashMap is an extra allocation. A minor optimization would be to deserialize directly into a `HashMap<cesr::Digest256, Value>` using serde's `Deserialize` impl on `Digest256` — but JSON object keys always deserialize as strings, so the current approach is actually the only correct one.

**Suggested fix:** No action needed — current approach is correct. This is a non-issue.

---

## Positive Observations

- **Clean trait design.** The unified `SadStore` trait with `load()` returning `Option` and `load_or_not_found()` as a default method is a good API design — it lets callers choose their error semantics without forcing one pattern.

- **Optimized batch methods on InMemorySadStore.** Overriding `store_batch` and `load_batch` with single-lock-acquisition implementations avoids per-item lock overhead, which matters for the credential compaction/expansion hot path.

- **Thorough type migration.** Every SAID parameter across 13 files was converted from `String` to `cesr::Digest256`, with no raw strings remaining in store operations. The `from_qb64` parse points are placed correctly at the JSON/string boundary.

- **Silent skip on invalid SAIDs in expansion.** Using `let Ok(digest) = Digest256::from_qb64(said)` in the expansion let-chains (compaction.rs:187, 210, 259, 274) means malformed SAID strings in JSON are silently skipped rather than causing errors. This is the right behavior — a non-SAID string in a compactable field means it wasn't compacted, so there's nothing to expand.

- **Backward-compatible FFI surface.** The C function signatures in `lib/ffi/include/libkels.h` didn't change — the String-to-Digest256 conversion happens internally in the Rust FFI layer, so Swift/C callers are unaffected.

- **Test coverage maintained.** All existing tests were migrated to use `InMemorySadStore` and `cesr::test_digest()`, plus new tests were added for `InMemorySadStore` (batch, list, delete, load_or_not_found). No test was silently dropped.
