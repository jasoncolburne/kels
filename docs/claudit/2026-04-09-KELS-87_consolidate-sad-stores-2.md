# Branch Audit: KELS-87_consolidate-sad-stores (Round 2) — 2026-04-09

Consolidates two SADStore traits into one unified `SadStore` in kels-core, adds `FileSadStore`, moves `InMemorySadStore` to kels-core, converts all SAID parameters from `String` to `cesr::Digest256`. 14 files changed, ~1670 lines diff, ~479 added / ~377 removed. Second round — all 4 findings from round 1 addressed.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 1        |

All 4 findings from round 1 (2 medium, 2 low) are resolved.

---

## Medium Priority

### ~~1. `FileSadStore` uses blocking filesystem I/O in async methods~~ — RESOLVED

**File:** `lib/kels/src/store/sad.rs:89-152`

~~`FileSadStore` implements `async fn store()`, `load()`, `list()`, and `delete()` but calls `std::fs::write`, `std::fs::read_to_string`, `std::fs::read_dir`, `std::fs::remove_file`, and `path.exists()` synchronously. These block the async runtime's thread. For the CLI use case this is fine today, but if `FileSadStore` is ever used in a multi-tenant tokio context (e.g., tests with `#[tokio::test]` running in parallel), it could cause stalls.~~

**Resolution:** Pre-existing pattern across all file-based stores (`FileKelStore`, `FileSadStore`, `FileKeyStateStore`). Tracked in #96 for deferred fix.

### ~~2. `disclosure.rs:115` loads root chunk via `load()` + manual `ok_or_else` instead of `load_or_not_found()`~~ — RESOLVED

**File:** `lib/creds/src/disclosure.rs:114-117`

~~The new `SadStore` trait provides `load_or_not_found()` which returns `KelsError::NotFound(said)` — more informative since it includes the SAID that was missing. This call site manually maps to a less informative `ExpansionError`.~~

**Resolution:** Kept the `ExpansionError` variant (switching to `load_or_not_found` would change to `KelError` via `From`) but included the SAID in the error message: `format!("chunk not found in SAD store for SAID: {digest}")`.

---

## Low Priority

### ~~3. `use cesr::Matter` imported but only used for `from_qb64` in several files~~ — RESOLVED

**File:** `lib/creds/src/compaction.rs:3`, `lib/creds/src/disclosure.rs:1`, `lib/ffi/src/credential.rs:5`

~~The `Matter` trait import is needed wherever `Digest256::from_qb64()` is called (since `from_qb64` is a trait method). This is correct, but the pattern of importing a trait solely for one method creates a non-obvious dependency.~~

**Resolution:** Non-issue — the import is required by Rust's trait method resolution. Closed as-is.

---

## Positive Observations

- **Clean consolidation.** The old two-trait split (`SadStore` in kels-core + a separate credential store trait in kels-creds) is now a single `SadStore` in kels-core. The trait API is well-designed: `load()` returns `Option`, `load_or_not_found()` is a default method, and batch methods have sensible defaults with optimized overrides.

- **Type safety at boundaries.** Every internal SAID parameter is now `cesr::Digest256`, with `String`↔`Digest256` conversion only at JSON/FFI/CLI boundaries (`from_qb64` at ingress, `.to_string()` at egress). This eliminates a class of bugs where invalid SAID strings could propagate through internal APIs.

- **Correct `SadStore::load` return type change.** Changing from `Result<Value>` (where missing = error) to `Result<Option<Value>>` (where missing = None) is the right semantic — not-found is not an error for a store. The `load_or_not_found` convenience method preserves the old ergonomics where callers want the error.

- **Thorough CLI migration.** The `cred.rs` CLI changes are surgical: `interact(&canonical_said)` instead of `interact(&anchor_digest)` removes an unnecessary parse step since `canonical_said` is already a `Digest256`; `load_or_not_found` in `cmd_cred_show` gives proper error messages; `Ok(Some(value))` pattern match in `cmd_cred_list` correctly handles the new `Option` return.

- **InMemorySadStore batch optimizations.** The overridden `store_batch` and `load_batch` on `InMemorySadStore` acquire the lock once instead of per-item, which is meaningful during credential compaction where dozens of chunks may be stored atomically.

- **Comprehensive test coverage for new code.** The `FileSadStore` gets tests for: creation, roundtrip, not-found, load_or_not_found error, list (empty, populated, paginated), delete, and delete-nonexistent. `InMemorySadStore` mirrors these plus batch and overwrite tests. No test was dropped from the old store.
