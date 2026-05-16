# Branch Audit: KELS-87_consolidate-sad-stores (Round 3) — 2026-04-09

Consolidates two SADStore traits into one unified `SadStore` in kels-core, adds `FileSadStore` and `InMemorySadStore` to kels-core, converts all SAID parameters from `String` to `cesr::Digest256`. 15 files changed, ~1737 lines diff. Third round — all 7 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 1        |

All 7 findings from rounds 1-2 (2 medium, 2 low from round 1; 2 medium, 1 low from round 2) are resolved.

---

## Low Priority

### ~~1. `docs/design/creds.md` SADStore trait definition is stale~~ — RESOLVED

**File:** `docs/design/creds.md:177-193`

~~The "SADStore" section still shows the old trait signature with `store_chunks(&HashMap<String, Value>)`, `get_chunks(&HashSet<String>)`, `get_chunk(&str)`, `store_chunk(&str, &Value)` returning `CredentialError`. The actual trait is now `SadStore` in kels-core with `store(&Digest256, &Value)`, `load(&Digest256) -> Option`, `store_batch`, `load_batch` returning `KelsError`. The `InMemorySADStore` mention on line 193 is also outdated.~~

**Resolution:** Updated the trait definition code block, all prose references (`SADStore` → `SadStore`, `InMemorySADStore` → `InMemorySadStore`), function signatures in code blocks, and the file tree description across 8 locations in `docs/design/creds.md`.

---

## Positive Observations

- **Clean trait unification.** The old two-trait split (one in kels-creds, one in kels-core) is now a single `SadStore` with a well-designed API: `load()` returns `Option` (not-found is not an error), `load_or_not_found()` as a default method, and batch methods with sensible defaults plus optimized overrides on `InMemorySadStore`.

- **Smooth re-export migration.** `lib/creds/src/lib.rs:21` re-exports `InMemorySadStore` and `SadStore` from `kels_core`, so downstream crates that were importing from `kels_creds` don't need to change their import paths. The old `store_credentials` function continues to be exported separately.

- **`said_from_value` helper eliminates duplication.** The new `Credential::said_from_value()` method (credential.rs:201-210) extracts the compacted SAID parsing logic that was duplicated between `build()` and `compact()`, with clear error messages on both failure modes (not a string, invalid CESR).

- **Massive test boilerplate reduction.** The `Digest256` return from `build()` eliminates ~80 lines of `{ use cesr::Matter; builder.interact(&cesr::Digest256::from_qb64(&compacted_said).unwrap()) }` blocks across 8 test functions, replaced by direct `builder.interact(&compacted_said)` calls.

- **Type safety enforced at all store boundaries.** Every store operation now takes `cesr::Digest256` — invalid SAID strings can only enter the system at JSON/FFI/CLI parse boundaries (`from_qb64` calls in disclosure.rs, ffi/credential.rs, cli/cred.rs). Internal code paths cannot pass unvalidated strings to the store.

- **Error type migration is correct.** `store_credentials` now calls `SadStore::store_batch()` which returns `KelsError`, and the `?` operator converts via the existing `From<KelsError> for CredentialError` impl (error.rs:45). No error information is lost in the conversion.
