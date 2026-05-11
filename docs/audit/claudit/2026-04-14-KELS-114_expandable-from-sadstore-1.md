# Branch Audit: KELS-114_expandable-from-sadstore (Round 1) — 2026-04-14

Branch `KELS-114_expandable-from-sadstore` vs `main`: ~1,160 lines changed across 12 files. Moves disclosure DSL parser to kels-core, adds heuristic SAD expansion to SADStore fetch endpoint, with SADbomb protection limits.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. `expand_recursive` silently swallows storage errors during expansion~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:177-180`

~~The let-chain treats `Err` from `sad_store.load()` the same as `Ok(None)` — both silently skip expansion. If MinIO returns a transient error (network timeout, 503), the field stays as a SAID string with no indication that expansion failed vs the SAID not existing.~~

**Resolution:** Changed `let Ok(Some(expanded)) = sad_store.load(&digest).await` to `let Some(expanded) = sad_store.load(&digest).await?` in both the object and array branches. `?` propagates storage errors; `None` skips gracefully.

---

## Medium Priority

### ~~2. `ExpandRecursive(path)` resets depth to 0 after targeted expansion~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:97-102`

~~After expanding at a path, the recursive expansion started at depth 0, effectively granting extra depth beyond the limit for deep paths.~~

**Resolution:** Changed `expand_recursive(child, ..., 0)` to `expand_recursive(child, ..., path.len())` so depth counts from document root. Fixed in `apply_tokens` (shared function, covers both production and tests).

### ~~3. `Compact(path)` silently no-ops on missing fields~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:244-258`

~~`compact_at_path` returns silently if the field doesn't exist at the path, unlike the schema-aware version which returns errors.~~

**Resolution:** Accepted as-is. The heuristic path is best-effort by design — the caller verifies the expanded result against their schema. Silent no-ops on missing fields are consistent with the lenient expansion semantics (e.g., expanding a non-existent field also no-ops).

### ~~4. Duplicated token dispatch logic between `apply_disclosure_to_sad` and `apply_test_disclosure`~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:85-115` and `services/sadstore/src/expansion.rs:432-458`

~~The token dispatch match block was duplicated between production and test code.~~

**Resolution:** Extracted shared `apply_tokens(&mut Value, &[PathToken], &dyn SadStore)` function. Both `apply_disclosure_to_sad` and `apply_test_disclosure` call it.

---

## Low Priority

### ~~5. `ObjectStoreSadAdapter` visibility is broader than needed~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:22-30`

~~`ObjectStoreSadAdapter` and `new()` were `pub`, accessible outside the crate.~~

**Resolution:** Made both `struct ObjectStoreSadAdapter` and `fn new` private (no visibility modifier). Only used within this module.

### ~~6. `SadRequest.disclosure` is accepted but ignored on `exists` endpoints~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1062-1088`

~~The `exists` endpoints accept `SadRequest` with an optional `disclosure` field that is silently ignored.~~

**Resolution:** Accepted as-is. The field is optional with `serde(default)`, harmless when ignored. Existence checks don't return content so disclosure has no meaning there.

---

## Positive Observations

- **Clean parser extraction.** Moving `PathToken` and `parse_disclosure` to `lib/kels` was done with minimal disruption — the re-export in `lib/creds/src/lib.rs` preserves the public API, the `From<KelsError>` impl maps `InvalidDisclosure` specifically rather than losing the error variant, and all existing tests continue to pass unchanged.

- **SADbomb protection is well-designed.** The dual-limit approach (depth 32, expansions 1000) with soft limits (partial expansion, not errors) is the right call for a presentation-layer feature. The limits are tracked via a simple `ExpansionState` struct rather than over-engineering with atomics or configuration, and the tests explicitly verify both limits with assertion counts.

- **`serve_sad` helper eliminates duplication cleanly.** The three `serve_from_minio` call sites (no custody, custody passed, once consumed) were replaced with `serve_sad` without changing the control flow of the handler, and the error mapping (400 for invalid disclosure, 404 for missing chunks) is correct.

- **Test coverage is thorough.** 15 tests covering round-trip, selective expansion, recursive expansion, compact-after-expand, arrays, non-SAID strings, depth limits, expansion count limits, and invalid expressions. The test helpers (`compact_and_store`, `compact_value_for_test`) correctly mirror the schema-free compaction from `compaction.rs`.

- **`compact_children_only` correctly separates root-level `CompactRecursive` semantics.** The distinction between `compact_recursive` (replaces root with SAID) and `compact_children_only` (keeps root expanded, compacts children) matches the credential-layer behavior in `lib/creds/src/disclosure.rs:compact_children`.

- **No unnecessary dependencies added.** The decision to move the parser to `lib/kels` (which sadstore already depends on) rather than adding `kels-creds` as a dependency avoids pulling credential-specific code into the SAD store service.
