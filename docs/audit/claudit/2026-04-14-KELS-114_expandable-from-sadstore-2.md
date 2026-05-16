# Branch Audit: KELS-114_expandable-from-sadstore (Round 2) — 2026-04-14

Branch `KELS-114_expandable-from-sadstore` vs `main`: ~1,228 lines changed across 13 files. Moves disclosure DSL parser to kels-core, adds heuristic SAD expansion to SADStore fetch endpoint, with SADbomb protection limits. All 6 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 5        |
| Low      | 0    | 3        |

---

## High Priority

### ~~1. `expand_recursive` silently swallows storage errors during expansion~~ — RESOLVED

Round 1 finding. Fixed by propagating errors with `?`.

### ~~7. `expand_recursive` double-checks `can_expand()` after entering the SAID branch~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:189-194` and `services/sadstore/src/expansion.rs:213-216`

~~In both the Object and Array branches, `can_expand()` is checked in the outer loop condition (line 162 / line 208) and again inside the let-chain (`&& state.can_expand()`). The Object branch iterates all keys without re-checking `can_expand()` between iterations, unlike the Array branch which breaks early.~~

**Resolution:** Added `!state.can_expand()` break at top of Object key iteration loop (matching Array pattern). Removed redundant `state.can_expand()` from let-chains in both branches — loop-level guards are sufficient. Also added comment on `said` skip explaining the self-reference rationale (#10).

---

## Medium Priority

### ~~2. `ExpandRecursive(path)` resets depth to 0 after targeted expansion~~ — RESOLVED

Round 1 finding. Fixed by starting depth at `path.len()`.

### ~~3. `Compact(path)` silently no-ops on missing fields~~ — RESOLVED

Round 1 finding. Accepted by design.

### ~~4. Duplicated token dispatch logic~~ — RESOLVED

Round 1 finding. Extracted shared `apply_tokens`.

### ~~8. `expansion` module is `pub` but only used internally by handlers~~ — RESOLVED

**File:** `services/sadstore/src/lib.rs:9`

~~The `expansion` module is declared `pub mod expansion;`, making `apply_disclosure_to_sad` and the `SadStore` trait impl on `ObjectStoreSadAdapter` publicly accessible outside the crate.~~

**Resolution:** Changed to `pub(crate) mod expansion;`.

### ~~9. `compact_at_path` silently no-ops when target has no `said` field but is an expanded object~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:258-272`

~~`compact_at_path` only compacts if the target object has a `said` field. The credential-layer version returns an explicit error. Asymmetry between expand and compact means round-trips could silently fail to re-compact.~~

**Resolution:** Accepted as intentional leniency (same rationale as round 1 #3). Added comment on `compact_at_path` documenting that silent no-op on missing `said` is by design.

---

## Low Priority

### ~~5. `ObjectStoreSadAdapter` visibility is broader than needed~~ — RESOLVED

Round 1 finding. Made private.

### ~~6. `SadRequest.disclosure` is accepted but ignored on `exists` endpoints~~ — RESOLVED

Round 1 finding. Accepted by design.

### ~~10. `compact_recursive` skips the `said` key but doesn't skip other non-compactable reserved keys~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:276-318`

~~`expand_recursive` and `compact_recursive` skip only `key == "said"` without explaining why. If future conventions add other reserved keys, both would need updating.~~

**Resolution:** Added comment on the `said` skip in `expand_recursive` explaining that expanding it would self-reference the containing object, causing incorrect replacement. Included as part of #7 fix.

---

## Positive Observations

- **Clean parser extraction.** Moving `PathToken` and `parse_disclosure` to `lib/kels` was done with minimal disruption — the re-export in `lib/creds/src/lib.rs` preserves the public API, the `From<KelsError>` impl maps `InvalidDisclosure` specifically rather than losing the error variant, and all existing tests continue to pass unchanged.

- **SADbomb protection is well-designed.** The dual-limit approach (depth 32, expansions 1000) with soft limits (partial expansion, not errors) is the right call for a presentation-layer feature. The `ExpansionState` struct is simple and effective, and the tests explicitly verify both limits.

- **Consistent error propagation.** The `?` operator on `sad_store.load(&digest).await?` in both the Object and Array expansion branches (post round 1 fix) correctly surfaces storage errors while letting `None` (not-found) silently skip. This is the right semantics for heuristic expansion.

- **`serve_sad` helper is well-structured.** The fast path (no disclosure → raw bytes from MinIO, no JSON parsing) avoids unnecessary deserialization overhead for the common case. The error mapping (400 for invalid disclosure, 404 for missing chunks) is correct and specific.

- **Test helpers mirror production compaction correctly.** `compact_and_store` and `compact_value_for_test` in the test module correctly reproduce the schema-free compaction behavior including SAID derivation via `compute_said_from_value`, ensuring tests exercise the same data shapes that production code handles.

- **`SadFetchRequest` disclosure field is well-placed.** Adding `disclosure` as an optional field on the authenticated fetch request means disclosure expansion can be requested through the same signed-request flow that already handles custody verification, without a separate endpoint or wrapper type.
