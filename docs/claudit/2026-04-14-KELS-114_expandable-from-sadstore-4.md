# Branch Audit: KELS-114_expandable-from-sadstore (Round 4) — 2026-04-14

Branch `KELS-114_expandable-from-sadstore` vs `main`: ~1,916 diff lines across 16 files. Moves disclosure DSL parser to kels-core, adds heuristic SAD expansion to SADStore fetch endpoint, with SADbomb protection limits. All 12 findings from rounds 1-3 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

---

## Medium Priority

### ~~1. `expand_recursive` recurses into non-string, non-expandable children without depth gating the recursion call~~ — RESOLVED

**File:** `services/sadstore/src/expansion.rs:204-207` and `services/sadstore/src/expansion.rs:225-227`

~~In both the Object and Array branches of `expand_recursive`, when a child is *not* a string (lines 204-207 for objects, 225-227 for arrays), the code recurses with `depth + 1`. This is correct. However, the recursion into *successfully expanded* children (lines 202 and 223) also passes `depth + 1`, which means a malicious document tree shaped as a single chain of SAIDs (each resolving to an object with one SAID child) would consume both one expansion *and* one depth level per hop. This is fine — the depth limit and expansion limit both bound it.~~

~~However, consider a document shaped as a wide fan: at each level, every expanded object contains ~32 non-SAID nested objects, each containing a SAID leaf. The recursion into non-string children (line 206) burns depth but not expansion count, meaning the function can visit `32^32` paths before depth-limiting. In practice this is bounded by the JSON document size (which is bounded by `max_sad_object_size`, default 1 MiB), so the traversal is finite. But the computation cost of *visiting* all those paths (even if no expansions happen) is proportional to the total node count in the expanded tree, which could be large if an attacker chains many small expansions that each fan out.~~

**Resolution:** Accepted as-is. The wide-fan scenario requires `32^32` paths, but each level's document is bounded by `max_sad_object_size` (1 MiB). A 1 MiB JSON document cannot contain anywhere near that many nested objects. The existing triple bound (depth 32, expansions 1000, document size cap) is sufficient to prevent computational amplification in practice.

---

## Low Priority

### ~~2. `serve_sad` double-parses disclosure expression on invalid syntax~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:787-791` and `services/sadstore/src/expansion.rs:75`

~~The early validation at `handlers.rs:787-791` calls `kels_core::parse_disclosure(d)` to validate syntax before custody checks. Then `serve_sad` calls `apply_disclosure_to_sad` which calls `parse_disclosure` again at `expansion.rs:75`. The parse is cheap (no I/O), so this is purely a minor inefficiency — the early validation is the right design choice to prevent `once` consumption on invalid input. But the double-parse could be avoided by passing the pre-parsed tokens through to `serve_sad`.~~

**Resolution:** Accepted as-is. The correctness benefit of early validation far outweighs the negligible cost of re-parsing a short string. Threading `Vec<PathToken>` through the handler would add complexity for no meaningful gain.

---

## Positive Observations

- **Clean re-export preserves public API.** The `lib/creds/src/lib.rs` change switches from re-exporting `PathToken` and `parse_disclosure` from the local `disclosure` module to re-exporting them from `kels_core`. External consumers see identical types — no breaking change despite the code moving to a lower-level crate.

- **`From<KelsError>` for `CredentialError` maps `InvalidDisclosure` specifically.** Rather than losing the error variant by converting to a generic `KelError(String)`, the new match arm in `lib/creds/src/error.rs:47-49` preserves the `InvalidDisclosure` variant through the conversion. This ensures credential-layer callers can distinguish parse errors from other KEL errors.

- **Early disclosure validation placement is precise.** The validation at `handlers.rs:787-791` runs after `parse_fetch_request` (so the disclosure string is available) but before any custody checks, `once` consumption, or MinIO I/O. This is exactly the right insertion point — it rejects malformed input at the earliest possible moment without adding validation to code paths that don't need it.

- **`SadFetchRequest.disclosure` participates in SAID computation.** Because `disclosure` is a regular field on a `SelfAddressed` struct, it's included in the SAID hash. Different disclosure expressions produce different request SAIDs and therefore different signed payloads — an authenticated request for `"*"` can't be replayed to fetch with `"claims"`.

- **400 vs 500 error mapping in the client is well-stratified.** The `get_sad_object_with_disclosure` client method (lines 162-164) maps 400 to `InvalidDisclosure`, 404 to `NotFound`, and everything else to `ServerError`. This gives callers three distinct error categories to handle without needing to inspect error message strings.

- **Test coverage exercises the full disclosure lifecycle.** The expansion tests cover round-trip expand/compact, selective expansion, recursive expansion through arrays, depth limits, expansion count limits, non-SAID string handling, and invalid expression rejection. The credential-layer tests separately cover schema-aware expansion with the same parser, confirming the shared parser works correctly in both contexts.
