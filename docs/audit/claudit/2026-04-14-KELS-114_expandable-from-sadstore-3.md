# Branch Audit: KELS-114_expandable-from-sadstore (Round 3) — 2026-04-14

Branch `KELS-114_expandable-from-sadstore` vs `main`: ~1,331 lines changed across 15 files. Moves disclosure DSL parser to kels-core, adds heuristic SAD expansion to SADStore fetch endpoint, with SADbomb protection limits. All 10 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 0        |
| Low      | 0    | 1        |

---

## High Priority

### ~~1. `once` custody objects consumed before disclosure validation~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:872-896`

~~For objects with `once: true` custody, the handler atomically deletes the PG row (`delete_by_sad_said`) **before** calling `serve_sad`, which is where the disclosure expression is first parsed. If the client sends a syntactically invalid disclosure expression (e.g., `"-"`, `"claims..address"`), the object is irrecoverably consumed due to a client-side error.~~

**Resolution:** Added early disclosure validation after `parse_fetch_request` returns and before custody checks begin. `kels_core::parse_disclosure` is called (no I/O, just string parsing) and returns 400 on invalid syntax before any state-mutating operations.

---

## Low Priority

### ~~2. `get_sad_object_with_disclosure` maps 400 (invalid disclosure) to `ServerError(_, InternalError)`~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:146-166`

~~The client method maps all non-2xx/non-404 responses — including 400 from invalid disclosure syntax — to `KelsError::ServerError(text, ErrorCode::InternalError)`. Callers must inspect the error message string to distinguish "invalid disclosure" from actual server errors.~~

**Resolution:** Added a `reqwest::StatusCode::BAD_REQUEST` branch before the generic error fallback, mapping 400 responses to `KelsError::InvalidDisclosure(text)`.

---

## Positive Observations

- **Early return for no-disclosure fast path.** `serve_sad` checks `let Some(disclosure) = disclosure else { return serve_from_minio(...) }` — when no disclosure is requested, the response is raw bytes from MinIO with zero JSON parsing overhead. This is the common case for machine-to-machine sync.

- **Disclosure committed in signed request SAID.** `SadFetchRequest.disclosure` is included in the SAID computation, so different disclosure expressions produce different SAIDs and nonces. An authenticated request with one disclosure can't be replayed to fetch with a different disclosure — the signature won't verify. This is a subtle but important property.

- **SADbomb self-reference protection.** The `said` key skip in `expand_recursive` (with the added comment from round 2) correctly prevents infinite self-referencing — expanding a document's own SAID would replace it with the document itself, creating an object cycle. The comment makes the non-obvious rationale explicit.

- **Consistent error mapping in `serve_sad`.** `InvalidDisclosure` → 400, `NotFound` → 404, everything else → 500 with a logged warning. The error mapping is precise and doesn't leak internal details in error messages.

- **`apply_tokens` shared between production and test.** The extracted function from round 1 ensures the token dispatch logic is tested identically to how it runs in production, with no behavioral divergence between the two code paths.

- **CLAUDE.md condensation preserves all semantic content.** The editorial pass reduced the document by ~40% without losing any instruction or constraint. The more concise format makes it easier to scan and reduces the chance of skipping an important rule.
