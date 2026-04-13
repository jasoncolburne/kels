# Branch Audit: KELS-104_remove-sad-said-from-path (Round 4) — 2026-04-13

Move SAIDs/prefixes from URL path params to POST request bodies, type request structs with `cesr::Digest256`, rename `sad_records` to `sad_pointers`. 55 files changed, ~1602 lines. Round 4 after all findings from rounds 1-3 were resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

All 6 findings from Round 1, 3 findings from Round 2, and 4 findings from Round 3 are resolved (13 total across prior rounds).

---

## High Priority

No high-priority findings.

---

## Medium Priority

No medium-priority findings.

---

## Low Priority

No low-priority findings.

---

## Positive Observations

- **Uniform POST-body migration with no stragglers.** Every service (KELS, SADStore, Registry, Identity), every client (CLI, bench, FFI), every sync path (HttpKelSource, HttpKelSink, HttpSadSource, HttpSadSink), all test scripts, and all operational scripts were updated atomically. No endpoint was left on GET-with-path-params. The `CLAUDE.md` rule codifies this for all future development.

- **`sad_records` to `sad_pointers` rename improves clarity.** The repository field name now matches the domain concept (SAD pointers) rather than the generic "records," making the code more self-documenting. The rename was applied consistently across all handler code and test files.

- **Clean removal of `get_kel_archived` endpoint.** The bulk-archived-events endpoint was removed along with its handler, route, test helpers, and test assertions — no orphaned code. The per-recovery `get_recovery_events` endpoint remains for targeted forensics, which is the more useful query pattern.

- **Identity endpoint serde compatibility is well-documented.** Both call sites where `HttpKelSource` sends `KelPageRequest` (with `prefix`) to the identity endpoint (which expects `IdentityKelPageRequest`, no `prefix`) include comments explaining that serde ignores the extra field. This prevents future confusion about the type mismatch.

- **`admin_vote_proposal` correctly simplified.** Removing the `proposal_prefix` path parameter and extracting the proposal digest from `vote.proposal` eliminates the redundant "vote references this proposal" check (step 3), which was verifying that the vote's self-declared proposal matched the URL — a check that was only necessary because two separate sources of truth existed. Now there's one.

- **Integration tests use the actual wire format.** Tests construct request bodies with `serde_json::json!({"prefix": prefix.to_string()})`, exercising the real `cesr::Digest256` deserialization path rather than relying on path parameter parsing. This validates that typed CESR deserialization works correctly at the HTTP boundary.
