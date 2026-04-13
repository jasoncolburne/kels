# Branch Audit: KELS-104_remove-sad-said-from-path (Round 2) — 2026-04-13

Move SAIDs/prefixes from URL path params to POST request bodies across all services. 51 files changed, ~1292 lines changed. Round 2 after all 6 Round 1 findings were resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 1    | 0        |
| Low      | 0    | 2        |

All 6 findings from Round 1 are resolved.

---

## High Priority

No high-priority findings.

---

## Medium Priority

### 1. `get_kel_audit` and `get_recovery_events` accept unvalidated prefix/said strings

**File:** `services/kels/src/handlers.rs:569-608`

The `get_kel_audit` handler passes `&request.prefix` (a `String` from the JSON body) directly to the repository `get_by_kel_prefix(&str)` without first validating it as a CESR digest. Similarly, `get_recovery_events` passes `&request.said` directly to `get_recovery_archived_events`. Contrast this with `get_effective_said` (line 641) and `get_kel` (line 536), which both parse to `cesr::Digest256` before proceeding. The repository methods use these as SQL `WHERE` clause values so there's no injection risk, but an attacker can query with arbitrary strings (not just valid CESR digests) and get empty results rather than a 400 Bad Request. This is an inconsistency rather than a vulnerability — the DB returns empty for invalid prefixes, so the fail mode is correct (empty response, not leak or crash). The same pattern exists in the SAD handlers (`get_sad_pointer` at line 735, `get_sad_pointer_repairs` at line 893, `get_sad_pointer_repair_records` at line 919).

**Suggested fix:** Add `cesr::Digest256::from_qb64()` validation at handler entry for these endpoints, matching the pattern in `get_effective_said`.

---

## Low Priority

### ~~2. Claudit file edits unrelated to KELS-104 are included in the diff~~ — RESOLVED

**Files:** `docs/claudit/2026-04-08-KELS-86_transpose-1.md`, `docs/claudit/2026-04-08-KELS-86_transpose-2.md`, `docs/claudit/2026-04-08-main-1.md`

~~The diff includes edits to prior claudit files. Including unrelated file changes in a feature branch diff makes review harder.~~

**Resolution:** Accepted as minor noise — not worth separating.

### ~~3. `test-reconciliation.sh` removes archived endpoint helpers~~ — RESOLVED

**File:** `clients/test/scripts/test-reconciliation.sh`

~~The diff shows ~45 lines removed from the reconciliation test script.~~

**Resolution:** False positive. The removed code was `get_archived_count`, `archived_match_all`, `wait_for_archived_convergence` helpers and their 3 test assertions — all of which called the removed `GET /api/v1/kels/kel/$prefix/archived` endpoint. The core recovery/convergence test scenarios remain intact.

---

## Positive Observations

- **Complete and consistent migration.** Every service (KELS, SADStore, Registry, Identity), every client (CLI, bench, FFI), every sync path (HttpKelSource, HttpKelSink, HttpSadSource, HttpSadSink), and all test scripts were updated atomically. No endpoint was left on GET-with-path-params.

- **Well-designed shared request types.** The `KelPageRequest`, `SadRequest`, `SadPointerPageRequest`, etc. in `lib/kels/src/types/{kel,sad}/request.rs` are minimal, correctly derive `Serialize + Deserialize`, and are cleanly exported via `lib.rs`. Client and server share the same wire format by construction.

- **Bench tool correctly uses POST with pre-serialized body.** The `BenchRequest::Post` variant pre-serializes the JSON once and clones `Bytes` per iteration (line 414), avoiding repeated serialization in the hot loop. The `#[allow(clippy::expect_used)]` annotations are properly scoped.

- **Identity client handles the empty-prefix gracefully.** `IdentityClient::get_key_events` sends `prefix: String::new()` (line 155), and the identity handler ignores it (uses its own builder prefix). This is a clean design since the identity service only serves its own KEL.

- **Cache path optimization preserved.** The `get_kel` handler (line 503-563) keeps the fast cache path using the raw string prefix before falling back to CESR parsing. This avoids an unnecessary `from_qb64` call on cache hits — a thoughtful performance decision.

- **`KeyEventsQuery` dead code was cleaned up.** Removing the now-unused `KeyEventsQuery` from `serving.rs` and its export (Round 1 finding 5) keeps the API surface tight.
