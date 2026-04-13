# Branch Audit: KELS-104_remove-sad-said-from-path (Round 3) — 2026-04-13

Typed CESR fields in request structs + new `IdentityKelPageRequest`. 53 files changed, ~1442 lines. Round 3 after all 6 Round 1 and 2 Round 2 low-priority findings were resolved. Round 2 medium-priority finding (unvalidated prefix/said strings) resolved by this round's core change.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 1    | 0        |
| Medium   | 1    | 1        |
| Low      | 1    | 0        |

All 6 findings from Round 1 are resolved. All 3 findings from Round 2 are resolved (1 medium, 2 low).

---

## High Priority

### 1. FFI `kels_sad_fetch_pointer` silently swallows invalid `since` CESR

**File:** `lib/ffi/src/sad.rs:283`

The `since` parameter parsing changed from passing the raw string through to the server (which would reject it) to parsing it locally with `.ok()`:

```rust
let since_digest = from_c_string(since).and_then(|s| cesr::Digest256::from_qb64(&s).ok());
```

If a caller passes a non-empty but invalid CESR string for `since`, the error is silently swallowed — `since_digest` becomes `None`, and the query fetches the entire chain from the beginning instead of returning an error. A C caller cannot distinguish "fetch from beginning" from "your since parameter was garbage." This is a fail-open behavior: the caller believes they're doing a delta fetch but actually gets a full fetch, which could mask bugs or cause unexpected data volumes.

**Suggested fix:** Match on the `from_qb64` result explicitly. If `since` is non-null and non-empty but fails CESR parsing, call `set_last_error` and return null, matching the pattern used for the `prefix` parameter 8 lines above.

---

## Medium Priority

### ~~2. Unvalidated prefix/said strings in handlers~~ — RESOLVED

**File:** `services/kels/src/handlers.rs`, `services/sadstore/src/handlers.rs`

~~Round 2 finding: `get_kel_audit`, `get_recovery_events`, and several SAD handlers passed raw `String` fields to repository methods without CESR validation.~~

**Resolution:** All request struct fields are now `cesr::Digest256`, so serde rejects invalid CESR at deserialization time (HTTP 422). Validation is now enforced uniformly at the wire boundary.

### 3. `docs/endpoints.md` gossip peer-to-peer table still shows `GET /api/v1/kels/kel/:prefix`

**File:** `docs/endpoints.md:127`

The gossip peer-to-peer HTTP table still lists `GET /api/v1/kels/kel/:prefix` for fetching individual KELs from peers. In the actual code, gossip uses `HttpKelSource::new(&peer_kels_url, "/api/v1/kels/kel/fetch")` (POST with `KelPageRequest` body) — the old GET path no longer exists. This means the documentation doesn't match the running code, which could mislead someone debugging gossip sync issues.

Additionally, `docs/registry.md:121-122` still shows `GET /api/v1/member-kels/kel/:prefix` and `GET /api/v1/member-kels/kel/:prefix/effective-said`, and several design docs (`docs/gossip.md:183`, `docs/design/divergence-detection.md:273-293`, `docs/design/security-invariant.md:11`) reference the old GET paths. These were stale before this branch, but since `docs/endpoints.md` was already updated for the other services, completing it here would prevent confusion.

**Suggested fix:** Update the gossip peer-to-peer table in `docs/endpoints.md` to show `POST /api/v1/kels/kel/fetch` with `KelPageRequest` body. Consider a follow-up pass on `docs/registry.md` and the design docs.

---

## Low Priority

### 4. `docs/endpoints.md` KEL endpoint notes reference `?since=SAID` and `?limit=N` query parameter syntax

**File:** `docs/endpoints.md:21,45-46`

The notes section for the KELS service (line 45) says `The ?since=SAID parameter returns events after the given SAID. The ?limit=N parameter controls page size...` and the identity section (line 21) says `?limit=N (default 32) and ?since=SAID for delta fetch`. These describe query parameters, but all endpoints now use POST with JSON bodies. The table entries themselves are correct (they reference `KelPageRequest` body), but the notes still describe the old query parameter interface.

**Suggested fix:** Update the notes to reference JSON body fields instead of query parameters.

---

## Positive Observations

- **Type-safe wire format eliminates a class of bugs.** By using `cesr::Digest256` directly in request structs, serde enforces CESR validation at deserialization — no handler can accidentally skip validation. This is a better design than manual `from_qb64` calls scattered across handlers.

- **`IdentityKelPageRequest` is a clean API design.** The identity service serves exactly one KEL, so requiring a prefix in the request was a leaky abstraction. The new type makes the contract explicit, and the comment documenting that `HttpKelSource` sends the superset `KelPageRequest` (which serde deserializes by ignoring the extra `prefix` field) is well-placed in both call sites.

- **Client APIs now take `&cesr::Digest256` instead of `&str`.** Functions like `fetch_key_events`, `fetch_kel_audit`, `fetch_sad_pointer`, `fetch_proposal` all take typed CESR references. This pushes parsing to the system boundary (CLI, FFI, admin tool) where it belongs, and eliminates redundant `.to_string()` / `from_qb64()` round-trips through the client layer.

- **FFI prefix validation is properly gated.** In `kels_sad_fetch_pointer`, the prefix parameter correctly uses explicit error handling with `set_last_error` on parse failure — the right pattern for C interop where callers can't catch Rust panics.

- **Cache key uses `prefix.as_ref()` consistently.** The `get_kel` handler passes `prefix.as_ref()` to the cache (which expects `&str`), avoiding any format mismatch between the typed `Digest256` and the cache's string-keyed storage.

- **Benchmark and test code updated in lockstep.** The `test_digest` helper in client tests, the `BenchRequest::Post` pre-serialization, and all shell test scripts were updated to match the new typed request format, ensuring the test suite validates the actual wire protocol.
