# Branch Audit: KELS-104_remove-sad-said-from-path (Round 1) — 2026-04-12

Move all SAIDs, prefixes, and other identifiers from URL path parameters to POST request bodies across SADStore, KELS, Registry, and Identity services. 36 files changed, ~2200 diff lines. Also removes the `/archived` endpoint and `benchmark_key_events` stale doc reference.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. `IdentityClient::get_key_events` still uses GET~~ — RESOLVED

**File:** `lib/kels/src/client/identity.rs:148-161`

~~The identity service endpoint was changed from `GET /api/v1/identity/kel` with query params to `POST /api/v1/identity/kel` with `KelPageRequest` JSON body. But `IdentityClient::get_key_events()` was not updated — it still sends a GET with `?limit=N&since=SAID` query params. This breaks gossip bootstrap (the gossip service calls `identity_client.get_key_events()` to fetch its own KEL at startup) and any other caller of `IdentityClient`.~~

**Resolution:** Fixed in this round. Client now sends POST with `KelPageRequest` body.

---

## Medium Priority

### ~~2. `limit` type inconsistency between KEL and SAD request structs~~ — RESOLVED

**File:** `lib/kels/src/types/kel/request.rs` vs `lib/kels/src/types/sad/request.rs`

~~KEL request types use `Option<usize>` for `limit` while SAD request types use `Option<u64>`. Both ultimately get cast to `u64` in handlers (`as u64`). The inconsistency means the wire format differs: a JSON `limit` larger than `usize::MAX` on 32-bit targets would silently truncate for KEL requests but not SAD requests. This also means `KelPageRequest` (used by `HttpKelSource::fetch_page`) serializes `limit` as `usize` but the receiving handler immediately casts to `u64`.~~

**Resolution:** Changed SAD request types to use `Option<usize>` consistently. Updated handlers and client method signatures to match.

### ~~3. `fetch_sad_object_by_digest` is a dead abstraction~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:391-409`

~~`fetch_sad_object_by_digest` is a private helper extracted from the old `get_sad_object` during the refactor. It only has one caller (`fetch_sad_object`). The old GET handler that also called it was removed, so the extraction no longer serves a purpose — it's an unnecessary indirection.~~

**Resolution:** Inlined the body back into `fetch_sad_object`.

### ~~4. Benchmark `unwrap_or_else(|_| unreachable!())` is not an `expect`~~ — RESOLVED

**File:** `clients/bench/src/main.rs:290-294`

~~The `BenchRequest` match arms use `.unwrap_or_else(|_| unreachable!())` on `hyper::Request::get/post().body()`. Per CLAUDE.md, impossible failures should use `.expect("reason")` with `#[allow(clippy::expect_used)]`. The `unreachable!()` approach panics with a less informative message and doesn't match the project convention.~~

**Resolution:** Changed to `.expect()` with `#[allow(clippy::expect_used)]` on the enclosing block.

---

## Low Priority

### ~~5. `KeyEventsQuery` may now be dead code~~ — RESOLVED

**File:** `lib/kels/src/serving.rs:16-19`

~~`KeyEventsQuery` is still defined in `serving.rs` and exported from `lib.rs`, but no handler uses it anymore (identity, kels, and registry all switched to the new request types). It may still be used by external consumers or tests outside this repo. If not, it's dead code.~~

**Resolution:** Removed `KeyEventsQuery` from `serving.rs` and its export from `lib.rs`. No external usage found.

### ~~6. `get_kel_not_found_with_audit` test changed expected behavior without comment~~ — RESOLVED

**File:** `services/kels/tests/integration_tests.rs:791-802`

~~The test was changed from expecting 404 to expecting 200 with empty records. This is correct (the recoveries endpoint returns empty results for nonexistent prefixes, not 404), but the old test name `test_get_kel_not_found_with_audit` now misrepresents what it tests — it's testing "recoveries returns empty for nonexistent prefix," not "not found."~~

**Resolution:** Renamed to `test_recoveries_empty_for_nonexistent_prefix`.

---

## Positive Observations

- **Shared request types in kels-core.** Putting the request structs in `lib/kels/src/types/` rather than duplicating them across services means the client and server always agree on the wire format. Derive `Serialize + Deserialize` on all of them enables both sides.

- **Clean removal of the `/:prefix/archived` endpoint.** Removing the redundant endpoint alongside the refactor simplifies the API surface without leaving stubs or deprecation shims — appropriate for a greenfield project.

- **`submit_vote` signature cleanup.** Removing the redundant `proposal_prefix` parameter (since it's already in `vote.proposal`) is a good API simplification that fell out naturally from removing the path param.

- **Benchmark POST body handling.** The `BenchRequest` enum cleanly separates GET (health baseline) from POST (KEL fetch) without adding unnecessary complexity. The body bytes are pre-serialized once and cloned per iteration, avoiding repeated JSON serialization in the hot loop.

- **Consistent application across all services.** The refactor didn't stop at SADStore — it covered KELS, Registry, Identity, gossip `HttpKelSource`, CLI, FFI, and bench tool. No partial migration.

- **Shell script helper functions updated in place.** Functions like `sad_chain_exists`, `get_effective_said`, `get_chain_tip_said` in the test scripts were updated to POST, so all callers get the fix automatically.
