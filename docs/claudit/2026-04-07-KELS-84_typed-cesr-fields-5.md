# Branch Audit: KELS-84_typed-cesr-fields (Round 5) — 2026-04-07

Branch replaces `String` fields with typed CESR types (`cesr::Digest`, `cesr::PublicKey`, `cesr::Signature`, `cesr::EncapsulationKey`, `cesr::KemCiphertext`, `cesr::Nonce`) throughout the codebase. 118 files changed, ~3369 insertions, ~2478 deletions. Focus: residual untyped String fields/parameters/return types that represent CESR values, silent error handling patterns introduced alongside conversions.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 1        |

All 16 findings from rounds 1-4 are resolved. All 4 findings from round 5 are resolved.

---

## Medium Priority

### ~~1. `SyncHandler` internal state maps keyed by `String` instead of `cesr::Digest`~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:298,304`

~~`SyncHandler::local_saids: HashMap<String, String>` maps KEL prefix → SAID — both are CESR digests that should be `HashMap<cesr::Digest, cesr::Digest>`. Similarly, `peer_fetch_counts: HashMap<String, (u32, Instant)>` maps peer prefix to rate-limiting state and should be `HashMap<cesr::Digest, (u32, Instant)>`.~~

**Resolution:** Changed both maps to typed keys/values. Updated `get_local_effective_said`, `refresh_local_effective_said`, and `fetch_local_effective_said` to take `&cesr::Digest` and return `cesr::Digest`. `get_peer_kels_urls` now returns `Vec<(cesr::Digest, String)>`. `KelsClient::fetch_effective_said` return type changed to `Option<(cesr::Digest, bool)>`. All callers across gossip sync, bootstrap, and registry federation sync updated.

### ~~2. Pagination cursor fields remain `Option<String>` in sync API types~~ — RESOLVED

**File:** `lib/kels/src/types/sync.rs:21,41`

~~`PaginatedSelfAddressedRequest::cursor: Option<String>` and `PrefixListResponse::next_cursor: Option<String>` both carry CESR prefix digests as pagination cursors.~~

**Resolution:** Changed both to `Option<cesr::Digest>`. Also changed `SadObjectListResponse::next_cursor` to `Option<cesr::Digest>`. Updated `list_prefixes` in kels and sadstore repositories, `list` in sadstore, all client methods (`fetch_prefixes`, `fetch_sad_objects`, `fetch_sad_pointer_prefixes`), all handlers, and all bootstrap pagination loops.

### ~~3. `ManageKelResponse::event_kind` remains `String` instead of `EventKind`~~ — RESOLVED

**File:** `lib/kels/src/client/identity.rs:59`

~~`ManageKelResponse::event_kind: String` is always populated with an event kind value. Using `String` here means the identity admin CLI could receive an unexpected kind without type-level validation.~~

**Resolution:** Changed to `event_kind: EventKind`. Updated identity server construction to pass the `EventKind` directly instead of `event_kind.short_name().to_string()`. Admin CLI display uses `EventKind`'s `Display` impl.

---

## Low Priority

### ~~4. Silent `.ok()` on `from_qb64` in gossip sync discards errors without logging~~ — RESOLVED

**Files:** `services/gossip/src/sync.rs:551,1632,1666,1835,1871`

~~Five instances of `.and_then(|s| cesr::Digest::from_qb64(s).ok())` silently discard CESR parse errors when converting `since` digests for delta sync.~~

**Resolution:** KEL-related instances eliminated entirely — `fetch_effective_said` now returns `cesr::Digest` directly, removing the need for `from_qb64` conversion. SAD-related instances (which still receive `String` from `fetch_sad_pointer_effective_said`) replaced with match expressions that `warn!` log on parse failure before falling back to `None`.

---

## Positive Observations

- **Complete structural type conversion.** All core data structures, trait interfaces, function signatures, and return types across 118 files are converted. The remaining gaps (findings 1-3) are in internal state maps, pagination cursors, and a single admin response field — not in any security-critical paths.

- **Correct boundary discipline maintained.** CESR parsing continues to happen exclusively at system boundaries (HTTP handlers, CLI arguments, FFI layer) with proper `.context()` / `ApiError::bad_request()` error wrapping. No new interior parsing was introduced.

- **Signing pattern fully consistent.** All signing and verification sites uniformly use `.qb64().as_bytes()` — the round 4 fix to sadstore handlers was the last inconsistency. Zero `.to_string()` calls remain in any signing/verification path.

- **DB boundary conversions are appropriate.** The `.to_string()` calls in `kels/repository.rs:94-124` and `registry/federation/storage.rs:486,534` correctly convert `cesr::Digest` to `String` at the verifiable-storage query API boundary. These are not type-safety gaps — the DB layer requires string parameters for SQL binding.

- **Gossip allowlist typed correctly.** `SharedAllowlist` uses `HashMap<cesr::Digest, AllowlistEntry>` with typed digest keys. The allowlist lookup methods all take `&cesr::Digest`. The compound-key `RecentlyStoredFromGossip` is correctly kept as `HashMap<String, Instant>` since its keys are heterogeneous format strings.

- **Import ordering clean.** All touched files follow the three-group convention (std/tokio/serde → external crates → local/workspace imports) with proper blank-line separation. No inline imports remain in non-test, non-feature-gated, non-proc-macro code.
