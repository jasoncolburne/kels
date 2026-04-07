# Branch Audit: KELS-84_typed-cesr-fields (Round 1) — 2026-04-07

Branch replaces `String` fields with typed CESR types throughout the codebase. 104 files changed, ~2800 insertions, ~2215 deletions. Focus: missed fields/params, conversion correctness, test data validity.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. ExchangePayload SAID references remain as String~~ — RESOLVED

**File:** `lib/exchange/src/message.rs:58-114`

~~`ExchangePayload` enum variants contain SAID references typed as `String`: `Apply.schema`, `Offer.schema`, `Offer.policy`, `Agree.offer`, `Admit.grant`. These are all SAIDs that should be `cesr::Digest`.~~

**Resolution:** All SAID reference fields changed to `cesr::Digest`. Callers updated.

### ~~2. Credential subject field remains as String~~ — RESOLVED

**File:** `lib/creds/src/credential.rs:74`, `lib/creds/src/verification.rs:23`

~~`Credential.subject: Option<String>` is a KELS prefix. Should be `Option<cesr::Digest>`. Also `CredentialVerification.credential` and `.policy` were `String`.~~

**Resolution:** `Credential.subject`, `CredentialVerification.credential`, `.policy`, and `.subject` all changed to `cesr::Digest` / `Option<cesr::Digest>`.

### ~~3. SAID vectors in merge.rs and SadObjectListResponse remain as Vec\<String\>~~ — RESOLVED

**Files:** `lib/kels/src/merge.rs`, `lib/kels/src/types/sad/object.rs:23`, `lib/kels/src/repository.rs`

~~Multiple `Vec<String>` for SAID collections used in deletion, adversary tracking, and API responses.~~

**Resolution:** All changed to `Vec<cesr::Digest>`. Internal SQL binding uses `.as_ref()` / `.to_string()` at the boundary. `SadStore::list()` return type also updated.

---

## Low Priority

### ~~4. KelServer trait methods still take &str for prefix/said~~ — RESOLVED

**File:** `lib/kels/src/serving.rs:23-46`

~~`KelServer` trait methods and `serve_kel_page` take `prefix: &str` and `said: &str`. Should take `&cesr::Digest` for consistency.~~

**Resolution:** All `KelServer` trait methods changed to take `&cesr::Digest`. All implementations (kels service, identity service, derive macro generated code, test mocks) updated. `serve_kel_page` updated to take `&cesr::Digest` and `Option<&cesr::Digest>`.

### ~~5. Cache methods still take &str for prefix~~ — RESOLVED

**File:** `lib/kels/src/cache.rs`

~~`KelCache` methods (`publish_update`, `store`, `invalidate`, `get_full`) take `prefix: &str`. Callers have `cesr::Digest` and call `.as_ref()`.~~

**Resolution:** All cache methods changed to take `&cesr::Digest`. Internal Redis key construction uses `.as_ref()`.

---

## Positive Observations

- **Comprehensive type coverage.** All core struct fields (`KeyEvent`, `EventSignature`, `SignedKeyEvent`, `SadPointer`, `SignedSadPointer`, `Peer`, `Vote`, `PeerAdditionProposal`, `PeerRemovalProposal`, `SignedRequest`, exchange types, credential types) are fully converted to typed CESR fields.

- **Correct boundary handling.** CESR parsing (`from_qb64`) happens at system boundaries (HTTP handlers, CLI args, FFI), and typed values flow internally. This is the right pattern — validate once at the edge, trust the type system internally.

- **Wire format preserved.** Since `cesr::Digest` serializes/deserializes as the qb64 string via serde, the JSON wire format is identical. No migration or backward compatibility concerns.

- **Gossip KEM simplification.** Hardcoding ML-KEM-1024 for gossip transport eliminated a race condition in the allowlist algorithm check that caused handshake failures. The previous design checked peer KELs for signing algorithms before the KELs were available — a chicken-and-egg problem. The fix is both simpler and more secure.

- **Derive macro integration.** The `save_with_merge` generated code correctly parses the prefix string to `cesr::Digest` at the derive macro boundary, maintaining the contract that `MergeTransaction` works with typed prefixes internally.

- **Test data consistency.** All test helper functions use `cesr::Digest::blake3_256(name.as_bytes())` for deterministic test digests, and `K`-prefixed 44-char strings for CESR literals in test scripts. No remaining `E`-prefixed CESR values.
