# Branch Audit: KELS-84_typed-cesr-fields (Round 2) — 2026-04-07

Branch replaces `String` fields with typed CESR types (`cesr::Digest`, `cesr::PublicKey`, `cesr::Signature`) throughout the codebase. 115 files changed, ~3182 insertions, ~2426 deletions. Focus: residual String fields/returns that should be typed, consistency across the conversion.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 4        |
| Low      | 0    | 2        |

All 5 findings from round 1 are resolved. All 6 findings from round 2 are resolved.

---

## Medium Priority

### ~~1. KelServer trait returns `Option<String>` instead of `Option<cesr::Digest>`~~ — RESOLVED

**File:** `lib/kels/src/serving.rs:42-51`

~~`KelServer::effective_said()` returns `Result<Option<String>>` and `event_prefix_by_said()` returns `Result<Option<String>>`. These are SAIDs and prefixes respectively — both should be `cesr::Digest`. The consuming code in `serve_kel_page` does string-level comparisons that would be cleaner as typed digest comparisons.~~

**Resolution:** Both return types changed to `Result<Option<cesr::Digest>>`. Mock implementation, derive macro generated code, and `serve_kel_page` comparisons all updated. Federation sync code in `registry/federation/sync.rs` simplified — no longer needs `from_qb64` conversion since the return is already typed.

### ~~2. Edge SAID fields remain as `String`~~ — RESOLVED

**File:** `lib/creds/src/edge.rs:13-19`

~~`Edge.schema: String`, `Edge.policy: Option<String>`, `Edge.credential: Option<String>` are all SAIDs — the schema validation marks them as `SchemaFieldType::Said`. Inconsistent with `Credential` which has these as `cesr::Digest`.~~

**Resolution:** Changed to `cesr::Digest` / `Option<cesr::Digest>`. `Edge.nonce` correctly remains `Option<String>`. Updated `parse_edges` in json_api.rs to validate CESR at the JSON boundary. Updated all test data and verification code in `verification.rs`.

### ~~3. SharedAllowlist and RecentlyStoredFromGossip keyed by `String`~~ — RESOLVED

**Files:** `services/gossip/src/allowlist.rs:25`, `services/gossip/src/sync.rs:30`

~~`SharedAllowlist` uses `String` keys (peer prefixes). `RecentlyStoredFromGossip` uses `String` keys (compound keys).~~

**Resolution:** `SharedAllowlist` key changed to `cesr::Digest`. All gossip methods (`is_in_allowlist`, `public_key_from_key_events`, `try_verify`, `try_verify_refreshed`, `get_peer_sadstore_url`, `handle_sad_object_announcement`, `handle_sad_chain_announcement`) updated to take `&cesr::Digest`. `NodePrefix` is parsed to `cesr::Digest` once in `verify_peer` and threaded through. `RecentlyStoredFromGossip` intentionally kept as `HashMap<String, Instant>` — keys are heterogeneous compound strings (`"sad-object:{said}"`, `"sad-record:{prefix}:{said}"`, `"mail:{said}"`).

### ~~4. FederationConfig lookup methods take `&str` instead of `&cesr::Digest`~~ — RESOLVED

**File:** `services/registry/src/federation/config.rs:173-184`

~~`member_by_prefix(&str)`, `is_member(&str)`, and `is_trusted_prefix(&str)` all take `&str` and use `.as_ref() == prefix` for comparison.~~

**Resolution:** All three methods changed to take `&cesr::Digest` with direct digest comparison. `is_trusted_prefix` simplified to `self.trusted_prefixes.contains(prefix)` per clippy. All callers in registry handlers and federation state machine updated to pass typed digests directly (removing `.as_ref()` calls). Tests updated.

---

## Low Priority

### ~~5. Schema::fetch takes `said: &str`~~ — RESOLVED

**File:** `lib/creds/src/schema.rs:220`

~~`Schema::fetch(said: &str, ...)` takes a raw string for the SAID lookup.~~

**Resolution:** Changed to `said: &cesr::Digest`, uses `.as_ref()` at the `get_chunk` boundary.

### ~~6. Import ordering: workspace crates before external crates~~ — RESOLVED

**File:** `lib/creds/src/verification.rs:1-7`

~~`kels_core` and `kels_policy` placed before `verifiable_storage`.~~

**Resolution:** Fixed in `verification.rs` — `std` in group 1, `serde`/`verifiable_storage` in group 2, `kels_core`/`kels_policy` in group 3. Fixed in `essr.rs` — `serde` separated into its own group before external crates, `kels_core` correctly grouped with `crate::` imports.

---

## Positive Observations

- **Thorough struct-level conversion.** Core types (`KeyEvent`, `SignedKeyEvent`, `EventSignature`, `Peer`, `Vote`, `SadPointer`, `SignedSadPointer`, `SignedRequest`, all exchange types, all credential types) are fully converted. The remaining gaps are in trait interfaces and lookup methods, not in data structures.

- **Correct boundary handling.** CESR parsing (`from_qb64`) consistently happens at HTTP handler and CLI argument boundaries with proper `.context()` error wrapping. Internal code works with typed values throughout.

- **Wire format stability.** Since `cesr::Digest` serializes as the QB64 string via serde, the JSON wire format is unchanged. No migration concerns.

- **Allowlist simplification.** The gossip allowlist was significantly simplified — removing algorithm-based filtering in favor of hardcoded ML-KEM-1024 for gossip transport. This eliminated a subtle race condition where peer KELs weren't available during handshake, making the system both simpler and more secure.

- **Consistent test patterns.** All test helpers use `cesr::Digest::blake3_256(name.as_bytes())` for deterministic test digests, maintaining a uniform test idiom across the codebase.

- **Good fail-secure patterns.** The `SignedRequest::verify_signature` correctly rejects divergent KELs before checking signatures (auth.rs:34-36), and identity server defaults to `true` (fail-secure) when verification state is unknown.
