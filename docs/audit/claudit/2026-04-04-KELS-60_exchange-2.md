# Branch Audit: KELS-60_exchange (Round 2) — 2026-04-04

Exchange protocol branch: ~8960 insertions / ~2610 deletions across 75 files. Focus on new findings after all 12 round-1 findings were resolved. Reviewed lib/exchange, services/mail, CLI commands, FFI modules, crypto changes, and integration test scripts.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

All 12 findings from round 1 are resolved.

---

## High Priority

### ~~1. Decapsulation key written without restrictive file permissions~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:32`

~~`save_decap_key` writes the ML-KEM decapsulation key (private key material) using `std::fs::write`, which creates files with default permissions (typically 0o644 — world-readable). The signing key infrastructure in `lib/kels/src/crypto/keys.rs` uses `std::os::unix::fs::PermissionsExt` to set 0o600 (owner-only) on key files. The decapsulation key deserves the same protection.~~

**Resolution:** Added `#[cfg(unix)]` block after `std::fs::write` that sets 0o600 permissions via `std::os::unix::fs::PermissionsExt`, matching the signing key pattern.

---

## Medium Priority

### ~~2. `establishment_serial: 0` hardcoded in publish-key and rotate-key~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:137,142,225`

~~Both `cmd_exchange_publish_key` and `cmd_exchange_rotate_key` hardcode `establishment_serial: 0` on all `SignedSadPointer` records. After any signing key rotation (KEL serial > 0), the signature is made with the rotated key, but the pointer claims it was signed at serial 0. SADStore verifies signatures against the key at the claimed serial, so pointer submissions will fail with "Signature verification failed" after any key rotation.~~

**Resolution:** Added `current_establishment_serial` helper that uses `completed_verification` on the local KEL store (same pattern as `cmd_exchange_send`). Both `cmd_exchange_publish_key` and `cmd_exchange_rotate_key` now use it instead of hardcoding 0.

### ~~3. Unbounded `saids` vector in ack handler~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:419-458`

~~The `ack` handler processes every SAID in `AckRequest.saids` without any size limit. Each SAID triggers up to 4 operations: DB lookup (`get_by_said`), blob deletion, metadata deletion, and Redis publish. An authenticated user could submit ~30,000 SAIDs in a single request.~~

**Resolution:** Added a cap of 128 SAIDs per ack request, returning 400 if exceeded.

---

## Low Priority

### ~~4. Import ordering: std imports split by external crate~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:1-8`

~~std imports (`PathBuf` and `BTreeSet`) were split by `base64::Engine` instead of being grouped together.~~

**Resolution:** Merged std imports into `use std::{collections::BTreeSet, path::PathBuf};` and moved `base64::Engine` to its own group below.

### ~~5. Inline import in function body~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:461`

~~`base64_decode` imported `use base64::Engine` inside the function body.~~

**Resolution:** Moved `use base64::Engine;` to the top-level imports.

---

## Positive Observations

- **All round-1 findings resolved thoroughly.** The cumulative storage cap, sequential blob writes, batch expiry deletion, sender serial lookup, and fetch implementation all address the prior issues correctly.

- **Mail service authentication is consistent and complete.** All four endpoints (send, inbox, fetch, ack) verify KEL + signature with timestamp and nonce replay protection. The authentication flow is factored into a single `authenticate_request` helper, avoiding duplication.

- **FFI memory management is careful.** Each result struct has a corresponding `*_result_free` function, payload bytes use `Box::into_raw`/`Vec::from_raw_parts` correctly, and static strings (like `kels_encap_key_kind`) use `LazyLock` to avoid lifetime issues. The tests exercise the full alloc/free lifecycle.

- **Exchange message threading is well-designed.** Using `SelfAddressed` + `Chained` derives for `ExchangeMessage` gives deterministic thread prefixes via v0 inception, with cryptographic chaining between messages. The IPEX-style protocol (Apply/Offer/Agree/Grant/Admit/Reject) maps cleanly to credential exchange flows.

- **Integration test scripts are comprehensive.** `test-exchange.sh` covers the full lifecycle including cross-node gossip convergence with a timeout loop, and `test-creds.sh` tests credential issuance, storage, listing, and poisoning end-to-end.

- **Blob integrity verification on fetch is a strong defense-in-depth measure.** The fetch handler recomputes the Blake3 digest after retrieving from MinIO and compares against stored metadata, catching any storage corruption or tampering.
