# Branch Audit: KELS-60_exchange (Round 4) — 2026-04-04

Exchange protocol branch: ~9677 insertions / ~3155 deletions across 101 files. Focus on new findings after all 19 findings from rounds 1-3 were resolved. Full read of lib/exchange, services/mail, CLI commands, FFI modules, crypto module, gossip changes, sadstore handler changes, and integration test scripts.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 0        |
| Low      | 0    | 2        |

All 19 findings from rounds 1-3 are resolved.

---

## High Priority

### ~~1. GC reaper deletes expired blobs by message SAID instead of blob digest — orphans in MinIO~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:88-90` and `services/mail/src/repository.rs:55-76`

~~`delete_expired()` returned `Vec<String>` containing message SAIDs. The reaper passed these SAIDs to `blob_store.delete(said)`, but `BlobStore::delete()` expects a `blob_digest` — blobs are stored at `messages/{blob_digest}`, not `messages/{said}`. Every expired blob deletion targeted the wrong key, leaving blobs permanently orphaned in MinIO.~~

**Resolution:** Changed `delete_expired()` to return `Vec<(String, String)>` pairs of `(said, blob_digest)`. The reaper now uses `blob_digest` for blob cleanup and `said` for gossip announcements. Also replaced `unwrap_or(false)` with explicit match + `warn!()` logging on DB errors (finding #3).

---

## Medium Priority

No new medium-priority findings.

---

## Low Priority

### ~~2. Unchecked string slicing on encapsulation key display~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:298-299`

~~Unchecked `[..20]` and `[len - 10..]` slicing on the encapsulation key would panic if the SADStore returned a truncated key shorter than 30 characters.~~

**Resolution:** Added a length guard — keys longer than 30 chars get the truncated `prefix...suffix` display, shorter keys are printed in full.

### ~~3. `delete_expired` silently swallows DB errors via `unwrap_or(false)`~~ — RESOLVED

**File:** `services/mail/src/repository.rs:70`

~~`unwrap_or(false)` on the delete result silently swallowed DB errors, making transient database issues invisible.~~

**Resolution:** Fixed as part of finding #1 — replaced with explicit `match` that logs errors via `warn!()` before continuing.

---

## Positive Observations

- **All 19 prior findings resolved thoroughly.** Cumulative storage caps, sequential blob writes, sender serial lookups, file permissions, blob size limits, ack caps, import ordering — every issue from rounds 1-3 has been addressed correctly.

- **Mail service authentication is well-structured.** The `authenticate_request` helper centralizes KEL verification + signature check + timestamp + nonce dedup across all four endpoints (send, inbox, fetch, ack), with no code duplication and proper error responses.

- **ESSR protocol implementation is cryptographically sound.** The seal/open flow correctly implements all four unforgeability properties. Signature verification happens before decryption (step 2 before step 5 in `open()`), inner sender is verified against envelope sender (step 6), and the KDF context provides domain separation.

- **CLI refactoring dramatically improves navigability.** The extraction from a monolithic 1800-line `main.rs` into domain-specific command modules (`kel.rs`, `exchange.rs`, `cred.rs`, `sad.rs`, `dev.rs`) with shared `helpers.rs` is clean and preserves the exact same public CLI surface.

- **Fetch handler integrity check is excellent defense-in-depth.** Recomputing the Blake3 digest after retrieving from MinIO and comparing against stored metadata catches storage corruption or tampering before serving blobs to clients.

- **Rate limiting is well-layered with proper cleanup.** Three independent limits (per-IP token bucket, per-sender daily cap, per-recipient storage cap) plus the background reaper for stale rate limit entries prevent both abuse and memory leaks.
