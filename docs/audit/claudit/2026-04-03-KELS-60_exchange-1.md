# Branch Audit: KELS-60_exchange (Round 1) — 2026-04-03

Exchange protocol branch: ~8311 insertions / ~2579 deletions across 54 files. New `lib/exchange` crate, `services/mail` service, FFI module breakdown, CLI command restructuring, crypto module refactor, and integration test scripts.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 3        |
| Medium   | 0    | 5        |
| Low      | 0    | 4        |

---

## High Priority

### ~~1. Storage cap check compares blob size, not cumulative storage~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:252-254`

~~The storage cap check compares `blob.len()` (the size of a single blob) against `max_storage_per_recipient_mb * 1024 * 1024`. This checks whether a *single* blob exceeds the *total* storage cap — it doesn't check cumulative storage. A recipient could receive 100MB of mail across many small messages that individually pass this check.~~

**Resolution:** Added `blob_size: i64` to `MailMessage`, `QueryExecutor::sum()` to `verifiable-storage-rs`, and `local_storage_for_recipient()` method that computes `SUM(blob_size) WHERE source_node_prefix = our_node AND recipient_kel_prefix = $1`. The cap now enforces cumulative local storage per recipient.

### ~~2. Parallel blob+metadata write is not atomic — partial failure leaves orphans~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:283-301`

~~`tokio::join!(blob_future, meta_future)` writes the blob to MinIO and metadata to PostgreSQL in parallel. If one succeeds and the other fails: orphaned blob or dangling metadata.~~

**Resolution:** Changed to sequential writes: blob first, then metadata. On metadata failure, the blob is cleaned up via delete.

### ~~3. `count_for_recipient` fetches all messages to count them~~ — RESOLVED

**File:** `services/mail/src/repository.rs:69-77`

~~`count_for_recipient` fetches *all* `MailMessage` rows for a recipient into memory, then calls `.len()`. For a recipient at the 10,000-message inbox cap, this loads 10K rows into RAM per send request.~~

**Resolution:** Added `QueryExecutor::count()` method to `verifiable-storage-rs` (generates `SELECT COUNT(*)`) and updated `count_for_recipient` to use it.

---

## Medium Priority

### ~~4. `delete_expired` also fetches all expired rows before deleting~~ — RESOLVED

**File:** `services/mail/src/repository.rs:55-66`

~~Same pattern as finding #3 — fetches all expired messages into memory, then deletes one-by-one.~~

**Resolution:** Paginated into batches of 100 with a loop. Each batch fetches a bounded set, deletes them, and repeats until no expired messages remain.

### ~~5. Nonce encoding uses plain base64 instead of CESR in ESSR envelope~~ — RESOLVED

**File:** `lib/exchange/src/essr.rs:50`

~~The doc comment for `nonce` says "CESR-encoded AES-GCM nonce" but the field is actually plain base64.~~

**Resolution:** Updated doc comment to "Base64-encoded AES-GCM nonce (12 bytes)".

### ~~6. `sender_serial` is always hardcoded to 0 in CLI send~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:326`

~~`kels_exchange::seal(&inner, 0, recipient, &encap_key, &signing_key)` always passes `sender_serial: 0`.~~

**Resolution:** Now looks up the sender's latest establishment event serial from the local KEL via `completed_verification` and passes the actual serial.

### ~~7. `exchange fetch` command is unimplemented~~ — RESOLVED

**File:** `clients/cli/src/main.rs:527-533`

~~The `Exchange::Fetch` variant just prints a TODO and returns `Ok(())`.~~

**Resolution:** Implemented full fetch flow: authenticate to source node's mail service, retrieve blob, verify sender's KEL with establishment key collection at `sender_serial`, load local decapsulation key, ESSR-open, write decrypted payload to stdout.

### ~~8. IP rate limiter tokens can go negative (off-by-one drain)~~ — WON'T FIX

**File:** `services/mail/src/handlers.rs:129-145`

~~The token bucket check-then-decrement appeared non-atomic across concurrent requests.~~

**Resolution:** Not a real issue. DashMap's `entry()` returns a `RefMut` that holds a shard lock, so the check and decrement are atomic within the lock scope. The `f64` rounding in refill calculation is cosmetic — sub-millisecond precision loss is irrelevant when casting to `u32` at 100 tokens/sec granularity. The hand-rolled implementation is adequate for an internal service behind ingress with three other rate-limiting layers.

---

## Low Priority

### ~~9. Dead code: `_load_decap_key` has underscore prefix~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:33`

~~The function `_load_decap_key` was prefixed with `_` to suppress unused warnings.~~

**Resolution:** Renamed to `load_decap_key` and used by the new `cmd_exchange_fetch` implementation.

### ~~10. `exchange` crate has unused dependencies~~ — RESOLVED

**File:** `lib/exchange/Cargo.toml:33-40`

~~`async-trait` and `chrono` were listed as dependencies but not used.~~

**Resolution:** Removed both unused dependencies.

### ~~11. Import of `use base64::Engine` inside function body~~ — RESOLVED

**File:** `lib/exchange/src/essr.rs:194-195`

~~`base64_encode` and `base64_decode` imported `use base64::Engine` inline.~~

**Resolution:** Moved `use base64::Engine;` to the top-level imports.

### ~~12. CLI `exchange inbox` displays `sourceNodePrefix` but not sender~~ — WON'T FIX

**File:** `clients/cli/src/commands/exchange.rs:426-433`

~~The inbox display shows `sourceNodePrefix` (which node stored the blob) but not the sender's KEL prefix. The `MailMessage` metadata doesn't include the sender — that information is inside the encrypted blob.~~

**Resolution:** By design. The mail service is intentionally sender-blind — the sender identity is only available inside the ESSR ciphertext, protecting sender privacy.

---

## Positive Observations

- **ESSR protocol design is sound.** The four-property unforgeability (TUF-PTXT, TUF-CTXT, RUF-PTXT, RUF-CTXT) is correctly implemented: sender inside ciphertext for RUF-PTXT, recipient in signed plaintext for anti-KCI. The seal/open functions are well-structured with clear step numbering.

- **Clean FFI module decomposition.** Breaking the monolithic `lib.rs` (was ~1800 lines) into domain-specific modules (`kel.rs`, `exchange.rs`, `credential.rs`, `sad.rs`, `registry.rs`, `dev.rs`) dramatically improves navigability while maintaining the same public C API surface.

- **Mail service rate limiting is well-layered.** Three independent limits (per-IP token bucket, per-sender daily cap, per-recipient inbox cap) provide defense in depth against abuse. The background reaper for rate limit entries prevents memory leaks.

- **Proper GC lifecycle for mail messages.** TTL-based expiration with gossip-announced removals, blob cleanup on ack and expiry, and the background reaper create a complete lifecycle with no permanent resource leaks.

- **AEAD module extraction is well-motivated.** Pulling `aes_gcm_encrypt`/`aes_gcm_decrypt`/`derive_aes_key` into `lib/kels/src/crypto/aead.rs` allows sharing between the gossip transport layer and the ESSR exchange protocol without circular dependencies. The KDF context parameter ensures domain separation.

- **Test coverage is thorough.** Every new module includes focused unit tests — ESSR roundtrip, wrong-key failures, tampered ciphertext, SAID derivation, serialization roundtrips, FFI key generation, seal/open through FFI layer. The integration test scripts cover end-to-end flows.
