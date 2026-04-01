# Branch Audit: KELS-76_replicated-sad-store (Round 4) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: ~10,100 lines diff, 76 files changed. Full review of SADStore handlers, repository, transfer infrastructure, gossip sync/anti-entropy, and bootstrap. All 22 findings from rounds 1-3 are resolved (including round 3's open finding #5).

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. Gossip publish after partial storage failure announces non-existent SAID~~ — RESOLVED

**File:** `services/kels-sadstore/src/handlers.rs:658-671`

~~After storing records in normal (non-repair) mode, Redis gossip publishes `records.last()` — the last record from the **input** batch. If mid-batch storage fails, the published SAID may not exist locally, creating unnecessary sync cycles.~~

**Resolution:** The storage loop now tracks `last_stored_said` and the gossip publish uses that instead of the input batch's last record. If no records were stored, nothing is published. Repair submissions include a `:repair` suffix in the Redis message.

---

## Medium Priority

### ~~2. `truncate_and_replace` does not verify internal chain linkage of replacement batch~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs:183-188`

~~In the repair path, `truncate_and_replace` only validated the first replacement record against the predecessor. Subsequent records in the batch were not checked for chain linkage, sequential versions, or consistent kel_prefix/kind.~~

**Resolution:** Added `windows(2)` loop before insertion that verifies each record chains from the previous one: previous SAID linkage, sequential versions, consistent kel_prefix, consistent kind.

### ~~3. `verify_sad_records` accumulates entire chain in memory during verification~~ — RESOLVED

**File:** `lib/kels/src/types/sad_transfer.rs`

~~`transfer_sad_records` accumulated all records from all pages into memory before verification.~~

**Resolution:** Restructured to mirror the KEL pattern. `transfer_sad_records` now takes `Option<&mut SadChainVerifier>` for inline structural verification per page — matching `transfer_key_events` with `Option<&mut KelVerifier>`. `verify_sad_records` uses a two-pass approach: pass 1 for structure + serial collection via `transfer_sad_records` with verifier + NoOpSink, KEL verification between passes, pass 2 for signature verification. O(page_size) memory. `SadRecordChain` removed.

---

## Low Priority

### ~~4. `SadStoreClient::verify_sad_records` has duplicate doc comment block~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:269-284`

~~The doc comment was repeated verbatim.~~

**Resolution:** Doc comment is now a single block. Round 3 finding resolved.

### ~~5. SAD anti-entropy stale prefix re-queue has no backoff or retry limit~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~Stale prefixes that failed repair were immediately re-queued with no backoff, retrying every anti-entropy cycle indefinitely. Same pattern in both KEL and SAD anti-entropy.~~

**Resolution:** Both KEL and SAD anti-entropy now use exponential backoff with retry limits. Stale entry values encode `{source}:{retries}:{not_before_epoch}`. `drain_due_stale_entries` filters by `not_before` timestamp, re-queuing entries that aren't due yet. Failed repairs increment the retry count with exponential backoff (30s base, doubling each retry). After 10 retries, the entry is dropped — phase 2 random sampling will rediscover it if the inconsistency persists.

---

## Additional Changes (Beyond Original Findings)

### Repair gossip propagation

Divergent SAD chains were unrepairable via gossip — `save_with_verified_signature` rejects all appends on frozen chains, so repairs on one node couldn't propagate.

**Fix:** Added `repair: bool` field to `SadGossipMessage::Chain` (`#[serde(default)]`). When a repair succeeds, the SADStore handler publishes with `:repair` suffix. The gossip subscriber parses this and sets the flag. `handle_sad_chain_announcement` uses `HttpSadSink::new_repair()` (submits with `?repair=true`) when the flag is set, fetching the full chain (no delta) to replace local divergent state.

If a node misses the gossip repair message, the owner re-submits the repair directly to that node.

---

## Positive Observations

- **Comprehensive validation pipeline in `submit_sad_records`.** Nine validation steps before storage — IP rate limiting, prefix consistency, SAID integrity, bounded establishment serial collection, KEL verification, signature verification, and prefix derivation — all in the correct order with early returns. Rate limit accrual only counts actually-stored records.

- **Clean repair mechanism.** `truncate_and_replace` with advisory locking, predecessor validation, internal chain linkage verification, and FK cascade deletes is simple and correct. The `?repair=true` query parameter keeps the API surface minimal.

- **Transfer infrastructure mirrors KEL pattern.** `transfer_sad_records` takes `Option<&mut SadChainVerifier>` for inline structural verification, matching `transfer_key_events` with `Option<&mut KelVerifier>`. Two-pass verification for SAD chains stays O(page_size) in memory while the forward path remains a clean single pass.

- **Bidirectional SAD anti-entropy with backoff.** Three-phase cycle (targeted stale repair with exponential backoff, random chain sampling with pull+push, object set comparison) covers all consistency gaps. The wrap-around cursor ensures unbiased random sampling.

- **Repair propagation via gossip.** The `repair` flag on `SadGossipMessage::Chain` allows divergent chains to be repaired across the federation without manual intervention on each node.

- **Well-structured two-pass verification.** Pass 1 (structure + serial collection) and pass 2 (signature verification with KEL keys) cleanly separate concerns. The establishment key collection is bounded by the existing `page_size()` cap on unique serials per chain.
