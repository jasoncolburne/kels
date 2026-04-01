# Branch Audit: KELS-76_replicated-sad-store (Round 3) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: ~10,000 lines diff, 74 files changed. Full review of new `kels-sadstore` service, SAD transfer infrastructure, gossip SAD replication, bootstrap sync, and anti-entropy. All 17 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 2        |
| Low      | 1    | 0        |

---

## High Priority

### ~~1. SAD gossip handlers missing feedback-loop prevention — broadcast storms~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:299-400`

~~`handle_sad_object_announcement` and `handle_sad_chain_announcement` fetch data from a remote peer and store it locally via HTTP. The local SADStore handler publishes updates to Redis (`sad_updates` / `sad_chain_updates`). `run_sad_redis_subscriber` picks these up, checks `recently_stored`, finds nothing, and re-broadcasts to gossip — creating a feedback loop.~~

**Resolution:** Both SAD gossip handlers now insert into `recently_stored` before storing locally, matching the KEL pattern at `sync.rs:472-476`. Cache keys use descriptive prefixes (`sad-object:{said}` and `sad-record:{prefix}:{said}`) to distinguish between the two types. The subscriber's feedback-loop check was updated to use the same key formats.

### ~~2. Bootstrap `preload_sad_records` only fetches one page per chain — multi-page chains truncated~~ — RESOLVED

**File:** `services/kels-gossip/src/bootstrap.rs:275-293`

~~When syncing chains during bootstrap, the code calls `remote_client.fetch_sad_chain(&state.prefix, None)` which returns a single `SadRecordPage`. If `has_more` is true, the remaining records are silently discarded. The `forward_sad_records` infrastructure was built exactly for this (round 2 resolved this for gossip sync) but is not used in the bootstrap path.~~

**Resolution:** Replaced the manual `fetch_sad_chain` + `submit_sad_records` with `forward_sad_records` from `HttpSadSource` to `HttpSadSink`, supporting delta via `local_said`. Content objects are already handled by the prior `preload_sad_objects` step which runs first.

---

## Medium Priority

### ~~3. `is_divergent` / `is_divergent_in` fetch ALL records for a chain to check for duplicate versions~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs:194-221`

~~Both methods fetch every record for a given chain prefix into memory, then scan adjacent pairs for duplicate versions. For long chains (thousands of records), this is wasteful in both memory and database I/O.~~

**Resolution:** Both methods now use `ColumnQuery` with `GROUP BY version ORDER BY COUNT(*) DESC LIMIT 1`, matching the KEL service's `is_divergent` pattern. Added `fetch_grouped_count` to the `TransactionExecutor` trait in `verifiable-storage-rs` so the in-transaction variant works correctly within its isolation boundary.

### ~~4. `list_prefixes` issues N+1 divergence checks — one `is_divergent()` per prefix in page~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs:424-442` and `services/kels/src/repository.rs:130-148`

~~After listing up to 100 prefixes, the code loops through each and calls `self.is_divergent(&state.prefix)`. Each call fetches ALL records for that prefix. For a full page of 100 prefixes, this issues 100 additional queries.~~

**Resolution:** Both SADStore and KEL `list_prefixes` now use a single batched query: `SELECT DISTINCT prefix FROM table WHERE prefix IN (...) GROUP BY prefix, version/serial HAVING COUNT(*) > 1`. Added `having_count_gt` to `ColumnQuery` and `r#in` convenience method in `verifiable-storage-rs`. The result is collected into a `HashSet` for O(1) lookup when replacing divergent SAIDs.

---

## Low Priority

### 5. `SadStoreClient::verify_sad_records` has duplicate doc comment block

**File:** `lib/kels/src/client/sadstore.rs:269-284`

The doc comment is repeated verbatim — two copies of the same description stacked on top of each other.

**Suggested fix:** Remove the duplicate block (lines 277-284).

---

## Positive Observations

- **Transfer infrastructure fully mirrored for SAD chains.** `PagedSadSource`/`PagedSadSink` with `transfer_sad_records`, `forward_sad_records`, and `verify_sad_records` cleanly parallels the KEL pattern. Good reuse of proven architecture.

- **SAD anti-entropy is thorough and bidirectional.** Phase 1 (targeted stale repair), Phase 2 (random sampling with pull+push), and Phase 3 (object set comparison) cover all consistency gaps. The wrap-around prefix/object listing ensures unbiased sampling.

- **Chain integrity enforcement in `save_with_verified_signature` is comprehensive.** Advisory locking, divergence detection, v0 determinism enforcement, previous SAID linkage, kel_prefix/kind consistency, and sequential version checks — all within a single transaction.

- **FK cascade deletes across all services.** Every signature table has `ON DELETE CASCADE` to its parent. No manual cleanup code needed, and no orphaned signatures possible. Applied consistently across all five services.

- **Gossip topic separation.** KEL announcements and SAD announcements use separate gossip topics (`kels/events/v1` vs `kels/sad/v1`), keeping the protocol clean and allowing independent subscription.

- **`SadRecordVerification` as a proof token.** The `pub(crate)` constructor pattern (matching `KelVerification`) ensures consuming code can't fabricate verification proofs. Consistent type-level security enforcement across both KEL and SAD paths.
