# Branch Audit: KELS-76_replicated-sad-store (Round 2) — 2026-03-28

Branch `KELS-76_replicated-sad-store` vs `main`: 59 files changed, ~5100 insertions, ~420 deletions. New `kels-sadstore` service, MinIO integration, gossip SAD replication, CLI commands, batch endpoints, anti-entropy. All 9 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 3        |
| Low      | 0    | 3        |

---

## High Priority

### ~~1. Gossip chain sync fetches only one page — large chains silently truncated~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:366-399`

~~`handle_sad_chain_announcement` calls `remote_client.fetch_sad_chain(prefix, None)` which returns a single `SadRecordPage`. If `has_more` is true, the remaining records are silently discarded.~~

**Resolution:** Built `transfer_sad_records` infrastructure mirroring the KEL `transfer_key_events` pattern. `PagedSadSource`/`PagedSadSink` traits, `HttpSadSource`/`HttpSadSink` implementations, and public `forward_sad_records`/`verify_sad_records` functions. Gossip sync now uses `forward_sad_records` which pages through the full chain. The `since` parameter uses effective SAIDs (not version numbers) to support delta sync and divergence detection.

### ~~2. `verify_sad_records` in client accumulates full chain in memory — unbounded~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:232`

~~`verify_sad_records` calls `fetch_sad_chain(prefix, None)` which fetches a single page. For chains within one page this is fine, but chains longer than one page are only partially verified.~~

**Resolution:** `SadStoreClient::verify_sad_records` now delegates to the `transfer_sad_records` infrastructure with a NoOp sink. The core function pages through the full chain up to `max_pages`, verifies structural integrity, and verifies all signatures against the owner's KEL with bounded establishment key collection. Fails secure if `max_pages` is exceeded.

---

## Medium Priority

### ~~3. SAD object gossip fetch doesn't verify SAID integrity~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:322-327`

~~`handle_sad_object_announcement` fetches the remote object then stores it locally without the gossip handler checking SAID integrity.~~

**Resolution:** Not a real finding — the gossip handler calls `local_client.put_sad_object()` which hits the same `PUT /api/v1/sad/{said}` endpoint that users use. That handler verifies SAID integrity before storing. Verification happens at the server on every PUT regardless of caller.

### ~~4. `SadObjectEntry` has redundant structure — `said` (PK) differs from `sad_said`~~ — RESOLVED

**File:** `lib/kels/src/types/sad_record.rs:268-275` and `services/kels-sadstore/migrations/0001_initial.sql:29-34`

~~`SadObjectEntry` is `SelfAddressed`, so it computes its own SAID from its content (which includes the `sad_said` field). This means the `said` PK column is a hash of the record that contains `sad_said`, while `sad_said` is the actual MinIO key.~~

**Resolution:** By design — the `said` field is required by the `SelfAddressed` derive macro, which provides automatic SAID derivation and verification. The cost of the extra PK column is acceptable for the derive macro benefits.

### ~~5. No foreign key constraint between `sad_record_signatures` and `sad_records`~~ — RESOLVED

**File:** `services/kels-sadstore/migrations/0001_initial.sql:19-26`

~~`sad_record_signatures.record_said` references `sad_records.said` logically but has no `REFERENCES` constraint.~~

**Resolution:** Added `REFERENCES ... ON DELETE CASCADE` to all signature tables across all five services (kels, kels-registry, identity, kels-gossip, kels-sadstore) and their archive tables. Explicit signature delete code removed from the KEL archive path (`merge.rs`) and SAD truncate path (`repository.rs`) — the DB now handles cascade deletes.

---

## Low Priority

### ~~6. Duplicate error handling string for `"duplicate key"` detection~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs:274`

~~`e.to_string().contains("duplicate key")` is fragile — it relies on PostgreSQL's English error message format.~~

**Resolution:** `verifiable-storage-postgres` already maps PG error code 23505 (unique_violation) to `StorageError::DuplicateRecord`. Replaced the string match with a proper enum variant match.

### ~~7. Time-keyed maps grow without proactive cleanup~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:30-38` and all services

~~The `HashMap<String, Instant>` tracking recently stored gossip items is only cleaned lazily. Rate limit DashMaps in all services had the same issue — attacker-generated prefixes/IPs could grow maps unboundedly.~~

**Resolution:** Added periodic reaper tasks across all services. `spawn_rate_limit_reaper` spawns a background `tokio::spawn` that calls `retain` every 5 minutes on rate limit and nonce DashMaps (kels, sadstore, registry). The gossip `RecentlyStoredFromGossip` HashMap gets a dedicated reaper at TTL interval. The gossip `peer_fetch_counts` is reaped via `tokio::select!` in the sync handler event loop.

### ~~8. SAD anti-entropy random sampling is a no-op~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs:1185-1202`

~~Phase 2 of `run_sad_anti_entropy_loop` constructs a `remote_client` but immediately discards it.~~

**Resolution:** Implemented phase 2 mirroring the KEL anti-entropy pattern. Uses `generate_nonce()` as a random cursor with the wrapping `list_prefixes` endpoint to sample a random page of chain prefixes. Compares effective SAIDs with a random peer, pulls missing/different chains via `forward_sad_records`, and pushes local-only chains to the remote. The prefix listing endpoint now wraps around (fills remaining slots from the beginning of the prefix space) to ensure unbiased random sampling.

---

## Positive Observations

- **Transfer infrastructure mirrors KEL pattern.** `PagedSadSource`/`PagedSadSink` traits with `transfer_sad_records` core, `forward_sad_records` for gossip, and `verify_sad_records` for consuming — same proven architecture as KEL sync.

- **Divergence detection parallels KEL divergence.** Multiple records at the same version are stored (not replaced), chain is frozen, effective SAID becomes synthetic `hash_effective_said("divergent:{prefix}")`, and repair via `?repair=true` truncate-and-replace. Clean, predictable model.

- **Unified record submission endpoint.** Single `POST /api/v1/sad/records` replaces separate single/batch endpoints. Check-before/accrue-after rate limiting with dedup-aware counting matches the KEL `submit_events` pattern.

- **Prefix derivation is fully deterministic.** The v0 inception record with no `created_at` or `content_said` field means anyone can compute the chain prefix offline from just `kel_prefix` + `kind`. No directory service needed for discovery.

- **`SadRecordVerification` as a proof token.** The `pub(crate)` constructor pattern (matching `KelVerification`) ensures consuming code can't fabricate verification proofs. Good type-level security enforcement.

- **FK constraints with cascade deletes across all services.** Every signature table now has a database-enforced FK to its parent event/record table. Explicit signature delete code removed — the DB handles it. Consistent across all five services and their archive tables.
