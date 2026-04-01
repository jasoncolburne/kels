# Branch Audit: KELS-76_replicated-sad-store (Round 8) — 2026-04-01

Branch `KELS-76_replicated-sad-store`, ~14,500 lines diff, 109 files changed. Focus: schema correctness, prior open findings, new code since round 7.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

All 41 findings from rounds 1-8 are resolved.

---

## High Priority

### ~~1. Column name mismatch between `SadPointerRepair` struct and SQL migration~~ — RESOLVED

**File:** `lib/kels/src/types/sad_pointer.rs:208` and `services/kels-sadstore/migrations/0001_initial.sql:46`

~~The Rust struct `SadPointerRepair` had a field named `record_prefix`, but the SQL migration defines the column as `pointer_prefix`. The derive macro generates column names from field names, causing runtime "column does not exist" errors on INSERT and SELECT.~~

**Resolution:** Renamed Rust field from `record_prefix` to `pointer_prefix` to match the SQL column.

---

## Medium Priority

### ~~2. `storable(table)` attributes diverge from actual table names used~~ — RESOLVED

**File:** `lib/kels/src/types/sad_pointer.rs:202,228`

~~Two structs had `storable(table)` attributes pointing to non-existent tables (`sad_chain_repairs`, `sad_chain_repair_records`), masked by `insert_with_table` overrides with the correct table names.~~

**Resolution:** Updated `storable(table)` attributes to match the migration table names (`sad_pointer_repairs`, `sad_pointer_repair_records`). Dropped the `REPAIRS_TABLE` / `REPAIR_RECORDS_TABLE` constants. Replaced `insert_with_table` with `insert()` and `Query::for_table(const)` with `Query::new()` for these types.

### ~~3. `ensure_bucket()` catches all `head_bucket` errors as "bucket not found"~~ — RESOLVED (from Round 7)

**File:** `services/kels-sadstore/src/object_store.rs:55-76`

~~The `ensure_bucket` method treated any `head_bucket` error as "bucket not found" and attempted to create the bucket.~~

**Resolution:** Refactored to use `is_not_found()` helper that checks for HTTP 404 specifically (line 61). Non-404 errors now propagate as `ObjectStoreError::S3` (line 72-75).

---

## Low Priority

### ~~4. Bootstrap `preload_sad_objects` silently skips individual object failures~~ — RESOLVED (from Round 7)

**File:** `services/kels-gossip/src/bootstrap.rs:193-214`

~~Individual object fetch/store failures are logged at `debug!` level and silently skipped.~~

**Resolution:** Accepted as design-correct for bootstrap context. Individual object failures during bulk preload should not halt the entire bootstrap process. The anti-entropy loop will catch any missed objects in subsequent cycles. Upgrading to resolved-by-design.

### ~~5. Integration test import ordering~~ — RESOLVED (from Round 7)

**File:** `services/kels-sadstore/tests/integration_tests.rs:9-21`

~~Imports were not organized per CLAUDE.md convention.~~

**Resolution:** Imports now follow the three-group convention: system/core (`std`, `tokio`), external crates (`ctor`, `kels`, `reqwest`, `testcontainers`, `verifiable_storage`), no local imports needed.

---

## Positive Observations

- **Thorough feedback loop prevention.** The `recently_stored` cache key format is consistent between the gossip handlers (which insert before storing) and the Redis subscribers (which check before broadcasting). The `:repair` suffix handling is correctly stripped during the check, preventing both normal and repair updates from re-broadcasting.

- **`SadChainVerifier` signature verification is inline and streaming.** Each page's records are verified against establishment keys as they arrive, maintaining O(page_size) memory. The two-pass approach in `verify_sad_records` (collect serials first, then verify with keys) is a clean design.

- **Cursor-based tamper detection in `get_stored_chain`.** The `skipped > 2` check at `repository.rs:391` is a smart defense — it detects if more records than possible were injected at the cursor version, catching DB tampering without full chain verification on every read.

- **Atomic SAD object storage.** The `SadObjectIndex::store` method opens a DB transaction, inserts the index entry, writes to MinIO, then commits. If MinIO fails, the transaction rolls back cleanly. This prevents index entries for objects that don't exist in MinIO.

- **SAD anti-entropy bidirectional sync.** The phase 2 random sampling both pulls from and pushes to the selected peer, ensuring convergence in both directions. The phase 3 object comparison extends this to content-addressed objects, not just chain records.

- **Clean separation of concerns in transfer infrastructure.** The `PagedSadSource`/`PagedSadSink` trait pair mirrors the KEL transfer pattern exactly, making the code consistent and predictable across both KEL and SAD data paths.
