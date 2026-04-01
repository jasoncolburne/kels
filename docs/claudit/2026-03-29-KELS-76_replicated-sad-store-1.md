# Branch Audit: KELS-76_replicated-sad-store (Round 1) — 2026-03-29

Branch `KELS-76_replicated-sad-store` vs `main`: 45 files changed, 4517 insertions, 309 deletions. New `kels-sadstore` service, MinIO integration, gossip replication for SAD data, CLI commands, deployment manifests.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 4        |
| Low      | 0    | 3        |

---

## High Priority

### ~~1. Chain record gossip replication re-verifies KEL on every record — potential DoS vector~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~When gossip replicates a chain, each record is submitted to the local SADStore via `submit_sad_record`. The handler performs a full KEL verification on every submission. For a chain with N records, this means N full KEL verifications.~~

**Resolution:** Added `POST /api/v1/sad/pointers/batch` endpoint that accepts `Vec<SignedSadRecord>`, verifies the KEL once with bounded establishment key collection (`KelVerifier::with_establishment_key_collection`), verifies all signatures against collected keys, and stores all records. Gossip sync, anti-entropy, and bootstrap all use `submit_sad_records_batch`. Added `verify_key_events_with_establishment_keys` to the verification infrastructure.

### ~~2. Conflict resolution replaces records but doesn't verify the incoming record's signature~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs`

~~When a conflict is detected, the record with the smaller SAID wins and replaces the existing one. The conflict resolution path doesn't verify the signature — it trusts the caller.~~

**Resolution:** Renamed to `save_with_verified_signature` — the method name communicates the precondition. Added explicit doc comment: "Precondition: the caller must have already verified the record's signature against the KEL."

---

## Medium Priority

### ~~3. N+1 query pattern in `get_stored_chain`~~ — RESOLVED

**File:** `services/kels-sadstore/src/repository.rs`

~~`get_stored_chain` fetches all records, then fetches each signature individually in a loop.~~

**Resolution:** Batch-fetches all signatures in one query using `Filter::In` on record SAIDs, then zips with records via HashMap lookup.

### ~~4. SAD object existence check does full GET in gossip handler~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~`handle_sad_object_announcement` checks existence by doing a full GET (downloads the blob).~~

**Resolution:** Added `GET /api/v1/sad/:said/exists` endpoint (HEAD check, no data transfer) and `sad_object_exists()` client method. Gossip handler now uses the lightweight existence check.

### ~~5. `SadRecordPage.has_more` is always `false`~~ — RESOLVED

**File:** `services/kels-sadstore/src/handlers.rs`

~~The chain fetch handler always sets `has_more: false` with no pagination.~~

**Resolution:** Added `?limit=` query parameter. Handler fetches `limit + 1` records and sets `has_more` based on overflow. `get_stored_chain` accepts an optional limit parameter.

### ~~6. `sadstore_url_from_kels_url` fallback uses `replacen` which is fragile~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~The fallback does `kels_url.replacen("kels", "kels-sadstore", 1)` which could produce wrong URLs.~~

**Resolution:** Deleted `sadstore_url_from_kels_url` entirely. Replaced `kels_url` field on `Peer`, `PeerAdditionProposal`, `NodeInfo`, and `AddPeerRequest` with `base_domain`. All service URLs now derived from `base_domain` via `format!("http://kels.{}", base_domain)` and `format!("http://kels-sadstore.{}", base_domain)`. No string replacement hacks.

---

## Low Priority

### ~~7. `list_sad_objects` response reuses `PrefixListResponse` with confusing semantics~~ — RESOLVED

**File:** `services/kels-sadstore/src/handlers.rs`

~~The `list_sad_objects` endpoint returned `PrefixListResponse` with `prefix` and `said` set to the same value.~~

**Resolution:** Created dedicated `SadObjectListResponse` with `saids: Vec<String>` field. Clear semantics.

### ~~8. MinIO credentials in environment variables~~ — RESOLVED

**File:** `services/kels-sadstore/src/server.rs`

~~MinIO access key and secret key defaulted to `minioadmin` in code.~~

**Resolution:** Removed defaults. Server now fails on startup if `MINIO_ACCESS_KEY` or `MINIO_SECRET_KEY` are not set.

### ~~9. `verify_sad_records` only verifies the tip record's signature~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs`

~~The verification function only checked the tip signature against the current KEL key. Earlier records signed by rotated keys were not verified.~~

**Resolution:** `verify_sad_records` now collects all unique establishment serials from the chain, verifies the KEL with `with_establishment_key_collection`, and verifies every record's signature against its corresponding establishment key. Same pattern as the batch endpoint.

---

## Positive Observations

- **Deterministic prefix computation.** The v0 inception record with no `created_at` field ensures anyone can compute the chain prefix offline with just `kel_prefix` + `kind`. Clean, no-directory-service-needed discovery.

- **Deterministic conflict resolution.** Smallest-SAID-wins is simple, stateless, and guarantees all nodes converge without coordination. Much simpler than KEL divergence/recovery.

- **Separate signature table.** Keeping `SadRecordSignature` in its own table (not mixed into the SAID-driven record table) maintains the integrity of the `SelfAddressed` pattern. Good discipline.

- **Advisory locking + chain integrity in one transaction.** `save_with_verified_signature` acquires the lock, validates, and inserts atomically. No race window between check and write.

- **`BASE_DOMAIN` service discovery.** Single env var derives both KELS and SADStore URLs. `base_domain` field on peer records eliminates URL string manipulation. Consistent URL override pattern (`--kels-url`, `--sadstore-url`) in the CLI.

- **Bounded establishment key collection.** The `KelVerifier::with_establishment_key_collection` pattern allows batch signature verification with bounded memory — the caller specifies which serials to collect, capped at `page_size()`.
