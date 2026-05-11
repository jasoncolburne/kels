# Branch Audit: Streaming Verification (Final 2) — 2026-03-04

Automated audit of `kels-52_paginate-kels-requests` branch changes vs `main`. Scope: full `git diff main` (~22.8K lines). Focus: correctness, security, performance, and API design.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 4        |
| Low      | 0    | 5        |

---

## Medium Priority

### ~~1. `cnt_serial - 1` underflows when contest serial is 0~~ — RESOLVED

**File:** `lib/kels/src/merge.rs:587`

~~`let cnt_serial = first.event.serial;` followed by `anchor_event.event.serial != cnt_serial - 1`. If an adversary submits a contest event with `serial: 0`, the subtraction wraps to `u64::MAX` in release mode (panics in debug mode). The comparison then fails and an error is returned, so no security impact — but in debug builds this panics the service.~~

**Resolution:** Added an explicit `cnt_serial == 0` guard that returns `InvalidKeyEvent` before the subtraction is reached.

### ~~2. Anti-entropy failed repairs re-queued — hot retry loop risk~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~The old code explicitly avoided re-queuing failed repairs: `"Don't re-add — Phase 2 will rediscover if still needed. Re-adding causes a hot retry loop when the source peer is unreachable."` The new code reverses this and calls `record_stale_prefix` on failure. If a source peer is persistently unreachable, every anti-entropy cycle retries the same prefix against the same peer, generating repeated warnings and wasted connection attempts.~~

**Resolution:** Re-queuing on per-prefix merge failure (`RepairResult::Failed`) is intentional — the 30s cycle is infrequent enough, and three-way divergence (the unsyncable case) is already suppressed by the seen SAIDs mechanism. The batch fetch failure path (network/timeout — peer unreachable) was split out to avoid re-queuing: `ServerError` re-queues (transient server issue, worth retrying), while `HttpError`/`Timeout` drops (Phase 2 rediscovers when the peer comes back).

### ~~3. Gossip startup fetches only one page of identity KEL~~ — RESOLVED

**File:** `services/kels-gossip/src/lib.rs:291`

~~`identity_client.get_key_events(None, MAX_EVENTS_PER_KEL_RESPONSE)` fetches a single page and ignores `has_more`. If the identity KEL exceeds 512 events, only the first page is submitted to local KELS. Identity KELs are typically short, so this is low practical risk, but it violates the project's pagination principle. Should use `forward_key_events` or paginate.~~

**Resolution:** Gossip startup now uses `sync_member_kel` which calls `forward_key_events` (paginated, streaming). The single-page `get_key_events` call was removed.

### ~~4. Anti-entropy Phase 2 no longer skipped when Phase 1 has work~~ — RESOLVED

**File:** `services/kels-gossip/src/sync.rs`

~~The old `continue; // skip Phase 2 when we had stale entries` was removed. Now Phase 2 (random sampling against a peer) runs even when Phase 1 (stale entries) had work. During recovery scenarios with many stale prefixes, this doubles the anti-entropy work per cycle.~~

**Resolution:** Intentional. Running both phases improves convergence speed.

---

## Low Priority

### ~~5. `sync_own_kel` always does full fetch (no `since` cursor)~~ — RESOLVED

**File:** `services/kels-registry/src/federation/sync.rs`

~~`sync_own_kel` passes `since: None` to `forward_key_events`, meaning every 30s cycle fetches the entire identity KEL from the identity service. For efficiency, it could compare the local effective SAID and pass it as `since`. Impact is low (localhost, small KELs), but grows linearly with KEL size.~~

**Resolution:** `sync_own_kel` now queries the local effective SAID from `MemberKelRepository` and passes it as `since` for delta fetch.

### ~~6. `load_local_registry_kels` accumulates all events in memory~~ — RESOLVED

**File:** `services/kels-gossip/src/lib.rs`

~~The function loops through pages and accumulates `all_events` into a `Vec` before calling `client.load_local_events(prefix, all_events)`. Per CLAUDE.md, services should use `transfer_key_events` infrastructure rather than accumulating unbounded events in memory. Registry KELs are small in practice, but it violates the architectural pattern.~~

**Resolution:** `load_local_registry_kels` was removed. Gossip startup now uses `sync_member_kel` which calls `forward_key_events` (page-at-a-time streaming to a `RepositoryKelStore` sink).

### ~~7. `MemoryKelSource` doesn't handle composite SAID cursors~~ — RESOLVED

**File:** `lib/kels/src/types/verifier.rs` (test infrastructure)

~~`MemoryKelSource::fetch_page` matches `since` against individual event SAIDs. After divergence detection, `transfer_key_events` uses composite SAIDs (hash of sorted tip SAIDs). The composite won't match any event, causing an empty page return. This means divergent transfer tests only work when all events fit in one page. Test limitation, not a production bug.~~

**Resolution:** Added `effective_said()` method to `MemoryKelSource` that computes branch tips (events whose SAID is not referenced as `previous` by any other event) and produces a composite hash for divergent KELs. `fetch_page` now recognizes composite SAID cursors and returns an empty page (in sync).

### ~~8. Shell `get_latest_said` sorts by non-existent field~~ — RESOLVED

**File:** `clients/test/scripts/lib/test-common.sh`

~~`sort_by(.event.version)` references `.event.version` but key events have a `serial` field, not `version`. jq sorts by `null`, making it a no-op. Works by accident because events arrive in serial order from the API. Pre-existing bug carried forward from old code.~~

**Resolution:** Changed `sort_by(.event.version)` to `sort_by(.event.serial)`.

### ~~9. `trace_chain_backward_to_serial` does individual DB lookups per event~~ — RESOLVED

**File:** `lib/kels/src/merge.rs`

~~`trace_chain_backward_to_serial` and `trace_establishment_backward` call `get_event_by_said` in a loop, issuing one query per event in the chain. For long chains between the recovery point and divergence point this is O(N) queries. These are rare paths (divergence/recovery only) and are now bounded by `max_verification_pages * MAX_EVENTS_PER_KEL_QUERY`, so the impact is limited.~~

**Resolution:** Replaced `trace_chain_backward_to_serial` and `scan_divergent_events` with `find_adversary_event`, which exploits the invariant that one divergent branch is always exactly 1 event. Identifies the adversary's single event in at most 1 page query by checking rec/cnt `previous` against divergent SAIDs (direct match) or finding which divergent event has a child (N case). Also validates the divergence invariant (exactly 2 events at divergence serial, no other serials duplicated) to reject DB tampering.

---

## Positive Observations

- **CESR uses base64url (RFC 4648):** The `URL_SAFE_NO_PAD` encoding avoids `+` and `/` characters, so direct URL interpolation of SAIDs (e.g., `&since={}`) is safe without percent-encoding.
- **Verification invariant remains rigorous:** `Verification` has private fields, can only be constructed through `KelVerifier::into_verification()`. All consuming paths use `completed_verification`. The type system makes bypass unrepresentable.
- **`handle_overlap_submission` correctly bounds memory:** The divergent events accumulation loop caps at `max_pages * page_size` (default 262K events) and returns an explicit error if the cap is reached.
- **Contest path re-verification under advisory lock is correct:** The re-verification in `handle_divergent_submission` is redundant (the advisory lock prevents interleaved modifications) but constitutes valid defense-in-depth. Not a performance concern since contest events are extremely rare.
- **Push model for member KELs is well-structured:** Fan-out uses `propagate` query param to prevent loops. Anti-entropy sync loop handles gaps. `submit_member_key_events` rejects events for untrusted prefixes. Fail-secure behavior is preserved.
- **`forward_key_events` adoption is comprehensive:** Gossip handler, anti-entropy `sync_prefix`, registry `push_own_kel_to_members`, and federation `push_to_stale_members` all use the paginated transfer infrastructure correctly.
- **`truncate_incomplete_generation` limitations are explicitly documented:** The doc comment acknowledges the linear-to-divergent transition edge case and explains how `transfer_key_events`'s held-back event strategy compensates.
- **Identity builder reads are correct for `push_kel_to_registry`:** The identity service creates all its own KEL events through the builder (behind an RwLock), so reading from the builder gives the authoritative state. The old `get_kel` comment about "other processes" referred to the same service's anchoring operations, which also go through the builder.
