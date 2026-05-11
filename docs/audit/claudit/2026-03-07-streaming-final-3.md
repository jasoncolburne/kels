# Branch Audit: Streaming Verification (Final 3) — 2026-03-07

Automated audit of `kels-52_paginate-kels-requests` branch changes vs `main`. Scope: full `git diff main` (~24.6K lines). Focus: correctness, security, performance, and API design. Incremental from `2026-03-04-streaming-final-2.md`.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 5        |

---

## Medium Priority

### ~~1. Vote expiry check uses `>` instead of `>=`~~ — RESOLVED

**File:** `lib/kels/src/types/peer.rs:388`

~~`vote.voted_at > *expires_at` accepts votes cast at exactly the expiry timestamp. Typically "expires at" means "invalid at or after this time." Using `>=` would be more conservative (fail-secure).~~

**Resolution:** Intentional. The `expires_at` timestamp represents the last valid moment. A vote at exactly that time is valid. The semantic is "expires after", consistent with the proposal creation logic.

### ~~2. State machine lock held during async DB I/O~~ — RESOLVED

**File:** `services/kels-registry/src/federation/state_machine.rs`

~~`apply()` holds `self.inner.lock().await` while calling `verify_member_anchoring_from_repo().await` multiple times, each performing DB queries. Under DB pressure, this could block all Raft progress and cause election timeouts.~~

**Resolution:** This is an inherent tradeoff. Raft requires sequential `apply()` — releasing the lock between anchor checks would allow concurrent applies, violating Raft's guarantee. The old code held the lock during synchronous in-memory lookups; the new code holds it during async DB calls. Registry KELs are small (tens of events), DB is colocated (localhost), and `apply()` runs infrequently (only on membership changes). Operational risk is negligible.

### ~~3. `federation_rpc` uses baked-in prefix instead of `{prefix}` template~~ — RESOLVED

**File:** `services/kels-registry/src/handlers.rs:500-503`

~~`HttpKelSource::new(&member.url, &format!("/api/member-kels/kel/{}", signed_rpc.sender_prefix))` bakes the prefix into the path string. Other call sites use `"/api/member-kels/kel/{prefix}"` with the template placeholder. `fetch_page` does `self.path.replace("{prefix}", prefix)`, which is a no-op here since there's no literal `{prefix}`. Works correctly but inconsistent — if template logic changes, this would break.~~

**Resolution:** This is a one-off case where the path is known at construction time (the prefix comes from the RPC sender, not the transfer function). Using `format!` is clearer here than relying on template substitution. The `HttpKelSource` contract is that `path` is used as-is if no `{prefix}` placeholder exists. No fragility — the replace is explicitly a no-op by design.

---

## Low Priority

### ~~4. `push_own_kel_to_members` always does full push (no delta)~~ — RESOLVED

**File:** `services/kels-registry/src/handlers.rs:385-459`

~~`forward_key_events` is called with `since: None` for every member push after anchoring, sending the full KEL rather than a delta.~~

**Resolution:** Intentional. The eager push after anchoring is rare (only on membership changes) and registry KELs are small. The background `push_to_stale_members` in `sync.rs` correctly uses delta via effective SAID comparison. Optimizing the rare eager path adds complexity for negligible gain.

### ~~5. `HttpKelSource`/`HttpKelSink` creates new `reqwest::Client` per instance~~ — RESOLVED

**File:** `lib/kels/src/types/verifier.rs`

~~Each `HttpKelSource::new()` and `HttpKelSink::new()` creates a fresh `reqwest::Client`. These don't share connection pools. For gossip sync of many prefixes, this could cause connection churn.~~

**Resolution:** In practice, each source/sink is short-lived (one transfer, then dropped). The gossip anti-entropy loop processes one prefix at a time, not concurrently. The allowlist refresh creates one source per registry URL. Connection reuse across transfers to the same host would be a nice optimization but is not a correctness or security concern.

### ~~6. Per-page merge transaction overhead with `RepositoryKelStore` sink~~ — RESOLVED

**File:** `lib/kels/src/store/repository.rs`

~~`RepositoryKelStore::save` delegates to `save_with_merge`, which runs full merge logic (advisory lock, verification, divergence detection) per page. A 10-page transfer means 10 full merge cycles.~~

**Resolution:** This is correct by design. Each page submission must be verified independently — the sink cannot trust the source. The advisory lock ensures serialization. For the common case (non-divergent KELs), the merge is fast (insert new events, no divergence handling). The per-page overhead is dominated by the network fetch, not the merge.

### ~~7. `list_completed_proposals` uses `latest()` threshold vs `inception()` in `verify_and_authorize`~~ — RESOLVED

**File:** `services/kels-registry/src/handlers.rs:613,626`

~~The non-audit filter uses `awv.history.latest().threshold` while `verify_and_authorize` uses `inception().threshold`. If proposals could be updated with a different threshold, these paths could disagree.~~

**Resolution:** Proposals have a 1-2 record chain: inception (with threshold) optionally followed by withdrawal. For non-withdrawn proposals, `latest() == inception()`. For withdrawn proposals, `status()` returns `Withdrawn` before the threshold check is reached. No functional difference.

### ~~8. `kels_discover_nodes` FFI parameter accepted but unused~~ — RESOLVED

**File:** `lib/kels-ffi/src/lib.rs`

~~`registry_prefix` parameter is validated but unused. Comment says "accepted for API compatibility but no longer used."~~

**Resolution:** The FFI API must maintain backwards compatibility with existing Swift/mobile clients. The parameter will be removed in a future major version. Documenting it as unused is the correct approach.

---

## Session-Specific Changes (since Final 2)

These are the changes made in the current session, all verified via `test-comprehensive`:

### `change_membership` retain=false

**File:** `services/kels-registry/src/federation/mod.rs:188`

Changed `change_membership(expected_voters, true)` to `change_membership(expected_voters, false)`. With `retain=true`, OpenRaft kept removed voters as learners in the `nodes` map, causing "Unknown target node: 1" replication errors on registry-d. With `retain=false`, decommissioned nodes are fully removed from the Raft cluster. **Correct — fail-secure.**

### Pre-Raft member KEL sync

**File:** `services/kels-registry/src/federation/sync.rs` (new `sync_all_member_kels`)
**File:** `services/kels-registry/src/server.rs` (call before `FederationNode::new()`)

Before Raft initialization, syncs all member KELs from peer registries via `forward_key_events`. This ensures Raft log replay can verify vote anchoring against local member KEL data. Without this, registry-d (joining after decommission of registry-b) had no member KELs, causing all anchoring checks to fail and proposals to never reach "completed" state.

Uses `forward_key_events` (no verification) — a compromised peer could serve a fabricated KEL. However, this is **fail-secure**: the Raft `apply()` function re-verifies anchoring via `verify_member_anchoring_from_repo` (full KEL verification + anchor check). A corrupt pre-sync has the same effect as no pre-sync (anchoring fails), and the background sync eventually fixes it.

### Removed `member_prefixes` / `approval_threshold` from `CompletedProposalsResponse`

**File:** `lib/kels/src/types/peer.rs`

These fields were misleading — threshold is per-proposal (baked at creation), not a federation-wide constant. Callers now use the proposal's own threshold. **Correct simplification.**

### Vote expiry verification

**File:** `lib/kels/src/types/peer.rs:370-393`

Added check that votes are cast before the proposal's `expires_at` timestamp. Previously, expired votes were accepted. This closes a timing attack where a compromised registry could cast votes on expired proposals.

### Fixed removals in non-audit proposals endpoint

**File:** `services/kels-registry/src/handlers.rs:620-631`

The non-audit path was hardcoded to return `removals: vec![]`. Now returns actual approved removal proposals. Also removed the `active_peer_prefixes` filter that could return empty results when registries disagreed on active peers.

### ContestedKel early return in gossip

**File:** `services/kels-gossip/src/sync.rs`

Added early return when `forward_key_events` returns `KelsError::ContestedKel`. A contested KEL is permanently frozen — no amount of syncing will change it. This eliminates noisy repeated forwarding attempts.

---

## Positive Observations

- **Verification invariant remains rigorous:** `Verification` has private fields, constructed only via `KelVerifier::into_verification()`. All consuming paths enforce this. The type system makes bypass unrepresentable.
- **Streaming architecture eliminates unbounded memory in services:** Services never hold more than one page (512 events) in memory. `CollectSink` (unbounded) is restricted to CLI/FFI clients.
- **Deterministic event ordering:** All queries use `serial ASC, kind sort_priority ASC, said ASC` via `EventKind::sort_priority_mapping()`. Consistent across all services.
- **Gossip `previous` index exists:** `services/kels-gossip/migrations/0001_initial.sql` includes `idx_registry_key_events_prefix_previous`. All services have the required index for `compute_prefix_effective_said`.
- **Pre-Raft sync is fail-secure:** Worst case (corrupt data from compromised peer) = same as no sync. Raft `apply()` re-verifies independently.
- **`retain=false` fully removes decommissioned nodes:** No lingering learner state, no replication to dead nodes, no "Unknown target node" errors.
- **Vote expiry closes timing attack:** Historical votes on expired proposals are now rejected during verification.
- **Max 2 events per generation invariant:** `KelVerifier` rejects >2 events at the same serial and rejects multiple events after divergence. Prevents adversary from injecting unbounded events.
- **Redis cache size-gating:** `MAX_CACHED_KEL_EVENTS` (512) prevents caching of large KELs, bounding Redis memory usage.
