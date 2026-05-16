# Branch Audit: KELS-105_sad-custody (Round 6) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering. 35 files changed, ~4100 lines. Focus: finding #15 resolution verification, post-consumption lifecycle, gossip policy edge cases.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 3        |
| Medium   | 0    | 11       |
| Low      | 1    | 4        |

All 7 findings from round 1 are resolved. 4 of 5 findings from round 2 are resolved (finding #10 remains open by design). All 3 findings from round 3 are resolved. 1 finding from round 4 resolved. Finding #15 from round 5 is resolved. Finding #16 resolved, #17 withdrawn (invalid premise).

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED (Round 1)

**Resolution:** Two-phase compaction in `compaction.rs`.

### ~~2. `resolve_gossip_policy` fails open when nodes can't be resolved~~ — RESOLVED (Round 2)

**Resolution:** All NodeSet resolution error paths now return `GossipPolicy::LocalOnly`.

### ~~15. Consumed `once` records remain accessible via MinIO fallback, bypassing `readPolicy`~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:785-793`

~~When a `once` record was consumed, the DB index entry was deleted but the MinIO object remained. Subsequent fetch requests hit the "not tracked in index" fallback path, which served directly from MinIO without any custody checks — bypassing both `once` atomicity and `readPolicy`.~~

**Resolution:** The MinIO fallback path has been completely removed. When `get_by_sad_said` returns `Ok(None)`, the handler now returns `(StatusCode::NOT_FOUND, "not found")` instead of calling `serve_from_minio`. This eliminates the bypass entirely — consumed records are inaccessible regardless of MinIO state. The MinIO object becomes orphaned but unreachable through the API (see finding #16).

---

## Medium Priority

### ~~3-5. Round 1 findings~~ — RESOLVED

**Resolution:** See round 1 audit for custody SAID validation, TTL reaper format, repository delete encapsulation, pointer custody validation.

### ~~6. Two integration tests pass for the wrong reason (route mismatch)~~ — RESOLVED (Round 2)

**Resolution:** Changed to POST with JSON request bodies.

### ~~7. TTL reaper bypasses `delete_by_sad_said`~~ — RESOLVED (Round 2)

**Resolution:** Uses repository method.

### ~~8. `evaluate_signed_policy` Delegate node checks only the delegator~~ — RESOLVED (Round 2)

**Resolution:** Delegate nodes rejected with error in signed evaluation.

### ~~11. `resolve_gossip_policy` fails open when custody SAID exists but custody record is unresolvable~~ — RESOLVED (Round 3)

**Resolution:** Both `Ok(None)` and `Err` arms now return `GossipPolicy::LocalOnly`.

### ~~12. Missing index on `sad_objects.custody` for TTL reaper queries~~ — RESOLVED (Round 3)

**Resolution:** Added `sad_objects_custody_idx`.

### ~~13. `submit_sad_pointer` only validates custody on `records[0]`~~ — RESOLVED (Round 3)

**Resolution:** Iterates all records, validates every unique custody SAID.

### ~~14. TTL reaper timing across nodes~~ — RESOLVED (Round 4)

**Resolution:** Not a real finding — each node has its own MinIO.

---

## Low Priority

### 10. `once: true` without `readPolicy` allows unauthenticated consumption — OPEN BY DESIGN (Round 2)

**File:** `services/sadstore/src/handlers.rs:871-896`

Working as intended: `once` without `readPolicy` is a public ephemeral record. With finding #15 resolved, post-consumption access is no longer possible regardless.

### ~~16. Consumed `once` records leave orphaned objects in MinIO~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:878-895`

~~When a `once` record was consumed, the DB index entry was atomically deleted and the object was served from MinIO. However, the MinIO object was never deleted, causing orphaned objects to accumulate.~~

**Resolution:** Added fire-and-forget `tokio::spawn` MinIO delete after serving the response. The DB row is already deleted atomically; the MinIO cleanup is best-effort — the TTL reaper catches any failures on its next cycle.

### ~~17. Gossip policy for pointer batches uses only the first record's custody~~ — WITHDRAWN

**File:** `services/sadstore/src/handlers.rs:1164`

~~Flagged as a potential metadata leak when the first record has no custody but later records do.~~

**Withdrawn:** Invalid premise. `write_policy` is required on all pointer records, so `records[0].custody` is always present when the chain has custody. readPolicy/nodes are immutable per chain — all records in a batch share the same gossip-relevant custody fields. Checking `records[0]` is correct.

---

## Positive Observations

- **Finding #15 resolution is the cleanest possible fix.** Removing the MinIO fallback path entirely (`handlers.rs:787-789`) is far stronger than the round 5 suggestion of fire-and-forget MinIO deletion after consumption. The old fallback (`serve_from_minio` on `Ok(None)`) was a broad bypass of the entire custody/readPolicy/once enforcement chain. Eliminating it reduces code complexity and closes the vulnerability class, not just the specific bug.

- **Deterministic pointer prefix derivation from `(write_policy, topic)` enables clean patterns.** The `exchange_write_policy` function at `exchange.rs:16-18` shows the natural design: the KEL prefix itself is the write policy for owner-authored chains. `compute_sad_pointer_prefix` at `pointer.rs:56-62` constructs a v0 pointer from only deterministic fields, making prefixes offline-computable without server interaction.

- **readPolicy enforcement chain is thorough and defense-in-depth.** The fetch handler at `handlers.rs:814-857` chains: check readPolicy exists → require authenticated request → verify signer committed to the correct readPolicy SAID (preventing downgrade) → verify signatures → evaluate policy against verified prefixes. The `read_policy` field in `SadFetchRequest` is a particularly good design — it makes the signer commit to which policy they're satisfying, preventing an attacker from replaying a request against a weaker policy.

- **Two-phase compaction with depth bound prevents resource amplification and stack exhaustion.** `compact_sad`/`commit_compacted` in `compaction.rs` correctly separates SAID computation from storage. The `MAX_COMPACTION_DEPTH = 32` bound at both `compact_children` and `compact_value` entry points prevents stack overflow from malicious nesting. The test coverage (4 tests) validates idempotency for pre-compacted inputs.

- **`SadChainVerifier` generation-buffering handles divergence correctly across page boundaries.** The `flush_generation` method at `verification.rs:88-184` correctly processes same-version records together, tracks per-branch state via `HashMap<Digest256, SadBranchState>`, carries un-extended branches forward, and rejects >2 records per generation. The multi-page test at `verification.rs:295-312` exercises the critical page-boundary case.

- **Fail-secure gossip policy resolution is consistent.** All error paths in `resolve_gossip_policy` (`handlers.rs:538-604`) — custody not cached, custody fetch error, NodeSet parse failure, NodeSet fetch error — correctly return `GossipPolicy::LocalOnly` with `warn!` logging. Only explicit absence of `nodes` permits `BroadcastAll`.
