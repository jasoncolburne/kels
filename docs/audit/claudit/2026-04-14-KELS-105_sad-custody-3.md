# Branch Audit: KELS-105_sad-custody (Round 3) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering. 31 files changed, ~3900 lines. Focus: fail-secure gaps post-round-2, schema/index coverage, batch validation edge cases.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 10       |
| Low      | 1    | 3        |

All 7 findings from round 1 are resolved. 4 of 5 findings from round 2 are resolved (finding #10 remains open by design). All 3 new findings from round 3 are resolved.

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED (Round 1)

**Resolution:** Two-phase compaction in `compaction.rs`.

### ~~2. `resolve_gossip_policy` fails open when nodes can't be resolved~~ — RESOLVED (Round 2)

**Resolution:** All NodeSet resolution error paths now return `GossipPolicy::LocalOnly`.

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

### ~~11. `resolve_gossip_policy` fails open when custody SAID exists but custody record is unresolvable~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:546-559`

~~When `custody_said` is `Some` but the custody record can't be fetched from the Postgres cache (`Ok(None)` or `Err`), the function returns `GossipPolicy::BroadcastAll`. This violates fail-secure.~~

**Resolution:** Both `Ok(None)` and `Err` arms now return `GossipPolicy::LocalOnly` with `warn!` logging, consistent with the NodeSet resolution fix from round 2.

### ~~12. Missing index on `sad_objects.custody` for TTL reaper queries~~ — RESOLVED

**File:** `services/sadstore/migrations/0001_initial.sql:29`

~~The TTL reaper queries `sad_objects` filtered by `custody` without an index, causing sequential scans as the table grows.~~

**Resolution:** Added `CREATE INDEX IF NOT EXISTS sad_objects_custody_idx ON sad_objects(custody);` to the initial migration.

### ~~13. `submit_sad_pointer` only validates custody on `records[0]`~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1105-1120`

~~Pointer custody validation only checked `records[0].custody`. Later records with different custody SAIDs bypassed validation.~~

**Resolution:** Now iterates all records and validates every unique custody SAID against `CustodyContext::Pointer`, using a `HashSet` to skip already-validated SAIDs.

---

## Low Priority

### ~~9. `sadstore.md` documentation extensively stale~~ — RESOLVED (Round 2)

**Resolution:** Full rewrite.

### ~~6-7. Round 1 findings~~ — RESOLVED

**Resolution:** See round 1 audit.

### 10. `once: true` without `readPolicy` allows unauthenticated consumption — OPEN BY DESIGN (Round 2)

**File:** `services/sadstore/src/handlers.rs:859-884`

Working as intended: `once` without `readPolicy` is a public ephemeral record. If the creator wants to restrict who consumes it, they add `readPolicy`.

---

## Positive Observations

- **Write path ensures custody is always cached before gossip resolution.** The handler sequence in both `post_sad_object` and `submit_sad_pointer` guarantees that `extract_and_cache_custody` / `resolve_and_cache_custody_by_said` runs before `resolve_gossip_policy`. This makes the fail-open gap in finding #11 practically unreachable — a good defense-in-depth property even if the gap should still be closed.

- **`SadChainVerifier` generation-buffering handles divergence correctly.** The `flush_generation` method at `verification.rs:88-184` correctly processes same-version records together, tracks per-branch state, carries un-extended branches forward, and rejects >2 records per generation. The multi-page test at `verification.rs:295-312` exercises the critical page-boundary case.

- **Deterministic pointer prefix derivation is clean and well-tested.** The `compute_sad_pointer_prefix` function at `pointer.rs:56-62` creates a v0 pointer from `(write_policy, topic)` alone, making prefixes offline-computable. The exchange CLI at `exchange.rs:16-18` shows the natural pattern. Integration tests at `integration_tests.rs:349-367` verify determinism and collision avoidance.

- **`parse_and_validate_custody` safety valve is principled.** Unknown fields disengage server-side enforcement (`Ok(None)`) rather than rejecting, allowing newer clients to publish records with future custody extensions without being blocked by older servers. The context-specific rejection of `ttl`/`once` on pointers is correctly applied before the safety valve — known-but-disallowed fields are rejected regardless.

- **Two-phase compaction is a solid defense against resource amplification.** `compact_sad`/`commit_compacted` in `compaction.rs` ensures nested SADs are never written to MinIO until the parent's canonical SAID is confirmed via HEAD check. The depth bound at 32 levels prevents stack exhaustion from malicious nesting.

- **`authenticate_peer_request` correctly bounds peer cache refresh.** The "refresh at most once" pattern at `handlers.rs:344-353` prevents an attacker from forcing repeated registry calls by submitting signatures with unknown prefixes. After one refresh, unknown prefixes are silently skipped.
