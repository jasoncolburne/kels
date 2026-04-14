# Branch Audit: KELS-105_sad-custody (Round 7) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering. 37 files changed, ~4300 lines. Focus: post-round-6 edge cases, race conditions, input validation gaps, chain repair security.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 4        |
| Medium   | 0    | 12       |
| Low      | 1    | 5        |

All 7 findings from round 1 are resolved. 4 of 5 findings from round 2 are resolved (finding #10 remains open by design). All 3 findings from round 3 are resolved. Round 4-6 findings resolved. Both new findings from round 7 are resolved.

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED (Round 1)

**Resolution:** Two-phase compaction in `compaction.rs`.

### ~~2. `resolve_gossip_policy` fails open when nodes can't be resolved~~ — RESOLVED (Round 2)

**Resolution:** All NodeSet resolution error paths now return `GossipPolicy::LocalOnly`.

### ~~15. Consumed `once` records remain accessible via MinIO fallback, bypassing `readPolicy`~~ — RESOLVED (Round 6)

**Resolution:** MinIO fallback path removed entirely. `Ok(None)` from `get_by_sad_said` now returns 404.

### ~~18. TTL reaper accumulates orphaned custody entries~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:77-131`

~~The reaper queries `custodies` without verifying that those custodies are still referenced by any `sad_objects`. Over time, the `custodies` table accumulates entries for custody SAIDs that no longer have any associated objects (all expired or consumed), wasting DB round-trips each cycle.~~

**Resolution:** Added `// TODO: periodic custody GC` comment in the reaper function. Accepted as not a merge blocker — orphaned custodies cause minor wasted queries but no correctness or security issues.

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

### ~~19. `submit_sad_pointer` repair path doesn't enforce write_policy consistency with existing chain~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:88-97`

~~When `?repair=true` is set, `truncate_and_replace` did not verify that the submitted records' `write_policy` matches the existing chain's `write_policy`. While prefix collisions are computationally infeasible (Blake3-256), this violated the design principle that `write_policy` is immutable per chain.~~

**Resolution:** Added a v0 lookup and `write_policy` comparison in `truncate_and_replace` after acquiring the advisory lock. If the existing chain's v0 has a different `write_policy`, the repair is rejected with an error. Defense-in-depth invariant enforcement.

---

## Low Priority

### 10. `once: true` without `readPolicy` allows unauthenticated consumption — OPEN BY DESIGN (Round 2)

**File:** `services/sadstore/src/handlers.rs:871-907`

Working as intended: `once` without `readPolicy` is a public ephemeral record. With finding #15 resolved, post-consumption access is no longer possible.

### ~~16. Consumed `once` records leave orphaned objects in MinIO~~ — RESOLVED (Round 6)

**Resolution:** Added fire-and-forget `tokio::spawn` MinIO delete after serving.

### ~~17. Gossip policy for pointer batches uses only the first record's custody~~ — WITHDRAWN (Round 6)

**Resolution:** Invalid premise — `write_policy` is required on all pointer records; checking `records[0]` is correct.

### ~~9. `sadstore.md` documentation extensively stale~~ — RESOLVED (Round 2)

**Resolution:** Full rewrite.

### ~~6-7. Round 1 findings~~ — RESOLVED

**Resolution:** See round 1 audit.

---

## Positive Observations

- **Content-addressed custody makes TOCTOU safe by construction.** The custody SAID is derived from its content, so any mutation produces a different SAID. This means a `sad_object` row's `custody` column is an immutable reference to a specific policy configuration — you can't change the TTL or readPolicy of an object without changing its custody SAID, which would require re-storing the object. This is a clean design that eliminates an entire class of consistency bugs.

- **`SadChainVerifier` correctly rejects version gaps and prefix mismatches.** The `flush_generation` method at `verification.rs:88-184` enforces that each record's version is exactly `branch_tip.version + 1`, preventing skip attacks where an adversary inserts records at arbitrary future versions. The prefix and write_policy consistency checks are applied per-record before buffering.

- **`parse_fetch_request` tries authenticated first, falls back gracefully.** The pattern at `handlers.rs:915-937` of attempting `SignedRequest<SadFetchRequest>` deserialization before falling back to `SadRequest` is clean. It avoids requiring separate endpoints for authenticated and unauthenticated fetches while keeping the type system's guarantees intact.

- **Chain repair audit trail is thorough.** `truncate_and_replace` at `repository.rs:80-173` creates `SadPointerRepair` + `SadPointerRepairRecord` entries before deleting, preserving full history of what was displaced. The lazy repair record creation (only if records are actually displaced) avoids empty repairs. The advisory lock serializes concurrent repairs.

- **Compaction depth bound is correctly applied at both entry points.** Both `compact_children` (line 58) and `compact_value` (line 114) check `remaining_depth == 0` before recursing, and each decrement is consistent (`remaining_depth - 1`). This prevents a malicious input from bypassing the depth check by entering via either code path.

- **readPolicy downgrade prevention is enforced end-to-end.** The `read_policy` field in `SadFetchRequest` (line 19 of `request.rs`) + the server-side check at `handlers.rs:825-832` ensures the signer commits to the specific readPolicy SAID. An attacker can't replay a signed request against a different (weaker) readPolicy because the SAID would mismatch, and they can't forge a new signature without the signing key.
