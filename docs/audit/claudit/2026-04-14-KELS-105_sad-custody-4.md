# Branch Audit: KELS-105_sad-custody (Round 4) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering. 32 files changed, ~3900 lines. Focus: edge cases in new write paths, custody-gossip interaction, chain repair atomicity, MinIO orphan scenarios.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 11       |
| Low      | 1    | 3        |

All 7 findings from round 1 are resolved. 4 of 5 findings from round 2 are resolved (finding #10 remains open by design). All 3 findings from round 3 are resolved. 1 new finding from round 4 accepted by design.

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

### ~~11. `resolve_gossip_policy` fails open when custody SAID exists but custody record is unresolvable~~ — RESOLVED (Round 3)

**Resolution:** Both `Ok(None)` and `Err` arms now return `GossipPolicy::LocalOnly`.

### ~~12. Missing index on `sad_objects.custody` for TTL reaper queries~~ — RESOLVED (Round 3)

**Resolution:** Added `sad_objects_custody_idx`.

### ~~13. `submit_sad_pointer` only validates custody on `records[0]`~~ — RESOLVED (Round 3)

**Resolution:** Iterates all records, validates every unique custody SAID.

### ~~14. TTL reaper timing across nodes~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:110-128`

~~Initially flagged as a potential issue where one node's reaper could affect another node's MinIO. Not applicable — each node has its own MinIO instance, so reaper operations are node-local and cannot interfere with peer nodes' object stores.~~

**Resolution:** Not a real finding. Each node has its own MinIO; reapers are purely local.

---

## Low Priority

### 10. `once: true` without `readPolicy` allows unauthenticated consumption — OPEN BY DESIGN (Round 2)

**File:** `services/sadstore/src/handlers.rs:872-897`

Working as intended: `once` without `readPolicy` is a public ephemeral record.

---

## Positive Observations

- **Pointer re-keying is a clean, complete simplification.** The removal of `SignedSadPointer`, `SadPointerSignature`, `establishment_serial`, and KEL verification from pointer operations is consistent across all layers: core types (`pointer.rs`), client (`sadstore.rs`), CLI (`exchange.rs`, `sad.rs`), FFI (`sad.rs`), handlers, repository, and tests. The `write_policy` field replaces the old `kel_prefix`-based derivation with a more general mechanism that decouples chain ownership from KEL identity — the exchange CLI shows the natural pattern where `write_policy = kel_prefix`.

- **`SadChainVerifier` generation-buffering is correct and well-tested.** The `flush_generation` method at `verification.rs:88-184` correctly handles the critical edge cases: single v0 inception, max 2 records per generation (owner + adversary fork), branch tracking via `HashMap<Digest256, SadBranchState>`, un-extended branches carried forward. Multi-page test at `verification.rs:295-312` exercises page boundary splits. The `finish()` method correctly picks the highest-version tip.

- **Custody context validation with safety valve is principled.** `parse_and_validate_custody` at `custody.rs:122-162` orders checks correctly: unknown fields trigger the safety valve first (returning `Ok(None)`), then context-specific rejections for known-but-disallowed fields (`ttl`/`once` on pointers), then structural requirements (`once` requires `nodes`). This means newer clients can always store data, while older servers enforce what they understand.

- **Chain repair with audit trail is well-structured.** `truncate_and_replace` in `repository.rs:80-173` correctly: skips leading records that already exist (deduplication), pages through displaced records for archival, creates the repair audit record lazily (only if records are actually displaced), uses advisory locks for serialization, and performs everything in a single transaction. The test coverage (`repair_tests.rs`) exercises full replacement from v0, partial replacement, pagination of repairs and archived records.

- **Two-phase compaction with depth bound prevents both resource amplification and stack exhaustion.** `compact_sad`/`commit_compacted` in `compaction.rs` correctly separates SAID computation from storage. The `MAX_COMPACTION_DEPTH = 32` bound at both `compact_children` and `compact_value` entry points prevents stack overflow from malicious nesting. The `compact_value` function correctly processes depth-first (compact children before computing parent's canonical SAID).

- **readPolicy enforcement is thorough end-to-end.** The fetch handler at `handlers.rs:774-899` correctly chains: parse signed/unsigned request → look up index entry → resolve custody → enforce readPolicy (verify signatures, evaluate policy against verified prefixes) → check TTL → enforce `once` semantics. The `SadFetchRequest` type includes `read_policy` so the signer commits to which policy they're satisfying, preventing downgrade attacks where an attacker submits a request against a different policy.
