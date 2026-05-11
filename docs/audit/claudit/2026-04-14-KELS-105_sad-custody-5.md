# Branch Audit: KELS-105_sad-custody (Round 5) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering. 32 files changed, ~3900 lines. Focus: post-consumption data lifecycle, MinIO cleanup gaps, fallback path authorization.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 1    | 2        |
| Medium   | 0    | 11       |
| Low      | 1    | 3        |

All 7 findings from round 1 are resolved. 4 of 5 findings from round 2 are resolved (finding #10 remains open by design). All 3 findings from round 3 are resolved. 1 new high finding in round 5.

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED (Round 1)

**Resolution:** Two-phase compaction in `compaction.rs`.

### ~~2. `resolve_gossip_policy` fails open when nodes can't be resolved~~ — RESOLVED (Round 2)

**Resolution:** All NodeSet resolution error paths now return `GossipPolicy::LocalOnly`.

### 15. Consumed `once` records remain accessible via MinIO fallback, bypassing `readPolicy`

**File:** `services/sadstore/src/handlers.rs:786-790`, `services/sadstore/src/handlers.rs:872-883`

When a `once` record is consumed, the DB index entry is atomically deleted (`delete_by_sad_said` returns count=1) and the data is served from MinIO. However, the MinIO object is never deleted. On subsequent fetch requests, `get_by_sad_said` returns `Ok(None)` (no index entry), and the handler falls through to the "not tracked in index" path at line 788-790:

```rust
Ok(None) => {
    // Not tracked in index — try MinIO directly (legacy or uncustodied)
    return serve_from_minio(&state.object_store, &object_said).await;
}
```

This serves the object from MinIO without any custody checks. Consequences:

1. **`once` atomicity is broken** — the data remains accessible after consumption by anyone who knows the SAID.
2. **`readPolicy` bypass** — if the record had a `readPolicy`, it is no longer enforced after the first consumption. The fallback path skips all custody resolution, readPolicy evaluation, and authentication.

The TTL reaper correctly deletes both the DB entry and the MinIO object for expired records (`handlers.rs:110-128`), but the `once` consumption path only deletes the DB entry.

**Suggested fix:** After serving from MinIO in the `once` consumption path (line 883), delete the MinIO object as a fire-and-forget background operation:

```rust
Ok(1) => {
    let response = serve_from_minio(&state.object_store, &object_said).await;
    // Best-effort MinIO cleanup — prevents post-consumption access
    let os = state.object_store.clone();
    let said = object_said;
    tokio::spawn(async move {
        if let Err(e) = os.delete(&said).await {
            warn!("Failed to delete consumed once object {} from MinIO: {}", said, e);
        }
    });
    return response;
}
```

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

**File:** `services/sadstore/src/handlers.rs:872-897`

Working as intended: `once` without `readPolicy` is a public ephemeral record. Note: this interacts with finding #15 — even without `readPolicy`, the `once` semantics are broken because the data remains accessible after consumption.

---

## Positive Observations

- **Two-phase compaction with depth bound is solid.** `compact_sad`/`commit_compacted` in `compaction.rs` correctly separates SAID computation from storage, preventing resource amplification. The `MAX_COMPACTION_DEPTH = 32` bound prevents stack exhaustion. The `compact_value` function correctly processes depth-first (compact children before computing parent's canonical SAID).

- **Chain divergence handling in `save_batch` is well-guarded.** The pre-insert divergence check at `repository.rs:36-48` prevents appends to frozen chains, and the advisory lock serializes concurrent writes. The `GROUP BY version` approach is efficient and correct for detecting >1 record at any version.

- **Pointer custody validation iterates all records with deduplication.** The `HashSet<cesr::Digest256>` at `handlers.rs:1120-1133` correctly validates every unique custody SAID in the batch, not just the first record, while avoiding redundant validation for records sharing the same custody.

- **`SadChainVerifier` generation buffering handles page boundaries correctly.** The verifier accumulates records at the same version in `generation_buffer`, flushing when the version changes. This ensures same-generation records are processed together even when split across pages. The `finish()` call flushes the final generation.

- **TTL reaper correctly cleans up both DB and MinIO.** The reaper at `handlers.rs:110-128` deletes the DB entry via the repository method (consistent with `once`), then deletes from MinIO with best-effort semantics. The per-custody iteration with `BATCH_SIZE` bound prevents unbounded queries. This stands in contrast to the `once` path (finding #15) which only cleans up the DB side.

- **readPolicy downgrade prevention via `read_policy` field in `SadFetchRequest`.** The signer commits to which readPolicy they're satisfying (line 826-833), preventing an attacker from submitting a request against a different (weaker) policy. This is a clean defense against downgrade attacks.
