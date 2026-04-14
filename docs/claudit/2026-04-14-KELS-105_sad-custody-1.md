# Branch Audit: KELS-105_sad-custody (Round 1) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip nodes filtering. 28 files changed, ~3300 lines.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 4        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED

**File:** `services/sadstore/src/compaction.rs`, `services/sadstore/src/handlers.rs`

~~The write path verifies the parent's SAID, then compacts. But compaction stores nested SADs in MinIO before the parent's identity is confirmed — resource amplification vector.~~

**Resolution:** Compaction is now two-phase: `compact_sad()` computes SAIDs and builds compacted JSON in memory (no MinIO writes), then `commit_compacted()` writes to MinIO only after the HEAD check passes. The handler sequence is: verify SAID → compact in memory → derive canonical SAID → HEAD check → commit nested SADs → store parent.

---

## Medium Priority

### ~~2. `extract_and_cache_custody` returns `Ok(Some(said))` for pre-compacted custody SAID without validation~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs`

~~When the `custody` field is already a SAID string, the function immediately returned without validation or policy caching.~~

**Resolution:** Added `resolve_and_cache_custody_by_said()` helper. The pre-compacted SAID path now resolves the custody from cache (or MinIO fallback), validates the context-specific allowlist via `parse_and_validate_custody()`, caches the custody and referenced policies. Rejects if unresolvable.

### ~~3. TTL reaper uses custody SAID equality, not custody SAID join~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs`

~~The reaper used `custody.said.as_ref()` for the custody column match, with implicit format coupling.~~

**Resolution:** Changed to `custody.said.to_string()` to explicitly match the format stored by the Stored derive's insert path.

### ~~4. `once` delete uses `pool.delete()` directly, bypassing the repository layer~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs`, `services/sadstore/src/handlers.rs`

~~The handler reached into `pool` directly for the atomic delete.~~

**Resolution:** Added `SadObjectIndex::delete_by_sad_said()` method that encapsulates the delete and returns the count. The `once` handler path now calls this method.

### ~~5. `submit_sad_pointer` doesn't validate custody context for pointer records~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs`

~~Pointer records with custody containing `ttl`/`once` were accepted silently.~~

**Resolution:** Added pointer custody validation after prefix verification. If `records[0].custody` is Some, the handler calls `resolve_and_cache_custody_by_said()` with `CustodyContext::Pointer`, which rejects `ttl`/`once` with explicit errors.

---

## Low Priority

### ~~6. Unused imports in repair tests~~ — RESOLVED

**File:** `services/sadstore/tests/repair_tests.rs`

~~`cesr::{SigningKey, VerificationKey, generate_secp256r1}` imports, `test_keys()`, and `_sk` parameters were vestigial.~~

**Resolution:** Removed `test_keys()`, all `_sk` parameters from `build_chain`/`build_replacement`, and the unused cesr signing imports.

### ~~7. `SadPointerVerification::current_content()` renamed but doc still references old field~~ — RESOLVED

**File:** `docs/design/sadstore.md`

~~Documentation referenced `current_content_said()` and `establishment_serial()` which no longer exist.~~

**Resolution:** Updated the verification section in `docs/design/sadstore.md` to reflect single-pass structural verification with current accessor names.

---

## Positive Observations

- **Clean separation of compaction and storage.** The `compact_sad` function in `compaction.rs` is a well-isolated recursive walker with proper depth bounds. It handles the remove-compact-reinsert pattern to work around Rust's borrow checker cleanly, and the `compact_value` vs `compact_children` split correctly avoids compacting the top-level SAD.

- **Custody validation is thorough and well-structured.** The `CustodyContext` enum + `parse_and_validate_custody` function correctly distinguishes SAD object vs pointer contexts, applies the safety valve for unknown fields, and gives explicit rejection messages for known-but-disallowed fields. The test coverage (15 tests) is comprehensive.

- **`evaluate_signed_policy` is a clean simplification.** The new function correctly walks the same policy AST as `evaluate_anchored_policy` but checks prefix set membership instead of KEL anchors — no async KEL calls, no poison checks. The cycle detection and depth limiting are preserved. The test suite covers the key scenarios including nested policies and the no-poison-checks guarantee.

- **Atomic `once` semantics via delete count.** Using `delete()` return count (1 = consumed, 0 = already consumed) is a clean solution that provides the same serialization guarantee as `DELETE ... RETURNING *` without requiring framework changes. The comment about MinIO fetch failure being acceptable for ephemeral records documents the known edge case.

- **Pointer re-keying is a massive net simplification.** Removing `SadPointerSignature`, `SignedSadPointer`, the two-pass verification approach, all establishment serial tracking, and the KEL verification dependency from pointer operations is a -1000 line win. The structural-only `SadChainVerifier` is dramatically simpler while preserving the same divergence detection semantics.

- **TTL reaper is conservative and bounded.** The batch-limited (100 records/cycle), per-custody iteration pattern avoids unbounded queries. Best-effort MinIO cleanup with warn-level logging on failure is the right tradeoff — orphaned objects are harmless, and the reaper will retry on the next cycle.
