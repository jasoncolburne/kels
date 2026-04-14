# Branch Audit: KELS-105_sad-custody (Round 2) — 2026-04-14

SAD object custody: compacting store, per-record policy, pointer re-keying, readPolicy enforcement, TTL reaper, gossip filtering, evaluate_signed_policy. 30 files changed, ~3600 lines. Focus: post-resolution issues from round 1, new code paths, integration test validity.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 7        |
| Low      | 1    | 3        |

All 7 findings from round 1 are resolved. 4 of 5 new findings from round 2 are resolved. Finding #10 is open by design (working as intended).

---

## High Priority

### ~~1. Compaction stores nested SADs before SAID verification of the parent~~ — RESOLVED (Round 1)

**Resolution:** Two-phase compaction in `compaction.rs`.

### ~~2. `resolve_gossip_policy` fails open when nodes can't be resolved~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:536-581`

~~The `resolve_gossip_policy` function returns `GossipPolicy::BroadcastAll` when it fails to resolve a custody's `NodeSet` from MinIO (parse failure, fetch failure, or missing custody). This violates the project's fail-secure principle.~~

**Resolution:** Changed all NodeSet resolution error paths to return `GossipPolicy::LocalOnly` with warn-level logging. When `custody.nodes` is set but unresolvable, gossip is skipped rather than broadcasting to all peers. Only falls through to `BroadcastAll` when no `nodes` restriction exists.

---

## Medium Priority

### ~~2-5. Round 1 findings~~ — RESOLVED

**Resolution:** See round 1 audit for details on custody SAID validation, TTL reaper format, repository delete encapsulation, and pointer custody validation.

### ~~6. Two integration tests pass for the wrong reason (route mismatch)~~ — RESOLVED

**File:** `services/sadstore/tests/integration_tests.rs:370-404`

~~`test_chain_fetch_not_found` uses `GET /api/v1/sad/pointers/{prefix}` and `test_effective_said_not_found` uses `GET /api/v1/sad/pointers/{prefix}/effective-said`. Neither route exists — the 404 came from the router, not from chain lookup logic.~~

**Resolution:** Changed both tests to use POST with JSON request bodies (`SadPointerPageRequest` and `SadPointerEffectiveSaidRequest`), matching the actual API contract.

### ~~7. TTL reaper bypasses `delete_by_sad_said` repository method~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:109-114`

~~The TTL reaper constructed its own `Delete` query directly against `pool.delete()` instead of calling `delete_by_sad_said()`.~~

**Resolution:** Replaced the raw delete with `state.repo.sad_objects.delete_by_sad_said(&entry.sad_said).await?;`, consistent with the `once` code path.

### ~~8. `evaluate_signed_policy` Delegate node checks only the delegator~~ — RESOLVED

**File:** `lib/policy/src/evaluator.rs:443-454`

~~For `PolicyNode::Delegate(delegator, delegate)` in `evaluate_signed_node`, only the delegator's prefix was checked. This made delegation useless for readPolicy.~~

**Resolution:** `evaluate_signed_node` now rejects `Delegate` nodes with `PolicyError::EvaluationError`. Delegation is an issuance concern for scaling credential issuance via delegation chains (#77), not an access-control concern. readPolicies should use direct `endorse()` nodes. Added `test_signed_policy_rejects_delegate_nodes` test. Updated `docs/design/sadstore.md` with a "Policy evaluation modes" section documenting the distinction.

---

## Low Priority

### ~~6-7. Round 1 findings~~ — RESOLVED

**Resolution:** See round 1 audit for details on unused imports in repair tests and stale doc references.

### ~~9. `sadstore.md` documentation extensively stale after pointer re-keying~~ — RESOLVED

**File:** `docs/design/sadstore.md`

~~Multiple sections referenced removed concepts (`kel_prefix`, `kind`, `SignedSadPointer`, `establishment_serial`, etc.). API table showed GET methods with path parameters.~~

**Resolution:** Full rewrite of `sadstore.md`. Updated: field names (`write_policy`, `topic`, `content`), removed obsolete types, corrected all API endpoints to POST, added Custody/NodeSet documentation, added "Policy evaluation modes" section documenting `evaluate_anchored_policy` vs `evaluate_signed_policy`, added Gossip Policy section with fail-secure documentation, updated CLI commands, added TTL reaper config, added new use cases.

### 10. `once: true` without `readPolicy` allows unauthenticated consumption

**File:** `services/sadstore/src/handlers.rs:849-874`, `lib/kels/src/types/sad/custody.rs:155`

When a SAD object has `once: true` + `nodes` but no `readPolicy`, any unauthenticated client that can reach the node can consume the object (triggering the atomic delete). Working as intended: `once` without `readPolicy` is a public ephemeral record. If the creator wants to restrict who consumes it, they add `readPolicy`.

---

## Positive Observations

- **Deterministic pointer prefix derivation from `(write_policy, topic)` is a clean design.** The v0 inception record contains only deterministic fields (no content, no created_at), so anyone can compute the chain prefix offline. The `compute_sad_pointer_prefix` function in `pointer.rs:56-62` correctly constructs and derives. Exchange commands in `exchange.rs:16-17` show the natural pattern: write_policy = KEL prefix for owner-authored chains.

- **Custody validation safety valve is well-reasoned.** Unknown fields in `parse_and_validate_custody` disengage server-side enforcement (return `Ok(None)`) rather than rejecting. This means future custody extensions from newer clients won't be blocked by older servers — the enforcement just gracefully degrades. The test at `custody.rs:340-358` covers this.

- **`SadChainVerifier` handles divergence correctly across page boundaries.** The generation-buffering approach (`generation_buffer` + `current_generation_version`) ensures that records at the same version are processed together even when split across pages. Branch tracking via `HashMap<Digest256, SadBranchState>` correctly handles fork extension and carries un-extended branches forward.

- **Two-phase compaction prevents resource amplification.** The `compact_sad`/`commit_compacted` split in `compaction.rs` ensures nested SADs are never written to MinIO until the parent's canonical SAID is confirmed via HEAD check. This is a clean defense against an attacker submitting expanded SADs to fill storage.

- **`evaluate_signed_policy` now correctly rejects Delegate nodes.** The clear separation between issuance-context evaluation (anchored, supports delegation) and access-control evaluation (signed, rejects delegation) eliminates a semantic confusion. The new test and documentation make the design intent explicit.

- **Atomic `once` semantics via delete count remain solid.** The `delete_by_sad_said` encapsulation from round 1 is clean. The three-way match on delete count (1 = consumed, 0 = already consumed, other = error) at `handlers.rs:851-873` correctly handles all cases including the MinIO fetch-after-delete edge case documented in the comment.
