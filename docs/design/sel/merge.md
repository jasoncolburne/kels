# SEL Submit Protocol

This document describes the submit / merge protocol used when new events are submitted to a SAD Event Log (SEL). It is the SEL counterpart to [../iel/merge.md](../iel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle and the discriminator algorithm in detail, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler in `services/sadstore/src/handlers.rs::submit_sad_events` integrates new events into an existing SEL while handling:
- Inception batches (`[Icp, Upd, ...]` minimum — Icp alone is rejected)
- Normal event appends (`Upd`, `Sea`)
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same version)
- Repair (`Rpr`) — discriminator-driven archival of adversary events
- Contest (`Cnt`) — terminal authority conflict, no archival
- Decommission (`Dec`) — terminal owner-initiated end
- Algorithmic `ContestRequired` for normal-event submissions when the seal has advanced past the submitter's view

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. **Authorization for v1+ events is resolved through the bound IEL** via each event's `identity_event` field. See [event-log.md §Authorization via IEL](event-log.md#authorization-via-iel--and-why-thats-enough).

## Submit Outcome

`submit_sad_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected. |
| `diverged_at_version` | First version at which divergence was observed, or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / divergent / contested / decommissioned per batch contents |
| `ContestRequired { reason }` | Normal-event at version ≤ `last_governance_version` (write-authorized but seal advanced past submitter's view) | unchanged |
| `RepairRequired` | Non-Rpr submission to a divergent chain | unchanged |
| `ContestedSel` | Submission to a chain with a `Cnt` event in it | terminal, unchanged |
| `DecommissionedSel` | Submission to a chain with a `Dec` event in it | terminal, unchanged |
| `IncompleteInception` | Submission contains `Icp` but not `Upd` at v1 | unchanged (rejected) |
| `BadIdentityBinding(reason)` | `identity_event` does not resolve to a real IEL event with matching prefix, or fails monotonic ratchet | unchanged |
| `IelDivergent(prefix)` | Bound IEL event is on a divergent IEL branch | unchanged |

## Submit Flow

`submit_sad_events` is the single HTTP entry point for all write paths. It validates the batch, walks the existing chain, then routes to one of several handler paths.

### 1. Structural and Authorization Validation

```
for each event:
    SadEvent::validate_structure()  // per-kind field rules per [events.md]
    verify event.prefix derives from declared (identity, topic) for v0
    verify each batch event shares the same prefix

for v0 (Icp): no authorization gate (permissionless, deterministic prefix derivation)
              BUT: batch must contain an Upd at v1 (inception batch rule)

for v1+: cross-chain authorization resolution:
    fetch IEL event by event.identity_event
    confirm IEL event's prefix == SE chain's bound identity
    if IEL is divergent at the bound branch → reject IelDivergent

    pick the relevant policy:
        Upd → IEL-resolved auth_policy at identity_event
        Sea/Rpr/Cnt/Dec → IEL-resolved governance_policy at identity_event

    verify event.said is anchored under the resolved policy

    monotonic ratchet check:
        event.identity_event must be at-or-after branch.last_identity_event
        in IEL chain order; reject BadIdentityBinding otherwise
```

The `identity_event` resolution may walk back through the IEL chain if the named event doesn't carry the relevant policy field (e.g., `identity_event` points at an Evl that evolved governance only; the auth_policy in effect is what was tracked at that version, which may have been seeded at IEL Icp). The walk is bounded by IEL chain length and cached aggressively.

### 2. Inception Batch Rule

```
if batch contains Icp:
    if batch does NOT contain Upd at version 1 (in same submission):
        reject IncompleteInception
```

SE Icp is permissionless and deterministic, so anyone can submit `[Icp]` alone — but doing so produces a chain with no content and no authorized event. The rule forces inception batches to include at least one Upd (which carries `identity_event` and is policy-enforced), so every chain is born with both content and a binding. See [events.md §Inception batch rule](events.md#inception-batch-rule).

### 3. Terminal-State Gate

```
if chain has any Cnt event → reject ContestedSel
if chain has any Dec event → reject DecommissionedSel
```

Fires before all other routing. Terminal state means no further events of any kind.

### 4. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 5. Routing

The handler inspects the post-dedup batch for kind discriminators:

```
let is_repair = new_events.iter().any(|e| e.kind.is_repair());
let is_contest = new_events.iter().any(|e| e.kind.is_contest());
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

if is_repair       → repair path (truncate_and_replace)
else if is_contest → contest path (insert + mark contested)
else if is_decommission → decommission path (insert + mark decommissioned)
else if chain is divergent → reject RepairRequired
else if normal-event AND version ≤ last_governance_version AND auth_policy satisfied → reject ContestRequired
else if event creates a fork (overlap) → insert single forking event, freeze
else → normal append
```

The repair / contest / decommission discriminators bind to predicate methods on `SadEventKind`. Any of these kinds at any position in the batch routes to its dedicated path.

### 6. Repair Path

Detected when any batch event has `kind = Rpr`. Calls `repository::truncate_and_replace`, which:

1. Computes archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
2. Fetches one page of events at `version >= L`, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`.
3. Feeds the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`).
4. Walks back from `Rpr.previous` through the verified page, accumulating owner SAIDs.
5. Archives non-owner events; deletes them from `sad_events` by SAID; inserts the new batch (pending events first, then `Rpr`).

Full algorithm: [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator). Mirrors KEL's `archive_adversary_chain`.

The repair path also creates `SelRepairEvent` link rows in `sel_repair_events`, providing an immutable audit trail. Archived events are queryable via the repair endpoints (`POST /api/v1/sad/events/repairs` and `.../repairs/events`).

### 7. Contest Path

Detected when any batch event has `kind = Cnt`. Inserts the batch (pending events first, then `Cnt`); no archival. Marks chain as contested. All future submissions return `ContestedSel`.

Contest is governance-authorized via IEL; the verifier confirms `Cnt` satisfies the IEL-resolved governance_policy before insertion.

### 8. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All future submissions return `DecommissionedSel`.

### 9. Normal Append

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ContestRequired` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event.version ≤ last_governance_version
   AND auth_policy was satisfied (from §1)
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ContestRequired { reason: "..." }
```

This fires when a write-authorized normal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain (someone with governance authority issued a `Sea`/`Rpr` while the submitter had stale state). The submitter has authority but cannot proceed via normal append; they must accept, contest, or abandon.

Note that the §1 cross-chain authorization check is the gate for "auth_policy satisfied" — by the time §9 runs, the new event has already passed its anchoring check upstream. The `ContestRequired` trigger here is the existing-chain sanity floor (the chain wasn't already broken), combined with the version-vs-seal arithmetic.

This mirrors KEL's `ContestRequired` shape: someone else used the privileged primitive (KEL: revealed the recovery key; SEL: advanced the seal), and safe normal-flow continuation is no longer possible. See [event-log.md §Contest (Cnt)](event-log.md#contest-cnt).

### 10. Overlap (non-divergent SEL, fork-creating event)

When a non-Rpr/Cnt/Dec event chains from an event earlier than the current tip:

```
diverged_at_version = first_branch_point.version + 1
insert single forking event (the first batch event that creates the fork)
return applied: true, diverged_at: Some(diverged_at_version)
```

Subsequent submissions return `RepairRequired` until owner repairs.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock (Postgres `pg_advisory_xact_lock`) so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `SelVerifier::new` from offset 0, or `resume` from a cached `SelVerification` if available).
2. Validate, dedup, route as above.
3. Insert / archive as the path requires.
4. Publish to Redis (`sel_updates`) for gossip propagation if any path mutated chain state.

The `SelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../security-invariant.md](../security-invariant.md)).

## Pagination

All SEL queries use `ORDER BY version ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same version. `MINIMUM_PAGE_SIZE = 64` controls page size for both reads and the discriminator's single-page fetch.

## Key Invariants

1. **Events are sorted deterministically** — by `(version, kind_priority, said)`. SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored.
3. **Governance-evaluation events are bounded** — proactive evaluation (`MAX_NON_EVALUATION_EVENTS = 63`) caps non-evaluation runs; the next event after 63 must be `Sea`/`Rpr`/`Cnt`/`Dec`.
4. **Repair cannot truncate at or before the evaluation seal** — `truncate_and_replace` rejects `from_version ≤ last_governance_version`.
5. **Terminal states are permanent** — any `Cnt` or `Dec` in the chain freezes it.
6. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.
7. **Inception is permissionless but bounded by batch rule** — Icp alone is rejected; `[Icp, Upd, ...]` is the minimum legal inception batch.
8. **Cross-chain bindings are path-agnostic** — same validation rules at submit, gossip, bootstrap, re-verification.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm in detail.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../iel/merge.md](../iel/merge.md) — IEL counterpart.
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle and cross-chain anchor stability.
- [../sadstore.md](../sadstore.md) — SADStore service architecture.
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
