# SEL Submit Protocol

This document describes the submit / merge protocol used when new events are submitted to a SAD Event Log (SEL). It is the SEL counterpart to [../kel/merge.md](../kel/merge.md). For chain lifecycle and the discriminator algorithm in detail, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler in `services/sadstore/src/handlers.rs::submit_sad_events` integrates new events into an existing SEL while handling:
- Normal event appends
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same version)
- Repair (`Rpr`) — discriminator-driven archival of adversary events
- Contest (`Cnt`) — terminal authority conflict, no archival
- Decommission (`Dec`) — terminal owner-initiated end
- Algorithmic `ContestRequired` for sealed normal-event submissions

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. Authorization is the chain's `write_policy` (for Est / Upd) or `governance_policy` (for Sea / Rpr / Cnt / Dec).

## Submit Outcome

`submit_sad_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if it was rejected (either dropped as duplicates or rejected by routing). |
| `diverged_at_version` | First version at which divergence was observed, or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / divergent / contested / decommissioned per batch contents |
| `ContestRequired` | Normal event submitted at version ≤ `last_governance_version` (write-policy satisfied but seal advanced past submitter's view) | unchanged |
| `RepairRequired` (existing "Chain is divergent — repair required") | Non-Rpr submission to a divergent chain | unchanged |
| `ContestedSel` | Submission to a chain with a `Cnt` event in it | terminal, unchanged |
| `DecommissionedSel` | Submission to a chain with a `Dec` event in it | terminal, unchanged |

## Submit Flow

`submit_sad_events` is the single HTTP entry point for all write paths. It validates the batch, walks the existing chain, then routes to one of several handler paths.

### 1. Structural and Authorization Validation

```
for each event:
    SadEvent::validate_structure()  // per-kind field rules per [events.md](events.md)
    verify event.prefix derives from declared write_policy + topic (for v0)
    verify each batch event shares the same prefix

for v0 (Icp): verify Icp.said is anchored under the declared write_policy
              (the inceptor proves membership in the policy they're naming)
for v1+:      verifier checks anchoring against branch.tracked_write_policy
              or branch.tracked_governance_policy per kind

for events introducing or evolving governance_policy (Icp v0 with G, Est, Sea):
    fetch the referenced policy by SAID
    if not policy.immune: reject with InvalidGovernancePolicy
              (governance-policy immunity rule — see events.md)
```

The Icp authorization gate closes a phishing class where an adversary could otherwise submit a v0 declaring an arbitrary `governance_policy` for a public `(write_policy, topic)` pair — the resulting chain has a different prefix, but a write-authorized party lured into `Upd`-ing on it could later have control rotated out from under them via the adversary's `governance_policy`. Anchoring Icp under `write_policy` ensures only members of the declared policy can incept. See [events.md §Authorization model](events.md#authorization-model).

The governance-policy immunity gate makes the evaluation seal structural: a non-immune policy can never be referenced as `governance_policy`, so no anchor used in a governance evaluation can ever be poisoned. Past evaluations stay satisfied by construction. See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability) for the rationale and the contrast with credential-side poison semantics (which stay current-state-aware).

### 2. Terminal-State Gate

Before routing, check whether the chain is already terminal:

```
if chain has any Cnt event → reject ContestedSel
if chain has any Dec event → reject DecommissionedSel
```

These checks fire before any other routing, including dedup — terminal state means no further events of any kind.

### 3. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 4. Routing

The handler inspects the post-dedup batch for kind discriminators (in priority order):

```
let is_repair = new_events.iter().any(|e| e.kind.is_repair());
let is_contest = new_events.iter().any(|e| e.kind.is_contest());
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

if is_repair       → repair path (truncate_and_replace)
else if is_contest → contest path (insert + mark contested)
else if is_decommission → decommission path (insert + mark decommissioned)
else if chain is divergent → reject RepairRequired
else if normal-event AND version ≤ last_governance_version AND write_policy satisfied → reject ContestRequired
else if event creates a fork (overlap) → insert single forking event, freeze
else → normal append
```

The repair / contest / decommission discriminators bind to the `is_repair` / `is_contest` / `is_decommission` predicates on `SadEventKind` (see [`lib/kels/src/types/sad/event.rs`](events.md)). Any of these kinds at any position in the batch routes to its dedicated path.

### 5. Repair Path

Detected when any batch event has `kind = Rpr`. Calls `repository::truncate_and_replace`, which:

1. Computes archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
2. Fetches one page of events at `version >= L`, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`.
3. Feeds the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`).
4. Walks back from `Rpr.previous` through the verified page, accumulating owner SAIDs.
5. Archives non-owner events; deletes them from `sad_events` by SAID; inserts the new batch (pending events first, then `Rpr`).

Full algorithm: [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator). Mirrors KEL's `archive_adversary_chain` (see [../kel/event-log.md §Server-side discriminator](../kel/event-log.md#server-side-discriminator)).

The repair path also creates `SelRepairEvent` link rows in `sel_repair_events`, providing an immutable audit trail. Archived events are queryable via the repair endpoints (`POST /api/v1/sad/events/repairs` and `.../repairs/events`).

### 6. Contest Path

Detected when any batch event has `kind = Cnt`. Inserts the batch (pending events first, then `Cnt`); no archival. Marks chain as contested. All future submissions return `ContestedSel`.

Contest is governance-authorized; the verifier confirms `Cnt` satisfies `governance_policy` before insertion.

### 7. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All future submissions return `DecommissionedSel`.

### 8. Normal Append

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ContestRequired` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event.version ≤ last_governance_version
   AND write_policy is satisfied
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ContestRequired
```

This fires when a write-authorized normal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain (someone with `governance_policy` authority issued a `Sea`/`Rpr` while the submitter had stale state). The submitter has authority but cannot proceed via normal append; they must accept, contest, or abandon.

This mirrors KEL's `ContestRequired` shape: someone else used the privileged primitive (KEL: revealed the recovery key; SEL: advanced the seal), and safe normal-flow continuation is no longer possible. See [event-log.md §Contest (Cnt)](event-log.md#contest-cnt).

### 9. Overlap (non-divergent KEL, fork-creating event)

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

All SEL queries use `ORDER BY version ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same version. The `CASE` expression uses `SadEventKind::sort_priority()` to ensure state-determining events (Sea, Rpr, Cnt, Dec) sort after normal events at the same version. `MINIMUM_PAGE_SIZE = 64` controls page size for both reads and the discriminator's single-page fetch.

## Key Invariants

1. **Events are sorted deterministically** — by `(version, kind_priority, said)`. The SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored (the chain freezes after).
3. **Governance-evaluation events are bounded** — proactive evaluation (`MAX_NON_EVALUATION_EVENTS = 63`) caps non-evaluation runs; the next event after 63 must be `Sea`/`Rpr`/`Cnt`/`Dec`.
4. **Repair cannot truncate at or before the evaluation seal** — `truncate_and_replace` rejects `from_version ≤ last_governance_version`.
5. **Terminal states are permanent** — any `Cnt` or `Dec` in the chain freezes it; no future submissions accepted.
6. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.

## References

- [event-log.md](event-log.md) — Chain lifecycle and the discriminator algorithm in detail.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../sadstore.md](../sadstore.md) — SADStore service architecture.
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
