# SEL Submit Protocol

This document describes the submit / merge protocol used when new events are submitted to a SAD Event Log (SEL). It is the SEL counterpart to [../iel/merge.md](../iel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle and the discriminator algorithm in detail, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler in `services/sadstore/src/handlers.rs::submit_sad_events` integrates new events into an existing SEL while handling:
- Inception batches (`[Icp, Est, ...]` minimum — Icp alone is rejected)
- Normal event appends (`Upd`, `Sea`)
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same version)
- Repair (`Rpr`) — discriminator-driven archival of the events on the branch not extended by `Rpr.previous`
- Contest (`Cnt`) — terminal authority conflict, no archival
- Decommission (`Dec`) — terminal owner-initiated end
- Algorithmic `ContestRequired` for normal-event submissions when the seal has advanced past the submitter's view

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. **Authorization for v1+ events is resolved through the bound IEL** via each event's `identity_event` field. See [event-log.md §Authorization via IEL](event-log.md#authorization-via-iel--and-why-thats-enough).

## Submit Outcome

`submit_sad_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected. |
| `divergence_ancestor` | SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / divergent / contested / decommissioned per batch contents |
| `ContestRequired { reason }` | Normal-event at-or-before `last_governance_event` in chain order (write-authorized but seal advanced past submitter's view) | unchanged |
| `RepairRequired` | Non-Rpr submission to a divergent chain | unchanged |
| `ContestedSel` | Submission to a chain with a `Cnt` event in it | terminal, unchanged |
| `DecommissionedSel` | Submission (other than an overriding `Cnt`) to a chain with a `Dec` event in it | terminal, unchanged |
| `IncompleteInception` | Verifier walked a chain whose tip is `Icp` (no v1 `Est`) | unchanged (rejected) |
| `BadIdentityBinding(reason)` | `identity_event` does not resolve to a real IEL event with matching prefix, or fails per-event parent-monotonic check | unchanged |
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
              BUT: chain may not end at Icp (inception batch rule, enforced inside the verifier)

for v1+: cross-chain authorization resolution:
    fetch IEL event by event.identity_event
    confirm IEL event's prefix == SEL's bound identity
    if IEL is divergent at the bound branch → reject IelDivergent

    pick the relevant policy:
        Est, Upd → IEL-resolved auth_policy at identity_event
        Sea/Rpr/Cnt/Dec → IEL-resolved governance_policy at identity_event

    verify event.said is anchored under the resolved policy with the
    anchor kind required by the event's tier — see
    [§Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation):
        Upd       → Ixn (tier 1)
        Est, Sea  → Rot (tier 2)
        Rpr, Cnt, Dec → Ror (tier 3)
    Each Endorse / Delegate leaf in the resolved policy must have an
    anchor of the required kind. Wrong-kind anchor for any leaf
    contributing to satisfaction → reject.

    per-event parent-monotonic check (per branch):
        event.identity_event must be at-or-after the parent event's identity_event
        (parent via previous SAID; this is the branch's tip identity_event when
        extending an existing branch tip) in IEL chain order; reject
        BadIdentityBinding otherwise. Branches with different parent-chains
        do not constrain each other.
```

The `identity_event` resolution may walk back through the IEL chain if the named event doesn't carry the relevant policy field (e.g., `identity_event` points at an Evl that evolved governance only; the auth_policy in effect is what was tracked at that version, which may have been seeded at IEL Icp). The walk is bounded by IEL chain length and cached aggressively.

### 2. Inception Batch Rule

The rule lives inside the verifier (`SelVerifier::finish_internal`): if any branch tip is still an `Icp`, finalization returns `IncompleteInception`. Icp is structurally pinned to v=0, so an Icp tip is precisely the "lone-`[Icp]` chain" shape. SEL Icp is permissionless and deterministic — anyone can submit `[Icp]` alone — but the resulting chain has no content and no authorized event, so the verifier rejects it at end-verification. The minimum inception batch is `[Icp, Est]`. Every consumer's verifier walk applies the same rule; submit handlers do not duplicate it. See [events.md §Inception batch rule](events.md#inception-batch-rule).

### 3. Terminal-State Gate

```
if chain has any Cnt event → reject ContestedSel
if chain has any Dec event:
    if batch is a single Cnt with previous = v_{d-1}.said (Dec's parent):
        // Cnt-overrides-Dec path — see ../../protocol-doctrine.md §Cnt Overrides Dec.
        // Cnt lands at v_d alongside Dec; privileged-divergence-is-terminal fires;
        // chain becomes Contested. Standard divergent-set verification handles
        // the {Dec, Cnt} set without new walker logic.
        accept and route to contest path
    else:
        reject DecommissionedSel
```

Fires before all other routing. Terminal state means no further events of any kind, with the single exception of an overriding `Cnt` on a Dec'd chain.

### 4. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 5. Routing

The handler inspects the post-dedup batch for kind discriminators and the chain's pre-batch sealed/unsealed predicate:

```
let is_repair       = new_events.iter().any(|e| e.kind.is_repair());
let is_contest      = new_events.iter().any(|e| e.kind.is_contest());
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());
let is_divergent    = first_divergent_version.is_some();
let is_sealed       =
    divergence_ancestor.is_some() && last_governance_event_is_at_or_after(divergence_ancestor);

if is_repair:
    if is_divergent and is_sealed → reject ContestRequired
                                    (can't truncate behind the seal; only Cnt is legal)
    else                          → repair path (truncate_and_replace)
elif is_contest:
                                    → contest path (insert + mark contested)
                                    (Cnt is legal on every non-terminal state, including
                                     both unsealed-divergent and sealed-divergent)
elif is_decommission:
    if is_divergent               → reject RepairRequired (unsealed) /
                                    ContestRequired (sealed)
    else                          → decommission path (insert + mark decommissioned)
elif is_divergent:
    if is_sealed                  → reject ContestRequired (Upd/Sea on sealed-divergent)
    else                          → reject RepairRequired
elif normal-event
       AND event is at-or-before `last_governance_event` in chain order
       AND kind-relevant authorization satisfied
       AND event.kind is non-terminal:
                                    → reject ContestRequired (algorithmic trigger)
elif event creates a fork (overlap):
                                    → insert single forking event, freeze
else:
                                    → normal append
```

The repair / contest / decommission discriminators bind to predicate methods on `SadEventKind`. Any of these kinds at any position in the batch routes to its dedicated path.

The sealed/unsealed predicate is computed from the **pre-batch** snapshot of `divergence_ancestor` and `last_governance_event`; the verifier's run on the new batch doesn't shift the predicate mid-flow. This matches the canonical [reconciliation.md §Local Submissions Matrix](reconciliation.md#local-submissions-matrix), which is the source-of-truth for cell-by-cell expected outcomes.

### 6. Repair Path

Detected when any batch event has `kind = Rpr`. Calls `repository::truncate_and_replace`, which:

1. Computes archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
2. Fetches one page of events at `version >= L`, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`.
3. Feeds the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`).
4. Walks back from `Rpr.previous` through the verified page, accumulating the surviving-branch SAIDs.
5. Archives events on the non-surviving branch; deletes them from `sad_events` by SAID; inserts the new batch (pending events first, then `Rpr`).

Full algorithm: [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator). Mirrors KEL's `archive_adversary_chain`.

The repair path also creates `SelRepairEvent` link rows in `sel_repair_events`, providing an immutable audit trail. Archived events are queryable via the repair endpoints (`POST /api/v1/sad/events/repairs` and `.../repairs/events`).

### 7. Contest Path

Detected when any batch event has `kind = Cnt`. Inserts the batch (pending events first, then `Cnt`); no archival. Marks chain as contested. All future submissions return `ContestedSel`.

Contest is governance-authorized via IEL; the verifier confirms `Cnt` satisfies the IEL-resolved governance_policy before insertion.

### 8. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. Subsequent submissions return `DecommissionedSel`, with one exception: a `Cnt` with `previous = v_{d-1}.said` overrides `Dec` per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec), routes through the contest path, and transitions the chain to Contested.

### 9. Normal Append

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ContestRequired` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event is at-or-before `last_governance_event` in chain order
   AND kind-relevant authorization was satisfied (from §1)
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ContestRequired { reason: "..." }
```

This fires when an authorized non-terminal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain (someone with governance authority issued a `Sea`/`Rpr` while the submitter had stale state). The submitter has authority but cannot proceed via normal append; they must accept, contest, or abandon.

The "kind-relevant authorization" wording matters: an `Upd` that passed its `auth_policy` check but lands at-or-before the seal triggers `ContestRequired`; a `Sea` that passed its `governance_policy` check at the same version triggers it too. Both kinds use the same algorithmic gate — what differs is which IEL-resolved policy the §1 check ran against. By the time §9 runs, the new event has already passed its anchoring check upstream. The `ContestRequired` trigger here is the existing-chain sanity floor (the chain wasn't already broken), combined with the version-vs-seal arithmetic.

This mirrors KEL's `ContestRequired` shape: someone else used the privileged primitive (KEL: revealed the recovery key; SEL: advanced the seal), and safe normal-flow continuation is no longer possible. See [event-log.md §Contest (Cnt)](event-log.md#contest-cnt).

### 10. Overlap (non-divergent SEL, fork-creating event)

When a non-Rpr/Cnt/Dec event chains from an event earlier than the current tip:

```
divergence_ancestor = first_branch_point.said    // the parent of v_d
insert single forking event (the first batch event that creates the fork)
return applied: true, divergence_ancestor: Some(first_branch_point.said)
```

Subsequent submissions return `RepairRequired` until owner repairs.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock (Postgres `pg_advisory_xact_lock`) so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `SelVerifier::new` from offset 0, or `resume` from a cached `SelVerification` if available).
2. Validate, dedup, route as above.
3. Insert / archive as the path requires.
4. Publish to Redis (`sel_updates`) for gossip propagation if any path mutated chain state.

The `SelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../protocol-doctrine.md](../../protocol-doctrine.md)).

## Pagination

All SEL queries use `ORDER BY version ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same version. `MINIMUM_PAGE_SIZE = 64` controls page size for both reads and the discriminator's single-page fetch.

## Gossip Send-Side Partitioning (divergent SELs)

Propagating a divergent SEL to a remote node requires more than canonical chain ordering. The receiver's submit handler routes batches by content predicates (`is_repair`, `is_contest`, `is_decommission`, divergent-rejection); a single batch that spans the divergence point with mixed kinds may route through `RepairRequired` or `ContestRequired`, blocking propagation. The SENDER partitions the chain into sub-batches the receiver will accept under its routing rules and sends them in sequence.

`send_divergent_sel_events` (analog of KEL's `send_divergent_events` at `lib/kels/src/types/kel/sync.rs:517`):

1. Trace forward from each fork event to partition post-divergence events into `chain_a` and `chain_b`.
2. Send **pre-divergence + non-cnt chain** as paged appends; each page lands as a non-divergent extension.
3. Send **cnt-chain** as an atomic single-page batch; routes to `is_contest`, accepts on divergent or linear.

For unrecovered divergence (no terminal in either branch — possible on SEL during the gossip-propagation window before the owner contests), the longer chain is sent as paged appends, then the fork event from the shorter chain establishes divergence at the receiver.

**Why send-side, not receive-side:** receive-side ordering can sort what arrived but cannot fix structural composition problems where the receiver's submit handler will reject a particular batch composition. The sender has full chain visibility and produces sequences that compose correctly given the receiver's routing rules. Same principle applies across KEL, IEL, and SEL — see [../iel/merge.md](../iel/merge.md#gossip-send-side-partitioning-divergent-iels) and [../kel/merge.md](../kel/merge.md).

## Key Invariants

1. **Events are sorted deterministically** — by `(version, kind_priority, said)`. SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored.
3. **Governance-evaluation events are bounded** — proactive evaluation (`MAX_NON_EVALUATION_EVENTS = 63`) caps non-evaluation runs; the next event after 63 must be `Sea`/`Rpr`/`Cnt`/`Dec`.
4. **Repair cannot truncate at or before the evaluation seal** — `truncate_and_replace` rejects fork-points at-or-before `last_governance_event` in chain order.
5. **Terminal states are permanent** — any `Cnt` or `Dec` in the chain freezes it.
6. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.
7. **Inception is permissionless but bounded by batch rule** — Icp alone is rejected; `[Icp, Est, ...]` is the minimum legal inception batch.
8. **Cross-chain bindings are path-agnostic** — same validation rules at submit, gossip, bootstrap, re-verification.
9. **Truncate-before-verify on `Rpr`** — when an `Rpr` is detected, `repository::truncate_and_replace` (`services/sadstore/src/handlers.rs:1809-1830`) archives the to-be-archived branch events and removes them from `sad_events` before the handler runs its post-truncation chain verification (`handlers.rs:1848+`). The post-truncation verifier walks the linear chain (surviving branch + new batch including `Rpr`); the divergent set is gone from storage before this walk runs. This honors the one-divergent-generation-at-a-time invariant (see [../protocol-doctrine.md §One Divergent Generation at a Time](../../protocol-doctrine.md#one-divergent-generation-at-a-time)) — SEL achieves the invariant via storage-side normalization, where KEL achieves it via branch-scoped verifier input (see [../kel/merge.md §Key Invariants](../kel/merge.md#key-invariants), invariant 6). Different implementation routes; same doctrinal outcome.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm in detail.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../iel/merge.md](../iel/merge.md) — IEL counterpart.
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle and cross-chain anchor stability.
- [../sadstore.md](../../infrastructure/sadstore.md) — SADStore service architecture.
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
