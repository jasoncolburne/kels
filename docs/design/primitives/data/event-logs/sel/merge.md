# SEL Merge Protocol

This document describes the submit / merge protocol used when new events are submitted to a SAD Event Log (SEL). It is the SEL counterpart to [../iel/merge.md](../iel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle and the discriminator algorithm in detail, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler in `services/sadstore/src/handlers.rs::submit_sad_events` integrates new events into an existing SEL while handling:
- Inception batches (`[Icp, Est, ...]` minimum — Icp alone is rejected)
- Normal event appends (`Upd`, `Sea`)
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same serial)
- Repair (`Rpr`) — discriminator-driven archival of the events on the branch not extended by `Rpr.previous`
- Decommission (`Dec`) — terminal event ending the chain
- Algorithmic `ParentLocked` for normal-event submissions when the seal has advanced past the submitter's view

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. **Authorization for v1+ events is resolved through the bound IEL** via each event's `ielEvent` field. See [event-log.md §Authorization via IEL](event-log.md#authorization-via-iel).

## Merge Outcome

`submit_sad_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected. |
| `divergenceAncestor` | SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / divergent / decommissioned per batch contents |
| `ParentLocked { reason }` | Normal-event at-or-before `lastSealAdvancingEvent` in chain order (write-authorized but seal advanced past submitter's view), OR a privileged event whose landing would create or join a divergent set per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) | unchanged |
| `RepairRequired` | Non-Rpr submission to a divergent chain | unchanged |
| `DecommissionedSel` | Submission to a chain with a `Dec` event in it. Decommissioned is fully terminal; the seal-cap rejects every submission whose parent sits at-or-before `v_{d-1}`. | terminal |
| `IncompleteInception` | Verifier walked a chain whose tip is `Icp` (no v1 `Est`) | unchanged (rejected) |
| `BadIdentityBinding(reason)` | `ielEvent` does not resolve to a real IEL event with matching prefix, or fails per-event parent-monotonic check | unchanged |
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
    fetch IEL event by event.ielEvent
    confirm IEL event's prefix == SEL's bound identity
    if IEL is divergent at the bound branch → reject IelDivergent

    pick the relevant policy:
        Est, Upd → IEL-resolved authPolicy at ielEvent
        Sea/Rpr/Dec → IEL-resolved governancePolicy at ielEvent

    verify event.said is anchored under the resolved policy with the
    anchor kind required by the event's tier — see
    [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation):
        Upd       → Ixn (tier 1)
        Est, Sea  → Rot (tier 2)
        Rpr, Dec  → Ror (tier 3)
    Each Endorse / Delegate leaf in the resolved policy must have an
    anchor of the required kind. Wrong-kind anchor for any leaf
    contributing to satisfaction → reject.

    per-event parent-monotonic check (per branch):
        event.ielEvent must be at-or-after the parent event's ielEvent
        (parent via previous SAID; this is the branch's tip ielEvent when
        extending an existing branch tip) in IEL chain order; reject
        BadIdentityBinding otherwise. Branches with different parent-chains
        do not constrain each other.

for Sea events: verify parent-kind constraint — Sea-Sea is allowed on SEL
                only when the new Sea's ielEvent strictly advances
                beyond the parent Sea's ielEvent in IEL chain order
                (a stricter check than the parent-monotonic ratchet above,
                which admits equality; equal ielEvent between
                consecutive Seas is semantically redundant and rejected).
                Sea forbidden after Dec (terminal). See [events.md](events.md)
                for the per-kind table. Chain-state check enforced in the
                verifier walk — validate_structure sees only the event in
                isolation; parent-kind requires chain context.
```

The `ielEvent` resolution may walk back through the IEL chain if the named event doesn't carry the relevant policy field (e.g., `ielEvent` points at an Evl that evolved governance only; the authPolicy in effect is what was tracked at that serial, which may have been seeded at IEL Icp). The walk is bounded by IEL chain length and cached aggressively.

### 2. Inception Batch Rule

The rule lives inside the verifier (`SelVerifier::finish_internal`): if any branch tip is still an `Icp`, finalization returns `IncompleteInception`. Icp is structurally pinned to v=0, so an Icp tip is precisely the "lone-`[Icp]` chain" shape. SEL Icp is permissionless and deterministic — anyone can submit `[Icp]` alone — but the resulting chain has no content and no authorized event, so the verifier rejects it at end-verification. The minimum inception batch is `[Icp, Est]`. Every consumer's verifier walk applies the same rule; submit handlers do not duplicate it. See [events.md §Inception batch rule](events.md#inception-batch-rule).

### 3. Terminal-State Gate

```
if chain has any Dec event → reject DecommissionedSel
                             (the seal-cap rejects any submission whose parent
                              sits at-or-before Dec's parent.)
```

Fires before all other routing. Decommissioned is the only per-node terminal state on SEL; the seal-cap rejects every submission. Cross-node priv-vs-priv races resolve at the federation layer via the contested-prefix table (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

### 4. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 5. Routing

The handler inspects the post-dedup batch for kind discriminators and the chain's pre-batch sealed/unsealed predicate:

```
let is_repair       = new_events.iter().any(|e| e.kind.is_repair());
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());
let is_divergent    = first_divergent_serial.is_some();
let is_sealed       =
    divergenceAncestor.is_some() && last_seal_advancing_event_is_at_or_after(divergenceAncestor);

if is_repair:
    if is_divergent and is_sealed → reject ParentLocked
                                    (can't truncate behind the seal)
    else                          → repair path (truncate_and_replace)
elif is_decommission:
    if Dec would land as a sibling of an existing event at v_d
       (creating/joining a divergent set per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal))
                                  → reject ParentLocked
    else                          → decommission path (insert + mark decommissioned)
elif is_privileged (Sea) and event would create or join a divergent set:
                                    → reject ParentLocked
                                      (per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal))
elif is_divergent:
    if is_sealed                  → reject ParentLocked (Upd on sealed-divergent)
    else                          → reject RepairRequired
elif normal-event
       AND event is at-or-before `lastSealAdvancingEvent` in chain order
       AND kind-relevant authorization satisfied
       AND event.kind is non-terminal:
                                    → reject ParentLocked (algorithmic trigger)
elif event creates a fork (overlap, non-privileged Upd at v ≥ 2):
                                    → insert single forking event; chain becomes Divergent
else:
                                    → normal append
```

The repair / decommission discriminators bind to predicate methods on `SadEventKind`. Any of these kinds at any position in the batch routes to its dedicated path.

The sealed/unsealed predicate is computed from the **pre-batch** snapshot of `divergenceAncestor` and `lastSealAdvancingEvent`; the verifier's run on the new batch doesn't shift the predicate mid-flow. This matches the canonical [reconciliation.md §Local Submissions Matrix](reconciliation.md#local-submissions-matrix), which is the source-of-truth for cell-by-cell expected outcomes.

### 6. Repair Path

Detected when any batch event has `kind = Rpr`. Calls `repository::truncate_and_replace`, which:

1. Computes archive lower bound `L = first_divergent_serial(prefix).unwrap_or(Rpr.serial)`.
2. Fetches one page of events at `serial >= L`, ordered `(serial ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`.
3. Feeds the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`).
4. Walks back from `Rpr.previous` through the verified page, accumulating the surviving-branch SAIDs.
5. Archives events on the non-surviving branch; deletes them from `sad_events` by SAID; inserts the new batch (pending events first, then `Rpr`).

Full algorithm: [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator). Mirrors KEL's `archive_adversary_chain`.

The repair path also creates `SelRepairEvent` link rows in `sel_repair_events`, providing an immutable audit trail. Archived events are queryable via the repair endpoints (`POST /api/v1/sad/events/repairs` and `.../repairs/events`).

### 7. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All subsequent submissions return `DecommissionedSel` (Decommissioned is fully terminal; the seal-cap rejects any submission whose parent sits at-or-before `v_{d-1}`).

### 8. Normal Append

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ParentLocked` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event is at-or-before `lastSealAdvancingEvent` in chain order
   AND kind-relevant authorization was satisfied (from §1)
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ParentLocked { reason: "..." }
```

This fires when an authorized non-terminal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain (someone with governance authority issued a `Sea`/`Rpr` while the submitter had stale state). The submitter has authority but cannot proceed via normal append; they must accept, contest, or abandon.

"Kind-relevant authorization" means each kind's gate uses the appropriate IEL-resolved policy: `Upd` checks `authPolicy`; `Sea` checks `governancePolicy`. Both kinds use the same algorithmic `ParentLocked` gate here — what differs is which policy the §1 check ran against.

The trigger fires after §1's anchoring check has already passed upstream. The `ParentLocked` trigger combines two things: the existing-chain sanity floor (chain wasn't already broken) and the serial-vs-seal arithmetic (the new event's serial lands at-or-before the seal).

This mirrors KEL's `ParentLocked` shape: someone else used the privileged primitive (KEL: revealed the recovery key; SEL: advanced the seal), and safe normal-flow continuation is no longer possible. The submitter must accept the new state, decommission via `Dec`, or abandon and reincept. See [event-log.md §Algorithmic trigger — `ParentLocked`](event-log.md#algorithmic-trigger--ParentLocked).

### 9. Overlap (non-divergent SEL, fork-creating Upd)

When a non-Rpr/Dec/Sea event chains from an event earlier than the current tip:

```
divergenceAncestor = first_branch_point.said    // the parent of v_d
insert single forking event (the first batch event that creates the fork)
return applied: true, divergenceAncestor: Some(first_branch_point.said)
```

Subsequent submissions return `RepairRequired` until owner repairs. A privileged event (`Sea` or `Dec`) reaching this shape is rejected by the routing block above per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal); only non-privileged `Upd` produces a fork at this path.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock (Postgres `pg_advisory_xact_lock`) so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `SelVerifier::new` from offset 0, or `resume` from a cached `SelVerification` if available).
2. Validate, dedup, route as above.
3. Insert / archive as the path requires.
4. Publish to Redis (`sel_updates`) for gossip propagation if any path mutated chain state.

The `SelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)).

## Pagination

All SEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. `MINIMUM_PAGE_SIZE = 64` controls page size for both reads and the discriminator's single-page fetch.

## Gossip Send-Side Partitioning (divergent SELs)

Propagating a divergent SEL to a remote node requires more than canonical chain ordering. The receiver's submit handler routes batches by content predicates (`is_repair`, `is_decommission`, divergent-rejection); a single batch that spans the divergence point with mixed kinds may route through `RepairRequired` or `ParentLocked`, blocking propagation. The SENDER partitions the chain into sub-batches the receiver will accept under its routing rules and sends them in sequence.

`send_divergent_sel_events` (analog of KEL's `send_divergent_events` at `lib/kels/src/types/kel/sync.rs:517`):

1. Trace forward from each fork event to partition post-divergence events into `chain_a` and `chain_b`.
2. Send the longer chain (pre-divergence + extension on one branch) as paged appends; each page lands as a non-divergent extension at the receiver.
3. Send the fork event from the shorter chain as a single-event batch; it establishes divergence at the receiver via the overlap path.

**Why send-side, not receive-side:** receive-side ordering can sort what arrived but cannot fix structural composition problems where the receiver's submit handler will reject a particular batch composition. The sender has full chain visibility and produces sequences that compose correctly given the receiver's routing rules. Same principle applies across KEL, IEL, and SEL — see [../iel/merge.md](../iel/merge.md#gossip-send-side-partitioning-divergent-iels) and [../kel/merge.md](../kel/merge.md).

## Key Invariants

1. **Events are sorted deterministically** — by `(serial, kind_priority, said)`. SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored.
3. **Seal-advance cap** — the seal-advance cap (`MINIMUM_PAGE_SIZE − 2 = 62`) caps non-seal-advancing runs; the next event after 62 must be a seal-advancing kind (`Est` at v=1, then `Sea` or `Rpr`; `Dec` enforces but does not advance).
4. **Repair cannot truncate at or before the evaluation seal** — `truncate_and_replace` rejects fork-points at-or-before `lastSealAdvancingEvent` in chain order. A competing `Rpr` arriving against an existing seal-defining `Rpr` is rejected by the seal-cap (locked-portion bound); federation-level convergence for that race is handled at the infrastructure layer.
5. **Decommissioned is fully terminal** — no submission of any kind is accepted. The seal-cap rejects every submission whose parent sits at-or-before `Dec`'s parent. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). Privileged events whose landing would create or join a divergent set are uniformly rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal).
6. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.
7. **Inception is permissionless but bounded by batch rule** — Icp alone is rejected; `[Icp, Est, ...]` is the minimum legal inception batch.
8. **Cross-chain bindings are path-agnostic** — same validation rules at submit, gossip, bootstrap, re-verification.
9. **Truncate-before-verify on `Rpr`** — `Rpr`'s discriminator archives the to-be-archived branch from `sad_events` before the post-truncation verifier walks the surviving chain. See §How SEL and KEL discriminators differ below.

### How SEL and KEL discriminators differ

Both KEL and SEL honor the one-divergent-generation-at-a-time invariant (see [../../../../protocol-doctrine.md §One Divergent Generation at a Time](../../../../protocol-doctrine.md#one-divergent-generation-at-a-time)), but via different implementation routes:

- **SEL — storage-side normalization (truncate-before-verify).** When an `Rpr` is detected, `repository::truncate_and_replace` (`services/sadstore/src/handlers.rs:1809-1830`) archives the to-be-archived branch events and removes them from `sad_events` *before* the handler runs its post-truncation chain verification (`handlers.rs:1848+`). The post-truncation verifier walks the linear chain (surviving branch + new batch including `Rpr`); the divergent set is gone from storage before this walk runs.
- **KEL — branch-scoped verifier input.** Verification is seeded from `Rec.previous`; the walker only sees the surviving branch + the pending batch. The divergent set is in storage but never in the walker's input stream. See [../kel/merge.md §Key Invariants](../kel/merge.md#key-invariants), invariant 6.

Different routes; same doctrinal outcome — the walker's running state never carries the divergent set across the archival boundary.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm in detail.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../iel/merge.md](../iel/merge.md) — IEL counterpart.
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle and cross-chain anchor stability.
- [../../../../infrastructure/sadstore.md](../../../../infrastructure/sadstore.md) — SADStore service architecture.
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
