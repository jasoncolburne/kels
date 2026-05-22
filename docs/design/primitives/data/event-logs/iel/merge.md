# IEL Merge Protocol

This document describes the submit / merge protocol used when new events are submitted to an Identity Event Log (IEL). It is the IEL counterpart to [../sel/merge.md](../sel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler integrates new events into an existing IEL while handling:
- Normal event appends (`Evl`)
- Idempotent resubmissions (dedup by SAID)
- Merge-layer rejection of privileged events that would create or join a divergent set (per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)) — since every IEL event is privileged, this is any second event at the same serial
- Decommission (`Dec`) — terminal event ending the chain
- Algorithmic `ParentLocked` for normal-event submissions that land at-or-before the evaluation seal on a linear chain (the seal has advanced past the submitter's view)

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. Every IEL event is governance-authorized: the chain's `governancePolicy` (declared at `Icp`, evolvable via `Evl`) is the gate for every kind including `Icp` itself. The chain's `authPolicy` is reserved for SEL Upd authorization through `ielEvent` binding (see [../sel/events.md](../sel/events.md)).

**There is no `Rpr` kind on IEL** (see [event-log.md §Why no Rpr](event-log.md#why-no-rpr)). Divergent sets cannot form locally on IEL — every IEL event is privileged, so a second event at the same serial is always privileged and the merge layer rejects it. There is no protocol-level repair path because there is no divergence to repair. Cross-node priv-vs-priv races surface at the federation layer via the irreconcilable-prefix table. Operator recourse against compromise is described in [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise).

## Merge Outcome

`submit_iel_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected (duplicates or routing rejection). |
| `divergenceAncestor` | SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / decommissioned per batch contents |
| `ParentLocked { reason }` | Normal-event submission at-or-before `lastSealAdvancingEvent` in chain order on a linear chain, OR a privileged event whose landing would create or join a divergent set per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) | unchanged |
| `IelDecommissioned` | Submission to a chain with a `Dec` event in it | terminal, unchanged |
| `NotImmunePolicy { policy }` | Icp or Evl introducing/evolving a non-immune policy | unchanged |
| `InvalidIel(reason)` | Structural validation failure | unchanged |

## Submit Flow

`submit_iel_events` is the single HTTP entry point for all write paths. It validates the batch, walks the existing chain, then routes to one of several handler paths.

### 1. Structural and Authorization Validation

```
for each event:
    IdentityEvent::validate_structure()  // per-kind field rules per [events.md]
    verify event.prefix derives from declared (authPolicy, governancePolicy, nonce) for v0
    verify each batch event shares the same prefix

for v0 (Icp): verify Icp.said is anchored under the declared governancePolicy
              with tier-2 (Rot) anchor per contributing policy member
              (the inceptor proves membership in the governance policy they're
               declaring — every IEL event is a governance act; the founding
               declaration is tier-2 like Evl)
for v1+ (Evl/Dec): verifier checks anchoring against branch.trackedGovernancePolicy
              with the kind required by the event's tier — see
              [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation):
                Evl       → Rot (tier 2)
                Dec       → Ror (tier 3)
              Wrong-kind anchor for any contributing leaf rejects the event.

for events introducing or evolving authPolicy or governancePolicy
    (Icp v0, Evl with policy field):
    fetch the referenced policy by SAID
    if not policy.immune: reject with NotImmunePolicy
              (policy immunity rule — see events.md)
```

The Icp authorization requirement is structural authentication of the inceptor against their own declared `governancePolicy`. Unlike SEL's Icp, there is no phishing class to defend against — the prefix is structurally unpredictable from outside (the inception `nonce` makes it unguessable).

The policy-immunity gate makes chain stability structural: a non-immune policy can never be referenced as `authPolicy` or `governancePolicy`, so no anchor used in any chain authorization (auth or governance) can ever be poisoned. Past authorizations stay satisfied by construction. To revoke an endorser's authority going forward, evolve the policy via `Evl` rather than poisoning past anchors.

### 2. Terminal-State Gate

Before routing, check whether the chain is already terminal:

```
if chain has any Dec event → reject IelDecommissioned
                             (Decommissioned is fully terminal; the seal-cap
                              rejects any subsequent submission whose parent
                              sits at-or-before Dec's parent.)
```

Fires before any other routing, including dedup — Decommissioned is the only per-node terminal state on IEL. There is no per-node Divergent state: divergent sets cannot form locally because every IEL event is privileged and the merge layer rejects any second event at the same serial per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Cross-node priv-vs-priv races resolve at the federation layer via the irreconcilable-prefix table.

### 3. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 4. Routing

The handler inspects the post-dedup batch:

```
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

(by §2 above, the chain reaching this routing block is necessarily linear:
 IEL has no per-node Divergent state; the only terminal state is Decommissioned.)

if event would create or join a divergent set at v_d
        (the chain has an existing event at v_d and this event extends v_{d-1})
                                       → reject ParentLocked
                                         (per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal):
                                          every IEL event is privileged; the second
                                          event would form a divergent set containing
                                          a privileged event.)
if is_decommission → decommission path (insert + mark decommissioned)
else if event is at-or-before `lastSealAdvancingEvent` in chain order
        AND policy satisfied AND non-terminal → reject ParentLocked
else → normal append
```

`Dec` lands only via clean linear extension of the chain's current tip.

Note the absence of a repair branch — IEL has no `Rpr` kind. Divergent sets cannot form locally on IEL, so there is no divergence to repair. Cross-node priv-vs-priv races surface at the federation layer via the irreconcilable-prefix table. See [event-log.md §Privileged-event merge-layer rejection](event-log.md#privileged-event-merge-layer-rejection) and [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise).

### 5. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All future submissions return `IelDecommissioned`.

### 6. Normal Append (Evl)

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ParentLocked` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event is at-or-before `lastSealAdvancingEvent` in chain order
   AND policy is satisfied
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ParentLocked { reason: "..." }
```

This fires when a write-authorized normal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain. The submitter has authority but cannot proceed via normal append; they must accept the new state and re-submit at a higher serial, contest, or abandon.

(For IEL, "policy is satisfied" means the event's anchor passes against `trackedGovernancePolicy` — every IEL event including `Icp` is governance-authorized; `Icp` is self-endorsed under its declared policy.)

### 7. Overlap (privileged-event merge-layer rejection)

When a submitted event chains from an event earlier than the current tip — its acceptance would create a divergent set at `v_d` (the chain has an existing event at `v_d`) — the merge layer rejects the submission per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Every IEL event is privileged, so any second event at the same serial is rejected without exception:

```
if event.previous corresponds to v_{d-1} and the chain has an existing event at v_d:
    return ParentLocked
        (the second event would create a divergent set containing a privileged event.
         Cross-node priv-vs-priv races resolve at the federation layer
         via the irreconcilable-prefix table.)
```

The chain stays at its prior state. There is no intermediate divergent state on IEL.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `IelVerifier::new` from offset 0, or `resume` from a cached `IelVerification` if available).
2. Validate, dedup, route as above.
3. Insert as the path requires (no archival on IEL — there is no `truncate_and_replace`).
4. Publish to gossip if any path mutated chain state.

The `IelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)).

## Pagination

All IEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The `CASE` expression uses `IdentityEventKind::sort_priority()` to order kinds at the same serial: `Icp` (0) → `Evl` (1) → `Dec` (2). `MINIMUM_PAGE_SIZE = 64` controls page size.

## Gossip propagation

IEL chains are linear per-node (Active or Decommissioned). Gossip propagation sends the chain as a single full-chain stream that the receiver applies as a normal append. Divergent sets cannot form locally on IEL, so there is no partitioning needed for divergent state.

Cross-node priv-vs-priv races (each `Evl`/`Dec` landing cleanly on its submitting node, gossip-arriving competing event rejected by the seal-cap) surface via the irreconcilable-prefix table at the infrastructure layer rather than as in-protocol partitioning. See [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205).

## Key Invariants

1. **Events are sorted deterministically** — by `(serial, kind_priority, said)`. The SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **No divergent sets form locally** — every IEL event is privileged; a second event at the same serial is rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The chain is `{Active, Decommissioned}` per-node.
3. **No archival** — no `truncate_and_replace`, no archive table. There is no divergent set to archive.
4. **Decommissioned is fully terminal** — no submission of any kind is accepted. The seal-cap rejects every submission whose parent sits at-or-before `Dec`'s parent. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).
5. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.

## References

- [event-log.md](event-log.md) — Chain lifecycle (privileged-event merge-layer rejection; no Rpr; no Divergent state).
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../sel/merge.md](../sel/merge.md) — SEL counterpart (which has `Rpr` and the discriminator).
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
