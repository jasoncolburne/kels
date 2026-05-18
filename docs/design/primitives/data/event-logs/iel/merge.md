# IEL Merge Protocol

This document describes the submit / merge protocol used when new events are submitted to an Identity Event Log (IEL). It is the IEL counterpart to [../sel/merge.md](../sel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler integrates new events into an existing IEL while handling:
- Normal event appends (`Evl`, `Sea`)
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same serial) → chain transitions to contested-terminal directly
- Decommission (`Dec`) — terminal owner-initiated end
- Algorithmic `ContestRequired` for normal-event submissions that land at-or-before the evaluation seal on a linear chain (the seal has advanced past the submitter's view)

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. Every IEL event is governance-authorized: the chain's `governancePolicy` (declared at `Icp`, evolvable via `Evl`) is the gate for every kind including `Icp` itself. The chain's `authPolicy` is reserved for SEL Upd authorization through `ielEvent` binding (see [../sel/events.md](../sel/events.md)).

**There is no `Rpr` kind on IEL** (see [event-log.md §Why no Rpr](event-log.md#why-no-rpr)). Divergence is preserved as data and is structurally terminal: the privileged-divergence-is-terminal rule fires immediately on any divergent set (every IEL event is privileged), and the chain transitions to Contested at the divergent serial with no protocol-level repair path. Operator recourse against compromise is described in [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise).

## Merge Outcome

`submit_iel_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected (duplicates or routing rejection). |
| `divergenceAncestor` | SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / contested (= divergent) / decommissioned per batch contents |
| `ContestRequired { reason }` | Normal-event submission at-or-before `lastSealAdvancingEvent` in chain order on a linear chain | unchanged |
| `ContestedIel` | Submission to a chain that is divergent (= contested-terminal on IEL) | terminal, unchanged |
| `IelDecommissioned` | Submission to a chain with a `Dec` event in it | terminal, unchanged |
| `NotImmunePolicy { policy }` | Icp or Evl introducing/evolving a non-immune policy | unchanged |
| `InvalidIel(reason)` | Structural validation failure | unchanged |

**Note on `ContestRequired` vs `ContestedIel`.** Divergent IEL is structurally contested-terminal, so divergent IEL → `ContestedIel`, not `ContestRequired`. The latter is reserved for the seal-cap case on linear IEL chains.

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
               declaration is tier-2 like Evl/Sea)
for v1+ (Evl/Sea/Dec): verifier checks anchoring against branch.trackedGovernancePolicy
              with the kind required by the event's tier — see
              [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation):
                Evl, Sea  → Rot (tier 2)
                Dec       → Ror (tier 3)
              Wrong-kind anchor for any contributing leaf rejects the event.

for events introducing or evolving authPolicy or governancePolicy
    (Icp v0, Evl with policy field):
    fetch the referenced policy by SAID
    if not policy.immune: reject with NotImmunePolicy
              (policy immunity rule — see events.md)

for Sea events: verify parent-kind constraint — parent must be Evl
                (Sea is forbidden after Icp, Sea, or Dec on IEL).
                Sea-Sea is forbidden on IEL because Sea carries no content
                field, so consecutive Seas have no semantic difference.
                See [events.md §Per-Kind Policy Field Discipline](events.md#per-kind-policy-field-discipline).
                Chain-state check enforced in the verifier walk — validate_structure
                sees only the event in isolation; parent-kind requires chain context.
```

The Icp authorization requirement is structural authentication of the inceptor against their own declared `governancePolicy`. Unlike SEL's Icp, there is no phishing class to defend against — the prefix is structurally unpredictable from outside (the inception `nonce` makes it unguessable).

The policy-immunity gate makes chain stability structural: a non-immune policy can never be referenced as `authPolicy` or `governancePolicy`, so no anchor used in any chain authorization (auth or governance) can ever be poisoned. Past authorizations stay satisfied by construction. To revoke an endorser's authority going forward, evolve the policy via `Evl` rather than poisoning past anchors.

### 2. Terminal-State Gate

Before routing, check whether the chain is already terminal:

```
if chain is divergent      → reject ContestedIel
                             (every IEL event is privileged; any divergent set
                              on IEL fires privileged-divergence-is-terminal.)
if chain has any Dec event:
    if event.previous = v_{d-1}.said AND event.serial = Dec.serial
       AND event.kind is non-archiving privileged (Evl/Sea/Dec):
        → accept as divergent extension at Dec's serial via
          the order-independent divergent transitions rule
          (see protocol-doctrine.md §Order-independent divergent transitions);
          chain transitions Decommissioned → Contested.
    else:
        → reject IelDecommissioned
          (Dec is terminal for linear extension; the locked-portion bound
           rejects any subsequent repair event targeting the locked portion.)
```

These checks fire before any other routing, including dedup — terminal state means no further events of any kind. The IEL-specific `is_divergent → ContestedIel` rule reflects that divergent IEL is structurally contested-terminal: every IEL event is governance-authorized, so any divergent set contains a privileged event by definition.

### 3. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 4. Routing

The handler inspects the post-dedup batch:

```
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

(by §2 above, the chain reaching this routing block is necessarily linear:
 divergent IEL is contested-terminal and was rejected upstream)

if is_decommission → decommission path (insert + mark decommissioned)
else if event is at-or-before `lastSealAdvancingEvent` in chain order
        AND policy satisfied AND non-terminal → reject ContestRequired
else if event creates a fork (overlap) → insert single concurrent event at v_d;
                                         the new 2-event divergent set is
                                         privileged → chain transitions to
                                         contested-terminal at this moment;
                                         subsequent submissions return ContestedIel.
else → normal append
```

`Dec` lands only on a linear chain (divergent IEL is contested-terminal per §2).

Note the absence of a repair branch — IEL has no `Rpr` kind. Divergent IEL is contested-terminal directly via the overlap path; there is no recoverable intermediate state. See [event-log.md §Divergence is Contested-Terminal](event-log.md#divergence-is-contested-terminal) and [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise).

### 5. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All future submissions return `IelDecommissioned`.

### 6. Normal Append (Evl / Sea)

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ContestRequired` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event is at-or-before `lastSealAdvancingEvent` in chain order
   AND policy is satisfied
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ContestRequired { reason: "..." }
```

This fires when a write-authorized normal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain. The submitter has authority but cannot proceed via normal append; they must accept the new state and re-submit at a higher serial, contest, or abandon.

(For IEL, "policy is satisfied" means the event's anchor passes against `trackedGovernancePolicy` — every IEL event including `Icp` is governance-authorized; `Icp` is self-endorsed under its declared policy.)

### 7. Overlap (linear IEL, fork-creating event)

When a non-Dec event chains from an event earlier than the current tip, creating a 2-event divergent set at `v_d`:

```
divergenceAncestor = first_branch_point.said    // the parent of v_d
insert single forking event (the first batch event that creates the fork)
mark chain as contested (every IEL event is privileged → privileged-divergence-is-terminal
fires immediately on the 2-event divergent set)
return applied: true, divergenceAncestor: Some(first_branch_point.said)
```

The chain is contested-terminal as of the overlap insertion; all subsequent submissions are rejected by the §2 terminal-state gate with `ContestedIel`. There is no intermediate "divergent-but-not-yet-contested" state on IEL — the divergent set IS the contested state, by construction.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `IelVerifier::new` from offset 0, or `resume` from a cached `IelVerification` if available).
2. Validate, dedup, route as above.
3. Insert as the path requires (no archival on IEL — there is no `truncate_and_replace`).
4. Publish to gossip if any path mutated chain state.

The `IelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)).

## Pagination

All IEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The `CASE` expression uses `IdentityEventKind::sort_priority()` to order kinds at the same serial: `Icp` (0) → `Evl` (1) → `Sea` (2) → `Dec` (3). `MINIMUM_PAGE_SIZE = 64` controls page size.

## Gossip Send-Side Partitioning (divergent IELs)

Propagating a divergent IEL chain to a remote node requires more than ordering events by canonical chain order. The receiver's submit handler rejects any submission to a divergent (= contested-terminal) chain with `ContestedIel`; a single batch that contains the divergent set as a whole would be split by the receiver's per-event routing — the first event in the batch lands as the chain's linear tip (clean append), and the second event triggers the §2 terminal-state gate AFTER the chain is already divergent locally. To make propagation succeed, the SENDER partitions the chain so each event lands in the routing-rule shape the receiver expects.

`send_divergent_iel_events` (analog of KEL's `send_divergent_events` at `lib/kels/src/types/kel/sync.rs:517`):

1. Send **pre-divergence chain** (everything up to and including `v_{d-1}`) as paged appends. Each page lands as a non-divergent extension at the receiver.
2. Send the **first divergent-set event** at `v_d` as a single-event batch — lands as a clean linear append at the receiver.
3. Send the **second divergent-set event** at `v_d` as a single-event batch — falls through §4's overlap path, creates the divergent set at `v_d` on the receiver, and the chain transitions to contested-terminal there.

After step 3 the receiver's chain mirrors the sender's exactly; both nodes converge on `effective_tail_said = hash_effective_said("contested:{prefix}")`. No archival on either side.

**Why send-side, not receive-side:** receive-side ordering can sort what arrived but cannot fix structural composition problems where the receiver's submit handler will reject a particular batch composition. The sender has full chain visibility and can produce sequences that compose correctly given the receiver's routing rules. Relying on the receiver's submit handler to "figure out" complex batches is invariant-protection reasoning; the cryptographic-soundness argument is that the sender produces sequences that the routing rules accept by construction.

## Key Invariants

1. **Events are sorted deterministically** — by `(serial, kind_priority, said)`. The SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored (the chain is Contested as of that point — no kind extends past divergence on IEL).
3. **No archival** — no `truncate_and_replace`, no archive table. History is encoded in the data, including divergent branches, forever.
4. **Contested is fully terminal; Decommissioned admits one divergent extension** — once the chain is Contested, no submission of any kind is accepted. Decommissioned accepts no linear extension; a non-archiving privileged event with `previous = v_{d-1}.said` and `serial = Dec.serial` is admitted as a divergent extension and transitions the chain Decommissioned → Contested via the order-independent rule (see [../../../../protocol-doctrine.md §Order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions)).
5. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.

## References

- [event-log.md](event-log.md) — Chain lifecycle (divergence is contested-terminal directly; no Rpr).
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../sel/merge.md](../sel/merge.md) — SEL counterpart (which has `Rpr` and the discriminator).
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
