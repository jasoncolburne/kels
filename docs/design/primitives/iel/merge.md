# IEL Submit Protocol

This document describes the submit / merge protocol used when new events are submitted to an Identity Event Log (IEL). It is the IEL counterpart to [../sel/merge.md](../sel/merge.md) and [../kel/merge.md](../kel/merge.md). For chain lifecycle, see [event-log.md](event-log.md). For the multi-node correctness proof, see [reconciliation.md](reconciliation.md).

## Overview

The submit handler integrates new events into an existing IEL while handling:
- Normal event appends (`Evl`)
- Idempotent resubmissions (dedup by SAID)
- Divergence detection (conflicting events at the same version)
- Contest (`Cnt`) — terminal authority conflict OR divergence resolution (the only divergence-resolver on IEL)
- Decommission (`Dec`) — terminal owner-initiated end
- Algorithmic `ContestRequired` for normal-event submissions when the chain is divergent or post-evaluation-seal

Events are linked by their `previous` SAID. Authority is via the anchoring model — the server does NOT verify signatures on submit; consumers verify when they use the data. Every IEL event is governance-authorized: the chain's `governance_policy` (declared at `Icp`, evolvable via `Evl`) is the gate for every kind including `Icp` itself. The chain's `auth_policy` is reserved for SEL Upd authorization through `identity_event` binding (see [../sel/events.md](../sel/events.md)).

**There is no `Rpr` kind on IEL** (see [event-log.md §Why no `Rpr`](event-log.md#why-no-rpr)). Divergence is preserved as data; only `Cnt` resolves it.

## Submit Outcome

`submit_identity_events` returns:

| Field | Meaning |
|---|---|
| `applied` | `true` if the batch was accepted; `false` if rejected (duplicates or routing rejection). |
| `divergence_ancestor` | SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), or `None` if linear. |

Server errors map to:

| Error | Meaning | Chain state after |
|---|---|---|
| `Ok({applied: true, ...})` | Batch accepted | linear / divergent / contested / decommissioned per batch contents |
| `ContestRequired { reason }` | Submission to a divergent chain (non-Cnt), OR normal-event submission at-or-before `last_governance_event` in chain order | unchanged |
| `ContestedIel` | Submission to a chain with a `Cnt` event in it | terminal, unchanged |
| `IelDecommissioned` | Submission to a chain with a `Dec` event in it | terminal, unchanged |
| `NotImmunePolicy { policy }` | Icp or Evl introducing/evolving a non-immune policy | unchanged |
| `InvalidIel(reason)` | Structural validation failure | unchanged |

## Submit Flow

`submit_identity_events` is the single HTTP entry point for all write paths. It validates the batch, walks the existing chain, then routes to one of several handler paths.

### 1. Structural and Authorization Validation

```
for each event:
    IdentityEvent::validate_structure()  // per-kind field rules per [events.md]
    verify event.prefix derives from declared (auth_policy, governance_policy, topic) for v0
    verify each batch event shares the same prefix

for v0 (Icp): verify Icp.said is anchored under the declared governance_policy
              (the inceptor proves membership in the governance policy they're
               declaring — every IEL event is a governance act)
for v1+ (Evl/Cnt/Dec): verifier checks anchoring against branch.tracked_governance_policy

for events introducing or evolving auth_policy or governance_policy
    (Icp v0, Evl with policy field):
    fetch the referenced policy by SAID
    if not policy.immune: reject with NotImmunePolicy
              (policy immunity rule — see events.md)
```

The Icp authorization requirement is structural authentication of the inceptor against their own declared `governance_policy`. Unlike SEL's Icp, there is no phishing class to defend against (identity chains are not third-party-discoverable; the prefix is private to the inceptor).

The policy-immunity gate makes chain stability structural: a non-immune policy can never be referenced as `auth_policy` or `governance_policy`, so no anchor used in any chain authorization (auth or governance) can ever be poisoned. Past authorizations stay satisfied by construction. To revoke an endorser's authority going forward, evolve the policy via `Evl` rather than poisoning past anchors.

### 2. Terminal-State Gate

Before routing, check whether the chain is already terminal:

```
if chain has any Cnt event → reject ContestedIel
if chain is divergent      → reject ContestedIel
                             (every IEL event is privileged; any divergent set on
                              IEL fires the privileged-divergence-is-terminal rule,
                              regardless of whether an explicit Cnt event has landed)
if chain has any Dec event → reject IelDecommissioned
```

These checks fire before any other routing, including dedup — terminal state means no further events of any kind. The IEL-specific `is_divergent → ContestedIel` rule reflects that divergent IEL is structurally contested-terminal: every IEL event is governance-authorized, so any divergent set contains a privileged event by definition.

### 3. Deduplication

Events whose SAID is already present in the chain are filtered out. If the entire batch is duplicates, return `applied: true` with no changes (idempotent).

### 4. Routing

The handler inspects the post-dedup batch for kind discriminators:

```
let is_contest = new_events.iter().any(|e| e.kind.is_contest());
let is_decommission = new_events.iter().any(|e| e.kind.is_decommission());

(by §2 above, the chain reaching this routing block is necessarily linear:
 divergent IEL is contested-terminal and was rejected upstream)

if is_contest        → contest path (insert; Cnt's previous = v_{tip-1}.said creates
                       fresh divergence at v_tip with the existing tip; the new
                       2-event divergent set is privileged → chain transitions to
                       contested-terminal at this moment)
else if is_decommission → decommission path (insert + mark decommissioned)
else if event is at-or-before `last_governance_event` in chain order AND policy satisfied AND non-terminal → reject ContestRequired
else if event creates a fork (overlap) → insert single concurrent event at v_d;
                                         the new 2-event divergent set is
                                         privileged → chain transitions to
                                         contested-terminal at this moment
else → normal append
```

`Cnt` lands on IEL in exactly one scenario: extending `v_{tip-1}` on a linear chain. Acceptance creates fresh 2-event divergence at v_tip (existing linear tip + Cnt, both with `previous = v_{tip-1}.said`); the privileged-divergence-is-terminal rule fires immediately. After divergence is observed the chain is contested-terminal and the §2 gate rejects any further submission with `ContestedIel` — including any further `Evl`/`Cnt`/`Dec` arriving via gossip (no 3rd event lands at v_d). The 2-event divergent shape can also be observed when two concurrent linear-chain submissions on different nodes (each accepted as a linear-chain extension on its own node — e.g., an `Evl` on one node and a `Cnt` on another, or two `Evl`s) merge via gossip; that's an emergent gossip-merge observation, not a separate acceptance scenario. `Dec` lands only on a linear chain (divergent IEL is contested-terminal per §2).

Note the absence of a repair branch — IEL has no `Rpr` kind. Divergent IEL is contested-terminal directly; there is no recoverable intermediate state.

### 5. Contest Path

Detected when any batch event has `kind = Cnt`. Inserts the batch (pending events first, then `Cnt`); no archival. Marks chain as contested. All future submissions return `ContestedIel`.

On IEL specifically, Cnt lands only on a linear chain: Cnt's `previous = v_{tip-1}.said` extends the parent of the chain's linear tip. Acceptance creates fresh 2-event divergence at v_tip (existing tip + Cnt); the new divergent set immediately fires the privileged-divergence-is-terminal rule (every IEL event is privileged). After divergence is observed, the chain is contested-terminal and no further Cnt is accepted — the §2 terminal-state gate rejects any post-divergence submission with `ContestedIel`. (The 2-event divergent shape is also reachable when two concurrent linear-chain submissions on different nodes — an `Evl` and a `Cnt`, or two `Evl`s — merge via gossip; that's an emergent gossip-merge observation, not a separate Cnt acceptance scenario.)

### 6. Decommission Path

Detected when any batch event has `kind = Dec`. Inserts the batch; no archival. Marks chain as decommissioned. All future submissions return `IelDecommissioned`.

### 7. Normal Append (Evl)

Events chain from the current tip, no divergence, no terminal kind in batch. Inserts via `save_batch`. Returns `applied: true`.

#### `ContestRequired` algorithmic trigger

Before inserting a non-terminal event, the handler checks:

```
if event is at-or-before `last_governance_event` in chain order
   AND policy is satisfied
   AND event.kind is non-terminal
   AND chain is not divergent:
   → return ContestRequired { reason: "..." }
```

This fires when a write-authorized normal event would land at or before the evaluation seal — meaning the seal has advanced past the submitter's view of the chain. The submitter has authority but cannot proceed via normal append; they must accept the new state and re-submit at a higher version, contest, or abandon.

(For IEL, "policy is satisfied" means the event's anchor passes against `tracked_governance_policy` — every IEL event after Icp is governance-authorized.)

### 8. Overlap (non-divergent IEL, fork-creating event)

When a non-Cnt/Dec event chains from an event earlier than the current tip:

```
divergence_ancestor = first_branch_point.said    // the parent of v_d
insert single forking event (the first batch event that creates the fork)
return applied: true, divergence_ancestor: Some(first_branch_point.said)
```

Subsequent submissions return `ContestRequired` until the chain is contested.

## Submit Handler Architecture

The submit handler runs under a per-prefix advisory lock so concurrent submissions for the same chain serialize. Within the locked transaction:

1. Verify the existing chain (paginated via `IelVerifier::new` from offset 0, or `resume` from a cached `IelVerification` if available).
2. Validate, dedup, route as above.
3. Insert as the path requires (no archival on IEL — there is no `truncate_and_replace`).
4. Publish to gossip if any path mutated chain state.

The `IelVerification` token is the trusted context for routing decisions. The DB cannot be trusted directly (the verification invariant — see [../security-invariant.md](../security-invariant.md)).

## Pagination

All IEL queries use `ORDER BY version ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same version. The `CASE` expression uses `IdentityEventKind::sort_priority()` to ensure state-determining events (Cnt, Dec) sort after `Evl` at the same version. `MINIMUM_PAGE_SIZE = 64` controls page size.

## Gossip Send-Side Partitioning (divergent IELs)

Propagating a divergent IEL chain to a remote node requires more than ordering events by canonical chain order. The receiver's submit handler routes batches by content predicates (`is_contest`, divergent-rejection); a single batch that contains both pre-divergence events and a post-divergence non-`Cnt` extension would route through "normal append (overlap creates fork)" and the second branch's events get rejected. To make propagation succeed, the SENDER partitions the chain into sub-batches the receiver will accept under its routing rules and sends them in sequence.

`send_divergent_iel_events` (analog of KEL's `send_divergent_events` at `lib/kels/src/types/kel/sync.rs:517`):

1. Trace forward from each fork event to partition post-divergence events into `chain_a` and `chain_b` (mirror KEL's chain-partition loop).
2. Send **pre-divergence + non-cnt chain** as paged appends. Each page lands as a non-divergent extension at the receiver.
3. Send **cnt-chain** as an atomic single-page batch. Routes to `is_contest`, accepts on divergent or linear, ends in contested state.

For an IEL that is divergent but not contested (no `Cnt` in either branch): in production this state is unreachable because the IEL submit handler returns `ContestRequired` for non-`Cnt` events on divergent chains. If a sender encounters one (e.g., during a defensive replay or a corrupted source), it sends the longer chain as paged appends, then the fork event from the shorter chain as a single-event batch. This mirrors KEL's unrecovered-divergence path.

**Why send-side, not receive-side:** receive-side ordering can sort what arrived but cannot fix structural composition problems where the receiver's submit handler will reject a particular batch composition. The sender has full chain visibility and can produce sequences that compose correctly given the receiver's routing rules. Relying on the receiver's submit handler to "figure out" complex batches is invariant-protection reasoning; the cryptographic-soundness argument is that the sender produces sequences that the routing rules accept by construction.

## Key Invariants

1. **Events are sorted deterministically** — by `(version, kind_priority, said)`. The SAID tiebreaker has no semantic meaning but ensures identical ordering across all nodes.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored (the chain freezes after; only `Cnt` extends past divergence).
3. **No archival** — no `truncate_and_replace`, no archive table. History is encoded in the data, including divergent branches, forever.
4. **Terminal states are permanent** — any `Cnt` or `Dec` in the chain freezes it; no future submissions accepted.
5. **Authorization is consumer-side** — the server does NOT verify anchor signatures on submit. Consumers verify the anchoring model when they use the data.

## References

- [event-log.md](event-log.md) — Chain lifecycle and divergence-by-Cnt-resolution.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../sel/merge.md](../sel/merge.md) — SEL counterpart (which has `Rpr` and the discriminator).
- [../kel/merge.md](../kel/merge.md) — KEL counterpart.
