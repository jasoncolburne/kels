# IEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all IEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the IEL design — without it, the submit handler and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, privileged-event merge-layer rejection, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For submit-handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Every IEL event is governance-authorized**: `Icp` is self-endorsed under its declared `governancePolicy`; `Evl`, `Dec` all require the branch's tracked `governancePolicy` satisfaction. There are no auth-only events on IEL. This eliminates the auth-vs-governance asymmetry that SEL needs Rpr to handle.

2. **No seal-advance cap needed**: every non-terminal post-Icp IEL event advances the seal (`Evl`), and only one Icp lands per chain. There is no "non-seal-advancing event run" for a cap to bound — the SEL seal-advance cap has no IEL analog.

3. **No archival**: history is encoded in the data, including divergent branches, forever. There is no `truncate_and_replace`, no `Rpr`, no archive table.

4. **Policy immunity** (storage commitment): every policy referenced as `authPolicy` or `governancePolicy` MUST have `immune: true`. Both submit and verify enforce, so every IEL-referenced policy stays resolvable for the chain's lifetime — past authorizations stay distinguishable from authorization failures. See [event-log.md §Evaluation Seal and Policy Immunity](event-log.md#evaluation-seal-and-policy-immunity).

5. **Divergent sets cannot form locally**: every IEL event is privileged; the merge layer rejects any second event at the same serial per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Cross-node priv-vs-priv races surface at the federation layer via the irreconcilable-prefix table. Operator recourse against compromise is described in [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise) — linear governance evolution or rotating the IEL out of parent policies.

These invariants are what let IEL ship without `Rpr` or an archival path.

## IEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Active** | Linear, no terminal event. |
| **Active, sealed** | Sub-state of Active where the submitter's view lands at-or-before `lastSealAdvancingEvent` (a governance-authorized party has advanced the seal past the submitter). Non-terminal `Evl` submissions targeting `v_{seal-1}` are rejected by the seal-cap with `ParentLocked`; only events extending the current tip are admissible. |
| **Decommissioned** | Exactly one `Dec`, ending a clean chain. Fully terminal: all submissions rejected with `IelDecommissioned`. |

There is **no Repaired state** — IEL has no `Rpr`. There is **no Divergent state** on IEL — every IEL event is privileged, and the merge layer rejects any second event at the same serial per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Cross-node priv-vs-priv races surface at the federation layer via the irreconcilable-prefix table.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| IEL State | Icp | Evl | Dec |
|-----------|-----|-----|-----|
| **Empty** | Append ✓ if `governancePolicy` satisfied; else reject | Reject (no chain) | Reject |
| **Active** | Reject (already incepted) | Append ✓ (clean linear extension); `ParentLocked` if extending `v_{d-1}` while an event exists at `v_d` | Append ✓ → Decommissioned (clean linear extension); `ParentLocked` if extending `v_{d-1}` while an event exists at `v_d` |
| **Active, sealed** (`Evl` would land at-or-before `lastSealAdvancingEvent` in chain order) | n/a | `ParentLocked` | `ParentLocked` |
| **Decommissioned** | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` |

### Notes on cell routing

- **`Dec` on Active** — Dec terminates the chain rather than extending it; routes to decommission via clean linear extension.
- **Privileged event extending `v_{d-1}`** — a privileged event (`Evl` or `Dec`) chaining from earlier than the linear tip would create a divergent set at `v_d`. The merge layer rejects it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The chain stays at its prior state. Cross-node priv-vs-priv races surface at the federation layer via the irreconcilable-prefix table (see [§Race matrix](#race-matrix) below).
- **Active, sealed `ParentLocked`** — the seal-cap rejects every submission whose parent sits at-or-before `v_{seal-1}`. When the rejected submission originated from another federation peer's locally-landed priv event (concurrent priv-vs-priv race — `Evl-vs-Evl`, `Evl-vs-Dec`, etc.), the chain does not structurally converge with that peer; federation-level convergence resolves at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). The per-race-shape enumeration is in [§Race matrix](#race-matrix) below.
- **Decommissioned IEL → `IelDecommissioned` everywhere.** Dec is fully terminal; the seal-cap rejects any subsequent submission. Federation-race convergence with concurrent competing privileged submissions is handled at the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205) and [§Race matrix](#race-matrix) below).

### Batch submissions

The submit handler treats a batch atomically:

- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page (`MINIMUM_PAGE_SIZE = 64`).
- **`[Icp]`** — chain inception. Standalone batch is fine (unlike SEL, which requires `[Icp, Upd]`). IEL Icp is itself policy-enforced (anchored under declared `governancePolicy`).
- **`[Icp, Evl]`** also valid — inception with immediate first evolution. (Icp + governance step in same batch.)

There is no `[..., Rpr]` batch — IEL has no `Rpr` kind.

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID for gossip. Peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. The receiving handler routes via the same per-event flow used for direct submissions (`Dec` → decommissioned; priv event whose landing would create or join a divergent set → rejected with `ParentLocked`-equivalent).

IEL chains are linear per-node (Active or Decommissioned). The source sends a single full-chain stream that the sink applies as a normal append. Cross-node priv-vs-priv races surface via the irreconcilable-prefix table at the federation layer rather than as in-protocol partitioning. See [merge.md §Gossip propagation](merge.md#gossip-propagation).

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column).

| Source | Sink: Empty | Sink: Active | Sink: Active (other branch authored) | Sink: Decommissioned |
|--------|-------------|--------------|--------------------------------------|----------------------|
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Priv-event-extending-`v_{d-1}` rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal); federation-layer dispute via irreconcilable-prefix table | `IelDecommissioned` |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | `IelDecommissioned` (concurrent priv-event race resolves at infrastructure layer per #205) | Effective SAIDs match; no-op |

### Notes on cell routing

- **Sink terminal state** (Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Cross-node priv-vs-priv races** — when one node lands `Evl`/`Dec` and another lands a competing `Evl`/`Dec` extending the same parent, the seal-cap rejects each peer's gossip-arriving event (its parent sits behind the seal advanced by the local first-receive). Nodes do not structurally converge in this case; federation-level convergence is handled at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). See [§Race matrix](#race-matrix) below.

The matrix is smaller than SEL's because IEL's gossip layer doesn't have a Repaired state — there's no `Rpr`-driven archival. There is no per-node Divergent state on IEL either.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip when no priv-vs-priv race is in flight; otherwise per-node tips may differ and federation-layer dispute is surfaced via the irreconcilable-prefix table). |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing privileged event extending `Dec`'s parent has been submitted to a different node, the federation does NOT structurally converge — each node's seal-cap rejects the other's submission; convergence is via the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205)). |

## Edge Cases

### 1. Two governance-authorized parties race a legitimate Evl

Both submit different `Evl` events at v3 within the gossip-propagation window. Each is governance-authorized; neither is "the adversary." Each event lands cleanly as a linear-chain extension on its submitting node and advances the local seal. Gossip then delivers each event to the other node, where the seal-cap rejects the late arrival. Per-node, each chain stays linear; cross-node, federation-level disagreement is surfaced via the irreconcilable-prefix table.

```
Pre-state (linear at v_2, replicated to nodes A and B):

  Node A:  [Icp] → [Evl_v1] → [Evl_v2]   (tip)
  Node B:  [Icp] → [Evl_v1] → [Evl_v2]   (tip)

Two governance parties submit Evl concurrently with previous = v_2.said:

  Party 1 → Node A:  Evl_v3a   (lands at v_3 on A; A's tip is now Evl_v3a; seal advances)
  Party 2 → Node B:  Evl_v3b   (lands at v_3 on B; B's tip is now Evl_v3b; seal advances)

Gossip propagates Evl_v3a → B and Evl_v3b → A. Each node's seal-cap
rejects the gossip-arriving competing event:

  Node A receives Evl_v3b: parent_serial = 2 < seal_serial = 3
    → rejected. A's tip stays at Evl_v3a.
  Node B receives Evl_v3a: parent_serial = 2 < seal_serial = 3
    → rejected. B's tip stays at Evl_v3b.

  Effective SAIDs:
    effective_said(A) = Evl_v3a.said
    effective_said(B) = Evl_v3b.said
    A ≠ B → federation does not converge at the protocol layer.

Federation-level convergence is provided via the irreconcilable-prefix table
(see [#205](https://github.com/jasoncolburne/kels/issues/205)). Operator
recourse: reconcile out-of-band, or reincept under a new IEL prefix.
```

The protocol does not pick a winner — picking would mean architecting around "who was first," which is unknowable globally. KELS events carry no wall-clock timestamps; ordering is by serial + cryptographic chain linkage (each event's `previous` SAID anchors it to its predecessor), not by clock. See [../../../../protocol-doctrine.md §Ordering Without Timestamps](../../../../protocol-doctrine.md#ordering-without-timestamps). Per-node, each chain is linear; the federation surfaces cross-node disagreement.

### 2. Adversary submits a conflicting Evl after governance compromise

Same shape as case 1 — no protocol-level distinction between "innocent race" and "compromise" since both produce the same per-node-linear-but-federation-disputed signal. Operator's protocol-level recourse is the same: reconcile out-of-band, or reincept under a new prefix. Forensic owner-attribution lives in out-of-band channels (operator publishes a signed statement under their KEL); the in-band signal is "the IEL prefix is in dispute via the irreconcilable-prefix table at v_3."

```
Identical signal to case 1:

  Node A: [Icp] → [Evl_v1] → [Evl_v2] → Evl_v3_operator
  Node B: [Icp] → [Evl_v1] → [Evl_v2] → Evl_v3_adversary

  Federation surfaces the disagreement via the irreconcilable-prefix table.

Race-vs-takeover indistinguishability: the federation signal records
disagreement without recording cause. Operator's protocol-level recourse
is the same in both cases — reconcile out-of-band or reincept under
a new prefix.
```

### 3. Cross-chain effect: SELs bound to an IEL event above the seal

If an SEL's `ielEvent` references an IEL event that lives above the IEL's `lastSealAdvancingEvent`, the SEL's authorization resolution returns "IEL state above the seal — cannot resolve" and SEL submissions to that chain are rejected with `IelDivergent`. SELs stay in their at-or-below-seal binding state.

```
IEL chain on Node A (federation-disputed at v_d via priv-vs-priv race):

  [Icp] → [Evl_v1] → ... → [Evl_{d-1}] → Evl_d_a   ← Node A's tip
                                                     (the federation layer
                                                      surfaces Node B's Evl_d_b
                                                      as in-dispute via the
                                                      irreconcilable-prefix table)

SEL chain bound to the IEL (last good at-or-below-seal binding):

  [Icp] → [Upd_v1, ielEvent=Evl_{d-1}.said] → ...

  Submitter tries:
    [Upd_v_new, ielEvent=Evl_d_a.said]   ← bound to an above-seal IEL event

  IEL resolver: "bound event lives above lastSealAdvancingEvent"
   → rejects with IelDivergent.

  Submitter retries with stable at-or-below-seal binding:
    [Upd_v_new, ielEvent=Evl_{d-1}.said]   ← bound at v_{d-1} ≤ seal

  IEL resolver: "bound event at-or-below seal" → OK for chain-validity,
   and consumer trust remains intact for the at-or-below-seal binding per
   [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability).
   Forward extension that would bind to an above-seal IEL event is what's
   blocked.
```

Bindings at-or-below `lastSealAdvancingEvent` resolve cleanly (the at-or-below-seal portion is structurally trustworthy). The seal-bound covers the federation-dispute case by construction — under a federation-level dispute the local seal stays at the prior linear-portion advance. Bindings above the seal are rejected as `IelDivergent`. SEL operator's recovery path: migrate to a different IEL.

### 4. Multiple injections to different nodes

Different parties (each with its own valid governance — implies multiple compromised governance authorities or multiple legitimate parties acting independently) inject different `Evl` events to different nodes. Each node sees its first injection as the linear tip; gossip-arriving competing events are rejected by the seal-cap. The federation surfaces cross-node disagreement via the irreconcilable-prefix table.

```
Pre-state (linear at v_2, replicated to nodes A, B, C):

  All nodes:  [Icp] → [Evl_v1] → [Evl_v2]

Three parties submit different Evl_v3 events to different nodes:

  Node A receives Evl_a   →  tip Evl_a   (linear append at A; seal advances)
  Node B receives Evl_b   →  tip Evl_b   (linear append at B; seal advances)
  Node C receives Evl_c   →  tip Evl_c   (linear append at C; seal advances)

Gossip propagates. Each node's seal-cap rejects every gossip-arriving
competing Evl_*:

  Node A:  tip Evl_a            (Evl_b and Evl_c rejected by seal-cap)
  Node B:  tip Evl_b            (Evl_a and Evl_c rejected by seal-cap)
  Node C:  tip Evl_c            (Evl_a and Evl_b rejected by seal-cap)

Federation surfaces the three-way disagreement via the irreconcilable-prefix
table. Operator reincepts under a new IEL prefix to resume forward
operation.
```

### 5. Concurrent Evl + Dec at v_d — federation race, infrastructure-layer convergence

Two governance-authorized parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec` (terminal); party 2 submits `Evl`. Each lands as a linear-chain extension on its submitting node — node A becomes Decommissioned, node B becomes Active with `Evl` as tip. Gossip then delivers each event to the other node, but the seal-cap rejects each — each peer's submission has `parent_serial = d-1 < seal_serial = d` after the local first-receive. Nodes do not structurally converge:

```
Pre-state (linear at v_{d-1}):

  Both nodes:  [Icp] → ... → [Evl_{d-1}]   (tip)

Concurrent submissions:

  Party 1 → Node A:  Dec.previous     = Evl_{d-1}.said, Dec.serial     = d
  Party 2 → Node B:  Evl_alt.previous = Evl_{d-1}.said, Evl_alt.serial = d

Each event lands as a linear-chain extension on its submitting node.

Gossip propagates:

  Node A (Decommissioned at v_d via Dec) receives Evl_alt:
    Evl_alt.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap.
    A's state unchanged: Decommissioned.

  Node B (Active at v_d via Evl_alt) receives Dec:
    Dec.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap.
    B's state unchanged: Active with Evl_alt as tip.

  Effective SAIDs:
    effective_said(A) = Dec.said
    effective_said(B) = Evl_alt.said
    A ≠ B → federation does not converge at the protocol layer.
```

Federation-level convergence in this scenario is provided at the infrastructure layer via a irreconcilable-prefix table that nodes maintain and gossip-sync; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205) for the design. The seal-cap stays unconditional; relaxing it to admit competing events at a sealed serial would re-open a stale-authority killswitch surface.

## Race matrix

Concurrent priv-vs-priv races between federation peers — both submitting privileged events extending the same parent `v_{d-1}` to different nodes — uniformly resolve via the same shape: each event lands as a clean linear-chain extension on its submitting node and advances the local seal; gossip then delivers each event to the other node, where the seal-cap rejects it (parent in locked portion). The chain does not structurally converge at the protocol layer; federation-level convergence is provided at the infrastructure layer via the irreconcilable-prefix table (see [#205](https://github.com/jasoncolburne/kels/issues/205)).

IEL has a smaller race surface than KEL/SEL because the kind set is `Icp`, `Evl`, `Dec` (no Rec/Rpr/Sea). Icp is structurally pinned to `v_0` and cannot participate in same-parent races on a post-Icp chain. The race participants — any pairing across `{Evl, Dec}` — produce identical structural outcomes per-node:

- Each node keeps its locally-landed first-receive.
- The gossip-arriving competing event is rejected by the seal-cap with `ParentLocked` (or `IelDecommissioned` on the Dec'd side, equivalently a seal-cap rejection).
- Federation-level convergence is via #205.

## References

- [events.md](events.md) — Per-kind reference.
- [event-log.md](event-log.md) — Chain lifecycle: states, privileged-event merge-layer rejection, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [../sel/reconciliation.md](../sel/reconciliation.md) — SEL counterpart (which has Rpr and Repaired state).
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart.
