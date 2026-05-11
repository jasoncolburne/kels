# IEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all IEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the IEL design — without it, the submit handler and gossip layer aren't proven sound.

For lifecycle prose (states, divergence-by-Cnt-resolution, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For submit-handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Every IEL event after Icp is governance-authorized**: `Evl`, `Cnt`, `Dec` all require `governance_policy` satisfaction. There are no auth-only events on IEL after Icp. This eliminates the auth-vs-governance asymmetry that today's SEL needs Rpr to handle.

2. **No proactive-evaluation bound needed**: every event after Icp is itself a governance evaluation. There is no "non-evaluation event run" to cap. (Icp counts as one non-evaluation event in the SEL sense, but only one Icp lands per chain.)

3. **No archival**: history is encoded in the data, including divergent branches, forever. There is no `truncate_and_replace`, no `Rpr`, no archive table.

4. **No retroactive poisoning**: every policy referenced as `auth_policy` or `governance_policy` MUST have `immune: true`. Both submit and verify enforce. Past evaluations stay satisfied by construction. See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability).

These invariants are what let IEL ship without Rpr and without an archival path.

## IEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Active** | Linear, non-divergent, no terminal event. |
| **Divergent** | Fork detected. Both branches preserved as forensic record. Only `Cnt` resolves; everything else returns `ContestRequired`. |
| **Contested** | `Cnt` present, permanently frozen. |
| **Decommissioned** | `Dec` present, permanently frozen. |

There is **no Repaired state** — IEL has no Rpr.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| IEL State | Icp | Evl | Cnt / pending+Cnt | Dec |
|-----------|-----|-----|-------------------|-----|
| **Empty** | Append ✓ if `governance_policy` satisfied (Icp.said anchored under declared governance_policy — every IEL event is governance-authorized); reject otherwise | Reject (no chain) | Reject | Reject |
| **Active** | Reject (already incepted) | Append ✓ (governance-authorized) | Contest ✓ (Cnt with `previous = v_{tip-1}.said` creates fresh divergence at v_tip with the existing tip; privileged-divergence-is-terminal fires; chain becomes Contested) | Append ✓ (terminates the chain) |
| **Active, sealed** (governance event at-or-before `last_governance_event` in chain order would re-evaluate the seal) | n/a | `ContestRequired` | Contest ✓ (Cnt with `previous = v_{tip-1}.said` creates fresh divergence at v_tip; on linear IEL the seal coincides with the tip, so land-version v_tip = seal_version, admitted by the seal-cap's parent-at-(seal − 1) boundary; chain becomes Contested) | Append ✓ (Dec on a non-divergent chain routes to decommission regardless of seal position; chain terminates cleanly) |
| **Divergent** | Reject (Icp can't appear at v1+) | `ContestedIel` (divergent IEL is structurally contested-terminal) | `ContestedIel` (divergent IEL is structurally contested-terminal — no further events including Cnt accepted; Cnt only lands as one of the events in the original 2-event divergent set, or on a linear chain) | `ContestedIel` (divergent IEL is structurally contested-terminal) |
| **Contested** | `ContestedIel` | `ContestedIel` | `ContestedIel` | `ContestedIel` |
| **Decommissioned** | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` |

### Batch submissions

The submit handler treats a batch atomically:

- **`[pending..., Cnt]`** — owner's pre-flush staged events plus the contest extending the last bundled tip. At most one page (`MINIMUM_PAGE_SIZE = 64`).
- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page.
- **`[Icp]`** — chain inception. Standalone batch is fine (unlike SEL, which requires `[Icp, Upd]`). IEL Icp is itself policy-enforced (anchored under declared `governance_policy`).
- **`[Icp, Evl]`** also valid — inception with immediate first evolution. (Icp + governance step in same batch.)

There is no `[..., Rpr]` batch — IEL has no Rpr.

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID for gossip. Peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. The receiving handler routes via the same kind-discriminator (`is_contest` / `is_decommission`) used for direct submissions.

For linear chains the source sends a single full-chain stream. For divergent chains the source uses `send_divergent_iel_events` (`lib/kels/src/types/iel/sync.rs`) to partition the chain into sub-batches the sink will accept under its routing rules: pre-divergence + non-`Cnt` chain as paged appends, then `Cnt` chain as an atomic single-page batch. See [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-iels). Sender-side composition is the cryptographic-soundness gate; the sink's routing rules are the constraint the sender designs around, not a safety net.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column).

| Source | Sink: Empty | Sink: Active | Sink: Active (other branch authored) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|--------------|--------------------------------------|-----------------|-----------------|----------------------|
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Overlap → divergence ✓ (sink stores both branches) | Duplicates of one branch, no-op for that branch ✓ | `ContestedIel` (sink terminal; gossip ignored) | `IelDecommissioned` (sink terminal; gossip ignored) |
| **Divergent** | Both fork events appended ✓ (sink becomes divergent) | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓; full anti-entropy may reconcile any-missing-branch-events | `ContestedIel` | `IelDecommissioned` |
| **Contested** | Full chain (incl. `Cnt`) appended ✓ | `Cnt` batch routes to contest path ✓ | `Cnt` batch routes to contest path ✓ | `Cnt` batch routes to contest path ✓ | Effective SAIDs match ✓ | `Cnt` batch → override → contest ✓ (gossip-delivered `Cnt` lands at `v_d` alongside the sink's `Dec`; privileged-divergence-is-terminal fires; sink transitions to Contested per [../../security-invariant.md §Cnt Overrides Dec](../../security-invariant.md#cnt-overrides-dec); effective SAIDs converge on `hash("contested:{prefix}")`) |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch routes to decommission ✓ | Overlap detected, `Dec` in chain → decommission ✓ | `Dec` does not resolve divergence — gossip's `Dec` extending one branch of a divergent sink is rejected with `ContestRequired`. The sink stays divergent until a `Cnt` arrives via gossip or direct submission. | `ContestedIel` | Effective SAIDs match (or both terminal-frozen at the Dec event SAID); no-op |

The matrix is smaller than SEL's because IEL's gossip layer doesn't have a Repaired state — there's no Rpr-driven archival, just contest-or-decommission-or-stay-divergent.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (a chain carrying both `Dec` and `Cnt` resolves here, since `is_contested = true` takes precedence over `is_decommissioned` — see [../../security-invariant.md §Cnt Overrides Dec](../../security-invariant.md#cnt-overrides-dec)) |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains; applies only when no `Cnt` has overridden the `Dec`) |

## Edge Cases

### 1. Two governance-authorized parties race a legitimate Evl

Both submit different `Evl` events at v3 within the gossip-propagation window. Each is governance-authorized; neither is "the adversary." Both reach storage at different nodes. Gossip propagates; nodes converge on divergent state. Owner submits `Cnt` to terminate; chain re-incepts under new prefix.

```
Pre-state (linear at v_2, replicated to nodes A and B):

  Node A:  [Icp] → [Evl_v1] → [Evl_v2]   (tip)
  Node B:  [Icp] → [Evl_v1] → [Evl_v2]   (tip)

Two governance parties submit Evl concurrently with previous = v_2.said:

  Party 1 → Node A:  Evl_v3a   (lands at v_3 on A; A's tip is now Evl_v3a)
  Party 2 → Node B:  Evl_v3b   (lands at v_3 on B; B's tip is now Evl_v3b)

Gossip propagates Evl_v3a → B and Evl_v3b → A. Each node observes a
2-event divergent set at v_3:

  Both nodes:  [Icp] → [Evl_v1] → [Evl_v2] ─┬─ Evl_v3a ┐
                                            └─ Evl_v3b ┴── contested-terminal
                                                            (both privileged →
                                                             privileged-divergence
                                                             fires)

All IEL events are privileged → chain transitions to contested-terminal at
first observation of divergence. Both events stay in storage as forensic
record. Operator reincepts under a new IEL prefix.
```

The protocol does not pick a winner — picking would mean architecting around "who was first," which is unknowable globally. KELS events carry no wall-clock timestamps; ordering is by version + cryptographic chain linkage (each event's `previous` SAID anchors it to its predecessor), not by clock. See [../security-invariant.md §Ordering Without Timestamps](../../security-invariant.md#ordering-without-timestamps). We accept the divergence as data.

### 2. Adversary submits a conflicting Evl after governance compromise

Same shape as case 1 — no protocol-level distinction between "innocent race" and "compromise" since both produce the same chain shape. Owner detects via federation status, submits `Cnt`. Chain terminates.

```
Identical chain shape to case 1:

  [Icp] → [Evl_v1] → [Evl_v2] ─┬─ Evl_v3_operator
                               └─ Evl_v3_adversary    ← contested-terminal

Race-vs-takeover indistinguishability: the chain mathematics record
divergence without recording cause. Operator's protocol-level recourse
is the same in both cases — reincept under a new prefix. The optional
explicit Cnt below makes intent visible:

  [Icp] → [Evl_v1] → [Evl_v2] ─┬─ Evl_v3_operator    ┐
                               ├─ Evl_v3_adversary   ├── still contested
                               └─ Cnt   (rejected by ┘   (gate already closed
                                        contested-state      at first divergence
                                        gate)                 observation)

Note: a Cnt submitted post-divergence to a contested IEL is rejected by
the contested-state gate. Cnt only lands on IEL as a linear-chain
extension or as one event in the original 2-event divergent set; once
the chain is contested-terminal, all subsequent submissions are rejected.
```

### 3. Cross-chain effect: SELs bound to a divergent IEL event

If an SEL's `identity_event` references an IEL event that lives on a now-divergent IEL branch, the SEL's authorization resolution returns "IEL is divergent at the bound branch — cannot resolve" and SEL submissions to that chain are rejected with `IelDivergent`. SELs stay in their pre-divergence state until the IEL is contested-and-replaced.

```
IEL chain (now divergent at v_d):

  [Icp] → [Evl_v1] → ... → [Evl_{d-1}] ─┬─ Evl_d_a
                                        └─ Evl_d_b    ← contested-terminal

SEL chain bound to the IEL (last good binding pre-divergence):

  [Icp] → [Upd_v1, identity_event=Evl_{d-1}.said] → ...

  Submitter tries:
    [Upd_v_new, identity_event=Evl_d_a.said]   ← bound to a divergent IEL event

  IEL resolver: "bound event lives at v_d ≥ first_divergent_version"
   → rejects with IelDivergent.

  Submitter retries with stable pre-divergence binding:
    [Upd_v_new, identity_event=Evl_{d-1}.said]   ← bound at v_{d-1} < d

  IEL resolver: "bound event is in pre-divergence shared prefix" → OK
   for chain-validity; consumer trust degraded per whole-chain-suspect rule.
```

Bindings at versions strictly less than `first_divergent_version` resolve cleanly (pre-divergence portion is unambiguous). Bindings at-or-after the divergent version are rejected as `IelDivergent`. SEL operator's recovery path: contest the SEL or migrate to a different IEL.

### 4. Multiple adversary injections to different nodes

Adversary injects different `Evl` events to different nodes (each with its own valid governance — implies multiple compromised governance authorities or multiple legitimate parties acting independently). Each node sees its first injection as the "tip"; gossip propagates, divergence is detected. With three or more conflicting events, the chain freezes after the first divergence; subsequent injections are dedup-rejected (only one extra event per version is accepted as the divergence marker). Owner submits `Cnt` to terminate.

```
Pre-state (linear at v_2, replicated to nodes A, B, C):

  All nodes:  [Icp] → [Evl_v1] → [Evl_v2]

Three parties submit different Evl_v3 events to different nodes:

  Node A receives Evl_a   →  tip Evl_a   (linear append at A)
  Node B receives Evl_b   →  tip Evl_b   (linear append at B)
  Node C receives Evl_c   →  tip Evl_c   (linear append at C)

Gossip propagates. Suppose Evl_b arrives at A first; A becomes divergent
at v_3 with {Evl_a, Evl_b}; chain becomes contested-terminal on A
immediately (privileged-divergence rule). Subsequent gossip of Evl_c to
A is rejected by A's now-closed contested-state gate.

Final state on each node depends on gossip ordering, but every node ends
up contested-terminal with effective SAID = hash_effective_said(
"contested:{prefix}"). Across all nodes:

  Node A:  ... → Evl_v2 ─┬─ Evl_a (first arrived)
                         └─ Evl_b           ← contested-terminal
                                              (Evl_c gossip rejected by gate)

  Node B:  ... → Evl_v2 ─┬─ Evl_b (local)
                         └─ Evl_c (or Evl_a) ← contested-terminal

  Node C:  ... → Evl_v2 ─┬─ Evl_c (local)
                         └─ Evl_a (or Evl_b) ← contested-terminal

Cross-node forensic divergence is acceptable; all nodes converge on the
same effective SAID for the contested state.
```

### 5. Concurrent Cnt + Evl at v_d

Two governance-authorized parties submit concurrently to different nodes at v_d: party 1 submits `Cnt` with `previous = v_{d-1}.said`; party 2 submits `Evl` with `previous = v_{d-1}.said`. Both land. The 2-event divergent set at v_d is privileged (Cnt is privileged; even without Cnt, Evl–Evl would still be privileged because every IEL event is privileged) → privileged-divergence-is-terminal fires immediately; chain becomes contested-terminal as of v_d. Subsequent submissions arriving at v_d via gossip — including any further `Cnt` — are rejected by the contested-state gate. Both events stay in storage as forensic record; all nodes converge on `hash_effective_said("contested:{prefix}")`.

```
Pre-state (linear at v_{d-1}):

  [Icp] → [Evl_v1] → ... → [Evl_{d-1}]   (tip)

Two governance parties submit concurrently to different nodes:

  Party 1 (operator) → Node A:
    Cnt.previous = v_{d-1}.said
    Cnt.version  = d
  Party 2 (second governance party) → Node B:
    Evl_v_d.previous = v_{d-1}.said
    Evl_v_d.version  = d

Each event lands as a linear-chain extension on its submitting node (no
divergence visible at submit time on either node). Gossip propagates.

Final state on every node (2-event privileged divergent set at v_d):

  [Icp] → ... → [Evl_{d-1}] ─┬─ Cnt     @ v_d ┐
                             └─ Evl_v_d @ v_d ┴── contested-terminal
                                                  (privileged-divergence fires;
                                                   every IEL event is privileged)

Both events stay as forensic record. Cross-node forensic divergence
acceptable (Node A's Cnt might also arrive at C via gossip from A
before Evl_v_d does, or vice versa — final 2-event subset depends on
gossip ordering). All nodes converge on hash_effective_said(
"contested:{prefix}").
```

The same shape applies to `[Evl_a, Evl_b]` (two governance parties racing) and `[Evl, Cnt]` (governance evolution racing operator contest, where the Cnt-submitter's node had its tip advanced to `v_d` via gossip-delivered `Evl`): in every case the 2-event divergent set is contested-terminal and no 3rd event lands.

Two operators may submit `Cnt` concurrently to different nodes — a real operational scenario — but the resulting divergent set on each individual log is `[Evl, Cnt]`, where the `Evl` is the chain's prior tip and the `Cnt` is whichever arrived first on that node. Gossip-delivered second `Cnt`s hit the contested-state gate and are rejected. Different nodes may land different winning `Cnt`s across the federation, but `[Cnt_a, Cnt_b]` as a single divergent set in one log cannot form — `Cnt` is absolute and terminal (at most one `Cnt` per log).

`Dec` cannot appear in a divergent set — `Dec.previous = tip.said` (extends tip directly), so `Dec` only lands on linear chains, decommissioning the chain on landing.

`Cnt` on a linear chain — operator-initiated termination — is the other scenario in which `Cnt` lands; see [event-log.md §Cnt: Operator Contestation Primitive](event-log.md#cnt-operator-contestation-primitive).

### 6. Cnt-Dec race (override)

Two parties race a terminal event onto a linear IEL chain: the operator submits `Dec` (clean retirement) to one node, while a second governance-authorized party submits `Cnt` (contest) to another. Each lands as a linear-chain extension on its submitting node. Gossip then carries each event to the other node, where the doctrine in [../../security-invariant.md §Cnt Overrides Dec](../../security-invariant.md#cnt-overrides-dec) governs the merge:

- The node that received `Dec` first now receives `Cnt` (with `previous = v_{d-1}.said`). The decommissioned-state gate accepts the override; `Cnt` lands at `v_d` alongside `Dec`; privileged-divergence-is-terminal fires; the chain becomes contested.
- The node that received `Cnt` first now receives `Dec` (with `previous = v_{d-1}.said`). The contested-state gate rejects `Dec` outright — the asymmetry is intentional. The sink's chain stays at `[Cnt]` alone at `v_d`.

```
Pre-state on both nodes (linear at v_{d-1}):

  [Icp] → ... → [Evl_{d-1}]    (tip)

Concurrent submissions:

  Node A (operator)               → dec.previous = v_{d-1}.said   (lands on A)
  Node B (other governance party) → cnt.previous = v_{d-1}.said   (lands on B)

After gossip merge:

  Node A receives Cnt → override accepted → divergent set at v_d:
    [Icp] → ... → [Evl_{d-1}] ─┬─ dec @ v_d ┐
                               └─ cnt @ v_d ┴── contested-terminal

  Node B receives Dec → contested-state gate rejects → unchanged:
    [Icp] → ... → [Evl_{d-1}] → cnt @ v_d    contested-terminal

  effective_said(A) = hash_effective_said("contested:{prefix}")
  effective_said(B) = hash_effective_said("contested:{prefix}")
                    = effective_said(A)    ✓
```

Both nodes converge on the contested effective SAID; cross-node forensic divergence at `v_d` is acceptable. Without the override, A would resolve to `hash_effective_said("decommissioned:{prefix}") = Dec.said` while B would resolve to `hash_effective_said("contested:{prefix}")`, and anti-entropy would spin forever.

## References

- [events.md](events.md) — Per-kind reference.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [../sel/reconciliation.md](../sel/reconciliation.md) — SEL counterpart (which has Rpr and Repaired state).
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart.
