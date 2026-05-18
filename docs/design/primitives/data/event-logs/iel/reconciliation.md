# IEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all IEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the IEL design — without it, the submit handler and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence-is-contested-terminal, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For submit-handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Every IEL event is governance-authorized**: `Icp` is self-endorsed under its declared `governancePolicy`; `Evl`, `Sea`, `Dec` all require the branch's tracked `governancePolicy` satisfaction. There are no auth-only events on IEL. This eliminates the auth-vs-governance asymmetry that SEL needs Rpr to handle.

2. **No proactive-evaluation bound needed**: every non-terminal post-Icp IEL event advances the seal (`Evl`/`Sea`), and only one Icp lands per chain. There is no "non-evaluation event run" for a bound to cap — the SEL `MAX_NON_EVALUATION_EVENTS` cap has no IEL analog.

3. **No archival**: history is encoded in the data, including divergent branches, forever. There is no `truncate_and_replace`, no `Rpr`, no archive table.

4. **No retroactive poisoning**: every policy referenced as `authPolicy` or `governancePolicy` MUST have `immune: true`. Both submit and verify enforce. Past evaluations stay satisfied by construction. See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability).

5. **Contested-state coincides with divergent state**: divergence on IEL is contested-terminal directly (every IEL event is privileged → privileged-divergence-is-terminal fires immediately). Operator recourse against compromise is described in [event-log.md §Operator recourse against compromise](event-log.md#operator-recourse-against-compromise) — linear governance evolution or rotating the IEL out of parent policies.

These invariants are what let IEL ship without `Rpr` or an archival path.

## IEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Active** | Linear, non-divergent, no terminal event. |
| **Active, sealed** | Sub-state of Active where the submitter's view lands at-or-before `lastSealAdvancingEvent` (a governance-authorized party has advanced the seal past the submitter). Non-terminal `Evl`/`Sea` submissions return `ContestRequired`; only `Dec` (clean termination) is admissible. |
| **Contested (= Divergent)** | Chain shape with 2 events at serial `d`; contested-terminal by privileged-divergence-is-terminal (every IEL event is privileged). Both branches preserved as forensic record. All submissions rejected with `ContestedIel`. On IEL these are the same state — `is_contested ⇔ is_divergent`. |
| **Decommissioned** | Exactly one `Dec`, ending a clean chain. Accepts no linear extension; admits a non-archiving privileged event with `previous = v_{d-1}.said` and `serial = Dec.serial` as a divergent extension, transitioning the chain to Contested (order-independent rule). |

There is **no Repaired state** — IEL has no `Rpr`. Contested and Divergent are the same state on IEL since every IEL event is privileged.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| IEL State | Icp | Evl | Sea | Dec |
|-----------|-----|-----|-----|-----|
| **Empty** | Append ✓ if `governancePolicy` satisfied; else reject | Reject (no chain) | Reject (no chain) | Reject |
| **Active** | Reject (already incepted) | Append ✓; if creates overlap → Contested | Append ✓; if creates overlap → Contested | Append ✓ → Decommissioned |
| **Active, sealed** (`Evl`/`Sea` would land at-or-before `lastSealAdvancingEvent` in chain order) | n/a | `ContestRequired` | `ContestRequired` | Append ✓ → Decommissioned |
| **Contested (= Divergent)** | Reject (Icp can't appear at v1+) | `ContestedIel` | `ContestedIel` | `ContestedIel` |
| **Decommissioned** | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` |

### Notes on cell routing

- **`Sea` shape constraints** — parent must not be `Icp`/`Sea`/`Dec`. See [events.md §Sea](events.md).
- **`Dec` on Active or Active, sealed** — Dec terminates the chain rather than extending it; routes to decommission regardless of seal position.
- **Overlap creates Contested** — a non-Dec event chaining from earlier than the linear tip creates a 2-event divergent set at `v_d`; privileged-divergence-is-terminal fires immediately, transitioning the chain to contested-terminal. There is no recoverable intermediate state — IEL has no `Rpr`.
- **Contested (= Divergent) IEL → `ContestedIel` everywhere** — contested-terminal accepts no further events of any kind. There is no upgrade path because there's no non-privileged-divergent state to upgrade from on IEL (every IEL event is privileged). See [event-log.md §Divergence is Contested-Terminal](event-log.md#divergence-is-contested-terminal).
- **Decommissioned IEL → `IelDecommissioned` for linear extension.** Dec is terminal with respect to linear extension; the locked-portion bound rejects any subsequent repair event targeting the locked portion. A non-archiving privileged event with `previous = v_{d-1}.said` and `serial = Dec.serial` is admitted as a divergent extension; the chain transitions Decommissioned → Contested per [../../../../protocol-doctrine.md §Order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions).

### Batch submissions

The submit handler treats a batch atomically:

- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page (`MINIMUM_PAGE_SIZE = 64`).
- **`[Icp]`** — chain inception. Standalone batch is fine (unlike SEL, which requires `[Icp, Upd]`). IEL Icp is itself policy-enforced (anchored under declared `governancePolicy`).
- **`[Icp, Evl]`** also valid — inception with immediate first evolution. (Icp + governance step in same batch.)

There is no `[..., Rpr]` batch — IEL has no `Rpr` kind.

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID for gossip. Peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. The receiving handler routes via the same per-event flow used for direct submissions (overlap → contested-terminal; `Dec` → decommissioned).

For linear chains the source sends a single full-chain stream. For divergent (= contested) chains the source uses `send_divergent_iel_events` (`lib/kels/src/types/iel/sync.rs`) to partition the chain into single-event batches the sink will accept under its routing rules: pre-divergence chain as paged appends, then the two divergent-set events as single-event batches (first lands as clean append, second triggers the overlap path and transitions the sink to contested-terminal). See [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-iels). Sender-side composition is the cryptographic-soundness gate; the sink's routing rules are the constraint the sender designs around, not a safety net.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column).

| Source | Sink: Empty | Sink: Active | Sink: Active (other branch authored) | Sink: Contested (= Divergent) | Sink: Decommissioned |
|--------|-------------|--------------|--------------------------------------|-------------------------------|----------------------|
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Overlap → contested ✓ | Duplicates of one branch, no-op ✓ | `IelDecommissioned` |
| **Contested (= Divergent)** | Both fork events appended ✓ (first as clean append, second triggers overlap → contested) | Fork event creates overlap → contested ✓ | Fork event creates overlap → contested ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `IelDecommissioned` |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | Overlap → contested ✓ (Dec lands on one branch and creates the divergent set; pre-Dec tip on the other branch) | `ContestedIel` | Effective SAIDs match; no-op |

### Notes on cell routing

- **Sink terminal states** (Contested, Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Decommissioned → Contested sink** — contested-terminal sink rejects every gossip-delivered event including the source's `Dec` with `ContestedIel`. The Decommissioned source, when it receives the Contested branch's non-archiving privileged event extending `v_{d-1}` via gossip, accepts it under the order-independent divergent transitions rule and transitions Decommissioned → Contested. Both nodes converge on `hash_effective_said("contested:{prefix}")`. See [../../../../protocol-doctrine.md §Order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions).
- **Contested → Contested sink** — effective SAIDs match by construction (both produce `hash("contested:{prefix}")` since IEL contested-state derives from divergence shape); full anti-entropy may reconcile any-missing-branch-events even when SAIDs already match.

The matrix is smaller than SEL's because IEL's gossip layer doesn't have a Repaired state — there's no `Rpr`-driven archival. Contested coincides with Divergent on IEL since every IEL event is privileged.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Contested (= Divergent)** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (covers all divergent-shape chains; IEL sets `is_contested = true` whenever it observes a divergent set, so the same value applies regardless of which fork events each node has) |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing non-archiving privileged event extending `Dec`'s parent has been submitted to any node, gossip delivery upgrades Dec-first nodes Decommissioned → Contested via the [order-independent rule](../../../../protocol-doctrine.md#order-independent-divergent-transitions); effective SAID becomes `hash_effective_said("contested:{prefix}")`. |

## Edge Cases

### 1. Two governance-authorized parties race a legitimate Evl

Both submit different `Evl` events at v3 within the gossip-propagation window. Each is governance-authorized; neither is "the adversary." Both reach storage at different nodes. Gossip propagates; nodes converge on contested (= divergent) state. The chain terminates structurally; the operator re-incepts under a new prefix.

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

The protocol does not pick a winner — picking would mean architecting around "who was first," which is unknowable globally. KELS events carry no wall-clock timestamps; ordering is by serial + cryptographic chain linkage (each event's `previous` SAID anchors it to its predecessor), not by clock. See [../../../../protocol-doctrine.md §Ordering Without Timestamps](../../../../protocol-doctrine.md#ordering-without-timestamps). Divergence is preserved as data.

### 2. Adversary submits a conflicting Evl after governance compromise

Same shape as case 1 — no protocol-level distinction between "innocent race" and "compromise" since both produce the same chain shape. Chain terminates structurally; operator re-incepts under a new prefix. Forensic owner-attribution after the fact lives in out-of-band channels (operator publishes a signed statement under their KEL); the in-band signal is "the IEL went divergent → contested-terminal at v_3."

```
Identical chain shape to case 1:

  [Icp] → [Evl_v1] → [Evl_v2] ─┬─ Evl_v3_operator
                               └─ Evl_v3_adversary    ← contested-terminal

Race-vs-takeover indistinguishability: the chain mathematics record
divergence without recording cause. Operator's protocol-level recourse
is the same in both cases — reincept under a new prefix. There is no
post-divergence event the operator can submit to make the contest
"intentional" — the chain is already contested-terminal by structure;
any new submission would be rejected by the contested-state gate.
```

### 3. Cross-chain effect: SELs bound to a divergent IEL event

If an SEL's `ielEvent` references an IEL event that lives on a now-divergent IEL branch, the SEL's authorization resolution returns "IEL is divergent at the bound branch — cannot resolve" and SEL submissions to that chain are rejected with `IelDivergent`. SELs stay in their pre-divergence state until the IEL is contested-and-replaced.

```
IEL chain (now divergent at v_d):

  [Icp] → [Evl_v1] → ... → [Evl_{d-1}] ─┬─ Evl_d_a
                                        └─ Evl_d_b    ← contested-terminal

SEL chain bound to the IEL (last good binding pre-divergence):

  [Icp] → [Upd_v1, ielEvent=Evl_{d-1}.said] → ...

  Submitter tries:
    [Upd_v_new, ielEvent=Evl_d_a.said]   ← bound to a divergent IEL event

  IEL resolver: "bound event lives at v_d ≥ first_divergent_serial"
   → rejects with IelDivergent.

  Submitter retries with stable pre-divergence binding:
    [Upd_v_new, ielEvent=Evl_{d-1}.said]   ← bound at v_{d-1} < d

  IEL resolver: "bound event is in pre-divergence shared prefix" → OK
   for chain-validity; consumer trust degraded per whole-chain-suspect rule.
```

Bindings at serials strictly less than `first_divergent_serial` resolve cleanly (pre-divergence portion is unambiguous). Bindings at-or-after the divergent serial are rejected as `IelDivergent`. SEL operator's recovery path: contest the SEL or migrate to a different IEL.

### 4. Multiple adversary injections to different nodes

Adversary injects different `Evl` events to different nodes (each with its own valid governance — implies multiple compromised governance authorities or multiple legitimate parties acting independently). Each node sees its first injection as the "tip"; gossip propagates, divergence is detected. With three or more conflicting events, the chain transitions to Contested at the first 2-event divergent set; subsequent injections are dedup-rejected (only one extra event per serial is accepted as the divergence marker). Chain terminates structurally on first 2-event divergent set; operator re-incepts under a new prefix.

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

### 5. Concurrent Evl + Dec at v_d (Decommissioned → Contested via order-independent transition)

Two governance-authorized parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec` (terminal); party 2 submits `Evl`. Each lands as a linear-chain extension on its submitting node — node A becomes Decommissioned, node B becomes Active with `Evl` as tip. Gossip then delivers each event to the other node, and the [order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions) rule produces convergence:

```
Pre-state (linear at v_{d-1}):

  Both nodes:  [Icp] → ... → [Evl_{d-1}]   (tip)

Concurrent submissions:

  Party 1 → Node A:  Dec.previous     = Evl_{d-1}.said, Dec.serial     = d
  Party 2 → Node B:  Evl_alt.previous = Evl_{d-1}.said, Evl_alt.serial = d

Each event lands as a linear-chain extension on its submitting node.

Gossip propagates:

  Node A (Decommissioned) receives Evl_alt:
    Evl_alt.previous = v_{d-1}.said matches Dec's parent;
    order-independent rule accepts Evl_alt as a divergent extension at
    Dec's serial. The chain transitions Decommissioned → Contested.
    A's final state: [Icp] → ... → [Evl_{d-1}] ─┬─ Dec     @ v_d ┐
                                                └─ Evl_alt @ v_d ┴── Contested

  Node B (Active) receives Dec: overlap → Contested at v_d.
    B's final state: [Icp] → ... → [Evl_{d-1}] ─┬─ Evl_alt @ v_d ┐
                                                └─ Dec     @ v_d ┴── Contested

  Effective SAIDs:
    effective_said(A) = hash_effective_said("contested:{prefix}")
    effective_said(B) = hash_effective_said("contested:{prefix}")
    A = B → federation converges.
```

The order-independent divergent transitions rule is what guarantees the convergence. Without it, node A would reject the gossip-arriving Evl_alt with `IelDecommissioned` and remain Decommissioned while node B was Contested — federation would fail to converge.

## References

- [events.md](events.md) — Per-kind reference.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [../sel/reconciliation.md](../sel/reconciliation.md) — SEL counterpart (which has Rpr and Repaired state).
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart.
