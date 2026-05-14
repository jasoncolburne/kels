# IEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all IEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the IEL design — without it, the submit handler and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../protocol-doctrine.md §Federation Convergence](../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence-by-Cnt-resolution, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For submit-handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Every IEL event after Icp is governance-authorized**: `Evl`, `Sea`, `Cnt`, `Dec` all require `governance_policy` satisfaction. There are no auth-only events on IEL after Icp. This eliminates the auth-vs-governance asymmetry that SEL needs Rpr to handle.

2. **No proactive-evaluation bound needed**: every event after Icp is itself a governance evaluation. There is no "non-evaluation event run" to cap. (Icp counts as one non-evaluation event in the SEL sense, but only one Icp lands per chain.)

3. **No archival**: history is encoded in the data, including divergent branches, forever. There is no `truncate_and_replace`, no `Rpr`, no archive table.

4. **No retroactive poisoning**: every policy referenced as `auth_policy` or `governance_policy` MUST have `immune: true`. Both submit and verify enforce. Past evaluations stay satisfied by construction. See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability).

These invariants are what let IEL ship without Rpr and without an archival path.

## IEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Active** | Linear, non-divergent, no terminal event. |
| **Divergent** | Chain shape with 2 events at serial `d`; treated as Contested per privileged-divergence (every IEL event is privileged). Both branches preserved as forensic record. All submissions rejected with `ContestedIel`. |
| **Contested** | `Cnt` present, permanently frozen. |
| **Decommissioned** | `Dec` present, permanently frozen. |

There is **no Repaired state** — IEL has no Rpr.

"Active, sealed" is a sub-state of **Active** where the submitter's view of the tip lands at-or-before `last_seal_advancing_event` (a governance-authorized party has advanced the seal past the submitter); non-terminal `Evl`/`Sea` submissions return `ContestRequired`. Only `Cnt` (repudiation) and `Dec` (clean termination) are admissible at the boundary.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| IEL State | Icp | Evl | Sea | Cnt / pending+Cnt | Dec |
|-----------|-----|-----|-----|-------------------|-----|
| **Empty** | Append ✓ if `governance_policy` satisfied; else reject | Reject (no chain) | Reject (no chain) | Reject | Reject |
| **Active** | Reject (already incepted) | Append ✓ | Append ✓ | Contest ✓ → Contested | Append ✓ → Decommissioned |
| **Active, sealed** (`Evl`/`Sea` would land at-or-before `last_seal_advancing_event` in chain order) | n/a | `ContestRequired` | `ContestRequired` | Contest ✓ → Contested | Append ✓ → Decommissioned |
| **Divergent** | Reject (Icp can't appear at v1+) | `ContestedIel` | `ContestedIel` | `ContestedIel` | `ContestedIel` |
| **Contested** | `ContestedIel` | `ContestedIel` | `ContestedIel` | `ContestedIel` | `ContestedIel` |
| **Decommissioned** | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` | `Cnt` with `previous = v_{d-1}.said` → override → Contested (see [§Cnt mechanics](event-log.md#cnt-mechanics)); other `Cnt` parent shapes → `IelDecommissioned` | `IelDecommissioned` |

### Notes on cell routing

- **`Cnt` on Active or Active, sealed** — Cnt with `previous = v_{tip-1}.said` creates a 2-event divergent set at `v_tip` with the existing tip; privileged-divergence-is-terminal fires immediately. On linear IEL the seal coincides with the tip, so `Cnt`'s land-serial equals `seal_serial` — admitted by the seal-cap's parent-at-(seal − 1) boundary case. See [event-log.md §Cnt mechanics](event-log.md#cnt-mechanics).
- **`Sea` shape constraints** — parent must not be `Icp`/`Sea`/`Cnt`/`Dec`. See [events.md §Sea](events.md).
- **`Dec` on Active or Active, sealed** — Dec terminates the chain rather than extending it; routes to decommission regardless of seal position.
- **Divergent IEL → `ContestedIel` everywhere** — divergent IEL is structurally contested-terminal (every IEL event is governance-authorized → privileged), so no further events including Cnt land in the divergent state. The Cnt-as-third-event upgrade path doesn't exist on IEL. See [event-log.md §Divergence and Contest-Only Resolution](event-log.md#divergence-and-contest-only-resolution).
- **Cnt-Overrides-Dec** — only Cnt overrides; other event kinds (Evl/Sea/Dec) on a Decommissioned chain → `IelDecommissioned`. See [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec).

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
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Overlap → divergence ✓ | Duplicates of one branch, no-op ✓ | `ContestedIel` | `IelDecommissioned` |
| **Divergent** | Both fork events appended ✓ | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `IelDecommissioned` |
| **Contested** | Full chain (incl. `Cnt`) appended ✓ | `Cnt` batch → contest ✓ | `Cnt` batch → contest ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | Effective SAIDs match ✓ | `Cnt` batch → override → contest ✓ |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | Overlap → divergence → Contested ✓ | `ContestedIel` | `ContestedIel` | Effective SAIDs match; no-op |

### Notes on cell routing

- **Sink terminal states** (Contested, Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns. The exception is **Source: Contested → Sink: Decommissioned**, where the gossip-delivered `Cnt` triggers Cnt-Overrides-Dec.
- **Cnt-Overrides-Dec** — gossip-delivered `Cnt` lands at `v_d` alongside the sink's `Dec`; privileged-divergence-is-terminal fires; sink transitions to Contested. Effective SAIDs converge on `hash("contested:{prefix}")`. See [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec).
- **Decommissioned → Divergent sink** — divergent IEL is structurally Contested per privileged-divergence-is-terminal (every IEL event is privileged); the §2 Terminal-State Gate rejects every gossip-delivered event including the source's `Dec` with `ContestedIel`. Effective SAIDs converge on `hash("contested:{prefix}")` for the sink; the decommissioned source's effective SAID is `Dec.said`, which does not converge — but the sink is the terminal state of record here and the source is the one that needs gossip from elsewhere to reconcile.
- **Divergent → Divergent sink** — effective SAIDs match by construction (both produce `hash("contested:{prefix}")` since IEL divergent-shape sets is_contested = true); full anti-entropy may reconcile any-missing-branch-events even when SAIDs already match.

The matrix is smaller than SEL's because IEL's gossip layer doesn't have a Repaired state — there's no Rpr-driven archival, just contest or decommission (divergent-shape always resolves as Contested).

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (covers all divergent-shape chains, with or without explicit `Cnt`, since IEL sets `is_contested = true` via privileged-divergence; same value regardless of which fork events each node has. Also covers a chain carrying both `Dec` and `Cnt` per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec).) |
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

The protocol does not pick a winner — picking would mean architecting around "who was first," which is unknowable globally. KELS events carry no wall-clock timestamps; ordering is by serial + cryptographic chain linkage (each event's `previous` SAID anchors it to its predecessor), not by clock. See [../../protocol-doctrine.md §Ordering Without Timestamps](../../protocol-doctrine.md#ordering-without-timestamps). Divergence is preserved as data.

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

  IEL resolver: "bound event lives at v_d ≥ first_divergent_serial"
   → rejects with IelDivergent.

  Submitter retries with stable pre-divergence binding:
    [Upd_v_new, identity_event=Evl_{d-1}.said]   ← bound at v_{d-1} < d

  IEL resolver: "bound event is in pre-divergence shared prefix" → OK
   for chain-validity; consumer trust degraded per whole-chain-suspect rule.
```

Bindings at serials strictly less than `first_divergent_serial` resolve cleanly (pre-divergence portion is unambiguous). Bindings at-or-after the divergent serial are rejected as `IelDivergent`. SEL operator's recovery path: contest the SEL or migrate to a different IEL.

### 4. Multiple adversary injections to different nodes

Adversary injects different `Evl` events to different nodes (each with its own valid governance — implies multiple compromised governance authorities or multiple legitimate parties acting independently). Each node sees its first injection as the "tip"; gossip propagates, divergence is detected. With three or more conflicting events, the chain freezes after the first divergence; subsequent injections are dedup-rejected (only one extra event per serial is accepted as the divergence marker). Owner submits `Cnt` to terminate.

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
    Cnt.serial  = d
  Party 2 (second governance party) → Node B:
    Evl_v_d.previous = v_{d-1}.said
    Evl_v_d.serial  = d

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

`Cnt` on a linear chain — operator-initiated termination — is the other scenario in which `Cnt` lands; see [event-log.md §Cnt mechanics](event-log.md#cnt-mechanics) for the linear-chain Cnt acceptance shape.

### 6. Cnt-Dec override

Two parties submit terminal events onto a linear IEL chain: the operator submits `Dec` (clean retirement) to one node; a second governance-authorized party submits `Cnt` (contest) to another. The doctrine in [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) generalizes the merge across two construction shapes — depending on whether the Cnt submitter observed Dec before constructing Cnt.

**Case A — Post-Dec sequential override.** The Cnt submitter observed Dec via gossip; their local tip is `Dec @ v_d`. Per `cnt.previous = v_{tip-1}.said`, the Cnt has `previous = v_{d-1}.said = Dec.previous`; Cnt lands at `v_d` alongside Dec.

```
Pre-Cnt state on both nodes (Dec landed on A, gossiped to B):

  [Icp] → ... → [Evl_{d-1}] → dec @ v_d    (tip)

Node B (second governance party, post-Dec view) submits:

  cnt.previous = v_{d-1}.said   → cnt lands at v_d on B alongside dec

After gossip merges:

  [Icp] → ... → [Evl_{d-1}] ─┬─ dec @ v_d ┐
                             └─ cnt @ v_d ┴── contested-terminal @ v_d
```

**Case B — Pre-Dec true-concurrent.** Both submitters' local tips are at `v_d` (the chain's pre-Dec tip, an `Evl` or `Sea`) at construction; neither observes the other before submitting. Per `cnt.previous = v_{tip-1}.said`, the Cnt has `previous = v_{d-1}.said`; Cnt lands at `v_d` as sibling of the pre-Dec tip. Dec extends the pre-Dec tip and lands at `v_{d+1}` on the surviving (forensic) branch.

```
Pre-state on both nodes (linear at v_d):

  [Icp] → ... → [v_{d-1}] → [Evl_d]    (tip)

Concurrent submissions (no mutual observation):

  Node A (operator):              dec.previous = v_d.said       → dec lands at v_{d+1} on A
  Node B (other governance):      cnt.previous = v_{d-1}.said   → cnt lands at v_d on B
                                                                   (sibling of Evl_d;
                                                                    both privileged → contested
                                                                    fires immediately at v_d)

After gossip merges:

  Node A (Dec'd) receives cnt with previous = v_{d-1}.said:
    decommissioned-state gate accepts (cnt creates divergence with pre-Dec Evl_d).
    Chain transitions to contested at v_d:

    [Icp] → ... → [v_{d-1}] ─┬─ Evl_d → dec @ v_{d+1}  ┐
                             └─ cnt @ v_d              ┴── contested-terminal @ v_d

  Node B (contested at v_d) receives dec:
    contested-state gate rejects; dec is dropped.

    [Icp] → ... → [v_{d-1}] ─┬─ Evl_d                  ┐
                             └─ cnt @ v_d              ┴── contested-terminal @ v_d
```

Both shapes converge to contested:

  effective_said(A) = hash_effective_said("contested:{prefix}")
  effective_said(B) = hash_effective_said("contested:{prefix}") = effective_said(A)    ✓

Cross-node forensic divergence (which events each node holds; at which serial contested fires) is acceptable. Without the override, A would resolve to `hash_effective_said("decommissioned:{prefix}") = Dec.said` while B would resolve to `hash_effective_said("contested:{prefix}")`, and anti-entropy would spin forever — a direct violation of [../../protocol-doctrine.md §Federation Convergence](../../protocol-doctrine.md#federation-convergence).

## References

- [events.md](events.md) — Per-kind reference.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [../sel/reconciliation.md](../sel/reconciliation.md) — SEL counterpart (which has Rpr and Repaired state).
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart.
