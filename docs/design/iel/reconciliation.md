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
| **Empty** | Append ✓ if `auth_policy` satisfied (Icp.said anchored under declared auth_policy); reject otherwise | Reject (no chain) | Reject | Reject |
| **Active** | Reject (already incepted) | Append ✓ (governance-authorized) | Append ✓ (terminates the chain) | Append ✓ (terminates the chain) |
| **Active, sealed** (governance event at version ≤ `last_governance_version` would re-evaluate the seal) | n/a | `ContestRequired` | Contest ✓ | n/a |
| **Divergent** | Reject (Icp can't appear at v1+) | `ContestRequired` (no Rpr on IEL) | Contest ✓ (extends one branch's tip; chain becomes Contested) | `ContestRequired` (Dec doesn't resolve divergence; only Cnt does) |
| **Contested** | `ContestedIel` | `ContestedIel` | `ContestedIel` | `ContestedIel` |
| **Decommissioned** | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` | `IelDecommissioned` |

### Batch submissions

The submit handler treats a batch atomically:

- **`[pending..., Cnt]`** — owner's pre-flush staged events plus the contest extending the last bundled tip. At most one page (`MINIMUM_PAGE_SIZE = 64`).
- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page.
- **`[Icp]`** — chain inception. Standalone batch is fine (unlike SE, which requires `[Icp, Upd]`). IEL Icp is itself policy-enforced (anchored under declared `auth_policy`).
- **`[Icp, Evl]`** also valid — inception with immediate first evolution. (Icp + governance step in same batch.)

There is no `[..., Rpr]` batch — IEL has no Rpr.

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID for gossip. Peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. IEL gossip does NOT reorder events — peers always fetch the full chain from origin and submit to their local store. The receiving handler routes via the same kind-discriminator (`is_contest` / `is_decommission`) used for direct submissions.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column).

| Source | Sink: Empty | Sink: Active | Sink: Active (other branch authored) | Sink: Divergent | Sink: Contested |
|--------|-------------|--------------|--------------------------------------|-----------------|-----------------|
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Overlap → divergence ✓ (sink stores both branches) | Duplicates of one branch, no-op for that branch ✓ | `ContestedIel` (sink terminal; gossip ignored) |
| **Divergent** | Both fork events appended ✓ (sink becomes divergent) | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓; full anti-entropy may reconcile any-missing-branch-events | `ContestedIel` |
| **Contested** | Full chain (incl. `Cnt`) appended ✓ | `Cnt` batch routes to contest path ✓ | `Cnt` batch routes to contest path ✓ | `Cnt` batch routes to contest path ✓ | Effective SAIDs match ✓ |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch routes to decommission ✓ | Overlap detected, `Dec` in chain → decommission ✓ | `Dec` does NOT resolve divergent state on IEL — but `Dec` extending one branch on a divergent IEL is itself a structurally-novel case: the receiving node has divergent state; gossip's `Dec` extends one branch; the chain becomes "divergent + decommissioned." Per merge.md routing, `Dec` on a divergent IEL is rejected with `ContestRequired` (only `Cnt` resolves divergence). | `ContestedIel` |

The matrix is smaller than SEL's because IEL's gossip layer doesn't have a Repaired state — there's no Rpr-driven archival, just contest-or-decommission-or-stay-divergent.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains) |

## Edge Cases

### 1. Two governance-authorized parties race a legitimate Evl

Both submit different `Evl` events at v3 within the gossip-propagation window. Each is governance-authorized; neither is "the adversary." Both reach storage at different nodes. Gossip propagates; nodes converge on divergent state. Owner submits `Cnt` to terminate; chain re-incepts under new prefix.

The protocol does not pick a winner — picking would mean architecting around "who was 'first,'" which is unknowable globally without timestamps. We accept the divergence as data.

### 2. Adversary submits a conflicting Evl after governance compromise

Same shape as case 1 — no protocol-level distinction between "innocent race" and "compromise" since both produce the same chain shape. Owner detects via federation status, submits `Cnt`. Chain terminates.

### 3. Cross-chain effect: SE chains bound to a divergent IEL event

If an SE chain's `identity_event` references an IEL event that lives on a now-divergent IEL branch, the SE chain's authorization resolution returns "IEL is divergent at the bound branch — cannot resolve" and SE submissions to that chain are rejected with `IelDivergent`. SE chains stay in their pre-divergence state until the IEL is contested-and-replaced.

### 4. Multiple adversary injections to different nodes

Adversary injects different `Evl` events to different nodes (each with its own valid governance — implies multiple compromised governance authorities or multiple legitimate parties acting independently). Each node sees its first injection as the "tip"; gossip propagates, divergence is detected. With three or more conflicting events, the chain freezes after the first divergence; subsequent injections are dedup-rejected (only one extra event per version is accepted as the divergence marker). Owner submits `Cnt` to terminate.

### 5. Cnt on one branch of a divergent IEL

Owner submits `Cnt` extending one branch's tip (say branch A). The other branch (branch B) stays in storage but accepts no further events (chain is contested). Gossip propagates `Cnt` to all nodes; all nodes mark the chain contested. The other branch B is preserved as forensic record everywhere.

## References

- [events.md](events.md) — Per-kind reference.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [../sel/reconciliation.md](../sel/reconciliation.md) — SEL counterpart (which has Rpr and Repaired state).
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart.
