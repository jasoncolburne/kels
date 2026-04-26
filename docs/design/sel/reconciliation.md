# SEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all SEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the SEL design — without it, the submit handler and gossip layer aren't proven sound.

For lifecycle prose (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the submit handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Proactive-evaluation compliance**: Every SEL has an evaluation event (`Sea` / `Rpr` / `Cnt` / `Dec`) at least every `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events. Surfaced by `SelVerifier` and enforced by the submit handler; the builder auto-inserts `Sea` when the bound is about to be crossed.

2. **Bounded divergence**: An adversary can only fork after the last evaluation event. Combined with invariant 1, divergence spans at most 63 events from the fork point. An adversary without `governance_policy` authority can only submit non-evaluation events (Est/Upd), so the proactive-evaluation enforcement limits them to at most 63 events before rejection.

3. **Bounded operations**: Repair batch (`pending + Rpr`) ≤ 64, contest batch (`pending + Cnt`) ≤ 64, adversary chain to archive ≤ 63. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

4. **No retroactive poisoning**: Once an evaluation lands, the policy state at that version is locked in. Subsequent revocation of any KEL anchor used by that evaluation does NOT retroactively unsatisfy the past evaluation. See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability).

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible.

## SEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix |
| **Active** | Linear, non-divergent, no terminal event |
| **Divergent** | Fork detected, no `Rpr`/`Cnt`/`Dec` yet |
| **Repaired** | Clean chain after `Rpr` archived adversary events |
| **Contested** | `Cnt` present, permanently frozen |
| **Decommissioned** | `Dec` present, permanently frozen |

"Divergent (sealed)" is a sub-state of **Divergent** where the seal has advanced past the divergence point — typically via an adversary's `Rpr` or `Sea` that landed before owner could repair. Owner's only legitimate response is `Cnt`.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| SEL State | Est / Upd | Sea | Rpr / pending+Rpr | Cnt / pending+Cnt | Dec |
|-----------|-----------|-----|-------------------|-------------------|-----|
| **Empty** (no Icp) | Reject (no chain) | Reject | Reject | Reject | Reject |
| **Empty** (Icp only batch) | Append ✓ if `write_policy` satisfied (Icp.said anchored under declared write_policy); reject otherwise | n/a | n/a | n/a | n/a |
| **Active** | Append ✓ (write_policy gated) | Append ✓ (governance_policy gated) | Reject `RepairRequired` if not divergent (or `NothingToRepair` from builder); else discriminator-driven repair ✓ | Append ✓ (only legal when seal-past-version on existing branch — see ContestRequired) | Append ✓ |
| **Active, sealed** (write_policy normal-event at version ≤ `last_governance_version`) | `ContestRequired` | n/a (Sea is governance-authorized; bypasses) | n/a | Contest ✓ (extends owner tip; chain becomes Contested) | n/a |
| **Divergent** | Reject `RepairRequired` | Reject `RepairRequired` | Discriminator-driven repair ✓ | Reject `RepairRequired` (no recovery-revealing event yet — repair, don't contest) | Reject `RepairRequired` |
| **Divergent (sealed)** | `ContestRequired` | `ContestRequired` | `ContestRequired` (seal already advanced; can't repair, must contest) | Contest ✓ | `ContestRequired` |
| **Repaired** | Same as Active | Same as Active | Same as Active | Same as Active | Same as Active |
| **Contested** | `ContestedSel` | `ContestedSel` | `ContestedSel` | `ContestedSel` | `ContestedSel` |
| **Decommissioned** | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` |

### Batch submissions

The submit handler treats a batch atomically:

- **`[pending..., Rpr]`** — owner's pre-flush staged events that never landed, plus the repair extending the last pending event (or owner's verified tip if pending is empty). At most one page (`MINIMUM_PAGE_SIZE = 64`). The discriminator preserves owner's chain; non-owner events at version ≥ `first_divergent_version` are archived.
- **`[pending..., Cnt]`** — owner's pending plus the contest. At most one page.
- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page.
- **`[Icp]`** — chain inception; standalone batch. Icp.said must be anchored under the declared `write_policy` for the handler to accept (uniformly anchor-gated with v1+ events).
- **`[Est]`** — v1 establishment of `governance_policy` (only valid when v0 omitted it).

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID to Redis (`sel_updates`). The gossip service broadcasts an announcement on the `kels/sad/v1` topic; peers compare their local effective SAID against the announcement and fetch the full chain from the origin if stale. SEL gossip does NOT reorder events as KEL does — peers always fetch a full chain from origin and submit to their local SADStore, where the receiving handler routes via the same kind-discriminator (`is_repair` / `is_contest` / `is_decommission`) used for direct submissions.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column). The source publishes its effective SAID; the sink (if it observes a mismatch) fetches the full chain via HTTP and submits to its local handler.

| Source | Sink: Empty | Sink: Active (owner) | Sink: Active (adversary) | Sink: Divergent | Sink: Contested |
|--------|-------------|----------------------|--------------------------|-----------------|-----------------|
| **Active** | Full chain appended ✓ | Duplicates, no-op ✓ | Overlap → divergence ✓ | `RepairRequired` | `ContestedSel` |
| **Repaired** | Full clean chain ✓ | `Rpr` batch detected → discriminator-driven repair ✓ | `Rpr` batch → repair archives sink's adversary chain ✓ | `Rpr` batch → repair ✓ | `ContestedSel` |
| **Divergent** | Both fork events appended ✓ (chain becomes divergent) | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedSel` |
| **Contested** | Full chain (incl. `Cnt`) appended ✓ | `Cnt` batch → contest ✓ | `Cnt` batch → contest ✓ | `Cnt` batch → contest ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | Overlap, `Dec` in chain → decommission ✓ | `RepairRequired` (until repair lands) | `ContestedSel` |

The matrix is smaller than KEL's because SEL's gossip layer doesn't reorder — full-chain fetch always converges. There is no `send_divergent_events` analogue; no transfer ordering concerns.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Repaired** | Tip event SAID (the `Rpr`) | ✓ (identical clean chains) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (same value on all nodes) |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains) |

## Archival

Archival happens synchronously within the submit-handler transaction that accepts the `Rpr` event. No background task or async processing.

### Owner identification

The discriminator identifies owner events via a single strategy (no two-strategy split as in KEL — SEL's repair always extends owner's authentic tip, so `Rpr.previous` is always owner's chain head):

- Walk back from `Rpr.previous` through the verified page; everything reached is owner's chain.
- Everything else at `version ≥ first_divergent_version` is adversary.

The single-page-fetch + resume-verifier trust gate + in-memory walkback shape mirrors KEL's `archive_adversary_chain` (see [../kel/event-log.md §Server-side discriminator](../kel/event-log.md#server-side-discriminator)). Cryptographic gate is signature verification on both sides — KEL verifies signatures directly attached to events; SEL verifies signatures on the anchoring `ixn` events that policy resolution requires. Same trust posture.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 63 | Proactive-evaluation seal limits fork distance |
| Archival scope | Single transaction | Synchronous in submit handler, bounded by `MINIMUM_PAGE_SIZE` |
| Owner events never archived | ✓ | Owner chain identified by walk-back from `Rpr.previous` |

## Edge Cases

### 1. Adversary `Sea` as normal append

The adversary submits `Sea` to a non-divergent chain (normal append, no divergence) — possible if the adversary satisfies `governance_policy` (e.g., a controller of one of the endorsing KELs went rogue). This advances the seal. Any future divergence at version ≤ the new seal triggers `ContestRequired`.

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created at one or more nodes. The first divergent event at each version is stored; subsequent ones are dedup-rejected. Repair (or contest) resolves it. All nodes converge after the resolution propagates.

### 3. Owner pending lost to adversary's `Rpr`

If the adversary submitted `Rpr` first, owner's pre-flush staged events may have been archived along with the rest of the adversary's reading of the chain. Owner's builder bundles pending into the repair batch via `repair()` — `[pending..., Rpr]` — and the submit handler accepts pending atomically with the repair, replaying owner's lost work onto the post-repair chain.

### 4. Post-repair events synced to a node that has the adversary chain

After repair on node A, new events (`Upd`, `Sea`) appended. When gossip propagates the chain to node B (still on the adversary version), node B fetches the full repaired chain and submits to its local handler. The handler observes the `Rpr` in the batch, runs the discriminator, archives node B's adversary events, and inserts the new chain.

### 5. Contested chains across nodes

Different nodes may have different event counts for a contested SEL (e.g., one node had owner's `Cnt` lands first; another had adversary `Sea` advance further before contest arrived). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any chain with a `Cnt` event. Anti-entropy sees matching SAIDs and does not re-queue.

## References

- [events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, repair, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [../sadstore.md](../sadstore.md) — SADStore service architecture and gossip layer.
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart; the discriminator and bounds analysis are mirrored on both sides.
