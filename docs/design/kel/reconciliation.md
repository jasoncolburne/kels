# KEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all KEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the KEL design — without it, the merge engine and gossip layer aren't proven sound.

For lifecycle prose (states, divergence, recovery via discriminator, contest, decommission, the proactive-ROR seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the merge engine routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Proactive ROR compliance**: Every KEL has a recovery-revealing event (`rec`, `ror`, `cnt`, `dec`) at least every `MINIMUM_PAGE_SIZE - 2 = 62` non-revealing events. Surfaced by `KelVerifier` and enforced by the merge engine; the builder auto-inserts `ror` when the bound is about to be crossed.

2. **Bounded divergence**: An adversary can only fork after the last recovery-revealing event (forking before triggers `ContestRequired`). Combined with invariant 1, divergence spans at most 62 events from the fork point. An adversary without the recovery key can only submit non-revealing events (`ixn`, `rot`), so the merge engine's proactive-ROR enforcement limits them to at most 62 events before rejection.

3. **Bounded operations**: Recovery batch (`events + rec + rot`) ≤ 64, contest batch (`events + cnt`) ≤ 63, adversary chain to archive ≤ 62. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible. The page+resume-verify discriminator (round-10 backport from SEL) relies on bound 3.

## KEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix |
| **Normal** | Non-divergent, active |
| **Divergent** | Fork detected, no `rec`/`cnt` yet |
| **Recovered** | Clean chain after synchronous archival in the merge transaction |
| **Contested** | `cnt` present, permanently frozen |
| **Decommissioned** | `dec` present, permanently frozen |

"Divergent with recovery revealed" is a sub-state of **Divergent** where a recovery-revealing event exists on one branch since the divergence point. Only `cnt` is accepted; non-`cnt` submissions return `ContestRequired`.

## Local Submissions Matrix

What happens when a client submits events to the merge engine on a single node.

| KEL State | ixn/rot | ror | rec / rec+rot | cnt / events+cnt | dec |
|-----------|---------|-----|---------------|------------------|-----|
| **Empty** | Reject (no KEL) | Reject | Reject | Reject | Reject |
| **Normal** | Append ✓ | Append ✓ | Append ✓ (accepted to support gossip-sync of recovered KELs) | Overlap: Contest ✓ (requires existing recovery-revealing event, creates divergence + freezes); Append: Reject | Append ✓ |
| **Divergent** | `RecoverRequired` | `RecoverRequired` | Recovered ✓ (creates `RecoveryRecord`) | `RecoverRequired` (no recovery revealed — recover, don't contest) | `RecoverRequired` |
| **Divergent (recovery revealed)** | `ContestRequired` | `ContestRequired` | `ContestRequired` | Contest ✓ | `ContestRequired` |
| **Recovered** | Same as Normal | Same as Normal | Same as Normal | Same as Normal | Same as Normal |
| **Contested** | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` |
| **Decommissioned** | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | Overlap: Contest ✓ (`dec` reveals recovery); Append: `KelDecommissioned` | `KelDecommissioned` |

### Batch submissions

The merge engine handles batches atomically:

- **`[events + rec + rot]`** — owner's chain from the fork point through recovery. At most 64 events (bounded by proactive ROR). Processed as a single overlap or divergent submission.
- **`[events + cnt]`** — owner's chain from the fork point through contest. At most 63 events. The `cnt` must be last in the batch.
- **`[ror, ixn]`** — auto-inserted by the builder when an `ixn` would exceed the proactive-ROR interval.
- **`[rot] → [ror]`** — the builder upgrades `rot` to `ror` when the proactive-ROR interval is due, since `ror` rotates both signing and recovery keys.

## Gossip Sync (transfer_key_events)

When node A syncs a KEL to node B, `transfer_key_events` reads from A and writes to B via `store_page` (which calls the merge engine on B).

### Transfer ordering

For divergent source KELs, `send_divergent_events` reorders events to ensure the KEL is reconstructed the same way. With synchronous archival, a recovered source KEL is always a clean linear chain — the adversary events are archived in the merge transaction. In normal operation, only unrecovered and contested cases reach `send_divergent_events`.

- **Divergent with rec (no cnt)** — Rejected with error. This state cannot exist through normal merge paths: synchronous archival means a `rec` immediately archives adversary events, leaving a clean chain. A divergent KEL with `rec` in the live tables indicates possible DB tampering. `send_divergent_events` refuses to propagate it.
- **Unrecovered (no rec, no cnt)** — Longer chain first as non-divergent appends. Only the fork event from the shorter chain is sent (no terminal event to deliver).
- **Contested (cnt found)** — Builds two chains by forward-tracing from the two fork events. Sends the non-cnt chain first as paged non-divergent appends (may exceed one page if the adversary extended with multiple ROR cycles before detection), then the cnt chain as an atomic batch (creates divergence + freezes; bounded to one page by the proactive-ROR invariant). If the cnt chain exceeds `MINIMUM_PAGE_SIZE`, propagation is rejected as possible DB tampering.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a KEL from a source node (row) to a sink node (column). The source's `transfer_key_events` reads its local KEL and sends events via `store_page` to the sink. The sink's merge engine processes the incoming events against whatever state it already has for that prefix.

"Normal (owner)" means the sink has the legitimate owner's non-divergent chain. "Normal (adversary)" means the sink has the adversary's non-divergent chain (submitted to that node before divergence was detected elsewhere).

| Source | Sink: Empty | Sink: Normal (owner) | Sink: Normal (adversary) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|---------------------|-------------------------|----------------|----------------|----------------------|
| **Normal** | Full KEL appended ✓ | Duplicates, no-op ✓ | Overlap → divergence | `RecoverRequired` | `ContestedKel` | `KelDecommissioned` |
| **Recovered** | Full clean chain ✓ | `rec`+`rot` append ✓ | Overlap → `rec` in batch → recovery ✓ | `RecoverRequired` (divergent, awaiting recovery) | `ContestedKel` | `KelDecommissioned` |
| **Divergent (unrecovered)** | Reordered: longer chain + fork event ✓ | Fork event creates overlap → divergence | Fork event creates overlap → divergence | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedKel` | `KelDecommissioned` |
| **Contested** | Non-cnt chain (paged) + cnt chain (atomic batch) ✓ | Non-cnt chain appends + cnt batch → contest ✓ | Non-cnt chain appends + cnt batch → contest ✓ | `cnt` batch → contest ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `KelDecommissioned` (sink dec'd before cnt arrived; sink stays dec'd) |
| **Decommissioned** | Full chain + `dec` ✓ | `dec` appends ✓ | Overlap, `dec` in chain ✓ | `RecoverRequired` | `ContestedKel` | Effective SAIDs match (Dec.said) ✓ |

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID computation | Converges? |
|-------|---------------------------|------------|
| **Normal** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Recovered** | Tip event SAID | ✓ (identical clean chains) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (same value on all nodes) |
| **Decommissioned** | `dec` event SAID | ✓ (identical chains) |

## Archival

Archival happens synchronously within the merge transaction that accepts the `rec` (or `rec+rot`) event. No background task or async processing.

### Owner identification

The merge engine identifies owner events via two strategies depending on the divergence geometry:

- **`collect_all_adversary_saids`** — owner has no events at the divergence serial. All events from `diverged_at` onward not on the owner walkback are adversary.
- **`collect_adversary_chain_saids`** — owner has events at the divergence serial. Walk backward from the adversary event at the divergence point to identify the adversary chain, then forward-trace to capture any adversary extensions.

Everything not in the owner's chain is archived to mirror tables.

The round-10 backport from SEL replaces per-hop DB queries in both strategies with a single page fetch + resume-mode verifier trust gate + in-memory walkback. The case enumeration in this doc is unchanged; only the implementation efficiency changes. See [key-event-log.md §Server-side discriminator](event-log.md#server-side-discriminator) for the algorithmic detail.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 62 | Proactive ROR limits fork distance |
| Archival scope | Single transaction | Synchronous in merge, bounded by `MINIMUM_PAGE_SIZE` |
| Owner events never archived | ✓ | Owner chain identified by backward/forward trace from `rec_previous` |

## Edge Cases

### 1. Adversary `rec` as normal append

The adversary submits `rec` to a non-divergent KEL (normal append, no divergence). This reveals the recovery key. Any future divergence at or after this `rec` requires `cnt` (contest) instead of `rec` (recovery). The owner must contest.

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created. Only one adversary event is written per overlap (the fork event). Recovery or contest resolves it. All nodes converge after recovery propagates via gossip.

### 3. Owner events archived by adversary's `rec`

If the adversary submitted `rec` (creating a `RecoveryRecord` and archiving the owner's events synchronously), the owner's builder detects missing events via `find_missing_owner_events`: it loads the last page of events from the local `KelStore`, then walks backward calling `event_exists` on the server for each SAID until it finds one the server still has. Everything after that boundary was archived by the adversary's `rec`. The builder resubmits those missing events + `cnt` as an atomic batch.

### 4. Post-recovery events synced to adversary node

After recovery on node A, new events (e.g., `ixn`) are appended. When synced to node B (which has the adversary chain), the overlap handler creates a `RecoveryRecord` and archives adversary events synchronously in the merge transaction.

### 5. Contested KELs across nodes

Different nodes may have different event sets for a contested KEL (e.g., one node archived adversary events via recovery before contest arrived; another received the contest first). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any KEL with a `cnt` event. Anti-entropy sees matching SAIDs and does not re-queue.

## References

- [docs/design/kel/events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [docs/design/kel/event-log.md](event-log.md) — KEL chain lifecycle: states, divergence, recovery, contest, decommission, proactive-ROR seal, discriminator algorithm.
- [docs/design/kel/merge.md](merge.md) — KEL merge engine; `MergeTransaction` API and full routing.
- [docs/design/sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator and pending-bundling shape are mirrored on both sides.
