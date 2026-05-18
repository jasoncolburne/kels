# KEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all KEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the KEL design — without it, the merge engine and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence, recovery via discriminator, contested-state transitions, decommission, the proactive-ROR seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the merge engine routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Proactive ROR compliance**: Every KEL has a recovery-revealing event (`rec`, `ror`, `dec`) at least every `MINIMUM_PAGE_SIZE - 2 = 62` non-revealing events. Surfaced by `KelVerifier` and enforced by the merge engine; the builder auto-inserts `ror` when the bound is about to be crossed.

2. **Bounded divergence**: An adversary can only fork after the last recovery-revealing event (forking before triggers `ContestRequired`). Combined with invariant 1, divergence spans at most 62 events from the fork point. An adversary without the recovery key can only submit non-revealing events (`ixn`, `rot`), so the merge engine's proactive-ROR enforcement limits them to at most 62 events before rejection.

3. **Bounded operations**: Recovery batch (`events + rec + rot`) ≤ 64, contested-transition batch (`events + Ror`/`Dec`) ≤ 63, adversary chain to archive ≤ 62. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible. The page+resume-verify discriminator (SEL backport) relies on bound 3.

## KEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix |
| **Active** | Linear chain, latest tip extends cleanly |
| **Divergent** | Fork detected, no `Rec` yet and no non-archiving privileged event upgrade |
| **Recovered** | Clean chain after synchronous archival in the merge transaction |
| **Contested** | Divergent set contains a non-archiving privileged event (`Ror` or `Dec`); no event of any kind lands |
| **Decommissioned** | Exactly one `Dec`, ending a clean (linear) chain. Accepts no linear extension; admits a non-archiving privileged event with `previous = v_{d-1}.said` and `serial = Dec.serial` as a divergent extension, transitioning the chain to Contested (order-independent rule) |

"Divergent with recovery revealed" is a sub-state of **Divergent** where a recovery-revealing event exists on one branch since the divergence point. Only a non-archiving privileged event (`Ror`/`Dec`) extending `v_{d-1}` is admissible; non-(Ror/Dec) submissions return `ContestRequired`.

## Local Submissions Matrix

What happens when a client submits events to the merge engine on a single node.

| KEL State | ixn/rot | ror | rec / rec+rot | dec |
|-----------|---------|-----|---------------|-----|
| **Empty** | Reject (no KEL) | Reject | Reject | Reject |
| **Active** | Append ✓ | Append ✓ (linear or contested-creating; see notes) | Append ✓ (gossip-sync of recovered KELs) | Append ✓ → Decommissioned (linear) or Contested (creates divergence at `v_d`) |
| **Active, sealed** (`ixn`/`rot`/`ror` would land at-or-before `lastSealAdvancingEvent` in chain order) | `ContestRequired` | `ContestRequired` (linear extension); non-archiving privileged extending `v_{seal-1}` → Contested via boundary case | n/a (`Rec` cannot truncate at-or-before the seal) | `ContestRequired` (linear extension); extending `v_{seal-1}` → Contested via boundary case |
| **Divergent** | `RecoverRequired` | `RecoverRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule | Recovered ✓ (creates `RecoveryRecord`) | `RecoverRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule |
| **Divergent (recovery revealed)** | `ContestRequired` | `ContestRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule | `ContestRequired` | `ContestRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule |
| **Recovered** | Same as Active | Same as Active | Same as Active | Same as Active |
| **Contested** | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` |
| **Decommissioned** | `KelDecommissioned` * | `KelDecommissioned` * | `KelDecommissioned` * | `KelDecommissioned` * |

### Notes on cell routing

- **Contested-state transition (linear chain)** — A non-archiving privileged event (`Ror` or `Dec`) with `previous = v_{d-1}.said` creates a 2-event divergent set at `v_d` (the new event + the existing event at `v_d`); privileged-divergence-is-terminal fires. See [event-log.md §Contested-state transitions](event-log.md#contested-state-transitions).
- **Contested-state transition (divergent chain)** — A non-archiving privileged event with `previous = v_{d-1}.said` joins the divergent set as a third event via the upgrade rule.
- **Active, sealed** — Non-privileged-revealing extensions return `ContestRequired`. The parent-at-(seal − 1) boundary case admits non-archiving privileged events at `event_serial = seal_serial` to trigger contested-transition; archiving `Rec` is forbidden at the boundary (would erase the seal-defining event).
- **`Divergent (recovery revealed)` → `ContestRequired` for non-(Ror/Dec)** — once the recovery key is revealed in a divergent branch, only a non-archiving privileged event extending `v_{d-1}` can resolve (by terminating the chain). See [event-log.md §Algorithmic merge-engine triggers](event-log.md#algorithmic-merge-engine-triggers).
- **\* Decommissioned exception** — a non-archiving privileged event (`Ror` or `Dec`) with `previous = v_{d-1}.said` and `serial = Dec.serial` is admitted as a divergent extension at Dec's serial; the chain transitions Decommissioned → Contested per [../../../../protocol-doctrine.md §Order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions). Other submissions (including any submission extending Dec's tip or violating the locked-portion bound) are rejected with `KelDecommissioned`.

### Batch submissions

The merge engine handles batches atomically:

- **`[events + rec + rot]`** — owner's chain from the fork point through recovery. At most 64 events (bounded by proactive ROR). Processed as a single overlap or divergent submission.
- **`[events + Ror]` or `[events + Dec]`** — owner's chain from the fork point through contested-transition. At most 63 events. The non-archiving privileged event must be last in the batch.
- **`[ror, ixn]`** — auto-inserted by the builder when an `ixn` would exceed the proactive-ROR interval.
- **`[rot] → [ror]`** — the builder upgrades `rot` to `ror` when the proactive-ROR interval is due, since `ror` rotates both signing and recovery keys.

## Gossip Sync (transfer_key_events)

When node A syncs a KEL to node B, `transfer_key_events` reads from A and writes to B via `store_page` (which calls the merge engine on B).

### Transfer ordering

For divergent source KELs, `send_divergent_events` reorders events to ensure the KEL is reconstructed the same way. With synchronous archival, a recovered source KEL is always a clean linear chain — the adversary events are archived in the merge transaction. In normal operation, only unrecovered and contested cases reach `send_divergent_events`.

- **Divergent with rec (and no contested-transition)** — Rejected with error. This state cannot exist through normal merge paths: synchronous archival means a `rec` immediately archives adversary events, leaving a clean chain. A divergent KEL with `rec` in the live tables indicates possible DB tampering. `send_divergent_events` refuses to propagate it.
- **Unrecovered (no rec, no contested-transition)** — Longer chain first as non-divergent appends. Only the fork event from the shorter chain is sent (no terminal event to deliver). Receiver routes the fork event through §6c Overlap → divergent state.
- **Contested (divergent set contains a non-archiving privileged event)** — Builds two chains by forward-tracing from the two fork events. Sends the non-contesting chain first as paged non-divergent appends (may exceed one page if the adversary extended with multiple ROR cycles before detection), then the contesting chain (ending in the `Ror`/`Dec` that triggered the transition) as an atomic batch (creates divergence + freezes; bounded to one page by the proactive-ROR invariant). If the contesting chain exceeds `MINIMUM_PAGE_SIZE`, propagation is rejected as possible DB tampering.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a KEL from a source node (row) to a sink node (column). The source's `transfer_key_events` reads its local KEL and sends events via `store_page` to the sink. The sink's merge engine processes the incoming events against whatever state it already has for that prefix.

"Active (owner)" means the sink has the legitimate owner's non-divergent chain. "Active (adversary)" means the sink has the adversary's non-divergent chain (submitted to that node before divergence was detected elsewhere).

| Source | Sink: Empty | Sink: Active (owner) | Sink: Active (adversary) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|---------------------|-------------------------|----------------|----------------|----------------------|
| **Active** | Full KEL appended ✓ | Duplicates, no-op ✓ | Overlap → divergence | `RecoverRequired` | `ContestedKel` | `KelDecommissioned` |
| **Recovered** | Full clean chain ✓ | `rec`+`rot` append ✓ | Overlap → `rec` in batch → recovery ✓ | `RecoverRequired` (sink awaiting recovery) | `ContestedKel` | `KelDecommissioned` |
| **Divergent (unrecovered)** | Reordered: longer chain + fork event ✓ | Fork event creates overlap → divergence | Fork event creates overlap → divergence | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedKel` | `KelDecommissioned` |
| **Contested** | Non-contesting chain (paged) + contesting chain (atomic batch ending in `Ror`/`Dec`) ✓ | Non-contesting appends + contesting batch → contested ✓ | Non-contesting appends + contesting batch → contested ✓ | Contesting batch → contested ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `KelDecommissioned` |
| **Decommissioned** | Full chain + `dec` ✓ | `dec` appends ✓ | Overlap, `dec` in chain ✓ | `RecoverRequired` | `ContestedKel` | Effective SAIDs match (Dec.said) ✓ |

### Notes on cell routing

- **Sink terminal states** (Contested, Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Source: Contested → Sink: Decommissioned** — Decommissioned sink admits the contesting chain's non-archiving privileged event extending `v_{d-1}` as a divergent extension at Dec's serial per the [order-independent rule](../../../../protocol-doctrine.md#order-independent-divergent-transitions); the chain transitions Decommissioned → Contested. Other events from the contesting chain are rejected by the now-Contested sink. Both nodes converge on `hash("contested:{prefix}")`.
- **Send-side partitioning** (Source: Divergent, Source: Contested) — the source partitions the chain into sub-batches the sink will accept under its routing rules. See [§Transfer ordering](#transfer-ordering) above and [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-kels).
- **Divergent → Divergent sink** — effective SAIDs match by construction; full anti-entropy may reconcile any-missing-branch-events even when SAIDs already match.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID computation | Converges? |
|-------|---------------------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Recovered** | Tip event SAID | ✓ (identical clean chains) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (same value on all nodes regardless of which divergent events each node holds) |
| **Decommissioned** | `dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing non-archiving privileged event extending `Dec`'s parent has been submitted to any node, gossip delivery upgrades Dec-first nodes Decommissioned → Contested via the [order-independent rule](../../../../protocol-doctrine.md#order-independent-divergent-transitions); effective SAID becomes `hash("contested:{prefix}")`. |

## Archival

Archival happens synchronously within the merge transaction that accepts the `rec` (or `rec+rot`) event. No background task or async processing.

### Owner identification

The merge engine identifies owner events via two strategies depending on the divergence geometry:

- **`collect_all_adversary_saids`** — owner has no events at the divergence serial. All events from `divergedAt` onward not on the owner walkback are adversary.
- **`collect_adversary_chain_saids`** — owner has events at the divergence serial. Walk backward from the adversary event at the divergence point to identify the adversary chain, then forward-trace to capture any adversary extensions.

Everything not in the owner's chain is archived to mirror tables.

Both strategies use a single page fetch + resume-mode verifier trust gate + in-memory walkback. See [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator) for the algorithmic detail.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 62 | Proactive ROR limits fork distance |
| Archival scope | Single transaction | Synchronous in merge, bounded by `MINIMUM_PAGE_SIZE` |
| Owner events never archived | ✓ | Owner chain identified by backward/forward trace from `rec_previous` |

## Edge Cases

### 1. Adversary Rec as normal append

The adversary submits `rec` to a non-divergent KEL (normal append, no divergence). This reveals the recovery key. Any future divergence at or after this `rec` cannot be resolved by `rec` (the recovery key is spent); only contested-termination via a non-archiving privileged event remains.

```
Pre-state (linear, owner's chain through s_N):
  s_0 → s_1 → ... → s_N   (tip at s_N; seal at last rec-revealing event ≤ N)

Adversary submits rec with previous = s_N.said (and dual-sig satisfied):
  s_0 → ... → s_N → rec_adv  (s_{N+1}; seal advances to N+1)

Effect: chain stays linear; seal advances to N+1; recovery key now spent for
this chain. Any future divergence at serial ≤ N+1 triggers ContestRequired
because the seal-cap forbids forking at-or-before the seal. Owner's recourse
is a non-archiving privileged event (`Ror` or `Dec`) with previous = v_N.said
(the parent of the new rec-tip at v_{N+1}); the event lands at v_{N+1} and
triggers the contested transition.
```

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created. Only one adversary event is written per overlap (the fork event). Recovery or contest resolves it. All nodes converge after recovery propagates via gossip.

```
Pre-state (linear at s_{d-1}, replicated to nodes A and B):

  Node A:  s_0 → ... → s_{d-1}    (tip)
  Node B:  s_0 → ... → s_{d-1}    (tip)

Adversary injects different events at s_d on each node:

  Node A receives ixn_a:  s_0 → ... → s_{d-1} → ixn_a @ s_d
  Node B receives ixn_b:  s_0 → ... → s_{d-1} → ixn_b @ s_d

Gossip propagates ixn_a → B, ixn_b → A. Each node's merge engine
observes overlap at s_d and writes the second event as the fork
event (one extra event per overlap, dedup-rejection on subsequent
adversary submissions at the same serial):

  Both nodes:  s_0 → ... → s_{d-1} ─┬─ ixn_a @ s_d   (non-priv divergent)
                                    └─ ixn_b @ s_d

Owner submits rec to any single node → discriminator archives the
non-extended branch → recovery propagates via gossip → all nodes
converge on the post-rec linear state.
```

### 3. Owner events archived by adversary's `rec`

If the adversary submitted `rec` (creating a `RecoveryRecord` and archiving the owner's events synchronously), the owner's builder detects missing events via `find_missing_owner_events`: it loads the last page of events from the local `KelStore`, then walks backward calling `event_exists` on the server for each SAID until it finds one the server still has. Everything after that boundary was archived by the adversary's `rec`. The builder resubmits those missing events plus a non-archiving privileged event (`Ror` or `Dec`) as an atomic batch.

```
Pre-state (divergent at s_d; client store holds the owner's branch):

  Server:  s_0 → ... → s_{d-1} ─┬─ owner_a @ s_d → owner_b @ s_{d+1}
                                └─ adv_a   @ s_d

  Client:  s_0 → ... → s_{d-1} → owner_a → owner_b   (client's local view)

Adversary submits rec extending adv_a (branch-tip-extending shape):

  Discriminator archives owner_a, owner_b; rec_adv lands at s_{d+1}.

  Server (post-archival):  s_0 → ... → s_{d-1} → adv_a → rec_adv

Client detects via find_missing_owner_events that owner_a, owner_b
no longer exist server-side (event_exists returns false). Owner bundles
[owner_a, owner_b, dec] (or similar non-archiving privileged terminator)
as atomic batch and submits to server. The missing events are verified
server-side and re-established under the batch's atomic transaction.
Post-batch the chain is linear with tip at owner_b (v_{d+1}); dec with
previous = owner_a.said (v_d) lands at v_{d+1} as sibling of owner_b →
2-event privileged divergent set → privileged-divergence-is-terminal
fires → chain becomes contested-terminal. Owner's lost work is preserved
as forensic record.
```

### 4. Post-recovery events synced to adversary node

After recovery on node A, new events (e.g., `ixn`) are appended. When synced to node B (which has the adversary chain), the overlap handler creates a `RecoveryRecord` and archives adversary events synchronously in the merge transaction.

```
Pre-sync state (post-recovery on A; adversary chain still on B):

  Node A:  s_0 → ... → s_{d-1} → owner_a → rec → ixn_new
           (clean linear chain after rec archived adv_a)

  Node B:  s_0 → ... → s_{d-1} → adv_a
           (still has adversary's chain; rec hasn't propagated)

Gossip propagates Node A's chain (including rec) to Node B. Node B's
merge engine observes overlap at s_d (its adv_a vs incoming owner_a),
sees rec in the batch, runs the discriminator (rec walkback identifies
owner_a as the surviving branch), and archives adv_a synchronously.

  Node B (post-sync):  s_0 → ... → s_{d-1} → owner_a → rec → ixn_new
                       (matches Node A; adv_a in archive table)

All nodes converge on the same effective SAID (tip event SAID).
```

### 5. Contested KELs across nodes

Different nodes may have different event sets for a contested KEL (e.g., one node archived adversary events via recovery before the contested-transition arrived; another received the contesting event first). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any KEL where the divergent set contains a non-archiving privileged event. Anti-entropy sees matching SAIDs and does not re-queue.

```
Different event sets, same effective SAID:

  Node A:  s_0 → ... → s_{d-1} ─┬─ adv_a @ s_d ┐
                                ├─ ixn_b @ s_d ├── 3-event set; contested
                                └─ ror_c @ s_d ┘   (ror upgraded set via
                                                    upgrade rule on this node)

  Node B:  s_0 → ... → s_{d-1} ─┬─ ixn_b @ s_d ┐
                                └─ ror_c @ s_d ┴── 2-event set; contested
                                                   (contested-transition
                                                    closed the gate before
                                                    adv_a's gossip arrived)

  effective_said(A) = hash_effective_said("contested:{prefix}")
  effective_said(B) = hash_effective_said("contested:{prefix}")
                    = effective_said(A)    ✓

Anti-entropy compares SAIDs, sees they match, does not re-queue
synchronization. Both nodes' chains stay as forensic record; cross-node
forensic divergence is acceptable (and unavoidable given the gossip-
window timing).
```

### 6. Concurrent Dec + Ror/Dec at v_d (Decommissioned → Contested via order-independent transition)

Two parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec` (clean retirement); party 2 submits a non-archiving privileged event (e.g., `Ror` or `Dec`) extending the same parent. Each lands as a linear-chain extension on its submitting node — node A becomes Decommissioned, node B becomes Active with the competing event as tip. Gossip then delivers each event to the other node, and the [order-independent divergent transitions](../../../../protocol-doctrine.md#order-independent-divergent-transitions) rule produces convergence:

```
Pre-state (linear at v_{d-1}):

  Both nodes:  ... → v_{d-1}    (tip)

Concurrent submissions:

  Party 1 → Node A:           dec.previous     = v_{d-1}.said, dec.serial     = d
  Party 2 → Node B:           ror_alt.previous = v_{d-1}.said, ror_alt.serial = d

Each event lands as a linear-chain extension on its submitting node.

Gossip propagates:

  Node A (Decommissioned) receives ror_alt:
    ror_alt.previous = v_{d-1}.said matches Dec's parent; order-independent
    rule accepts ror_alt as a divergent extension at Dec's serial. The chain
    transitions Decommissioned → Contested.
    A's final state: ... → v_{d-1} ─┬─ dec     @ v_d ┐
                                    └─ ror_alt @ v_d ┴── Contested

  Node B (Active) receives dec: overlap → Contested at v_d.
    B's final state: ... → v_{d-1} ─┬─ ror_alt @ v_d ┐
                                    └─ dec     @ v_d ┴── Contested

  Effective SAIDs:
    effective_said(A) = hash_effective_said("contested:{prefix}")
    effective_said(B) = hash_effective_said("contested:{prefix}")
    A = B → federation converges.
```

The order-independent rule is what guarantees the convergence. Without it, node A would reject the gossip-arriving ror_alt with `KelDecommissioned` and remain Decommissioned while node B was Contested — federation would fail to converge.

## References

- [docs/design/kel/events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [docs/design/kel/event-log.md](event-log.md) — KEL chain lifecycle: states, divergence, recovery, contested-state transitions, decommission, proactive-ROR seal, discriminator algorithm.
- [docs/design/kel/merge.md](merge.md) — KEL merge engine; `MergeTransaction` API and full routing.
- [docs/design/sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator and pending-bundling shape are mirrored on both sides.
