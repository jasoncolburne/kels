# KEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all KEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the KEL design — without it, the merge engine and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence, recovery via discriminator, contested-state transitions, decommission, the proactive-ROR seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the merge engine routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Proactive ROR compliance**: Every KEL has a recovery-revealing event (`rec`, `ror`, `dec`) at least every `MINIMUM_PAGE_SIZE - 2 = 62` non-revealing events. Surfaced by `KelVerifier` and enforced by the merge engine; the builder auto-inserts `ror` when the bound is about to be crossed.

2. **Bounded divergence**: An adversary can only fork after the last recovery-revealing event (forking before triggers `ParentLocked`). Combined with invariant 1, divergence spans at most 62 events from the fork point. An adversary without the recovery key can only submit non-revealing events (`ixn`, `rot`), so the merge engine's proactive-ROR enforcement limits them to at most 62 events before rejection.

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
| **Decommissioned** | Exactly one `Dec`, ending a clean (linear) chain. Fully terminal: all submissions rejected by the seal-cap. |

"Divergent with recovery revealed" is a sub-state of **Divergent** where a recovery-revealing event exists on one branch since the divergence point. A non-archiving privileged event (`Ror` or `Dec`) extending `v_{d-1}` joins the divergent set via the upgrade rule → Contested. Competing `Rec` against `v_{d-1}` and non-priv submissions both return `ParentLocked` (locked-portion bound).

## Local Submissions Matrix

What happens when a client submits events to the merge engine on a single node.

| KEL State | ixn/rot | ror | rec / rec+rot | dec |
|-----------|---------|-----|---------------|-----|
| **Empty** | Reject (no KEL) | Reject | Reject | Reject |
| **Active** | Append ✓ | Append ✓ (linear or contested-creating; see notes) | Append ✓ (gossip-sync of recovered KELs) | Append ✓ → Decommissioned (linear) or Contested (creates divergence at `v_d`) |
| **Active, sealed** (`ixn`/`rot`/`ror` would land at-or-before `lastSealAdvancingEvent` in chain order) | `ParentLocked` | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) |
| **Divergent** | `RecoverRequired` | `RecoverRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule | Recovered ✓ (creates `RecoveryRecord`) | `RecoverRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule |
| **Divergent (recovery revealed)** | `ParentLocked` | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}` once recovery has advanced the seal past `v_d`) | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) |
| **Recovered** | Same as Active | Same as Active | Same as Active | Same as Active |
| **Contested** | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` |
| **Decommissioned** | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` |

### Notes on cell routing

- **Contested-state transition on an Active (non-sealed) chain** — A non-archiving privileged event (`Ror` or `Dec`) with `previous = v_{d-1}.said` creates a 2-event divergent set at `v_d` (the new event + the existing non-privileged event at `v_d`); privileged-divergence-is-terminal fires. See [event-log.md §Contested-state transitions](event-log.md#contested-state-transitions).
- **Contested-state transition via upgrade rule (divergent chain, recovery not yet revealed)** — A non-archiving privileged event with `previous = v_{d-1}.said` joins a non-privileged divergent set at `v_d` as a third event → Contested. Once any recovery-revealing event lands and advances the seal past `v_d`, the seal-cap rejects further extensions of `v_{d-1}`.
- **Active, sealed and Divergent (recovery revealed)** — the seal-cap (`parent_serial >= seal_serial`) rejects every submission whose parent sits in the locked portion. All extensions of `v_{seal-1}` / `v_{d-1}` return `ParentLocked`. When the rejected submission originated from another federation peer's locally-landed priv event (concurrent priv-vs-priv race), the chain does not structurally converge with that peer; federation-level convergence resolves at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). The per-race-shape enumeration is in [§Race matrix](#race-matrix) below.
- **Decommissioned** — fully terminal. All submissions return `KelDecommissioned`. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205) and [§Race matrix](#race-matrix) below).

### Batch submissions

The merge engine handles batches atomically:

- **`[events + rec + rot]`** — the surviving chain from the fork point through recovery. At most 64 events (bounded by proactive ROR). Processed as a single overlap or divergent submission.
- **`[events + Ror]` or `[events + Dec]`** — the contesting chain from the fork point through contested-transition. At most 63 events. The non-archiving privileged event must be last in the batch.
- **`[ror, ixn]`** — auto-inserted by the builder when an `ixn` would exceed the proactive-ROR interval.
- **`[rot] → [ror]`** — the builder upgrades `rot` to `ror` when the proactive-ROR interval is due, since `ror` rotates both signing and recovery keys.

## Gossip Sync (transfer_key_events)

When node A syncs a KEL to node B, `transfer_key_events` reads from A and writes to B via `store_page` (which calls the merge engine on B).

### Transfer ordering

For divergent source KELs, `send_divergent_events` reorders events to ensure the KEL is reconstructed the same way. With synchronous archival, a recovered source KEL is always a clean linear chain — the archived-branch events are removed in the merge transaction. In normal operation, only unrecovered and contested cases reach `send_divergent_events`.

- **Divergent with rec (and no contested-transition)** — Rejected with error. This state cannot exist through normal merge paths: synchronous archival means a `rec` immediately archives the other-branch events, leaving a clean chain. A divergent KEL with `rec` in the live tables indicates possible DB tampering. `send_divergent_events` refuses to propagate it.
- **Unrecovered (no rec, no contested-transition)** — Longer chain first as non-divergent appends. Only the fork event from the shorter chain is sent (no terminal event to deliver). Receiver routes the fork event through §6c Overlap → divergent state.
- **Contested (divergent set contains a non-archiving privileged event)** — Builds two chains by forward-tracing from the two fork events. Sends the non-contesting chain first as paged non-divergent appends (may exceed one page if it extended with multiple ROR cycles before detection), then the contesting chain (ending in the `Ror`/`Dec` that triggered the transition) as an atomic batch (creates the divergent set + triggers privileged-divergence-is-terminal; bounded to one page by the proactive-ROR invariant). If the contesting chain exceeds `MINIMUM_PAGE_SIZE`, propagation is rejected as possible DB tampering.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a KEL from a source node (row) to a sink node (column). The source's `transfer_key_events` reads its local KEL and sends events via `store_page` to the sink. The sink's merge engine processes the incoming events against whatever state it already has for that prefix.

"Active (surviving)" means the sink has the eventual surviving branch's non-divergent chain. "Active (alternate)" means the sink has the eventual non-surviving branch's non-divergent chain (submitted to that node before divergence was detected elsewhere). The protocol cannot distinguish the two from chain data alone — "surviving" is the branch that `Rec` (whoever holds the recovery key) ultimately extends.

| Source | Sink: Empty | Sink: Active (surviving) | Sink: Active (alternate) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|---------------------|-------------------------|----------------|----------------|----------------------|
| **Active** | Full KEL appended ✓ | Duplicates, no-op ✓ | Overlap → divergence | `RecoverRequired` | `ContestedKel` | `KelDecommissioned` |
| **Recovered** | Full clean chain ✓ | `rec`+`rot` append ✓ | Overlap → `rec` in batch → recovery ✓ | `RecoverRequired` (sink awaiting recovery) | `ContestedKel` | `KelDecommissioned` |
| **Divergent (unrecovered)** | Reordered: longer chain + fork event ✓ | Fork event creates overlap → divergence | Fork event creates overlap → divergence | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedKel` | `KelDecommissioned` |
| **Contested** | Non-contesting chain (paged) + contesting chain (atomic batch ending in `Ror`/`Dec`) ✓ | Non-contesting appends + contesting batch → contested ✓ | Non-contesting appends + contesting batch → contested ✓ | Contesting batch → contested ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `KelDecommissioned` |
| **Decommissioned** | Full chain + `dec` ✓ | `dec` appends ✓ | Overlap, `dec` in chain ✓ | `RecoverRequired` | `ContestedKel` | Effective SAIDs match (Dec.said) ✓ |

### Notes on cell routing

- **Sink terminal states** (Contested, Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Source: Contested → Sink: Decommissioned** — the Decommissioned sink rejects every gossip-delivered event from the Contested source with `KelDecommissioned` (the seal-cap rejects extensions of `v_{d-1}`). Federation-level convergence in this scenario is provided at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).
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
| **Decommissioned** | `dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing privileged event extending `Dec`'s parent has been submitted to a different node, the federation does NOT structurally converge — each node's seal-cap rejects the other's submission; convergence is via the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205)). |

## Archival

Archival happens synchronously within the merge transaction that accepts the `rec` (or `rec+rot`) event. No background task or async processing.

### Surviving-branch identification

The merge engine identifies surviving-branch events via two strategies depending on the divergence geometry:

- **`collect_all_adversary_saids`** — the surviving branch has no events at the divergence serial (divergence-ancestor-extending shape: `Rec.previous = v_{d-1}.said`). All events from `divergedAt` onward not on the `Rec.previous` walkback are archived.
- **`collect_adversary_chain_saids`** — the surviving branch has events at the divergence serial (branch-tip-extending shape: `Rec.previous` is a branch tip at `v_d`). Walk backward from the non-surviving branch's event at the divergence point to identify the non-surviving chain, then forward-trace to capture any extensions.

Everything not on the surviving branch is archived to mirror tables. Whoever holds the recovery key dictates which branch survives (via choice of `Rec.previous`).

Both strategies use a single page fetch + resume-mode verifier trust gate + in-memory walkback. See [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator) for the algorithmic detail.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Non-surviving events to archive | ≤ 62 | Proactive ROR limits fork distance |
| Archival scope | Single transaction | Synchronous in merge, bounded by `MINIMUM_PAGE_SIZE` |
| Surviving-branch events never archived | ✓ | Surviving branch identified by backward/forward trace from `rec_previous` |

## Edge Cases

### 1. Rec landing as normal append (no divergence)

A submitter with the recovery key submits `rec` to a non-divergent KEL (normal append, no divergence). This reveals the recovery key. Any future divergence at or after this `rec` cannot be resolved by `rec` (the recovery key is spent); only contested-termination via a non-archiving privileged event remains.

```
Pre-state (linear chain through s_N):
  s_0 → s_1 → ... → s_N   (tip at s_N; seal at last rec-revealing event ≤ N)

A recovery-key holder submits rec with previous = s_N.said (dual-sig satisfied):
  s_0 → ... → s_N → rec_x  (s_{N+1}; seal advances to N+1)

Effect: chain stays linear; seal advances to N+1; recovery key now spent for
this chain. A non-archiving privileged event (`Ror` or `Dec`) extending
v_N.said arriving via gossip lands at v_{N+1} as a sibling of rec_x;
privileged-divergence-is-terminal fires; chain transitions to Contested.
Competing `Rec` against v_N is rejected by the locked-portion bound; non-priv
extensions submitted at serial ≤ N+1 are rejected with `ParentLocked`
(seal-cap).
```

### 2. Multiple competing events injected across nodes

Different events at the same serial are submitted to different nodes (federation race or threshold compromise — chain-indistinguishable). When gossip syncs, divergence is created. Only one extra event is written per overlap (the fork event). Recovery or contest resolves it. All nodes converge after recovery propagates via gossip.

```
Pre-state (linear at s_{d-1}, replicated to nodes A and B):

  Node A:  s_0 → ... → s_{d-1}    (tip)
  Node B:  s_0 → ... → s_{d-1}    (tip)

Different events submitted at s_d on each node:

  Node A receives ixn_a:  s_0 → ... → s_{d-1} → ixn_a @ s_d
  Node B receives ixn_b:  s_0 → ... → s_{d-1} → ixn_b @ s_d

Gossip propagates ixn_a → B, ixn_b → A. Each node's merge engine
observes overlap at s_d and writes the second event as the fork
event (one extra event per overlap, dedup-rejection on subsequent
submissions at the same serial):

  Both nodes:  s_0 → ... → s_{d-1} ─┬─ ixn_a @ s_d   (non-priv divergent)
                                    └─ ixn_b @ s_d

A recovery-key holder submits rec to any single node → discriminator
archives the non-extended branch → recovery propagates via gossip →
all nodes converge on the post-rec linear state.
```

### 3. Local events archived by a competing `rec`

If one recovery-key holder submits `rec` archiving the local builder's events synchronously, the local builder detects missing events via `find_missing_owner_events`: it loads the last page of events from the local `KelStore`, then walks backward calling `event_exists` on the server for each SAID until it finds one the server still has. Everything after that boundary was archived by the competing `rec`. The builder resubmits those missing events plus a non-archiving privileged event (`Ror` or `Dec`) as an atomic batch.

```
Pre-state (divergent at s_d; local store holds branch A):

  Server:  s_0 → ... → s_{d-1} ─┬─ branch_A @ s_d → branch_A' @ s_{d+1}
                                └─ branch_B @ s_d

  Local:   s_0 → ... → s_{d-1} → branch_A → branch_A'   (local view)

A second recovery-key holder submits rec extending branch_B
(branch-tip-extending shape):

  Discriminator archives branch_A, branch_A'; rec_B lands at s_{d+1}.

  Server (post-archival):  s_0 → ... → s_{d-1} → branch_B → rec_B

Local builder detects via find_missing_owner_events that branch_A,
branch_A' no longer exist server-side (event_exists returns false).
Builder bundles [branch_A, branch_A', dec] (or similar non-archiving
privileged terminator) as atomic batch and submits to server. The
missing events are verified server-side and re-established under the
batch's atomic transaction. Post-batch the chain is linear with tip at
branch_A' (v_{d+1}); dec with previous = branch_A.said (v_d) lands at
v_{d+1} as sibling of branch_A' → 2-event privileged divergent set →
privileged-divergence-is-terminal fires → chain becomes contested-
terminal. The previously-archived events are preserved as forensic
record.
```

### 4. Post-recovery events synced to a node holding the archived branch

After recovery on node A, new events (e.g., `ixn`) are appended. When synced to node B (which has the now-archived branch), the overlap handler creates a `RecoveryRecord` and archives the non-surviving events synchronously in the merge transaction.

```
Pre-sync state (post-recovery on A; archived branch still on B):

  Node A:  s_0 → ... → s_{d-1} → branch_A @ s_d → rec → ixn_new
           (clean linear chain after rec archived branch_B)

  Node B:  s_0 → ... → s_{d-1} → branch_B @ s_d
           (still has the alternate branch; rec hasn't propagated)

Gossip propagates Node A's chain (including rec) to Node B. Node B's
merge engine observes overlap at s_d (its branch_B vs incoming
branch_A), sees rec in the batch, runs the discriminator (rec walkback
identifies branch_A as the surviving branch), and archives branch_B
synchronously.

  Node B (post-sync):  s_0 → ... → s_{d-1} → branch_A → rec → ixn_new
                       (matches Node A; branch_B in archive table)

All nodes converge on the same effective SAID (tip event SAID).
```

### 5. Contested KELs across nodes

Different nodes may have different event sets for a contested KEL (e.g., one node archived the non-surviving events via recovery before the contested-transition arrived; another received the contesting event first). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any KEL where the divergent set contains a non-archiving privileged event. Anti-entropy sees matching SAIDs and does not re-queue.

```
Different event sets, same effective SAID:

  Node A:  s_0 → ... → s_{d-1} ─┬─ ixn_a @ s_d ┐
                                ├─ ixn_b @ s_d ├── 3-event set; contested
                                └─ ror_c @ s_d ┘   (ror upgraded set via
                                                    upgrade rule on this node)

  Node B:  s_0 → ... → s_{d-1} ─┬─ ixn_b @ s_d ┐
                                └─ ror_c @ s_d ┴── 2-event set; contested
                                                   (contested-transition
                                                    closed the gate before
                                                    ixn_a's gossip arrived)

  effective_said(A) = hash_effective_said("contested:{prefix}")
  effective_said(B) = hash_effective_said("contested:{prefix}")
                    = effective_said(A)    ✓

Anti-entropy compares SAIDs, sees they match, does not re-queue
synchronization. Both nodes' chains stay as forensic record; cross-node
forensic divergence is acceptable (and unavoidable given the gossip-
window timing).
```

### 6. Concurrent Dec + Ror/Dec at v_d — federation race, infrastructure-layer convergence

Two parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec` (clean retirement); party 2 submits a non-archiving privileged event (e.g., `Ror` or `Dec`) extending the same parent. Each lands as a linear-chain extension on its submitting node and advances the local seal. Gossip then delivers each event to the other node, but the seal-cap rejects each — under universal locking, no admission at a sealed serial:

```
Pre-state (linear at v_{d-1}):

  Both nodes:  ... → v_{d-1}    (tip)

Concurrent submissions:

  Party 1 → Node A:           dec.previous     = v_{d-1}.said, dec.serial     = d
  Party 2 → Node B:           ror_alt.previous = v_{d-1}.said, ror_alt.serial = d

Each event lands as a linear-chain extension on its submitting node.

Gossip propagates:

  Node A (Decommissioned at v_d via dec) receives ror_alt:
    ror_alt.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap with KelDecommissioned.
    A's state unchanged: Decommissioned.

  Node B (Active at v_d via ror_alt) receives dec:
    dec.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap with ParentLocked.
    B's state unchanged: Active with ror_alt as tip.

  Effective SAIDs:
    effective_said(A) = dec.said
    effective_said(B) = ror_alt.said
    A ≠ B → federation does not converge at the protocol layer.
```

Federation-level convergence in this scenario is provided at the infrastructure layer via a contested-prefix table that nodes maintain and gossip-sync; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205) for the design. The seal-cap stays unconditional; relaxing it to admit competing events at a sealed serial would re-open a stale-authority killswitch surface.

## Race matrix

Enumeration of concurrent priv-vs-priv races between federation peers, both submitting privileged events extending the same parent `v_{d-1}` to different nodes. Each event lands as a linear-chain extension on its submitting node and advances the local seal; gossip then delivers each event to the other node, where the seal-cap rejects it (parent in locked portion). The chain does not structurally converge at the protocol layer; federation-level convergence is provided at the infrastructure layer via the contested-prefix table (see [#205](https://github.com/jasoncolburne/kels/issues/205)).

| Race kind  | Receiving-node state at gossip arrival | Outcome |
|------------|----------------------------------------|---------|
| Rec-vs-Rec | Active-sealed (Rec at `v_d`) | `ParentLocked`; non-converging; #205 |
| Rec-vs-Ror | Active-sealed (Rec/Ror at `v_d`) | `ParentLocked`; non-converging; #205 |
| Rec-vs-Dec | Active-sealed / Decommissioned | `ParentLocked` / `KelDecommissioned`; non-converging; #205 |
| Ror-vs-Ror | Active-sealed (Ror at `v_d`) | `ParentLocked`; non-converging; #205 |
| Ror-vs-Dec | Active-sealed / Decommissioned | `ParentLocked` / `KelDecommissioned`; non-converging; #205 |
| Dec-vs-Dec | Decommissioned | `KelDecommissioned`; non-converging; #205 |

The matrix is symmetric in race participants — `Rec-vs-Ror` covers both `Rec` arriving at a node with `Ror` and `Ror` arriving at a node with `Rec`. The receiving-node-state column reflects what the local chain looks like after the local first-receive has landed; the outcome describes the gossip-arriving event's rejection.

## References

- [events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [event-log.md](event-log.md) — KEL chain lifecycle: states, divergence, recovery, contested-state transitions, decommission, proactive-ROR seal, discriminator algorithm.
- [merge.md](merge.md) — KEL merge engine; `MergeTransaction` API and full routing.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator and pending-bundling shape are mirrored on both sides.
