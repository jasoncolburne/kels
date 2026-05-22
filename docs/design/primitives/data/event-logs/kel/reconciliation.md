# KEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all KEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the KEL design — without it, the merge engine and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence, recovery via discriminator, privileged-event merge-layer rejection, decommission, cap doctrine), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the merge engine routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these protocol-enforced invariants:

1. **Seal-advance cap compliance**: Every KEL has a seal-advancing event (`rec`, `ror`, or `rot`) at least every `MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events. Surfaced by `KelVerifier` and enforced by the merge engine.

2. **Bounded divergence**: An adversary can only fork after the last seal-advancing event (forking before triggers `ParentLocked`). Combined with invariant 1, divergence spans at most 62 events from the fork point. An adversary holding less than the rotation-key preimage can only submit `ixn`, so the seal-advance cap limits them to at most 62 events before rejection.

3. **Bounded operations**: Recovery batch (`events + rec + rot`) ≤ 64, adversary chain to archive ≤ 62. All fit in one `MINIMUM_PAGE_SIZE`-bounded page.

Recovery-preimage rotation cadence (how often `Ror` should land) is **operator guidance**, not a protocol-enforced invariant — see [events.md §Seal-advance cap](events.md#seal-advance-cap). Reconciliation correctness does not depend on a cap on `Rec`/`Ror`/`Dec` frequency.

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible. The page+resume-verify discriminator (SEL backport) relies on invariant 4.

## KEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix |
| **Active** | Linear chain, latest tip extends cleanly |
| **Active, sealed** | Sub-state of Active where a submitter's view lands at-or-before `lastSealAdvancingEvent` (a seal-advancing event has landed past the submitter). Any extension whose parent sits in the locked portion returns `ParentLocked`. |
| **Divergent** | Fork detected (non-privileged `Ixn`-`Ixn`), no `Rec` yet. Privileged events extending `v_{d-1}` are rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). |
| **Divergent (sealed)** | Sub-state of Divergent where the seal has advanced past the divergence point — typically via a `Rec`/`Ror`/`Rot` that landed before resolution. Competing `Rec` against `v_{d-1}` is rejected by the locked-portion bound; non-priv extensions and priv submissions extending `v_{d-1}` return `ParentLocked`. |
| **Recovered** | Clean chain after synchronous archival in the merge transaction |
| **Decommissioned** | Exactly one `Dec`, ending a clean (linear) chain. Fully terminal: all submissions rejected by the seal-cap. |

## Local Submissions Matrix

What happens when a client submits events to the merge engine on a single node.

| KEL State | ixn | rot | ror | rec / rec+rot | dec |
|-----------|-----|-----|-----|---------------|-----|
| **Empty** | Reject (no KEL) | Reject | Reject | Reject | Reject |
| **Active** | Append ✓ | Append ✓ (linear extension; `ParentLocked` if extending `v_{d-1}` while an event exists at `v_d`) | Append ✓ (linear extension; `ParentLocked` if extending `v_{d-1}` while an event exists at `v_d`) | Append ✓ (gossip-sync of recovered KELs) | Append ✓ → Decommissioned (linear); `ParentLocked` if extending `v_{d-1}` while an event exists at `v_d` |
| **Active, sealed** (parent at-or-before `lastSealAdvancingEvent` in chain order) | `ParentLocked` | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{seal-1}`) |
| **Divergent** | `RecoverRequired` | `ParentLocked` (privileged event extending `v_{d-1}` rejected per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)) | `ParentLocked` (same as Rot) | Recovered ✓ (creates `RecoveryRecord`) | `ParentLocked` (same as Rot) |
| **Divergent (sealed)** | `ParentLocked` | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) | `ParentLocked` (the seal-cap rejects any extension of `v_{d-1}`) |
| **Recovered** | Same as Active | Same as Active | Same as Active | Same as Active | Same as Active |
| **Decommissioned** | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` |

### Notes on cell routing

- **Privileged event extending `v_{d-1}` (any chain state)** — A privileged event (`Rot`, `Ror`, or `Dec`) with `previous = v_{d-1}.said` whose landing would create or join a divergent set is rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The merge engine returns `ParentLocked`-equivalent. Cross-node priv-vs-priv races resolve at the federation layer (see [§Race matrix](#race-matrix) below).
- **Active, sealed and Divergent (sealed)** — the seal-cap (`parent_serial >= seal_serial`) rejects every submission whose parent sits in the locked portion. All extensions of `v_{seal-1}` / `v_{d-1}` return `ParentLocked`. When the rejected submission originated from another federation peer's locally-landed priv event (concurrent priv-vs-priv race), the chain does not structurally converge with that peer; federation-level convergence resolves at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). The per-race-shape enumeration is in [§Race matrix](#race-matrix) below.
- **Decommissioned** — fully terminal. All submissions return `KelDecommissioned`. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205) and [§Race matrix](#race-matrix) below).

### Batch submissions

The merge engine handles batches atomically:

- **`[events + rec + rot]`** — the surviving chain from the fork point through recovery. At most 64 events (bounded by the seal-advance cap). Processed as a single overlap or divergent submission.
- **`[rot, ixn]` or `[ror, ixn]`** — auto-inserted by the builder when an `ixn` would exceed the seal-advance cap interval. `rot` is the cheaper choice; `ror` is selected when the operator's recovery-preimage rotation cadence (operator guidance, not protocol-enforced) calls for it.

## Gossip Sync (transfer_key_events)

When node A syncs a KEL to node B, `transfer_key_events` reads from A and writes to B via `store_page` (which calls the merge engine on B).

### Transfer ordering

For divergent source KELs, `send_divergent_events` reorders events to ensure the KEL is reconstructed the same way. With synchronous archival, a recovered source KEL is always a clean linear chain — the archived-branch events are removed in the merge transaction. In normal operation, only unrecovered divergent cases reach `send_divergent_events`.

- **Divergent with rec** — Rejected with error. This state cannot exist through normal merge paths: synchronous archival means a `rec` immediately archives the other-branch events, leaving a clean chain. A divergent KEL with `rec` in the live tables indicates possible DB tampering. `send_divergent_events` refuses to propagate it.
- **Unrecovered (Ixn-Ixn divergent set)** — Longer chain first as non-divergent appends. Only the fork event from the shorter chain is sent. Receiver routes the fork event through §6c Overlap → divergent state.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a KEL from a source node (row) to a sink node (column). The source's `transfer_key_events` reads its local KEL and sends events via `store_page` to the sink. The sink's merge engine processes the incoming events against whatever state it already has for that prefix.

"Active (surviving)" means the sink has the eventual surviving branch's non-divergent chain. "Active (alternate)" means the sink has the eventual non-surviving branch's non-divergent chain (submitted to that node before divergence was detected elsewhere). The protocol cannot distinguish the two from chain data alone — "surviving" is the branch that `Rec` (whoever holds the recovery key) ultimately extends.

| Source | Sink: Empty | Sink: Active (surviving) | Sink: Active (alternate) | Sink: Divergent | Sink: Decommissioned |
|--------|-------------|---------------------|-------------------------|----------------|----------------------|
| **Active** | Full KEL appended ✓ | Duplicates, no-op ✓ | Overlap → divergence | `RecoverRequired` | `KelDecommissioned` |
| **Recovered** | Full clean chain ✓ | `rec`+`rot` append ✓ | Overlap → `rec` in batch → recovery ✓ | `RecoverRequired` (sink awaiting recovery) | `KelDecommissioned` |
| **Divergent (unrecovered)** | Reordered: longer chain + fork event ✓ | Fork event creates overlap → divergence | Fork event creates overlap → divergence | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `KelDecommissioned` |
| **Decommissioned** | Full chain + `dec` ✓ | `dec` appends ✓ | Overlap, `dec` in chain ✓ | `RecoverRequired` | Effective SAIDs match (Dec.said) ✓ |

### Notes on cell routing

- **Sink terminal state** (Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Send-side partitioning** (Source: Divergent) — the source partitions the chain into sub-batches the sink will accept under its routing rules. See [§Transfer ordering](#transfer-ordering) above and [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-kels).
- **Divergent → Divergent sink** — effective SAIDs match by construction; full anti-entropy may reconcile any-missing-branch-events even when SAIDs already match.
- **Cross-node priv-vs-priv races** — when sources/sinks land different competing privileged events at the same serial, the seal-cap rejects each peer's gossip-arriving event. Federation-level convergence resolves at the infrastructure layer via the irreconcilable-prefix table (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). See [§Race matrix](#race-matrix) below.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID computation | Converges? |
|-------|---------------------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Recovered** | Tip event SAID | ✓ (identical clean chains) |
| **Decommissioned** | `dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing privileged event extending `Dec`'s parent has been submitted to a different node, the federation does NOT structurally converge — each node's seal-cap rejects the other's submission; convergence is via the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205)). |
| **Irreconcilable** | `hash_effective_said("irreconcilable:{prefix}")` — federation-layer-sourced | ✓ (deterministic; same value across all nodes when the federation surfaces the prefix as in-dispute via the irreconcilable-prefix table per [#205](https://github.com/jasoncolburne/kels/issues/205); returned by the service in chain-query responses regardless of per-node tip state). |

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

A submitter with the recovery key submits `rec` to a non-divergent KEL (normal append, no divergence). This reveals the recovery key. Any future divergence at or after this `rec` is unrecoverable per-node: the recovery key is spent, non-priv events that form divergent sets cannot be archived, and priv events that would create or join the divergent set are rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Operator recourse is abandon-and-reincept under a new prefix.

```
Pre-state (linear chain through s_N):
  s_0 → s_1 → ... → s_N   (tip at s_N; seal at last rec-revealing event ≤ N)

A recovery-key holder submits rec with previous = s_N.said (dual-sig satisfied):
  s_0 → ... → s_N → rec_x  (s_{N+1}; seal advances to N+1)

Effect: chain stays linear; seal advances to N+1; recovery key now spent for
this chain. A privileged event (`Rot`, `Ror`, or `Dec`) extending
v_N.said arriving via gossip is rejected at the merge layer per
[../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal):
its acceptance would create a divergent set containing a privileged event.
Cross-node priv-vs-priv races resolve at the federation layer via the
irreconcilable-prefix table. Competing `Rec` against v_N is rejected by the
locked-portion bound; non-priv extensions submitted at serial ≤ N+1 are
rejected with `ParentLocked` (seal-cap).
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

If one recovery-key holder submits `rec` archiving the local builder's events synchronously, the local builder detects missing events via `find_missing_owner_events`: it loads the last page of events from the local `KelStore`, then walks backward calling `event_exists` on the server for each SAID until it finds one the server still has. Everything after that boundary was archived by the competing `rec`. The builder resubmits those missing events plus a privileged event (`Rot`, `Ror`, or `Dec`) as an atomic batch.

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
Builder bundles [branch_A, branch_A', dec] as atomic batch and submits.
The missing events are verified server-side and re-established under the
batch's atomic transaction. Post-batch, dec with previous = branch_A.said
(v_d) would land at v_{d+1} as a sibling of branch_A' — creating a
divergent set containing a privileged event. The merge layer rejects
the dec per
[../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal);
the chain stays at its prior server-side state (tip = rec_B at v_{d+1}).
Builder recourse is to re-fetch the server state and submit Dec extending
the current tip cleanly, or to accept the server-side state without
decommissioning.
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

### 5. Concurrent Dec + Ror/Dec at v_d — federation race, infrastructure-layer convergence

Two parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec` (clean retirement); party 2 submits a privileged event (e.g., `Ror` or `Dec`) extending the same parent. Each lands as a linear-chain extension on its submitting node and advances the local seal. Gossip then delivers each event to the other node, but the seal-cap rejects each — under universal locking, no admission at a sealed serial:

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

Federation-level convergence in this scenario is provided at the infrastructure layer via a irreconcilable-prefix table that nodes maintain and gossip-sync; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205) for the design. The seal-cap stays unconditional; relaxing it to admit competing events at a sealed serial would re-open a stale-authority killswitch surface.

## Race matrix

Concurrent priv-vs-priv races between federation peers — both submitting privileged events extending the same parent `v_{d-1}` to different nodes — uniformly resolve via the same shape: each event lands as a clean linear-chain extension on its submitting node and advances the local seal; gossip then delivers each event to the other node, where the seal-cap rejects it (parent in locked portion). The chain does not structurally converge at the protocol layer; federation-level convergence is provided at the infrastructure layer via the irreconcilable-prefix table (see [#205](https://github.com/jasoncolburne/kels/issues/205)).

The race participants — any pairing across `{Rec, Ror, Rot, Dec}` — produce identical structural outcomes per-node:

- Each node keeps its locally-landed first-receive.
- The gossip-arriving competing event is rejected by the seal-cap with `ParentLocked` (or `KelDecommissioned` on the Dec'd side, equivalently a seal-cap rejection per [§Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded)).
- Federation-level convergence is via #205.

The Rot-vs-Rot, Ror-vs-Rot, and similar privileged-vs-privileged races are the rotation-tier adversary path: a tier-2 adversary (rotation preimage but not recovery preimage) can force federation-level non-convergence by racing `Rot` against an honest concurrent `Rot`/`Ror`. See [../../../../protocol-doctrine.md §Tier-2 adversary federation-non-convergence path](../../../../protocol-doctrine.md#tier-2-adversary-federation-non-convergence-path) for the structural framing and [../../../../../analysis/protocol-attack-surface.md §Key Compromise](../../../../../analysis/protocol-attack-surface.md#key-compromise-kel) for the worked threat scenarios.

## References

- [events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [event-log.md](event-log.md) — KEL chain lifecycle: states, divergence, recovery, privileged-event merge-layer rejection, decommission, seal-advance cap, discriminator algorithm.
- [merge.md](merge.md) — KEL merge engine; `MergeTransaction` API and full routing.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator and pending-bundling shape are mirrored on both sides.
