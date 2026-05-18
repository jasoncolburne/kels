# SEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all SEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the SEL design — without it, the submit handler and gossip layer aren't proven sound. Cross-node convergence as a doctrinal property is stated upstream at [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence); this doc is its per-primitive proof.

For lifecycle prose (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the submit handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Identity-rooted authorization**: every v1+ SEL event carries `ielEvent` referencing a specific IEL event. Authorization for `Upd` resolves to the IEL's tracked `authPolicy` at that event; for `Sea`/`Rpr`/`Dec`, to the IEL's tracked `governancePolicy`. The IEL primitive's immunity rule guarantees those policies' contents are stable across time.

2. **Inception is permissionless but bounded by batch rule**: SEL Icp prefix derives deterministically from `(identity, topic)`. Anyone can submit `[Icp]` content-wise, but the verifier rejects any chain whose tip is still `Icp` (`IncompleteInception` from `SelVerifier::finish_internal`). Every chain is born with both content and a binding.

3. **Proactive-evaluation compliance**: Every SEL has an evaluation event (`Sea` / `Rpr` / `Dec`) at least every `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events. Surfaced by `SelVerifier` and enforced by the submit handler; the builder auto-inserts `Sea` when the bound is about to be crossed.

4. **Bounded divergence**: An adversary can only fork after the last evaluation event. Combined with invariant 3, divergence spans at most 63 events from the fork point. An adversary without `governancePolicy` (via the bound IEL's tracked governance) can only submit `Upd`, and proactive-evaluation enforcement limits them to at most 63 events before rejection.

5. **Bounded operations**: Repair batch (`pending + Rpr`) ≤ 64, decommission batch (`pending + Dec`) ≤ 64, adversary chain to archive ≤ 63. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

6. **No retroactive poisoning** (lives on IEL): every IEL-tracked policy is immune. Past authorizations stay satisfied by construction. See [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability).

7. **Per-event parent-monotonic on `ielEvent`** (SEL-specific; KEL/IEL have no analog because their authorization is intrinsic, not referenced via a separate field): each SEL event's `ielEvent` is at-or-after its parent event's `ielEvent` (parent via `previous` SAID) in IEL chain order, applied per branch independently. Branches with different parent-chains do not constrain each other; the chain-wide `lastIelEvent` is a derived aggregate (max across all events) used by consumers, not a flowing watermark gate. Within-chain policy variation across branches is bounded by the seal-cap and by privileged-divergence-is-terminal.

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible — and what make cross-chain authorization stable as IEL evolves.

## SEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Incepted, no v1** | Reachable transient state: someone submitted just `[Icp]`. **The verifier rejects this** (`SelVerifier::finish_internal` → `IncompleteInception` whenever any branch tip is `Icp`), so this state should never persist in storage; included here for completeness. |
| **Active** | Linear, non-divergent, no terminal event. |
| **Active, sealed** | Sub-state of Active where the submitter's view lands at-or-before `lastSealAdvancingEvent` (a governance-authorized party has advanced the seal past the submitter). Non-terminal `Upd`/`Sea` submissions return `ContestRequired`. |
| **Divergent** | Fork detected, no `Rpr`/`Dec` yet. |
| **Divergent, sealed** | Sub-state of Divergent where the seal has advanced past the divergence point — typically via a `Rpr` or `Sea` that landed before resolution. Submitter's only legitimate response is `Dec`, or accept the new state. |
| **Repaired** | Clean chain after `Rpr` archived adversary events. |
| **Contested** | Divergent set contains a non-archiving privileged event (`Sea` or `Dec`); no event of any kind lands. |
| **Decommissioned** | `Dec` present on a linear chain. Fully terminal: all submissions rejected by the seal-cap. |

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| SEL State | Upd | Sea | Rpr / pending+Rpr | Dec |
|-----------|-----|-----|-------------------|-----|
| **Empty** (no Icp) | Reject (no chain) | Reject | Reject | Reject |
| **Empty** (`[Icp, Est]` minimum) | Append ✓ if `ielEvent` binding + anchor satisfy IEL authPolicy; else `BadIdentityBinding` | n/a | n/a | n/a |
| **Active** | Append ✓ (authPolicy via IEL) | Append ✓; if creates overlap → Contested | Repair ✓ (clean: no-op archival; adversary extension: archives adversary chain) | Append ✓ → Decommissioned (linear) or Contested (creates divergence at `v_d`) |
| **Active, sealed** (`Upd`/`Sea` at-or-before `lastSealAdvancingEvent` in chain order) | `ContestRequired` | `ContestRequired` (the seal-cap rejects any extension of `v_{seal-1}`) | `ContestRequired` (the seal-cap rejects any extension of `v_{seal-1}`) | `ContestRequired` (the seal-cap rejects any extension of `v_{seal-1}`) |
| **Divergent** | `RepairRequired` | `RepairRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule | Discriminator-driven repair ✓ | `RepairRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule |
| **Divergent (sealed)** | `ContestRequired` | `ContestRequired` | `ContestRequired` (seal-cap rejects truncation at-or-before the seal) | `ContestRequired` (linear); extending `v_{d-1}` → Contested via upgrade rule |
| **Repaired** | Same as Active | Same as Active | Same as Active | Same as Active |
| **Contested** | `ContestedSel` | `ContestedSel` | `ContestedSel` | `ContestedSel` |
| **Decommissioned** | `DecommissionedSel` | `DecommissionedSel` * | `DecommissionedSel` | `DecommissionedSel` * |

Additional rejection cases that don't fit per-state cells:
- `IncompleteInception` — inception submission of `[Icp]` alone (no `Est`); verifier rejects whenever any branch tip is `Icp`. See [§Chain States](#chain-states) row "Incepted, no v1".
- `BadIdentityBinding` — `ielEvent` doesn't resolve to a real IEL event with matching prefix, or fails the per-event parent-monotonic check.
- `IelDivergent` — bound IEL event lives on a divergent IEL branch.

### Notes on cell routing

- **Contested-state transition on an Active (non-sealed) chain** — A non-archiving privileged event (`Sea` or `Dec`) with `previous = v_{d-1}.said` creates a 2-event divergent set at `v_d` (the new event + the existing non-privileged event at `v_d`); privileged-divergence-is-terminal fires. On `Active, sealed`, the seal-cap rejects this construction (parent in locked portion). See [event-log.md §Contested-state transitions](event-log.md#contested-state-transitions).
- **Contested-state transition (divergent chain)** — A non-archiving privileged event with `previous = v_{d-1}.said` joins the divergent set as a third event via the upgrade rule.
- **`Sea` / `Upd` `ContestRequired` on Active, sealed** — non-terminal, non-`Rpr` event at-or-before `lastSealAdvancingEvent` would re-evaluate the seal; the submitter must accept the new state, decommission via `Dec`, or abandon. See [merge.md §`ContestRequired` algorithmic trigger](merge.md#contestrequired-algorithmic-trigger).
- **Active, sealed and Divergent (sealed) — all kinds extending `v_{seal-1}` / `v_{d-1}`** — the seal-cap rejects every submission whose parent sits in the locked portion. When the rejected submission originated from another federation peer's locally-landed priv event (concurrent priv-vs-priv race — `Sea-vs-Sea`, `Sea-vs-Dec`, `Rpr-vs-Rpr`, `Rpr-vs-Sea`, etc.), the chain does not structurally converge with that peer; federation-level convergence resolves at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) and [#205](https://github.com/jasoncolburne/kels/issues/205)). The per-race-shape enumeration is in [§Race matrix](#race-matrix) below.
- **Decommissioned** — fully terminal. All submissions return `DecommissionedSel`. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205) and [§Race matrix](#race-matrix) below).

### Batch submissions

The submit handler treats a batch atomically:

- **`[Icp, Est]`** — minimum legal inception batch. Icp permissionless and deterministic; Est at v1 carries `ielEvent` and is anchored under the bound IEL's authPolicy (tier 2 per [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation)). Inception batches without v1 Est are rejected.
- **`[pending..., Rpr]`** — owner's pre-flush staged events plus the repair extending the last pending event (or owner's verified tip if pending is empty). At most one page (`MINIMUM_PAGE_SIZE = 64`). The discriminator preserves owner's chain; non-owner events at serial ≥ `first_divergent_serial` are archived.
- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page.

There is no standalone `[Icp]` batch (Icp alone is rejected). `Est` is structurally pinned to v1 and only appears as the v1 event of an inception batch.

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID to Redis (`sel_updates`). The gossip service broadcasts an announcement on the `kels/gossip/v1/topics/sel` topic; peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. The receiving handler routes via the same kind-discriminator (`is_repair` / `is_contest` / `is_decommission`) used for direct submissions.

For linear chains the source sends a single full-chain stream that the sink applies as a normal append. For divergent chains the source uses `send_divergent_sel_events` (`lib/kels/src/types/sad/sync.rs`) to partition the chain into sub-batches the sink will accept under its routing rules: pre-divergence + non-privileged chain as paged appends, then the contesting chain (ending in the non-archiving privileged event — `Sea` or `Dec` — that triggered the transition) as an atomic single-page batch. See [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-sels). Sender-side composition is the cryptographic-soundness gate; the sink's routing rules are the constraint the sender designs around, not a safety net.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column). The source publishes its effective SAID; the sink (if it observes a mismatch) fetches the full chain via HTTP and submits to its local handler.

| Source | Sink: Empty | Sink: Active (owner) | Sink: Active (adversary) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|----------------------|--------------------------|-----------------|-----------------|----------------------|
| **Active** | Full chain appended ✓ (incl. mandatory `[Icp, Est]` opening) | Duplicates, no-op ✓ | Overlap → divergence ✓ | `RepairRequired` | `ContestedSel` | `DecommissionedSel` |
| **Repaired** | Full clean chain ✓ | `Rpr` batch → discriminator-driven repair ✓ | `Rpr` batch → repair archives sink's adversary chain ✓ | `Rpr` batch → repair ✓ | `ContestedSel` | `DecommissionedSel` |
| **Divergent** | Both fork events appended ✓ | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedSel` | `DecommissionedSel` |
| **Contested** | Non-contesting chain (paged) + contesting chain (atomic batch ending in `Sea`/`Dec`) ✓ | Non-contesting appends + contesting batch → contested ✓ | Non-contesting appends + contesting batch → contested ✓ | Contesting batch → contested ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `DecommissionedSel` (federation race, infrastructure-layer convergence per #205) |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | Overlap, `Dec` in chain → decommission ✓ | `RepairRequired` (until repair lands) | `ContestedSel` | Effective SAIDs match (Dec.said) ✓ |

### Notes on cell routing

- **Sink terminal states** (Contested, Decommissioned) — gossip ignored once sink is terminal; the cell shows the error the sink returns.
- **Source: Contested → Sink: Decommissioned** — the Decommissioned sink rejects every gossip-delivered event from the Contested source with `DecommissionedSel` (the seal-cap rejects extensions of `v_{d-1}`). Federation-level convergence is provided at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) and [#205](https://github.com/jasoncolburne/kels/issues/205)).
- **Send-side partitioning** (Source: Divergent, Source: Contested, Source: Repaired) — the source partitions the chain into sub-batches the sink will accept under its routing rules. See [merge.md §Gossip Send-Side Partitioning](merge.md#gossip-send-side-partitioning-divergent-sels).
- **Decommissioned → Divergent sink** — `Dec` cannot resolve divergence; sink stays divergent until `Rpr` lands.
- **Divergent → Divergent sink** — effective SAIDs match by construction; full anti-entropy may reconcile any-missing-branch-events even when SAIDs already match.

The matrix is smaller than KEL's because SEL's discriminator handles repair-driven archival inline; the source-side partitioning (`send_divergent_sel_events`) ensures each sub-batch routes through a single discriminator predicate at the sink, so the matrix collapses around the source's terminal state rather than expanding into per-sub-batch cases.

### Path-agnostic acceptance

Gossip ingestion uses the same validation rules as direct submission. There is no submit-vs-gossip rule split; data is path-agnostic. See [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules).

### Successful sync = local effective SAID advanced

A successful gossip sync is defined as the **sink's local effective SAID advancing**, not as the receiving HTTP submit returning OK. The sink may accept events at the wire layer (HTTP 200 / batch applied) but still leave its effective SAID at the prior tip — for example, when a forwarded chain is rejected at verification time and the local stale entry should remain queued for retry rather than being cleared. The anti-entropy loop (`run_sad_anti_entropy_loop`, `services/gossip/src/sync.rs`) treats only "effective SAID advanced" as a `Repaired` outcome; HTTP-success-without-advance returns `NoOp` and the stale entry stays queued.

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Repaired** | Tip event SAID (the `Rpr`) | ✓ (identical clean chains) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ (same value on all nodes regardless of which divergent events each node holds) |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains across all Dec-first nodes when no competing event has been submitted). If a competing privileged event extending `Dec`'s parent has been submitted to a different node, the federation does NOT structurally converge — each node's seal-cap rejects the other's submission; convergence is via the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205)). |

## Archival

Archival happens synchronously within the submit-handler transaction that accepts the `Rpr` event. No background task or async processing.

### Owner identification

The discriminator identifies owner events via a single strategy — SEL's repair always extends owner's authentic tip, so `Rpr.previous` is always owner's chain head:

- Walk back from `Rpr.previous` through the verified page; everything reached is owner's chain.
- Everything else at `serial ≥ first_divergent_serial` is adversary.

The single-page-fetch + resume-verifier trust gate + in-memory walkback shape mirrors KEL's `archive_adversary_chain` (see [../kel/event-log.md §Server-side discriminator](../kel/event-log.md#server-side-discriminator)). Cryptographic gate is signature verification on KEL anchoring; same trust posture.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 63 | Proactive-evaluation seal limits fork distance |
| Archival scope | Single transaction | Synchronous in submit handler, bounded by `MINIMUM_PAGE_SIZE` |
| Owner events never archived | ✓ | Owner chain identified by walk-back from `Rpr.previous` |

## Edge Cases

### 1. Adversary Sea as normal append

The adversary submits `Sea` to a non-divergent chain (normal append, no divergence) — possible if the adversary satisfies the bound IEL's `governancePolicy` (e.g., a controller of one of the endorsing KELs went rogue). This advances the seal. Any future divergence at serial ≤ the new seal triggers `ContestRequired`.

```
Pre-state (linear at v_N; seal at last Sea/Rpr ≤ N):

  [Icp] → [Upd_v1] → ... → [Upd_v_N]   (tip)

Adversary submits Sea with previous = v_N.said (governance authorization
satisfied via bound IEL's current governancePolicy):

  [Icp] → ... → [Upd_v_N] → [Sea_v_{N+1}]   (seal advances to N+1)

Effect: chain stays linear; seal advances. Any subsequent submission whose
parent sits at-or-before v_N is rejected by the seal-cap with
ContestRequired (or DecommissionedSel / ContestedSel if the chain has
already transitioned to a terminal state). The seal-cap is unconditional;
no boundary case admits competing privileged events at a sealed serial.
Federation races between concurrent competing privileged submissions
resolve at the infrastructure layer (see [../../../../protocol-doctrine.md
§Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)
and [#205](https://github.com/jasoncolburne/kels/issues/205)).
```

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created at one or more nodes. The first divergent event at each serial is stored; subsequent ones are dedup-rejected. Repair (or contest) resolves it. All nodes converge after the resolution propagates.

```
Pre-state (linear at v_{d-1}, replicated to nodes A and B):

  All nodes:  [Icp] → [Upd] → ... → [Upd_{d-1}]   (tip)

Adversary submits different Upd events to different nodes:

  Node A receives Upd_a   →  tip Upd_a   (linear append)
  Node B receives Upd_b   →  tip Upd_b   (linear append)

Gossip propagates. Each node observes overlap at v_d and writes the
incoming event as the second fork event:

  Both nodes:  [Icp] → ... → [Upd_{d-1}] ─┬─ Upd_a @ v_d   (non-priv divergent)
                                          └─ Upd_b @ v_d

Operator submits Rpr (governance-authorized via bound IEL) extending
their preferred surviving branch; discriminator archives the other
branch; resolution propagates via gossip; all nodes converge on the
post-Rpr linear state.

  Post-Rpr (linear, repaired):
    [Icp] → ... → [Upd_{d-1}] → [surviving Upd] → [Rpr]   (tip)
                                       ↑
                                       other branch archived
```

### 3. Owner pending lost to adversary's Rpr

If the adversary submitted `Rpr` first, owner's pre-flush staged events may have been archived along with the rest of the adversary's reading of the chain. Owner's builder bundles pending into the repair batch via `repair()` — `[pending..., Rpr]` — and the submit handler accepts pending atomically with the repair, replaying owner's lost work onto the post-repair chain.

```
Pre-state (chain divergent at v_d; operator has pending events locally
staged but never flushed):

  Server:  [Icp] → ... → [Upd_{d-1}] ─┬─ Upd_d_op   (operator's branch tip)
                                      └─ Upd_d_adv  (other branch tip)

  Client:  staged pending_1, pending_2 chained from Upd_d_op (not flushed)

Operator's repair() bundles pending into the repair batch:

  Submit:  [pending_1, pending_2, Rpr]
           where Rpr.previous = pending_2.said   (Rpr extends last pending)

Server processes atomically:
  1. pending_1, pending_2 land on Upd_d_op's branch (now v_{d+1}, v_{d+2}).
  2. Rpr lands at v_{d+3}, walks back through pending_2 → pending_1 →
     Upd_d_op → Upd_{d-1} (surviving-branch walkback).
  3. Discriminator archives the other branch (Upd_d_adv and any extensions).

Post-state (linear, repaired, pending replayed):

  [Icp] → ... → [Upd_{d-1}] → Upd_d_op → pending_1 → pending_2 → Rpr
                                                        ↑
                                                        operator's lost work
                                                        preserved
```

### 4. Post-repair events synced to a node that has the adversary chain

After repair on node A, new events (`Upd`, `Sea`) appended. When gossip propagates the chain to node B (still on the adversary serial), node B fetches the full repaired chain and submits to its local handler. The handler observes the `Rpr` in the batch, runs the discriminator, archives node B's adversary events, and inserts the new chain.

```
Pre-sync state (post-repair on A; adversary chain still on B):

  Node A:  [Icp] → ... → [Upd_{d-1}] → Upd_d_op → Rpr → Upd_new → Sea_new
           (clean linear chain after Rpr archived adversary branch)

  Node B:  [Icp] → ... → [Upd_{d-1}] → Upd_d_adv
           (still has adversary's branch; Rpr hasn't propagated)

Gossip propagates Node A's chain (including Rpr and post-Rpr events) to
Node B. Node B's submit handler observes overlap at v_d (its Upd_d_adv vs
incoming Upd_d_op), sees Rpr in the batch, runs the discriminator (Rpr
walkback identifies Upd_d_op as surviving), and archives Upd_d_adv
synchronously.

  Node B (post-sync):  [Icp] → ... → [Upd_{d-1}] → Upd_d_op → Rpr →
                                     Upd_new → Sea_new
                       (matches Node A; Upd_d_adv in archive table)

All nodes converge on the same effective SAID (tip event SAID).
```

### 5. Contested chains across nodes

Different nodes may have different event counts for a contested SEL (e.g., one node had a `Sea` upgrade a non-priv divergent set via the upgrade rule; another saw a 2-event privileged divergent set directly). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any chain with a non-archiving privileged event in its divergent set. Anti-entropy sees matching SAIDs and does not re-queue.

```
Different event sets across nodes, same effective SAID:

  Node A:  [Icp] → ... → [Upd_{d-1}] ─┬─ Upd_a @ v_d ┐
                                      ├─ Upd_b @ v_d ├── 3-event set;
                                      └─ Sea   @ v_d ┘    contested
                                                          (Sea upgraded set
                                                           via upgrade rule
                                                           on this node)

  Node B:  [Icp] → ... → [Upd_{d-1}] ─┬─ Upd_b @ v_d ┐
                                      └─ Sea   @ v_d ┴── 2-event set;
                                                         contested (B's
                                                         local Sea closed
                                                         gate before Upd_a
                                                         gossip arrived)

  effective_said(A) = hash_effective_said("contested:{prefix}")
  effective_said(B) = hash_effective_said("contested:{prefix}")
                    = effective_said(A)    ✓

Anti-entropy compares SAIDs, sees they match, does not re-queue
synchronization. Both nodes' chains stay as forensic record.
```

### 6. Adversary races inception with stale identity binding

> **Operator never extends `Est_stale`.** Extending an adversary event would be a structural attestation that the predecessor is acceptable — equivalent to endorsing the adversary's content. The operator extends `Icp` (which is attested-shared via dedup-equivalence), not the adversary's `Est`. See [../../../../protocol-doctrine.md §Extension Discipline](../../../../protocol-doctrine.md#extension-discipline).

Adversary submits `[Icp, Est_stale]` — Icp is permissionless (dedup-idempotent across submitters), Est_stale binds to an old IEL event where the adversary still had auth. The chain is born with adversary's content at v_1. Operator submits `[Icp, Est_legit]` where `Est_legit.previous = Icp.said` (extending `Icp` via dedup-equivalence). `Icp` dedups; `Est_legit` lands at `v_1` alongside `Est_stale`, creating a non-privileged divergent set (both auth-authorized; Est-Est race shape). Operator submits `Rpr` (governance-authorized via the bound IEL's current `governancePolicy`) extending the `Est_legit` branch; the discriminator archives `Est_stale`. Chain becomes the operator's; `Est_stale` moves to the archive table (forensic-readable; not live).

```
Step 1 — Adversary submits [Icp, Est_stale] first; chain born at v_1
with adversary's content:

  [Icp_v0] → [Est_stale @ v_1, ielEvent=IEL_v_old]   (chain tip)

Step 2 — Operator submits [Icp, Est_legit] with Est_legit.previous =
Icp.said (extending Icp directly, NOT Est_stale):

  Icp dedups (same content, same SAID across submitters; no second Icp
  record created).
  Est_legit lands at v_1 alongside Est_stale, creating non-priv divergent
  set:

  [Icp_v0] ─┬─ [Est_stale @ v_1, ielEvent=IEL_v_old]
            └─ [Est_legit @ v_1, ielEvent=IEL_v_current]

  Both auth-authorized; neither privileged → non-privileged divergent.

Step 3 — Operator submits Rpr (branch-tip-extending shape, extending
Est_legit at v_2):

  Rpr.previous = Est_legit.said
  Rpr.serial  = 2

  Discriminator's walkback from Rpr.previous reaches Est_legit at v_1;
  Est_stale's branch is archived.

  [Icp_v0] → [Est_legit @ v_1] → [Rpr @ v_2]   (linear, repaired)
                                       ↑
                                       Est_stale moved to sad_event_archives
                                       (forensic; not on live chain)
```

The operator's response **never extends `Est_stale`** — extending an adversary event would be a structural attestation that the predecessor is acceptable, equivalent to endorsing the adversary's content. See [../../../../protocol-doctrine.md §Extension Discipline](../../../../protocol-doctrine.md#extension-discipline).

### 7. IEL evolves, SEL branch tip ratchets via Sea

After IEL governance evolves (an Evl on IEL changes governancePolicy), the operator submits `Sea` on each dependent SEL to advance the live branch's tip `ielEvent` forward to the new IEL Evl. After this advancement, an adversary with revoked governance who tries to submit a stale-bound `Sea`/`Dec` extending that branch tip fails the per-event parent-monotonic check (the adversary's `ielEvent` regresses relative to its parent's). See [../iel/event-log.md §Governance-evolution ratchet via Sea](../iel/event-log.md#governance-evolution-ratchet-via-sea).

```
IEL chain evolves governance from gov_old to gov_new:

  IEL:  [Icp] → [Evl_old] → [Evl_new]   (governance evolved; old gov revoked)

Dependent SEL pre-Sea (live branch tip bound to IEL's Evl_old):

  SEL:  [Icp] → [Est_v1, ielEvent=Evl_old.said] → ...
        → [Upd_v_N, ielEvent=Evl_old.said]   (tip)

SEL advances via Sea bound to IEL's current governance event:

  SEL:  ... → [Upd_v_N] → [Sea_v_{N+1}, ielEvent=Evl_new.said]   (tip)
                                  ↑
                                  tip's ielEvent now Evl_new.said

Adversary (holds gov_old preimage only) tries to extend the tip with
stale-bound Sea/Dec:

  Dec_stale.previous = Sea_v_{N+1}.said    (would extend the Sea tip)
  Dec_stale.ielEvent = Evl_old.said        (stale binding)

  Per-event parent-monotonic check (per branch):
    Dec_stale's parent: Sea_v_{N+1}, ielEvent=Evl_new.said
    Dec_stale's      : ielEvent=Evl_old.said
    Evl_old < Evl_new in IEL chain order → REGRESS → HARD-fail rejection.

The Sea-advanced tip closes the regression window for adversaries
extending the live branch. Fork-contest from v_{d-1} (a fresh branch,
not extending the live branch's tip) is not blocked by this rule (see
[../iel/event-log.md §What parent-monotonic blocks](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt)).
```

### 8. SEL bound to an IEL event whose IEL is now divergent

The submit handler rejects new SEL events with `IelDivergent` (bound IEL is divergent at the bound branch — cannot resolve authorization). Operator's recovery path is to wait for IEL to transition to Contested (terminating it) and then either: (a) decommission the SEL, or (b) incept a new SEL bound to a different (non-divergent) IEL.

```
IEL chain (now divergent at v_d, immediately contested-terminal):

  IEL:  [Icp] → [Evl_v1] → ... → [Evl_{d-1}] ─┬─ Evl_d_a
                                              └─ Evl_d_b   ← contested-terminal

Dependent SEL trying to extend:

  SEL:  [Icp] → ... → [Upd_v_N, ielEvent=Evl_{d-1}.said]   (tip)

  Submitter tries:
    [Upd_v_new, ielEvent=Evl_d_a.said]   ← bound to a divergent IEL event

  IEL resolver: "bound event lives at v_d ≥ first_divergent_serial"
   → rejects with IelDivergent.

  Submitter tries with pre-divergence binding:
    [Upd_v_new, ielEvent=Evl_{d-1}.said]   ← bound at v_{d-1} (pre-div)

  IEL resolver: "bound event in pre-divergence shared prefix" → chain-validity
   OK; but consumer trust on a contested IEL is whole-chain-suspect (see
   ../iel/event-log.md §Effect on Bound SELs). Operator's typical response
   is to migrate the SEL or decommission it rather than keep advancing under
   a contested IEL.
```

### 9. Concurrent Dec + Sea/Dec at v_d — federation race, infrastructure-layer convergence

Two governance-authorized parties submit concurrent privileged events extending `v_{d-1}` at the same serial `d` to different nodes: party 1 submits `Dec`; party 2 submits a non-archiving privileged event (`Sea` or `Dec`) extending the same parent. Each lands as a linear-chain extension on its submitting node and advances the local seal. Gossip then delivers each event to the other node, but the seal-cap rejects each — under universal locking, no admission at a sealed serial:

```
Pre-state (linear at v_{d-1}):

  Both nodes:  [Icp] → ... → [v_{d-1}]   (tip)

Concurrent submissions:

  Party 1 → Node A:           dec.previous     = v_{d-1}.said, dec.serial     = d
  Party 2 → Node B:           sea_alt.previous = v_{d-1}.said, sea_alt.serial = d

Each event lands as a linear-chain extension on its submitting node.

Gossip propagates:

  Node A (Decommissioned at v_d via dec) receives sea_alt:
    sea_alt.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap with DecommissionedSel.
    A's state unchanged: Decommissioned.

  Node B (Active at v_d via sea_alt) receives dec:
    dec.parent_serial = d-1 < seal_serial = d
    → rejected by seal-cap with ContestRequired.
    B's state unchanged: Active with sea_alt as tip.

  Effective SAIDs:
    effective_said(A) = dec.said
    effective_said(B) = sea_alt.said
    A ≠ B → federation does not converge at the protocol layer.
```

Federation-level convergence in this scenario is provided at the infrastructure layer via a contested-prefix table that nodes maintain and gossip-sync; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) and [#205](https://github.com/jasoncolburne/kels/issues/205) for the design. The seal-cap stays unconditional; relaxing it to admit competing events at a sealed serial would re-open a stale-authority killswitch surface.

## Race matrix

Enumeration of concurrent priv-vs-priv races between federation peers, both submitting privileged events extending the same parent `v_{d-1}` to different nodes. Each event lands as a linear-chain extension on its submitting node and advances the local seal; gossip then delivers each event to the other node, where the seal-cap rejects it (parent in locked portion). The chain does not structurally converge at the protocol layer; federation-level convergence is provided at the infrastructure layer via the contested-prefix table (see [#205](https://github.com/jasoncolburne/kels/issues/205)).

| Race kind  | Receiving-node state at gossip arrival | Outcome |
|------------|----------------------------------------|---------|
| Rpr-vs-Rpr | Active-sealed (Rpr at `v_d`) | `ContestRequired`; non-converging; #205 |
| Rpr-vs-Sea | Active-sealed (Rpr/Sea at `v_d`) | `ContestRequired`; non-converging; #205 |
| Rpr-vs-Dec | Active-sealed / Decommissioned | `ContestRequired` / `DecommissionedSel`; non-converging; #205 |
| Sea-vs-Sea | Active-sealed (Sea at `v_d`) | `ContestRequired`; non-converging; #205 |
| Sea-vs-Dec | Active-sealed / Decommissioned | `ContestRequired` / `DecommissionedSel`; non-converging; #205 |
| Dec-vs-Dec | Decommissioned | `DecommissionedSel`; non-converging; #205 |

The matrix is symmetric in race participants — `Rpr-vs-Sea` covers both `Rpr` arriving at a node with `Sea` and `Sea` arriving at a node with `Rpr`. The receiving-node-state column reflects what the local chain looks like after the local first-receive has landed; the outcome describes the gossip-arriving event's rejection.

## References

- [events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, repair, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [../iel/reconciliation.md](../iel/reconciliation.md) — IEL counterpart (smaller; no Rpr).
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle and cross-chain anchor stability.
- [../../../../infrastructure/sadstore.md](../../../../infrastructure/sadstore.md) — SADStore service architecture and gossip layer.
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart; the discriminator and bounds analysis are mirrored on both sides.
