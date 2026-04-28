# SEL Reconciliation: Multi-Node Correctness Matrix

> Exhaustive enumeration of all SEL state × submission × gossip combinations, demonstrating that every case terminates correctly and all nodes converge on the same effective SAID. This is the load-bearing correctness argument for the SEL design — without it, the submit handler and gossip layer aren't proven sound.

For lifecycle prose (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For per-kind field rules and chain shapes, see [events.md](events.md). For the submit handler routing internals, see [merge.md](merge.md). This doc is the proof; the others are the design.

## Invariants

All cases below depend on these invariants:

1. **Identity-rooted authorization**: every v1+ SE event carries `identity_event` referencing a specific IEL event. Authorization for `Upd` resolves to the IEL's tracked `auth_policy` at that event; for `Sea`/`Rpr`/`Cnt`/`Dec`, to the IEL's tracked `governance_policy`. The IEL primitive's immunity rule guarantees those policies' contents are stable across time.

2. **Inception is permissionless but bounded by batch rule**: SE Icp prefix derives deterministically from `(identity, topic)`. Anyone can submit `[Icp]` content-wise, but the merge handler rejects inception batches lacking an `Upd` at v1 (`IncompleteInception`). Every chain is born with both content and a binding.

3. **Proactive-evaluation compliance**: Every SEL has an evaluation event (`Sea` / `Rpr` / `Cnt` / `Dec`) at least every `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events. Surfaced by `SelVerifier` and enforced by the submit handler; the builder auto-inserts `Sea` when the bound is about to be crossed.

4. **Bounded divergence**: An adversary can only fork after the last evaluation event. Combined with invariant 3, divergence spans at most 63 events from the fork point. An adversary without `governance_policy` (via the bound IEL's tracked governance) can only submit `Upd`, and proactive-evaluation enforcement limits them to at most 63 events before rejection.

5. **Bounded operations**: Repair batch (`pending + Rpr`) ≤ 64, contest batch (`pending + Cnt`) ≤ 64, adversary chain to archive ≤ 63. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

6. **No retroactive poisoning** (lives on IEL): every IEL-tracked policy is immune. Past authorizations stay satisfied by construction. See [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability).

7. **Monotonic identity ratchet**: each SE event's `identity_event` is at-or-after the chain's prior `last_identity_event` in IEL chain order. The chain ratchets forward.

These invariants are what make synchronous archival, single-page discriminator walks, and atomic batched submissions all feasible — and what make cross-chain authorization stable as IEL evolves.

## SEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix. |
| **Incepted, no v1** | Reachable transient state: someone submitted just `[Icp]`. **The merge handler rejects this**, so this state should never persist in storage; included here for completeness. |
| **Active** | Linear, non-divergent, no terminal event. |
| **Divergent** | Fork detected, no `Rpr`/`Cnt`/`Dec` yet. |
| **Repaired** | Clean chain after `Rpr` archived adversary events. |
| **Contested** | `Cnt` present, permanently frozen. |
| **Decommissioned** | `Dec` present, permanently frozen. |

"Divergent (sealed)" is a sub-state of **Divergent** where the seal has advanced past the divergence point — typically via an adversary's `Rpr` or `Sea` that landed before owner could repair. Owner's only legitimate response is `Cnt`.

## Local Submissions Matrix

What happens when a client submits events to the submit handler on a single node.

| SEL State | Upd | Sea | Rpr / pending+Rpr | Cnt / pending+Cnt | Dec |
|-----------|-----|-----|-------------------|-------------------|-----|
| **Empty** (no Icp) | Reject (no chain) | Reject | Reject | Reject | Reject |
| **Empty** (`[Icp]` alone) | n/a | n/a | n/a | n/a | n/a — rejected as `IncompleteInception` |
| **Empty** (`[Icp, Upd]` minimum) | Append ✓ if Upd's `identity_event` resolves to bound IEL and anchor satisfies IEL-resolved auth_policy; reject `BadIdentityBinding` otherwise | n/a | n/a | n/a | n/a |
| **Active** | Append ✓ (auth_policy gated via IEL) | Append ✓ (governance_policy gated via IEL) | Reject `RepairRequired` if not divergent (or `NothingToRepair` from builder); else discriminator-driven repair ✓ | Append ✓ (only legal when seal-past-version on existing branch — see ContestRequired) | Append ✓ |
| **Active, sealed** (Upd at version ≤ `last_governance_version`) | `ContestRequired` | `ContestRequired` (Sea is non-terminal; algorithmic trigger fires for any non-terminal, non-Rpr event at version ≤ seal) | n/a (`Rpr` cannot truncate at-or-before the seal) | Contest ✓ (extends owner tip; chain becomes Contested) | Append ✓ (Dec is terminal; algorithmic trigger excludes terminal kinds; chain terminates cleanly) |
| **Divergent** | Reject `RepairRequired` | Reject `RepairRequired` | Discriminator-driven repair ✓ | Reject `RepairRequired` (no governance-revealing event yet — repair, don't contest) | Reject `RepairRequired` |
| **Divergent (sealed)** | `ContestRequired` | `ContestRequired` | `ContestRequired` (seal already advanced; can't repair, must contest) | Contest ✓ | `ContestRequired` |
| **Repaired** | Same as Active | Same as Active | Same as Active | Same as Active | Same as Active |
| **Contested** | `ContestedSel` | `ContestedSel` | `ContestedSel` | `ContestedSel` | `ContestedSel` |
| **Decommissioned** | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` | `DecommissionedSel` |

Additional rejection cases for v1+ events that don't fit per-state cells:
- `BadIdentityBinding` — `identity_event` doesn't resolve to a real IEL event with matching prefix, or fails the monotonic ratchet check.
- `IelDivergent` — bound IEL event lives on a divergent IEL branch.

### Batch submissions

The submit handler treats a batch atomically:

- **`[Icp, Upd]`** — minimum legal inception batch. Icp permissionless and deterministic; Upd at v1 carries `identity_event` and is anchored under the bound IEL's auth_policy. Inception batches without v1 Upd are rejected.
- **`[pending..., Rpr]`** — owner's pre-flush staged events plus the repair extending the last pending event (or owner's verified tip if pending is empty). At most one page (`MINIMUM_PAGE_SIZE = 64`). The discriminator preserves owner's chain; non-owner events at version ≥ `first_divergent_version` are archived.
- **`[pending..., Cnt]`** — owner's pending plus the contest. At most one page.
- **`[pending..., Dec]`** — owner's pending plus the decommission. At most one page.

There is no standalone `[Est]` or `[Icp]` batch (Est doesn't exist; Icp alone is rejected).

## Gossip Sync

When chain state transitions, the submit handler publishes the new effective SAID to Redis (`sel_updates`). The gossip service broadcasts an announcement on the `kels/sad/v1` topic; peers compare their local effective SAID against the announcement and fetch the full chain from origin if stale. SEL gossip does NOT reorder events — peers always fetch a full chain from origin and submit to their local SADStore, where the receiving handler routes via the same kind-discriminator (`is_repair` / `is_contest` / `is_decommission`) used for direct submissions.

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a chain from a source node (row) to a sink node (column). The source publishes its effective SAID; the sink (if it observes a mismatch) fetches the full chain via HTTP and submits to its local handler.

| Source | Sink: Empty | Sink: Active (owner) | Sink: Active (adversary) | Sink: Divergent | Sink: Contested | Sink: Decommissioned |
|--------|-------------|----------------------|--------------------------|-----------------|-----------------|----------------------|
| **Active** | Full chain appended ✓ (incl. mandatory `[Icp, Upd]` opening) | Duplicates, no-op ✓ | Overlap → divergence ✓ | `RepairRequired` | `ContestedSel` | `DecommissionedSel` |
| **Repaired** | Full clean chain ✓ | `Rpr` batch detected → discriminator-driven repair ✓ | `Rpr` batch → repair archives sink's adversary chain ✓ | `Rpr` batch → repair ✓ | `ContestedSel` | `DecommissionedSel` |
| **Divergent** | Both fork events appended ✓ (chain becomes divergent) | Fork event creates overlap → divergence ✓ | Fork event creates overlap → divergence ✓ | Effective SAIDs match (`hash("divergent:{prefix}")`) ✓ | `ContestedSel` | `DecommissionedSel` |
| **Contested** | Full chain (incl. `Cnt`) appended ✓ | `Cnt` batch → contest ✓ | `Cnt` batch → contest ✓ | `Cnt` batch → contest ✓ | Effective SAIDs match (`hash("contested:{prefix}")`) ✓ | `DecommissionedSel` (sink Dec'd first; gossip Cnt rejected) |
| **Decommissioned** | Full chain (incl. `Dec`) appended ✓ | `Dec` batch → decommission ✓ | Overlap, `Dec` in chain → decommission ✓ | `RepairRequired` (until repair lands) | `ContestedSel` | Effective SAIDs match (Dec.said) ✓ |

The matrix is smaller than KEL's because SEL's gossip layer doesn't reorder — full-chain fetch always converges. There is no `send_divergent_events` analogue.

### Path-agnostic acceptance

Gossip ingestion uses the same validation rules as direct submission. There is no submit-vs-gossip rule split; data is path-agnostic. See [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules).

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID | Converges? |
|-------|---------------|------------|
| **Active** | Tip event SAID | ✓ (identical chains after gossip) |
| **Divergent** | `hash_effective_said("divergent:{prefix}")` — deterministic | ✓ (same value regardless of which fork events each node has; avoids wasted anti-entropy sync) |
| **Repaired** | Tip event SAID (the `Rpr`) | ✓ (identical clean chains) |
| **Contested** | `hash_effective_said("contested:{prefix}")` — deterministic | ✓ |
| **Decommissioned** | `Dec` event SAID | ✓ (identical chains) |

## Archival

Archival happens synchronously within the submit-handler transaction that accepts the `Rpr` event. No background task or async processing.

### Owner identification

The discriminator identifies owner events via a single strategy — SEL's repair always extends owner's authentic tip, so `Rpr.previous` is always owner's chain head:

- Walk back from `Rpr.previous` through the verified page; everything reached is owner's chain.
- Everything else at `version ≥ first_divergent_version` is adversary.

The single-page-fetch + resume-verifier trust gate + in-memory walkback shape mirrors KEL's `archive_adversary_chain` (see [../kel/event-log.md §Server-side discriminator](../kel/event-log.md#server-side-discriminator)). Cryptographic gate is signature verification on KEL anchoring; same trust posture.

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 63 | Proactive-evaluation seal limits fork distance |
| Archival scope | Single transaction | Synchronous in submit handler, bounded by `MINIMUM_PAGE_SIZE` |
| Owner events never archived | ✓ | Owner chain identified by walk-back from `Rpr.previous` |

## Edge Cases

### 1. Adversary `Sea` as normal append

The adversary submits `Sea` to a non-divergent chain (normal append, no divergence) — possible if the adversary satisfies the bound IEL's `governance_policy` (e.g., a controller of one of the endorsing KELs went rogue). This advances the seal. Any future divergence at version ≤ the new seal triggers `ContestRequired`.

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created at one or more nodes. The first divergent event at each version is stored; subsequent ones are dedup-rejected. Repair (or contest) resolves it. All nodes converge after the resolution propagates.

### 3. Owner pending lost to adversary's `Rpr`

If the adversary submitted `Rpr` first, owner's pre-flush staged events may have been archived along with the rest of the adversary's reading of the chain. Owner's builder bundles pending into the repair batch via `repair()` — `[pending..., Rpr]` — and the submit handler accepts pending atomically with the repair, replaying owner's lost work onto the post-repair chain.

### 4. Post-repair events synced to a node that has the adversary chain

After repair on node A, new events (`Upd`, `Sea`) appended. When gossip propagates the chain to node B (still on the adversary version), node B fetches the full repaired chain and submits to its local handler. The handler observes the `Rpr` in the batch, runs the discriminator, archives node B's adversary events, and inserts the new chain.

### 5. Contested chains across nodes

Different nodes may have different event counts for a contested SEL (e.g., one node had owner's `Cnt` lands first; another had adversary `Sea` advance further before contest arrived). Their event counts may differ, but `compute_prefix_effective_said` returns a deterministic `hash_effective_said("contested:{prefix}")` for any chain with a `Cnt` event. Anti-entropy sees matching SAIDs and does not re-queue.

### 6. Adversary races inception with stale identity binding

Adversary submits `[Icp, Upd_stale]` — Icp is permissionless (dedup-idempotent across submitters), Upd_stale binds to an old IEL event where the adversary still had auth. The chain is born with adversary's content at v1. Owner submits `[Icp, Upd_owner]`; Icp dedups; Upd_owner extends as v2 with current IEL binding. Monotonic ratchet check: Upd_owner's `identity_event` ≥ Upd_stale's, satisfied since owner's binding is to a later IEL event. Owner's content takes precedence going forward; consumers reading the chain see Upd_owner's content as the latest. Adversary's stale v1 entry is buried but visible in chain history (forensic).

### 7. IEL evolves, owner ratchets dependent SE chain

After IEL governance evolves (a Sea on IEL changes governance_policy), owner submits `Sea` on each dependent SE chain to ratchet `last_identity_event` forward. After ratcheting, an adversary with revoked governance who tries to submit a stale-bound `Cnt`/`Dec` fails the monotonic check. See [../iel/event-log.md §Operator-discipline corollary for governance evolution](../iel/event-log.md#operator-discipline-corollary-for-governance-evolution).

### 8. SE chain bound to an IEL event whose IEL is now divergent

The submit handler rejects new SE events with `IelDivergent` (bound IEL is divergent at the bound branch — cannot resolve authorization). Owner's recovery path is to wait for IEL to be contested (terminating it) and then either: (a) decommission the SE chain, or (b) incept a new SE chain bound to a different (non-divergent) IEL.

## References

- [events.md](events.md) — Per-kind reference: kinds, field rules, chain shapes.
- [event-log.md](event-log.md) — Chain lifecycle: states, divergence, repair, contest, decommission, evaluation seal.
- [merge.md](merge.md) — Submit handler routing internals.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [../iel/reconciliation.md](../iel/reconciliation.md) — IEL counterpart (smaller; no Rpr).
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle and cross-chain anchor stability.
- [../sadstore.md](../sadstore.md) — SADStore service architecture and gossip layer.
- [../kel/reconciliation.md](../kel/reconciliation.md) — KEL counterpart; the discriminator and bounds analysis are mirrored on both sides.
