# Key Event Log (KEL) — Lifecycle, Recovery, Decommission

> Source-of-truth design doc for the KEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (merge engine routing), and [verification.md](verification.md) (KelVerifier algorithm).

The Key Event Log (KEL) is a per-prefix chain of `SignedKeyEvent` records describing the controller's evolving signing and recovery key state. Authority over the KEL is asserted by direct signature: every event carries one or more signatures verified against keys committed by prior establishment events.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, latest tip extends cleanly. | Yes — `Ixn`, `Rot`, `Ror`, `Rec`, `Dec` (per signature requirements). |
| **Divergent** | Two events at serial `d`, both non-privileged (`Ixn`-`Ixn`). Recoverable via `Rec`. | `Rec` (archives one branch; chain resumes). Privileged events (`Rot`/`Ror`/`Dec`) that would extend `v_{d-1}` are rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Bundled pending permitted. See [§Recovery (Rec)](#recovery-rec). |
| **Decommissioned** | Chain terminated cleanly via `Dec` — exactly one `Dec`, ending a clean linear chain. | None. Fully terminal: all submissions rejected with `KelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `KelVerification` token surfaces:
- `divergenceAncestor: Option<Digest256>` — SAID of `v_{d-1}` (the unique parent of all events at `v_d`) on a divergent chain, or `None` if linear.
- `is_decommissioned: bool` — `Dec` event in a linear chain (`Dec` whose landing would create or join a divergent set is rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)).
- `lastSealAdvancingEvent: Option<Digest256>` — SAID of the most recent `Rec`/`Ror`/`Rot` that landed cleanly on the linear chain. The seal never forks: privileged events that would create or join a divergent set are rejected at merge, so seal-advancing landings are linear-chain extensions by construction. The chain's seal-cap watermark (see §Seal and Key Immunity).
- `lastRecoveryRevealingEvent: Option<Digest256>` — SAID of the most recent `Rec`/`Ror`/`Dec`. Tracks recovery-key revelation for the spent-key / immunity rule; orthogonal to the seal (`Rot` advances the seal without revealing the recovery key; `Dec` reveals the recovery key without advancing the seal). Recovery-preimage rotation cadence is operator guidance, not protocol-enforced — see [events.md §Seal-advance cap](events.md#seal-advance-cap).

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` / `Dip` | Inception (s0). | Structural (self-authenticating; `Dip` additionally anchored by delegator). | No |
| `Rot` | Rotation. | Signing key (preimage of prior `rotationHash`). | No |
| `Ixn` | Interaction (anchor). | Current signing key. | No |
| `Rec` | Recovery — resolves divergence; rotates both keys. | Dual (signing + recovery). | No |
| `Ror` | Recovery rotation — pre-emptively rotates both keys (no divergence required). | Dual. | No |
| `Dec` | Decommission — terminal event ending the chain. | Dual. | **Yes** |

`Rec`, `Ror`, `Dec` all return `reveals_recovery_key() = true` — each requires dual signatures and exposes the current recovery key.

For per-kind field rules and typical chain shapes, see [events.md](events.md).

## Seal and Key Immunity

KEL tracks two related-but-distinct concepts. The membership sets diverge: seal-advance includes `Rot` (single-signed; no recovery-key revelation), while recovery-revealing includes `Dec` (terminal; doesn't advance the seal). The orthogonality lets the protocol bound chain-state changes (via the seal-advance cap) while leaving recovery-preimage rotation cadence to operator guidance — recovery keys are typically hardware-held and preimage-identified rather than usage-degraded, so a protocol-forced cadence would impose access on cold-stored / separated-custody recovery keys on a fixed schedule. See [events.md §Seal-advance cap](events.md#seal-advance-cap).

| Concept | Advances on | Used for |
|---|---|---|
| `lastSealAdvancingEvent` | `Rec`/`Ror`/`Rot` | Seal-cap rule: `event_serial >= seal_serial`; recovery cannot truncate at-or-before the seal. Bounds the chain-state advance cap (`MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events). See [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded). |
| `lastRecoveryRevealingEvent` | `Rec`/`Ror`/`Dec` | Spent-key rule. Once any recovery-revealing event lands, the recovery key is publicly known; subsequent attempts to recover using the spent key fail. Recovery-preimage rotation cadence (how often `Ror` should land to refresh the commitment) is operator guidance — see [events.md §Seal-advance cap](events.md#seal-advance-cap) — not a protocol-enforced cap. |

`Dec` is terminal — it enforces the seal but does not advance it.

**Once a recovery-revealing event lands, the dual-signature it proves is final.** Subsequent compromise or revocation of the keys it revealed does NOT retroactively unsatisfy the past authorization — the chain's history at that serial is locked. Without this, history could be invalidated retroactively by anyone who later comes to control the revealed key material, making terminal states (recovered, decommissioned) unstable. The trade-off is that a key controller who later turns adversarial cannot undo their past contributions; only the going-forward spent-key effect applies.

`lastSealAdvancingEvent` plays the same structural role across all three primitives — see [../iel/event-log.md §Evaluation Seal and Policy Immunity](../iel/event-log.md#evaluation-seal-and-policy-immunity) for the IEL-side discussion. A privileged-non-terminal primitive defines a forward-only watermark per chain; prior advancements are immutable.

The seal-cap rule is unconditional on KEL: a new event's parent must sit at-or-after `seal_serial`. Any submission whose parent is in the locked portion (`parent_serial < seal_serial`) is rejected. See [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded).

## Divergence and Termination

Divergence is detected when two events share the same `previous` SAID. The chain transitions per the privileged-divergence rule:
- If the divergent set contains an archiving event (`Rec`) — the discriminator runs first; one branch is archived; chain stays linear post-discriminator. (Archiving-precedence routes around the divergent-set check.)
- If the candidate event is privileged (`Rot`, `Ror`, or `Dec`) and its acceptance would create or join a divergent set — the merge layer rejects the submission. The chain's prior state stands.
- Otherwise (the divergent set contains only `Ixn` events) — chain enters **Divergent** state, recoverable via `Rec`.

s0 divergence is rejected outright — inception is fully deterministic; two distinct s0 events for the same prefix indicate protocol-level corruption, not authority conflict.

**Race-vs-takeover framing.** Divergence on a KEL — two events at the same serial — can arise from a federation race (two parties holding the current signing key submitting concurrently — rare, since signing keys are typically single-party) or a takeover (a second signing-key holder, whose access was acquired via compromise, forking against the original holder). The chain shape records the divergence in the data; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; the trust model degrades uniformly.

The divergence invariant — combined with the seal-advance cap (`MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events) — guarantees:
- **Divergent set** at serial `d`: max 2 events, both non-privileged (`Ixn`-`Ixn`). Recoverable via `Rec`. Privileged events that would create or join a divergent set are rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal).
- At most 62 events total on a divergent set's branches beyond `d` (the seal-advance cap bounds non-seal-advancing forks; a holder lacking rotation or recovery preimage cannot submit a seal-advancing event to extend further).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

### Cross-node priv-vs-priv races

Concurrent privileged events extending the same `v_{d-1}` on different federation nodes (e.g., `Rot_a` on Node A and `Rot_b` on Node B, both extending `v_{d-1}.said`) land cleanly as linear-chain extensions on their respective submitting nodes (the seal advances locally). Gossip then delivers each event to the other node, where the seal-cap rejects the late arrival (its parent sits in the locked portion behind the now-advanced seal). Per-node, each chain stays linear with its own first-receive as tip; cross-node, the federation does not converge at the protocol layer.

Federation-level convergence is provided by the irreconcilable-prefix table at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). The protocol enforces local invariants strictly; the federation layer surfaces the cross-node disagreement.

## Recovery (Rec)

Recovery resolves a divergent chain by archiving all events at `serial >= divergedAt` not on `Rec.previous`'s walkback, then appending the `Rec` (and optionally a follow-up `Rot`). `Rec.previous` takes one of two shapes:

1. **Branch-tip-extending shape — `Rec.previous` is a branch tip at `v_d`.** Rec extends that branch at `v_{d+1}`. The discriminator's walkback from `Rec.previous` reaches the surviving-branch tip at `v_d`; events on the other branch are archived. Use case: the submitter chooses one of the two branches at `v_d` as the surviving branch; Rec extends it.

   ```
   Pre-state (divergent at v_d):
       ... → v_{d-1} ─┬─ surviving-branch tip @ v_d
                      └─ other-branch tip     @ v_d

   Rec construction: rec.previous = surviving-branch tip's said
                     rec.serial   = d + 1

   Post-state (linear, recovered):
       ... → v_{d-1} → surviving-branch tip @ v_d → rec @ v_{d+1}
                     ↑
                     other branch archived
   ```

2. **Divergence-ancestor-extending shape — `Rec.previous` is `v_{d-1}` (the divergence ancestor).** Rec lands at `v_d`. The discriminator's walkback from `Rec.previous` stops immediately (serial drops below `divergedAt`); all events at `serial >= d` (both branches) are archived. Rec is the only event at `v_d` after the discriminator runs. Use case: the submitter does not preserve either of the existing branches at `v_d` and instead replaces `v_d` entirely with their own Rec extending `v_{d-1}`.

   ```
   Pre-state (divergent at v_d):
       ... → v_{d-1} ─┬─ branch-1 tip @ v_d
                      └─ branch-2 tip @ v_d

   Rec construction: rec.previous = v_{d-1}.said
                     rec.serial   = d

   Post-state (linear, recovered, Rec is the only event at v_d):
       ... → v_{d-1} → rec @ v_d
                     ↑
                     both prior branches archived
   ```

   The divergence-ancestor-extending shape's "both branches" archival is exhaustive by construction: divergent sets contain only non-privileged events (the merge layer rejects privileged events that would create or join a divergent set per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)). Rec applies only to the 2-event divergent sets at `v_d`.

The Rec submitter (whoever holds the recovery key) dictates which shape, and (in the branch-tip-extending shape) which branch Rec extends. Both shapes are handled uniformly by `archive_adversary_chain` — the walkback structure determines which events get archived without a separate code path per shape.

Privileged events (`Rot`, `Ror`, `Dec`) can share the divergence-ancestor-extending parent shape (`previous = v_{d-1}.said`) on a linear chain — landing cleanly as a sibling of the chain's existing event at `v_d` would create a divergent set, which the merge layer rejects per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The kind discriminator (archiving `Rec` vs privileged `Rot`/`Ror`/`Dec`) determines whether the parent-shape resolves divergence (archival via `Rec`) or is rejected (privileged kinds, when their landing would create or join a divergent set).

### Builder pre-flight

`KeyEventBuilder::recover()` (also `rotate_recovery()`, `decommission()`) runs one pre-flight check before constructing the dual-signed event:

- **`verify_server_chain_pre_repair`** — calls `client.verify_key_events(prefix, ..., KelVerifier::new(prefix), ...)` and wraps verifier errors as `ChainHasUnverifiedEvents`. Defense-in-depth: a buggy/malicious server otherwise gets taken at its word when the builder extends from its `get_owner_tail`.

This is the only pre-flight failure mode. Pending events do not trigger pre-flight failure — see §Pending events bundling for the separate concern of how unflushed operator work rides along with lifecycle ops.

### Pending events and user display

The library bundles pending into the lifecycle batch by default; the application SHOULD display pending events to the user for inspection before submission.

**Why:** the library cannot algorithmically distinguish "stale draft to discard" from "valuable signed work to keep" from "work made suspect by an incident." Human inspection is the only way to decide. The user-facing call (bundle vs. discard vs. selectively-discard) is application-level.

### Conditional Rot follow-up

**Rule.** `needs_extra_rot = archived_branch_rotated && !extending_branch_rotated`.

The `Rec` reveals the rotation key that may be known to a second party (preimage of prior `rotationHash`). If the archived branch has already used it but the extending branch hasn't, an extra `Rot` after `Rec` is needed to escape to a key only the Rec submitter (whoever holds the recovery key) knows. The "extending branch" is the branch `Rec.previous` walks back from; the "archived branch" is what the discriminator removes.

Truth table:

| Extending branch rotated since divergence? | Archived branch rotated? | Extra `Rot` after `Rec`? |
|---|---|---|
| No | No | No |
| No | Yes | **Yes** |
| Yes | Yes | No |
| Yes | No | No |

### Pending events bundling

Two distinct sets of operator-staged events may need to ride along with a lifecycle op:

- **Missing events** — events that the operator's local store has and has previously flushed to the server, but which the server's chain no longer contains (typically because an earlier `Rec` archived them server-side via the discriminator). The builder's `find_missing_owner_events` walks the local tail backward, calling `event_exists` on the server until it finds the boundary, and bundles the missing events into the lifecycle batch.
- **Pending events** — events the builder staged and signed (via `update`, `interact`, etc.) but never successfully flushed. These are application-level in-progress work; the user has explicitly chosen to bundle them by leaving them in pending when they invoke the lifecycle op (the application should display pending and offer discard before submission — see §Builder pre-flight).

`recover()` ships `[missing..., pending..., Rec, ?Rot]`. The server processes the batch atomically: missing events land first (re-establishing the operator's chain on the server), then any pending work, then `Rec` (and optional `Rot`) chains from the new tip. Both sets are verified server-side on submit — bundling poses no additional risk vs. flushing them in separate batches.

The cost of discarding pending may be substantial: a flush that involved collecting `ixn` anchors from many KELs (for SEL chains) or coordinating multi-party signatures may have taken meaningful operator effort. Bundling preserves that effort across lifecycle transitions. Mirrors SEL's repair flow (see [../sel/event-log.md](../sel/event-log.md#pending-events-bundling)).

### Server-side discriminator

`MergeTransaction::archive_adversary_chain` (`lib/kels/src/merge.rs`) discriminates the surviving branch (the one the Rec extends) from the archived branch using a `Rec.previous` walkback. Two strategies based on chain shape at the divergence serial:

- **`collect_all_adversary_saids`** — the surviving branch has no events at serial `d`. All events at `serial >= d` not on the surviving-branch walkback are archived.
- **`collect_adversary_chain_saids`** — the surviving branch has events at serial `d`. Walk backward from the non-surviving branch's event at `d`, then forward-trace any extensions; archive those.

Both follow the same algorithmic shape as SEL's `truncate_and_replace`:

1. Detect recovery: any event in the batch has `kind = Rec`.
2. Compute archive lower bound `L = serial of (divergenceAncestor) + 1` (i.e., the divergence serial `v_d`).
3. **Single page fetch**: events at `serial >= L` for the prefix, ordered `(serial ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`KelVerifier::resume(&prefix, &kel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and verifies each event's signatures against the establishment-declared keys. Verification failure aborts archival — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — bundled missing events may be referenced by `Rec.previous`).
6. **Walkback**: starting at `Rec.previous`, follow `event.previous` links through the map, accumulating the surviving-branch SAIDs for every event with `serial >= L`. Stop when serial drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (the seal-advance cap caps the walk well below this).
7. **Archive**: page events at `serial >= L` whose SAID is NOT on the surviving-branch walkback. Insert into `kels_archived_events` and create `RecoveryRecord` + `kels_recovery_events` link rows.
8. **Delete** archived events from `kels_key_events` by SAID (NOT by serial range — surviving-branch events at the same serials must remain).
9. Insert the batch's new events: pending first, then `Rec` (+ optional `Rot`).

The page+resume-verify pattern is the SEL backport: prior to it, the discriminator issued one DB query per walk hop. The new shape is one DB round-trip plus in-memory traversal, identical in structure to SEL's `truncate_and_replace` discriminator. The cryptographic gate is signature verification on both sides — KEL verifies signatures directly attached to the events; SEL verifies signatures on the anchoring `ixn` events that policy resolution requires. Trust posture is the same.

### Bounds

The seal-advance cap (`MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events) caps the chain since the last `Rec`/`Ror`/`Rot`. Recovery cannot truncate at or before the chain's seal, so the divergence ancestor is strictly after `lastSealAdvancingEvent` and the post-`d` window is at most 62 events combined. One page (limit 64) covers both branches and the bundled `[Rec, Rot]`; one DB round-trip; no per-hop queries.

Recovery-preimage rotation cadence (how often `Ror` should land between recovery-revealing events) is operator guidance, not a protocol-enforced cap — see [events.md §Seal-advance cap](events.md#seal-advance-cap).

## Privileged-event merge-layer rejection

A KEL rejects a privileged event (`Rot`, `Ror`, or `Dec`) at the merge layer when the event's landing would create or join a divergent set per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Two shapes reach this rejection:

- **On a linear chain** with an existing event at `v_d`, a privileged event with `previous = v_{d-1}.said` would land as a sibling and create a 2-event divergent set containing a privileged event. Rejected at merge.
- **On an already-divergent chain**, a privileged event with `previous = v_{d-1}.said` would join the existing divergent set. Rejected at merge.

In both cases the merge layer returns a `ParentLocked` rejection; the chain's prior state stands. Cross-node priv-vs-priv races (each event landing cleanly on its submitting node, gossip-arriving competing event rejected by the seal-cap) surface at the federation layer via the irreconcilable-prefix table (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races)).

**Distinction from Rec.** The divergence-ancestor-extending shape of `Rec` (`previous = v_{d-1}.said`) routes through the discriminator before any divergent-set check fires. `Rec` archives the other events at `v_d` and resolves the divergence; it never produces a divergent set containing a privileged event. The kind discriminator (archiving `Rec` vs privileged `Rot`/`Ror`/`Dec`) determines whether the parent-shape resolves divergence (archival via `Rec`) or is rejected (privileged kinds, when their landing would create or join a divergent set).

### Recourse against Tier-2 Rot takeover

If an adversary holding the rotation-key preimage submits a `Rot` at `v_N` to take over (Tier-2 compromise), the original holder's response is `Rec` with `previous = v_{N-1}.said` (divergence-ancestor-extending shape), dual-signed against `v_{N-1}`'s commitments. The keys committed by `v_{N-1}` are: signing key revealed by the `Rot` at `v_N` (both parties have it) + recovery key NOT revealed by `Rot` (only the original holder, who prepared it, has it; recovery is revealed only by `Rec`/`Ror`/`Dec`). The original holder's dual-sig succeeds; the adversary's does not. `Rec` lands at `v_N`; the discriminator archives the adversary's branch; the chain recovers, linear, tip = `Rec` at `v_N`.

The original holder does NOT respond by submitting a competing `Rot` extending `v_{N-1}`. Such a `Rot_op` would land as a sibling of `Rot_adv` (both privileged) and the merge layer would reject it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The `Rec` response routes through the archiving path and preserves operator recovery. See [../../../../protocol-doctrine.md §Limit of the Doctrine](../../../../protocol-doctrine.md#limit-of-the-doctrine) for the broader threat model where a federation-level priv-vs-priv race against an adversary `Rot_adv` surfaces as non-convergence at the infrastructure layer.

### Algorithmic merge-engine triggers

On a divergent KEL, the merge engine routes submissions per the divergent-set state:

| Divergent set state | Recovery path | Privileged submission | Other kinds |
|---|---|---|---|
| Non-privileged divergent (`Ixn`-`Ixn` at `v_d`); seal not yet advanced | `Rec` (archives losing branch) | Rejected (`ParentLocked`) per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) | `RecoverRequired` for any non-`Rec` submission |
| Sealed-divergent (seal-advancing event landed in one branch) | — (no normal archival path; competing `Rec` against `v_{d-1}` rejected by the locked-portion bound) | Rejected (`ParentLocked` — seal already advanced past `v_{d-1}`) | `ParentLocked` for any non-priv submission |

`ParentLocked` rejections mirror SEL's `ParentLocked` shape: someone has advanced the seal (via `Rec`/`Ror`/`Rot` on KEL; `Sea`/`Rpr` on SEL), and safe normal-flow continuation is no longer possible.

## Decommission (Dec)

Decommission is the clean terminal state — `Dec` lands on a linear chain and ends it.

### Trigger

Owner-initiated. No algorithmic merge-engine trigger — the owner runs `KeyEventBuilder::decommission()` and submits `Dec`. The merge engine has no mechanism to require a `Dec`; it only enforces that one terminates the chain.

### Dec event

`KeyEventKind::Dec`:
- `reveals_recovery_key() = true` (terminal authority assertion).
- Dec extends the current tip: `previous = tip.said`, `serial = tip.serial + 1`.
- Dual-signed (signing + recovery). No future-key commitments.

### Server semantics

- Verify `Dec`'s structure, dual signatures.
- Insert `Dec`. No archival.
- `Dec` event in a linear chain → `is_decommissioned = true`. Subsequent submissions rejected with `KelDecommissioned`. (`Dec` whose landing would create or join a divergent set is rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) — see §Privileged-event merge-layer rejection.)
- Effective SAID for a decommissioned KEL: the `Dec` event's own SAID.

### Builder

`KeyEventBuilder::decommission()`:
- Same pre-flight as `recover()`.
- Bundles missing AND pending events.
- Builds `Dec` extending the last bundled event (or owner tip if no bundling); submits `[missing..., pending..., Dec]`.

## Merge-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source-→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append at tip+1 | non-terminal events | Append. `Accepted`, `divergedAt: None`. |
| Linear, overlap at earlier serial (`Ixn`-`Ixn`) | non-seal-advancing events | Insert forking event; chain transitions to Divergent. `Diverged`, `divergedAt: Some(d)`. |
| Linear (active) | batch ending in `Rot`, `Ror`, or `Dec` (`previous = v_{d-1}.said`, would land as sibling of existing event at `v_d`) | Rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). `ParentLocked`. |
| Linear (active), normal-append privileged | batch ending in `Rot`, `Ror`, or `Dec` extending the current tip cleanly | Append. Seal advances on `Rot`/`Ror`; `Dec` marks decommissioned. `Accepted`. |
| Post-divergence-resolution linear (chain was Divergent; an extension advanced the seal on the surviving branch) | non-priv events or competing `Rec` extending `v_{d-1}` | `ParentLocked` (seal advanced; locked-portion bound rejects competing `Rec`). |
| Linear, overlap | batch ending in `Rec` | Discriminator-driven recovery. Branch-tip-extending Rec: `Rec.previous` is a branch tip at `v_d`, Rec extends it at `v_{d+1}`, the other branch archived. Divergence-ancestor-extending Rec: `Rec.previous = v_{d-1}.said`, Rec lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). `Recovered`. |
| Divergent, seal not yet advanced | non-`Rec`, non-(Rot/Ror/Dec) events | `RecoverRequired`. |
| Divergent, seal not yet advanced | batch ending in `Rec` | Discriminator-driven recovery. `Recovered`. |
| Divergent | batch ending in `Rot`, `Ror`, or `Dec` (`previous = v_{d-1}.said`, would join divergent set) | Rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). `ParentLocked`. |
| Divergent, seal advanced in branch extension | competing `Rec` extending `v_{d-1}.said` | `ParentLocked` (locked-portion bound rejects the competing `Rec`). |
| Linear, no conflict | batch ending in `Dec` | Insert `Dec`, mark decommissioned. `Accepted`. |
| Decommissioned | any submission | Rejected with `KelDecommissioned` (the seal-cap rejects any submission whose parent sits at-or-before `v_{d-1}`; concurrent priv-event federation races resolve at the infrastructure layer per [#205](https://github.com/jasoncolburne/kels/issues/205)). |

## Implementation Map

**Code:**
- `lib/kels/src/types/kel/event.rs` — `KeyEventKind` enum (`Icp`/`Dip`/`Rot`/`Ixn`/`Rec`/`Ror`/`Dec`); `validate_structure` enforces per-kind field rules (see [events.md](events.md)).
- `lib/kels/src/types/kel/verification.rs` — `KelVerifier` and `KelVerification`; surfaces `divergenceAncestor`, `is_decommissioned`, `lastSealAdvancingEvent`, `lastRecoveryRevealingEvent`. Enforces the seal-advance cap (62 non-seal-advancing events between `Rec`/`Ror`/`Rot`); recovery-preimage rotation cadence is operator guidance (no protocol-enforced cap on `Rec`/`Ror`/`Dec` frequency).
- `lib/kels/src/builder.rs` — `KeyEventBuilder::recover()`, `rotate_recovery()`, `decommission()`. Each runs `verify_server_chain_pre_repair` pre-flight, then bundles missing owner events (from `find_missing_owner_events`) AND any pending events into the batch ahead of the dual-signed lifecycle event, and submits atomically.
- `lib/kels/src/merge.rs` — `MergeTransaction::merge_events` (single entry point); `archive_adversary_chain` with `collect_all_adversary_saids` / `collect_adversary_chain_saids` strategies. Archival uses a single page fetch + resume-mode verifier trust gate + in-memory walkback (mirroring SEL's `truncate_and_replace` discriminator).
- Server submit handler (`services/kels/src/handlers.rs`) — calls `save_with_merge` which acquires advisory lock, constructs `MergeTransaction`, invokes `merge_events`. All routing is internal to the merge engine.

**Tests:**
- `archive_adversary_chain_aborts_on_tampered_page` — page-tamper test; the resume-verifier rejects the page (signature mismatch) and aborts the archival.
- `recover_bundles_pending_events_into_batch`, `rotate_recovery_bundles_pending_into_batch`, `decommission_bundles_pending_into_batch` — pin pending-bundling on each lifecycle op.

## References

- [events.md](events.md) — Per-kind reference: event kinds, field rules, typical chain shapes.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix. Exhaustive enumeration of state × submission × gossip combinations proving the design terminates correctly and converges across nodes.
- [merge.md](merge.md) — KEL merge engine; full routing taxonomy and `MergeTransaction` API.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator algorithm and pending-bundling shape are mirrored on both sides.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference.
- [recovery-workflow.md](recovery-workflow.md) — Operator-facing recovery workflow (federation context).
- [../../../../features/policy.md](../../../../features/policy.md) — `Delegate(delegator)` resolution for `Dip` events (single-arg open form per `events.md`).
