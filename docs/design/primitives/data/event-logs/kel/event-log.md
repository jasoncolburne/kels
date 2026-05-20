# Key Event Log (KEL) — Lifecycle, Recovery, Decommission

> Source-of-truth design doc for the KEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (merge engine routing), and [verification.md](verification.md) (KelVerifier algorithm).

The Key Event Log (KEL) is a per-prefix chain of `SignedKeyEvent` records describing the controller's evolving signing and recovery key state. Authority over the KEL is asserted by direct signature: every event carries one or more signatures verified against keys committed by prior establishment events.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, latest tip extends cleanly. | Yes — `Ixn`, `Rot`, `Ror`, `Rec`, `Dec` (per signature requirements). |
| **Divergent (non-privileged)** | Two events at serial `d`, both non-privileged (`Ixn`-`Ixn`). Recoverable via `Rec`. | `Rec` (archives one branch; chain resumes); a privileged event (`Rot`/`Ror`/`Dec`) with `previous = v_{d-1}.said` joining the set at `v_d` via the upgrade rule → Contested. Bundled pending permitted. See [§Recovery (Rec)](#recovery-rec). |
| **Contested** | Chain terminated — divergent set contains a privileged event (`Rot`, `Ror`, or `Dec`). | None. All submissions rejected with `ContestedKel`. |
| **Decommissioned** | Chain terminated cleanly via `Dec` — exactly one `Dec`, ending a clean linear chain. | None. Fully terminal: all submissions rejected with `KelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `KelVerification` token surfaces:
- `divergenceAncestor: Option<Digest256>` — SAID of `v_{d-1}` (the unique parent of all events at `v_d`) on a divergent chain, or `None` if linear.
- `is_contested: bool` — `true` iff divergent AND the divergent set contains a privileged event (`Rot`, `Ror`, or `Dec`).
- `is_decommissioned: bool` — `Dec` event in a linear chain (Dec landing in a divergent set produces contested, not decommissioned).
- `lastSealAdvancingEvent: Option<Digest256>` — SAID of the most recent `Rec`/`Ror`/`Rot` that landed cleanly on the linear chain. **A privileged event creating or joining a divergent set does NOT advance the seal** — the protocol cannot identify a canonical submitter, so the seal stays at the prior linear-portion advance. The chain's seal-cap watermark (see §Seal and Key Immunity).
- `lastRecoveryRevealingEvent: Option<Digest256>` — SAID of the most recent `Rec`/`Ror`/`Dec`. Tracks recovery-key revelation for the spent-key / immunity rule; orthogonal to the seal (`Rot` advances the seal without revealing the recovery key; `Dec` reveals the recovery key without advancing the seal). Recovery-preimage rotation cadence is operator guidance, not protocol-enforced — see [events.md §Cap doctrine](events.md#cap-doctrine).

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

KEL tracks two related-but-distinct concepts. The membership sets diverge: seal-advance includes `Rot` (single-signed; no recovery-key revelation), while recovery-revealing includes `Dec` (terminal; doesn't advance the seal). The orthogonality lets the protocol bound chain-state changes (via the seal-advance cap) while leaving recovery-preimage rotation cadence to operator guidance — recovery keys are typically hardware-held and preimage-identified rather than usage-degraded, so a protocol-forced cadence would impose access on cold-stored / separated-custody recovery keys on a fixed schedule. See [events.md §Cap doctrine](events.md#cap-doctrine).

| Concept | Advances on | Used for |
|---|---|---|
| `lastSealAdvancingEvent` | `Rec`/`Ror`/`Rot` | Seal-cap rule: `event_serial >= seal_serial`; recovery cannot truncate at-or-before the seal. Bounds the chain-state advance cap (`MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events). See [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded). |
| `lastRecoveryRevealingEvent` | `Rec`/`Ror`/`Dec` | Spent-key rule. Once any recovery-revealing event lands, the recovery key is publicly known; subsequent attempts to recover using the spent key fail. Recovery-preimage rotation cadence (how often `Ror` should land to refresh the commitment) is operator guidance — see [events.md §Cap doctrine](events.md#cap-doctrine) — not a protocol-enforced cap. |

`Dec` is terminal — it enforces the seal but does not advance it.

**Once a recovery-revealing event lands, the dual-signature it proves is final.** Subsequent compromise or revocation of the keys it revealed does NOT retroactively unsatisfy the past authorization — the chain's history at that serial is locked. Without this, history could be invalidated retroactively by anyone who later comes to control the revealed key material, making terminal states (recovered, contested, decommissioned) unstable. The trade-off is that a key controller who later turns adversarial cannot undo their past contributions; only the going-forward spent-key effect applies.

`lastSealAdvancingEvent` plays the same structural role across all three primitives — see [../iel/event-log.md §Evaluation Seal and Policy Immunity](../iel/event-log.md#evaluation-seal-and-policy-immunity) for the IEL-side discussion. A privileged-non-terminal primitive defines a forward-only watermark per chain; prior advancements are immutable.

The seal-cap rule is unconditional on KEL: a new event's parent must sit at-or-after `seal_serial`. Any submission whose parent is in the locked portion (`parent_serial < seal_serial`) is rejected. See [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded).

## Divergence and Termination

Divergence is detected when two events share the same `previous` SAID. The chain transitions per the privileged-divergence rule:
- If the divergent set contains an archiving event (`Rec`) — the discriminator runs first; one branch is archived; chain stays linear post-discriminator. (Archiving-precedence routes around the divergent-set check.)
- Otherwise, if the divergent set contains a privileged event (`Rot`, `Ror`, or `Dec`) — directly to **Contested** (terminal).
- If the divergent set is non-privileged (only `Ixn` events) — to **Divergent (non-privileged)**, recoverable via `Rec`.

s0 divergence is rejected outright — inception is fully deterministic; two distinct s0 events for the same prefix indicate protocol-level corruption, not authority conflict.

**Race-vs-takeover framing.** Divergence on a KEL — two events at the same serial — can arise from a federation race (two parties holding the current signing key submitting concurrently — rare, since signing keys are typically single-party) or a takeover (a second signing-key holder, whose access was acquired via compromise, forking against the original holder). The chain shape records the divergence in the data; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; the trust model degrades uniformly.

The divergence invariant — combined with the seal-advance cap (`MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events) — guarantees:
- **Non-privileged divergent set** at serial `d` (event kinds limited to `Ixn`): max 2 events. Recoverable via `Rec`.
- **Privileged divergent set** at serial `d` (exactly one event is a privileged kind — `Rot`, `Ror`, or `Dec`; universal locking blocks a second priv from joining via the seal-cap): max 3 events (2 non-privileged `Ixn`s that arrived first + 1 priv that landed via the upgrade rule and triggered the contested transition; OR 2 events exactly one of which is a privileged kind from the start, the other non-privileged). Contested-terminal.
- At most 62 events total on a non-privileged divergent set's branches beyond `d` (the seal-advance cap bounds non-seal-advancing forks; a holder lacking rotation or recovery preimage cannot submit a seal-advancing event to extend further).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

### Worked examples: upgrade-rule cross-node convergence

Two concrete scenarios showing the upgrade rule's role in cross-node consistency under attack. The upgrade event can be any privileged kind — `Rot`, `Ror`, or `Dec`. Both examples below show three concurrent submissions landing at different nodes, each with `previous = v_{d-1}.said` (whether this is a federation race or a takeover scenario is not chain-distinguishable). All three submitters have their local tip at `v_{d-1}` and submit events whose parent is `tip.said = v_{d-1}.said`; each event lands at `v_d`.

#### Variant A: ixn-ixn-ror

```
Pre-state on all three nodes (linear chain, tip at v_{d-1}):

    ... → v_{d-2} → v_{d-1}
                       ↑
                      tip

Each submitter constructs with previous = tip.said = v_{d-1}.said:

  ixn_a.previous = v_{d-1}.said,  serial = d   → ixn_a lands at v_d
  ixn_b.previous = v_{d-1}.said,  serial = d   → ixn_b lands at v_d
  ror_c.previous = v_{d-1}.said,  serial = d   → ror_c lands at v_d
```

`Ror` is privileged (and recovery-revealing) — its parent rule is the same as `Ixn`/`Rot`/`Dec`: `previous = tip.said`. When the submitter's tip is at `v_{d-1}`, `Ror.previous = v_{d-1}.said` directly; `Ror` lands at `v_d` and can join a divergent set there via the upgrade rule. (`Rec` would NOT fit this slot — `Rec` is the archiving kind on KEL, routed through the discriminator's archival path, which removes the divergent set before any divergent-set check fires.)

#### Variant B: ixn-ixn-rot

```
Pre-state on all three nodes (linear chain, tip at v_{d-1}):

    ... → v_{d-2} → v_{d-1}
                       ↑
                      tip

Each submitter constructs with previous = tip.said = v_{d-1}.said:

  ixn_a.previous = v_{d-1}.said,  serial = d   → ixn_a lands at v_d
  ixn_b.previous = v_{d-1}.said,  serial = d   → ixn_b lands at v_d
  rot_c.previous = v_{d-1}.said,  serial = d   → rot_c lands at v_d
```

`Rot` is privileged (single-signed; rotates the signing key against the prior establishment's `rotationHash`). Its parent rule is the same as `Ixn`/`Ror`/`Dec`. When the submitter's tip is at `v_{d-1}`, `Rot.previous = v_{d-1}.said` directly; `Rot` lands at `v_d` and joins a divergent set there via the upgrade rule. Rot single-sig vs Ror dual-sig is the per-event authorization shape — orthogonal to the privileged-class membership the upgrade rule checks.

#### Outcome (both variants)

Gossip propagates. Each node eventually receives the events that landed at others. Per-node outcome depends on order of arrival; the trajectory in each case is:

- If two non-privileged events (`ixn_a`, `ixn_b`) arrive first, the node enters non-privileged-divergent state; the later-arriving privileged event (`ror_c` in variant A or `rot_c` in variant B) promotes the chain to contested via the upgrade rule (3 events at `v_d`).
- If the privileged event arrives among the first two, the divergent set is privileged at first observation and the chain transitions to contested immediately; the gate closes before the third concurrent submission can join (2 events at `v_d`).

Using variant A for the table:

| Node | First two events | Final state |
|---|---|---|
| A | `ixn_b`, then `ror_c` | 3 events at `v_d` (contested via upgrade rule) |
| B | `ixn_a`, then `ror_c` | 3 events at `v_d` (contested via upgrade rule) |
| C | `ixn_a`, then `ror_c` (before `ixn_b`) | 2 events at `v_d` (contested at first observation; subsequent `ixn_b` rejected) |

```
Final state on Node A and B (3-way divergent at v_d, contested):
    ... → v_{d-1} ─┬─ ixn_a @ v_d
                   ├─ ixn_b @ v_d
                   └─ ror_c @ v_d

Final state on Node C (2-way mixed at v_d, contested when ror_c joined):
    ... → v_{d-1} ─┬─ ixn_a @ v_d
                   └─ ror_c @ v_d
```

Variant B has the same structural outcome with `rot_c` in place of `ror_c`.

All nodes have effective SAID `hash_effective_said("contested:{prefix}")` despite differing chain contents at `v_d`. Cross-node SAID convergence holds without forensic-record convergence — anti-entropy sees matching SAIDs and does not re-queue. This is the property [../../../../protocol-doctrine.md §Federation Convergence](../../../../protocol-doctrine.md#federation-convergence) asserts: semantic state agrees across nodes via deterministic effective-SAID even when chain contents diverge forensically. The upgrade rule's structural role is keeping nodes A and B from being stuck in non-privileged-divergent (recoverable) state when other nodes have already observed a contested-triggering privileged event. The same pattern applies on SEL with `Upd-Upd-Sea` — see [../sel/verification.md §Upgrade rule](../sel/verification.md#upgrade-rule).

## Recovery (Rec)

Recovery resolves a non-privileged-divergent chain by archiving all events at `serial >= divergedAt` not on `Rec.previous`'s walkback, then appending the `Rec` (and optionally a follow-up `Rot`). `Rec.previous` takes one of two shapes:

1. **Branch-tip-extending shape — `Rec.previous` is a branch tip at `v_d`.** Rec extends that branch at `v_{d+1}`. The discriminator's walkback from `Rec.previous` reaches the surviving-branch tip at `v_d`; events on the other branch are archived. Use case: the submitter chooses one of the two branches at `v_d` as the surviving branch; Rec extends it.

   ```
   Pre-state (non-priv divergent at v_d):
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
   Pre-state (non-priv divergent at v_d):
       ... → v_{d-1} ─┬─ branch-1 tip @ v_d
                      └─ branch-2 tip @ v_d

   Rec construction: rec.previous = v_{d-1}.said
                     rec.serial   = d

   Post-state (linear, recovered, Rec is the only event at v_d):
       ... → v_{d-1} → rec @ v_d
                     ↑
                     both prior branches archived
   ```

   The divergence-ancestor-extending shape's "both branches" archival is exhaustive by construction: a 3-event divergent set at `v_d` would imply a privileged event has already joined via the upgrade rule, transitioning the chain to contested-terminal — Rec is rejected by the contested-state gate. Rec applies only to non-privileged 2-event divergent sets at `v_d`; the upgrade rule's privileged-event-joins-divergent-set path is mutually exclusive with the discriminator's archival path.

The Rec submitter (whoever holds the recovery key) dictates which shape, and (in the branch-tip-extending shape) which branch Rec extends. Both shapes are handled uniformly by `archive_adversary_chain` — the walkback structure determines which events get archived without a separate code path per shape.

Privileged events (`Rot`, `Ror`, `Dec`) can share the divergence-ancestor-extending parent shape (`previous = v_{d-1}.said`, lands at `v_d`) but have a different effect: they join the existing divergent set as a 3rd event at `v_d` WITHOUT archival, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. The kind discriminator (archiving `Rec` vs privileged `Rot`/`Ror`/`Dec`) determines whether the chain recovers (archival) or terminates (no archival).

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

Recovery-preimage rotation cadence (how often `Ror` should land between recovery-revealing events) is operator guidance, not a protocol-enforced cap — see [events.md §Cap doctrine](events.md#cap-doctrine).

## Contested-state transitions

A KEL transitions to contested when a privileged event (`Rot`, `Ror`, or `Dec`) lands in a divergent set, firing privileged-divergence-is-terminal. The structural construction is the same as repair-event placement: the contesting event extends `v_{d-1}` (the divergence ancestor, shared cross-node by chain validity) with `previous = v_{d-1}.said` and `serial = d`, landing at `v_d`. The locked-portion bound (`previous.serial ≥ seal_serial − 1`) is enforced by the seal-cap.

- **On a linear chain**, a privileged event extending `v_{d-1}` lands at `v_d` as sibling of the existing event; the 2-event divergent set is contested by construction.
- **On an already-divergent (non-privileged) chain**, the privileged event joins the existing divergent set as a third event at `v_d` via the upgrade rule. The pre-existing branch may have extended past `v_d` before divergence was detected — up to ~62 events per the seal-advance cap.

**Distinction from Rec.** The divergence-ancestor-extending shapes of `Rec` and the contested-creating privileged events share parent (`previous = v_{d-1}.said`, lands at `v_d`) but differ in effect. `Rec` archives the other events at `v_d` via the discriminator (chain recovers, continues with `Rec` as the new `v_d`). Privileged events join the divergent set without archival (privileged-divergence-is-terminal fires; chain ends).

### Recourse against signing-key-only Rot takeover

If a second signing-key holder (whose access was acquired via signing-key-only compromise) submits a `Rot` at `v_N` to take over, the original holder's response is `Rec` with `previous = v_{N-1}.said` (divergence-ancestor-extending shape), dual-signed against `v_{N-1}`'s commitments. The keys committed by `v_{N-1}` are: signing key revealed by the `Rot` at `v_N` (both parties have it) + recovery key NOT revealed by `Rot` (only the original holder, who prepared it, has it; recovery is revealed only by `Rec`/`Ror`/`Dec`). The original holder's dual-sig succeeds; the second signing-key holder's does not. `Rec` lands at `v_N`; the discriminator archives the adversary's branch; the chain recovers, linear, tip = `Rec` at `v_N`.

The original holder does NOT respond by submitting a competing `Rot` extending `v_{N-1}`. Such a `Rot_op` lands at `v_N` as sibling of `Rot_adv` — both privileged — and the 2-event privileged divergent set fires privileged-divergence-is-terminal; the chain becomes contested-terminal and the original holder has lost recourse in-protocol. The `Rec` response routes through the archiving path before any divergent-set check fires, preserving operator recovery. See [../../../../protocol-doctrine.md §Limit of the Doctrine](../../../../protocol-doctrine.md#limit-of-the-doctrine) for the broader threat model where racing a `Rot_op` against an adversary `Rot_adv` is the contested-terminal path.

### Algorithmic merge-engine triggers

On a divergent KEL, the merge engine routes submissions per the divergent-set state:

| Divergent set state | Recovery path | Termination path | Merge engine returns for non-matching kinds |
|---|---|---|---|
| No seal-advancing event in the divergent set | `Rec` (archives surviving branch) | privileged event (`Rot`/`Ror`/`Dec`) extending `v_{d-1}` joins via upgrade rule | `RecoverRequired` for any non-`Rec`, non-(Rot/Ror/Dec) submission |
| At least one seal-advancing event in the divergent set (`Rec`/`Ror`/`Rot`/`Dec`) | — (seal already advanced; no normal archival path; competing `Rec` against `v_{d-1}` rejected by the locked-portion bound) | privileged event (`Rot`/`Ror`/`Dec`) extending `v_{d-1}` joins as the contested-creating event | `ParentLocked` for any non-priv submission |

`ParentLocked` mirrors SEL's `ParentLocked` shape: someone has advanced the seal (via `Rec`/`Ror`/`Rot` on KEL; `Sea`/`Rpr` on SEL), and safe normal-flow continuation is no longer possible. The trigger is structurally the same across primitives. A privileged submission (`Rot`, `Ror`, or `Dec`) extending `v_{d-1}` joins the divergent set via the upgrade rule → Contested via privileged-divergence-is-terminal.

### Effective SAID for contested

`hash_effective_said("contested:{prefix}")` — deterministic, cross-node consistent. All nodes converge on the same value regardless of which divergent events each node holds.

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
- `Dec` event in a linear chain → `is_decommissioned = true`. Subsequent submissions rejected with `KelDecommissioned`. (`Dec` landing in a divergent set produces contested, not decommissioned — see §Contested-state transitions.)
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
| Linear, overlap at earlier serial (non-privileged events only — `Ixn`-`Ixn`) | non-seal-advancing events | Insert forking event; chain transitions to Divergent (non-privileged). `Diverged (non-privileged)`, `divergedAt: Some(d)`. |
| Linear (active) | batch ending in `Rot`, `Ror`, or `Dec` (`previous = v_{d-1}.said`) | Insert; creates divergence at `v_d` (existing tip + new event); privileged-divergence rule fires; chain becomes contested-terminal. `Contested`. |
| Post-divergence-resolution linear (chain was Divergent; an extension advanced the seal on the surviving branch) | non-priv events or competing `Rec` extending `v_{d-1}` | `ParentLocked` (seal advanced; locked-portion bound rejects competing `Rec`). |
| Linear, overlap | batch ending in `Rec` | Discriminator-driven recovery. Branch-tip-extending Rec: `Rec.previous` is a branch tip at `v_d`, Rec extends it at `v_{d+1}`, the other branch archived. Divergence-ancestor-extending Rec: `Rec.previous = v_{d-1}.said`, Rec lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). `Recovered`. |
| Divergent (non-privileged), seal not yet advanced | non-`Rec`, non-(Rot/Ror/Dec) events | `RecoverRequired`. |
| Divergent (non-privileged), seal not yet advanced | batch ending in `Rec` | Discriminator-driven recovery. `Recovered`. |
| Divergent (non-privileged) | batch ending in `Rot`, `Ror`, or `Dec` (`previous = v_{d-1}.said`, joins divergent set via upgrade rule) | Insert as 3rd event at `v_d`; chain becomes contested-terminal. `Contested`. |
| Divergent, seal advanced in branch extension | competing `Rec` extending `v_{d-1}.said` | `ParentLocked` (locked-portion bound rejects the competing `Rec`). |
| Linear, no conflict | batch ending in `Dec` | Insert `Dec`, mark decommissioned. `Accepted`. |
| Contested | any submission | Rejected with `ContestedKel`. |
| Decommissioned | any submission | Rejected with `KelDecommissioned` (the seal-cap rejects any submission whose parent sits at-or-before `v_{d-1}`; concurrent priv-event federation races resolve at the infrastructure layer per [#205](https://github.com/jasoncolburne/kels/issues/205)). |

## Implementation Map

**Code:**
- `lib/kels/src/types/kel/event.rs` — `KeyEventKind` enum (`Icp`/`Dip`/`Rot`/`Ixn`/`Rec`/`Ror`/`Dec`); `validate_structure` enforces per-kind field rules (see [events.md](events.md)).
- `lib/kels/src/types/kel/verification.rs` — `KelVerifier` and `KelVerification`; surfaces `divergenceAncestor`, `is_contested`, `is_decommissioned`, `lastSealAdvancingEvent`, `lastRecoveryRevealingEvent`. `is_contested = true` iff divergent AND the divergent set contains a privileged event (`Rot`, `Ror`, or `Dec`). Enforces the seal-advance cap (62 non-seal-advancing events between `Rec`/`Ror`/`Rot`); recovery-preimage rotation cadence is operator guidance (no protocol-enforced cap on `Rec`/`Ror`/`Dec` frequency).
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
