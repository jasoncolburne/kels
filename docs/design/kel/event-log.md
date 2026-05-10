# Key Event Log (KEL) — Lifecycle, Recovery, Contest, Decommission

> Source-of-truth design doc for the KEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (merge engine routing), and [verification.md](verification.md) (KelVerifier algorithm).

The Key Event Log (KEL) is a per-prefix chain of `SignedKeyEvent` records describing the controller's evolving signing and recovery key state. Authority over the KEL is asserted by direct signature: every event carries one or more signatures verified against keys committed by prior establishment events.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain of events, latest tip extends cleanly. | Yes — `Ixn`, `Rot`, `Ror`, `Rec`, `Dec`, `Cnt` (per signature requirements). |
| **Divergent (non-privileged)** | Two events at some serial `d`, both non-privileged (e.g., `Rot`-`Rot`, `Rot`-`Ixn`, `Ixn`-`Ixn`). Chain is recoverable via `Rec` (extends one branch tip and archives the other branch). | `Rec` (resolves divergence by extending a tip at `v_{d+1}` and archiving the other branch); `Cnt` (joins divergent set at `v_d` via the upgrade rule, transitioning to Contested). Bundled pending events permitted in the same batch. |
| **Contested** | Chain has terminated due to a privileged event in a divergent set (privileged-divergence-is-terminal rule), or via an explicit `Cnt` extending `v_{tip-1}` on a linear chain (which creates fresh divergence at the tip's serial, immediately privileged-divergent → contested). KEL privileged events: `Rec`, `Ror`, `Cnt`, `Dec` (all recovery-revealing). | None. All submissions rejected with `ContestedKel`. |
| **Decommissioned** | Chain has terminated cleanly by operator action — at least one `Dec` event in the chain, no Cnt or privileged divergence. Decommission is unconditionally terminal. | None. All submissions rejected with `KelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `KelVerification` token surfaces:
- `divergence_ancestor: Option<Digest256>` — SAID of `v_{d-1}` (the unique parent of all events at `v_d`) on a divergent chain, or `None` if linear.
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `last_recovery_revealing_event: Option<Digest256>` — SAID of the most recent `Rec`/`Ror`/`Dec`/`Cnt` (the recovery-key revelation seal).

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` / `Dip` | Inception (s0). | Structural (self-authenticating; `Dip` additionally anchored by delegator). | No |
| `Rot` | Rotation. | Signing key (preimage of prior `rotation_hash`). | No |
| `Ixn` | Interaction (anchor). | Current signing key. | No |
| `Rec` | Recovery — resolves divergence; rotates both keys. | Dual (signing + recovery). | No |
| `Ror` | Recovery rotation — pre-emptively rotates both keys (no divergence required). | Dual. | No |
| `Dec` | Decommission — terminal owner-initiated end. | Dual. | **Yes** |
| `Cnt` | Contest — terminal due to authority conflict. | Dual. | **Yes** |

`Rec`, `Ror`, `Dec`, `Cnt` all return `reveals_recovery_key() = true` — each requires dual signatures and exposes the current recovery key.

For per-kind field rules and typical chain shapes, see [events.md](events.md).

## Recovery-Revelation Seal and Key Non-Poisonability

The `last_recovery_revealing_event` is the SAID of the most recent `Rec`/`Ror`/`Dec`/`Cnt` event. It is the chain's **recovery-revelation seal** — recovery cannot truncate at or before it (handlers reject attempts to displace any prior recovery-revealing event).

**Once a recovery-revealing event lands, the dual-signature it proves is final.** Subsequent compromise or revocation of the keys it revealed does NOT retroactively unsatisfy the past authorization. The seal locks in the key state at that serial.

This is an accepted security boundary. Without it, a chain's history could be invalidated retroactively by anyone who later comes to control the revealed key material — making the chain's terminal states (recovered, contested, decommissioned) unstable. The trade-off is that a key controller who later turns adversarial cannot undo their past contributions; only the going-forward effect (the recovery key is now spent — future divergent events must be resolved by `Cnt`) applies.

KEL's recovery-revelation seal is the structural analog of IEL's and SEL's evaluation seal (see [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability)): in both, a privileged primitive (recovery-key revelation / governance evaluation) defines a forward-only watermark, with prior advancements immutable.

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain transitions per the privileged-divergence rule:
- If the divergent set contains a privileged event (`Rec`/`Ror`/`Cnt`/`Dec`) — directly to **Contested** (terminal).
- If the divergent set is non-privileged (only `Rot`/`Ixn` events) — to **Divergent (non-privileged)**, recoverable via `Rec`.

s0 divergence is rejected outright — inception is fully deterministic; two distinct s0 events for the same prefix indicates protocol-level corruption, not authority conflict.

**Race-vs-takeover framing.** Divergence on a KEL — two events at the same serial — can arise from a federation race (two parties holding the current signing key submitting concurrently — rare, since signing keys are typically single-party) or a takeover (a second signing-key holder, whose access was acquired via compromise, forking against the original holder). The chain shape records the divergence in the data; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; the trust model degrades uniformly.

The divergence invariant — combined with the proactive-ROR rule (`MAX_NON_REVEALING_EVENTS = MINIMUM_PAGE_SIZE - 2 = 62`) — guarantees:
- **Non-privileged divergent set** at serial `d` (events kinds limited to `Rot`/`Ixn`): max 2 events. Recoverable via `Rec`.
- **Privileged divergent set** at serial `d` (at least one event is recovery-revealing): max 3 events (2 non-privileged that arrived first + 1 privileged that landed via the upgrade rule and triggered the contested transition; OR 2 events at least one of which is privileged from the start). Contested-terminal.
- At most 62 events total on a non-privileged divergent set's branches beyond `d` (proactive ROR caps non-revealing forks; a holder without the recovery key cannot submit a recovery-revealing event to extend further).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

### Worked example: ixn-ixn-ror cross-node convergence

A concrete scenario showing the upgrade rule's role in cross-node consistency under attack. Three concurrent submissions land at different nodes, each with `previous = v_{d-1}.said` (whether this is a federation race or a takeover scenario is not chain-distinguishable):

1. `ixn_a` to node A — accepted; node A's chain extends linearly to `v_d = ixn_a`.
2. `ixn_b` to node B — accepted; node B's chain extends linearly to `v_d = ixn_b`.
3. `ror_c` to node C — accepted; node C's chain extends linearly to `v_d = ror_c`.

Gossip propagates. Each node eventually receives the events that landed at others:

- **Node A** receives `ixn_b` first: chain becomes non-privileged-divergent (`ixn_a`-`ixn_b` at `v_d`); recoverable via `Rec`. Then receives `ror_c`: per the upgrade rule, the privileged `ror_c` joins as a third event; chain transitions to contested-terminal (`ror` is privileged → privileged-divergence-is-terminal fires). End: 3 events at `v_d`, contested.
- **Node B** receives `ixn_a` then `ror_c`: same trajectory, ends contested with 3 events.
- **Node C** receives `ixn_a` first: divergent set becomes mixed (`ror_c`-`ixn_a`); `ror_c` is privileged, so privileged-divergence-is-terminal fires immediately; chain contested with 2 events. Subsequent `ixn_b` arriving: rejected by the contested-state gate. End: 2 events at `v_d`, contested.

End state: all nodes have effective SAID `hash_effective_said("contested:{prefix}")`, despite differing chain contents at `v_d` (3 events on A and B; 2 events on C). Cross-node SAID convergence holds without forensic-record convergence — anti-entropy sees matching SAIDs and does not re-queue. The upgrade rule's structural role is keeping nodes A and B from being stuck in non-privileged-divergent (recoverable) state when other nodes have already observed a contested-triggering privileged event. The same pattern applies on SEL with `Upd-Upd-Sea` (or any non-privileged + non-privileged + privileged sequence): see [../sel/verification.md §Upgrade rule](../sel/verification.md#upgrade-rule).

## Recovery (Rec)

Recovery resolves a non-privileged-divergent chain by archiving all events at `serial >= diverged_at` not on `Rec.previous`'s walkback, then appending the `Rec` (and optionally a follow-up `Rot`). `Rec.previous` takes one of two shapes:

1. **`Rec.previous` is a branch tip at `v_d`.** Rec extends that branch at `v_{d+1}`. The discriminator's walkback from `Rec.previous` reaches the surviving-branch tip at `v_d`; events on the other branch are archived. Use case: one of the two branches at `v_d` is the operator's legitimate content; the operator preserves it via Rec.
2. **`Rec.previous` is `v_{d-1}` (the divergence ancestor).** Rec lands at `v_d`. The discriminator's walkback from `Rec.previous` stops immediately (serial drops below `diverged_at`); all events at `serial >= d` (both branches) are archived. Rec is the only event at `v_d` after the discriminator runs. Use case: both branches at `v_d` are adversary-planted (the operator's tip is still at `v_{d-1}`); the operator replaces `v_d` entirely with their own Rec.

Whoever holds the recovery key dictates which mode and (in mode 1) which branch the Rec extends. Both modes are handled uniformly by `archive_adversary_chain` — the walkback structure determines which events get archived without a separate code path per mode.

Cnt shares the Mode-2 parent shape (`previous = v_{d-1}.said`, lands at `v_d`) but has a different effect: Cnt joins the existing divergent set as a 3rd event at `v_d` WITHOUT archival, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. The kind discriminator (Rec vs Cnt) determines whether the chain recovers (archival) or terminates (no archival). See [§Cnt](#cnt).

### Builder pre-flight

`KeyEventBuilder::recover()` (also `contest()`, `rotate_recovery()`, `decommission()`) runs one pre-flight check before constructing the dual-signed event:

- **`verify_server_chain_pre_repair`** — calls `client.verify_key_events(prefix, ..., KelVerifier::new(prefix), ...)` and wraps verifier errors as `ChainHasUnverifiedEvents`. Defense-in-depth: a buggy/malicious server otherwise gets taken at its word when the builder extends from its `get_owner_tail`.

Pending events are NOT a pre-flight failure. They're operator-staged unflushed events — application-level state used to display in-progress work — and ship in the same batch (see §Pending events bundling). The server verifies bundled pending events on submit like any other event; the verifier's signature and chain-linkage checks are the trust gate, not the builder's gate. The lifecycle event chains from the last bundled event (pending tail, missing tail, or `get_owner_tail` if both are empty). The merge engine handles boundary detection server-side via the discriminator.

Whenever pending is non-empty, the application SHOULD display it to the user. Human inspection is the only way to decide what should happen with in-progress work — the library cannot algorithmically distinguish "stale draft to discard" from "valuable signed work to keep" from "work made suspect by an incident." The library bundles pending into the lifecycle batch by default; the user-facing decision (bundle vs. discard vs. selectively-discard) is application-level and requires inspection.

### Conditional rot follow-up

`Rec` only rotates the signing key if it itself is not enough to escape key material that may be known to the other party. Mapping (the "extending branch" is the branch the Rec extends; the "archived branch" is the branch the discriminator removes):

| Extending branch rotated since divergence? | Archived branch rotated? | Extra `Rot` after `Rec`? |
|---|---|---|
| No | No | No |
| No | Yes | **Yes** |
| Yes | Yes | No |
| Yes | No | No |

Logic: `needs_extra_rot = archived_branch_rotated && !extending_branch_rotated`. The `Rec` reveals the rotation key that may be known to a second party (preimage of prior `rotation_hash`); if both branches have already used it, an extra `Rot` after `Rec` is needed to escape to a key only the operator (whoever holds the recovery key dictates this) knows.

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

1. Detect recovery: any event in the batch has `kind = Rec` (or `Cnt` for contest).
2. Compute archive lower bound `L = serial of (divergence_ancestor) + 1` (i.e., the divergence version `v_d`).
3. **Single page fetch**: events at `serial >= L` for the prefix, ordered `(serial ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`KelVerifier::resume(&prefix, &kel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and verifies each event's signatures against the establishment-declared keys. Verification failure aborts archival — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — bundled missing events may be referenced by `Rec.previous`).
6. **Walkback**: starting at `Rec.previous`, follow `event.previous` links through the map, accumulating the surviving-branch SAIDs for every event with `serial >= L`. Stop when serial drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (proactive-ROR seal caps the walk well below this).
7. **Archive**: page events at `serial >= L` whose SAID is NOT on the surviving-branch walkback. Insert into `kels_archived_events` and create `RecoveryRecord` + `kels_recovery_events` link rows.
8. **Delete** archived events from `kels_key_events` by SAID (NOT by serial range — surviving-branch events at the same serials must remain).
9. Insert the batch's new events: pending first, then `Rec` (+ optional `Rot`).

The page+resume-verify pattern is the SEL backport: prior to it, the discriminator issued one DB query per walk hop. The new shape is one DB round-trip plus in-memory traversal, identical in structure to SEL's `truncate_and_replace` discriminator. The cryptographic gate is signature verification on both sides — KEL verifies signatures directly attached to the events; SEL verifies signatures on the anchoring `ixn` events that policy resolution requires. Trust posture is the same.

### Bounds

Proactive-ROR rule caps the chain since the last `Rec`/`Ror`/`Dec`/`Cnt` to `MAX_NON_REVEALING_EVENTS = 62`. Recovery cannot truncate at or before any prior recovery-revealing event, so the divergence ancestor is strictly after `last_recovery_revealing_event` and the post-`d` window is at most 62 events combined. One page (limit 64) covers both branches and the bundled `[Rec, Rot]`; one DB round-trip; no per-hop queries.

## Contest (Cnt)

Contest is the terminal state for authority conflict — the recovery key has been revealed by another party, the operator has detected key compromise, or the chain is otherwise unrecoverable. `Cnt` is dual-signed and freezes the chain.

### `Cnt`

`Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain (creates fresh divergence at `v_N`), or `v_{d-1}` on a divergent chain (the divergence ancestor; freeze-on-divergence keeps the shorter branch single-event with its tip at `v_d`, so its `v_{tip-1}` is `v_{d-1}` — same `v_{tip-1}` rule, different chain shape). On a divergent chain, Cnt joins the existing divergent set as a third event at `v_d` via the upgrade rule. Cross-node propagation works because `v_{d-1}` is structurally shared (lands cleanly before any divergence) — Cnt with `previous = v_{d-1}.said` validates uniformly across nodes regardless of which divergent contents each node received.

Cnt is privileged (recovery-revealing). Its presence in any divergent set triggers the privileged-divergence-is-terminal rule — the chain becomes contested-terminal. There is no separate "explicit Cnt" handling: Cnt is just another privileged event that triggers contested via the divergence rule.

**Distinction from Rec.** Cnt and Rec's Mode 2 (Rec extending `v_{d-1}` at `v_d`) share the same parent shape but have different effects. Rec.Mode-2 archives the existing events at `v_d` via the discriminator → chain becomes non-divergent with Rec as the new `v_d` event (recovery; chain continues). Cnt does NOT archive — it joins the existing divergent set as a 3rd event at `v_d`, privileged-divergence-is-terminal fires, chain becomes contested-terminal (chain ends). Submitting `Cnt` with `previous = v_{d-1}.said` is what creates a contest; submitting `Rec` with `previous = v_{d-1}.said` is what creates a Mode-2 recovery.

### Operator recourse against signing-key-only Rot takeover

Cnt's authorization is dual-signed against `v_{tip-1}`'s commitments: signing-key preimage of `v_{tip-1}`'s `rotation_hash` + recovery-key preimage of `v_{tip-1}`'s `recovery_hash`.

This authorization choice gives the operator a recourse against signing-key-only Rot takeover. If a second signing-key holder (whose access was acquired via signing-key-only compromise) submits a Rot at `v_N` to take over, the keys committed by `v_{N-1}` are: signing key revealed by the Rot at `v_N` (both parties have it) + recovery key NOT revealed by Rot (only the original holder, who prepared it, has it; recovery is revealed only by `Rec`/`Ror`/`Cnt`/`Dec`). The original holder's dual-sig succeeds; the second signing-key holder's does not. The original holder can submit Cnt, terminate the chain, and reincept under a new prefix.

Today's "Cnt extends tip" model leaves the original holder with no recourse in this scenario; this design restores it.

### Algorithmic trigger — `ContestRequired`

The merge engine returns `ContestRequired` when:
- The KEL is divergent.
- At least one event in the divergent chain reveals the recovery key (`Rec` / `Ror` / `Dec` / `Cnt`, or a `Ror`/`Dec` that pre-revealed proactively).
- The submitted batch is not a contest (i.e., does not contain `Cnt`).

The operator's only legitimate next event is `Cnt`. Any other submission — including `Rec` — is rejected with `ContestRequired`.

This mirrors SEL's `ContestRequired` shape: someone has used the privileged primitive (KEL: revealed the recovery key by submitting `Rec`/`Ror`/`Dec`/`Cnt`; SEL: advanced the seal by submitting `Sea`/`Rpr`), and safe normal-flow continuation is no longer possible. The trigger is structurally the same — "the privileged operation has been used, you can't safely follow with the same primitive" — instantiated against the chain's privileged primitive (recovery key for KEL, evaluation seal for SEL).

### Distinguishing from `RecoverRequired`

A merely-divergent chain (no recovery-revealing event yet) returns `RecoverRequired` for any non-`Rec` submission. The chain can be recovered, the discriminator preserves the surviving branch. `ContestRequired` is specifically the recovery-revealed case.

### Cnt event

`KeyEventKind::Cnt`:
- `reveals_recovery_key() = true` (same gate as `Rec`/`Ror`/`Dec`).
- `Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain, or `v_{d-1}` on a divergent chain (the divergence ancestor; freeze-on-divergence keeps the shorter branch single-event, so its `v_{tip-1}` is `v_{d-1}` — same rule applied to different chain shapes).
- `Cnt.serial = tip.serial` (linear case) or `d` (divergent case).
- Dual-signed against `v_{tip-1}`'s commitments: signing key (preimage of `v_{tip-1}`'s `rotation_hash`) + recovery key (preimage of `v_{tip-1}`'s `recovery_hash`).

`KeyEvent::create_contest(previous, public_key, recovery_key)` mirrors `create_decommission`. No future-key commitments — KEL ends.

#### Authorization symmetry vs. SEL `Cnt`

Both KEL and SEL `Cnt` require the chain's privileged primitive. The asymmetry of *mechanism* derives from the difference in primitives:

- KEL's signing key and recovery key are independent cryptographic primitives. Neither structurally encompasses the other; both must be exercised together to prove dual control. Hence dual signature.
- SEL's `governance_policy` is a *policy* — a composable predicate that can be crafted to subsume the matching `auth_policy`. Hence SEL `Cnt` requires only governance satisfaction.

The symmetry of *intent* — terminal authority assertion — is preserved on both sides. Both also satisfy the general invariant: any event with failed auth is rejected (HARD anchor).

### Server semantics

- Verify `Cnt`'s structure, dual signatures against `v_{tip-1}`'s commitments (HARD).
- Insert `Cnt`. **No archival** — the chain itself is the record (existing events preserved alongside Cnt).
- Cnt's `previous = v_{tip-1}.said` always creates or contributes to a divergent set at the tip's version. The privileged-divergence rule (Cnt is recovery-revealing → privileged) makes the chain contested-terminal at that point. Both branches' events (and Cnt) remain in storage as forensic record.
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions rejected with `ContestedKel`.
- Effective SAID for a contested chain: `hash_effective_said("contested:{prefix}")` — deterministic, cross-node consistent.

### Builder

`KeyEventBuilder::contest()`:
- Pre-flight: pre-flight server-chain re-verification.
- Bundles any missing events (events the local store has but the server lost — typically because a prior `Rec` archived them server-side) AND any pending events left in flight.
- Builds `Cnt.previous = v_{tip-1}.said` (parent of linear tip; or `v_{d-1}` on a divergent chain — freeze-on-divergence keeps the shorter branch single-event so its `v_{tip-1}` is `v_{d-1}`, the divergence ancestor; same rule, different chain shape). The lower-SAID tip-selection logic is no longer needed — `v_{tip-1}` is well-defined.
- Resolves authorization via `v_{tip-1}`'s commitments and constructs the dual signature accordingly.
- Submits `[missing..., pending..., Cnt]`.
- On success: builder transitions to a contested local state, refuses further staging.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated chain abandonment.

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
- Any `Dec` event in the chain → `is_decommissioned = true`. All future submissions rejected with `KelDecommissioned`.
- Effective SAID for a decommissioned chain: the `Dec` event's own SAID.

### Builder

`KeyEventBuilder::decommission()`:
- Same pre-flight as `recover()` / `contest()`.
- Bundles missing AND pending events.
- Builds `Dec` extending the last bundled event (or owner tip if no bundling); submits `[missing..., pending..., Dec]`.

## Merge-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source-→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append at tip+1 | non-terminal events | Append. `Accepted`, `diverged_at: None`. |
| Linear, overlap at earlier serial (non-privileged events only) | non-recovery events | Insert forking event, freeze. `Diverged (non-privileged)`, `diverged_at: Some(d)`. |
| Linear (active) | batch ending in `Cnt` (`previous = v_{N-1}.said`) | Insert; creates divergence at `v_N` (existing tip + Cnt); privileged-divergence rule fires; chain becomes contested-terminal. `Contested`. |
| Linear, overlap, recovery revealed in existing branch | non-`Cnt` events | `ContestRequired`. |
| Linear, overlap | batch ending in `Rec` | Discriminator-driven recovery. Rec.Mode-1: `Rec.previous` is a branch tip at `v_d`, Rec extends it at `v_{d+1}`, the other branch archived. Rec.Mode-2: `Rec.previous = v_{d-1}.said`, Rec lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). `Recovered`. |
| Divergent (non-privileged), no recovery revealed | non-`Rec`/non-`Cnt` events | `RecoverRequired`. |
| Divergent (non-privileged), no recovery revealed | batch ending in `Rec` | Discriminator-driven recovery. `Recovered`. |
| Divergent (non-privileged) | batch ending in `Cnt` (`previous = v_{d-1}.said`, joins divergent set via upgrade rule) | Insert as 3rd event at `v_d`; chain becomes contested-terminal. `Contested`. |
| Linear, no conflict | batch ending in `Dec` | Insert `Dec`, mark decommissioned. `Accepted`. |
| Contested | any submission | Rejected with `ContestedKel`. |
| Decommissioned | any submission | Rejected with `KelDecommissioned`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/kel/event.rs` — `KeyEventKind` enum (`Icp`/`Dip`/`Rot`/`Ixn`/`Rec`/`Ror`/`Dec`/`Cnt`); `validate_structure` enforces per-kind field rules (see [events.md](events.md)).
- `lib/kels/src/types/kel/verification.rs` — `KelVerifier` and `KelVerification`; surfaces `divergence_ancestor`, `is_contested`, `is_decommissioned`, `last_recovery_revealing_event`. Enforces proactive-ROR (`events_since_last_revealing > MAX_NON_REVEALING_EVENTS` rejected).
- `lib/kels/src/builder.rs` — `KeyEventBuilder::recover()`, `contest()`, `rotate_recovery()`, `decommission()`. Each runs `verify_server_chain_pre_repair` pre-flight, then bundles missing owner events (from `find_missing_owner_events`) AND any pending events into the batch ahead of the dual-signed lifecycle event, and submits atomically.
- `lib/kels/src/merge.rs` — `MergeTransaction::merge_events` (single entry point); `archive_adversary_chain` with `collect_all_adversary_saids` / `collect_adversary_chain_saids` strategies. The SEL backport replaces per-hop DB queries with a single page fetch + resume-mode verifier trust gate + in-memory walkback (mirroring SEL's `truncate_and_replace` discriminator).
- Server submit handler (`services/kels/src/handlers.rs`) — calls `save_with_merge` which acquires advisory lock, constructs `MergeTransaction`, invokes `merge_events`. All routing is internal to the merge engine.

**Tests:**
- `archive_adversary_chain_aborts_on_tampered_page` — page-tamper test; the resume-verifier rejects the page (signature mismatch) and aborts the archival.
- `recover_bundles_pending_events_into_batch`, `contest_bundles_pending_events_into_batch`, `rotate_recovery_bundles_pending_into_batch`, `decommission_bundles_pending_into_batch` — pin pending-bundling on each lifecycle op.
- Existing recovery/contest/archival tests stay green under the page+resume-verify shape with bundled batches.

## References

- [docs/design/kel/events.md](events.md) — Per-kind reference: event kinds, field rules, typical chain shapes.
- [docs/design/kel/reconciliation.md](reconciliation.md) — Multi-node correctness matrix. Exhaustive enumeration of state × submission × gossip combinations proving the design terminates correctly and converges across nodes.
- [docs/design/kel/merge.md](merge.md) — KEL merge engine; full routing taxonomy and `MergeTransaction` API.
- [docs/design/sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator algorithm and pending-bundling shape are mirrored on both sides.
- [docs/design/sel/events.md](../sel/events.md) — SEL per-kind reference.
- [docs/design/kel/recovery-workflow.md](recovery-workflow.md) — Operator-facing recovery workflow (federation context).
- [docs/design/policy.md](../policy.md) — `Delegate(delegator, delegate)` resolution for `Dip` events.
