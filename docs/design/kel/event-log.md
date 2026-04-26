# Key Event Log (KEL) — Lifecycle, Recovery, Contest, Decommission

> Source-of-truth design doc for the KEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (merge engine routing), and [verification.md](verification.md) (KelVerifier algorithm).

The Key Event Log (KEL) is a per-prefix chain of `SignedKeyEvent` records describing the controller's evolving signing and recovery key state. Authority over the KEL is asserted by direct signature: every event carries one or more signatures verified against keys committed by prior establishment events.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain of events, latest tip extends cleanly. | Yes — `Ixn`, `Rot`, `Ror`, `Rec`, `Dec`, `Cnt` (per signature requirements). |
| **Divergent** | Two events exist at some serial `d`. Chain is frozen until recovered or contested. | Only `Rec` (or `Cnt` if recovery key has been revealed in the divergence). Bundled owner-pending events permitted in the same batch. |
| **Contested** | Chain has terminated due to authority conflict — at least one `Cnt` event in the chain. | None. All submissions rejected with `ContestedKel`. |
| **Decommissioned** | Chain has terminated cleanly by owner action — at least one `Dec` event in the chain. | None. All submissions rejected with `KelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `KelVerification` token surfaces:
- `diverged_at_serial: Option<u64>` — first serial with multiple events, or `None` if linear.
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `last_recovery_revealing_serial: Option<u64>` — serial of the most recent `Rec`/`Ror`/`Dec`/`Cnt` (the recovery-key revelation seal).

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

The `last_recovery_revealing_serial` is the most recent serial at which a `Rec`/`Ror`/`Dec`/`Cnt` landed. It is the chain's **recovery-revelation seal** — recovery cannot truncate at or before it (handlers reject attempts to displace any prior recovery-revealing event).

**Once a recovery-revealing event lands, the dual-signature it proves is final.** Subsequent compromise or revocation of the keys it revealed does NOT retroactively unsatisfy the past authorization. The seal locks in the key state at that serial.

This is an accepted security boundary. Without it, a chain's history could be invalidated retroactively by anyone who later comes to control the revealed key material — making the chain's terminal states (recovered, contested, decommissioned) unstable. The trade-off is that a key controller who later turns adversarial cannot undo their past contributions; only the going-forward effect (the recovery key is now spent — future divergent events must be resolved by `Cnt`) applies.

KEL's recovery-revelation seal is the structural analog of SEL's evaluation seal (see [../sel/event-log.md](../sel/event-log.md#evaluation-seal-and-anchor-non-poisonability)): in both, a privileged primitive (recovery-key revelation / governance evaluation) defines a forward-only watermark, with prior advancements immutable.

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain is frozen at that point: the merge engine rejects all non-recovery, non-contest appends with `KelMergeResult::RecoverRequired` (or `ContestRequired` if the recovery key is already revealed in a divergent branch).

s0 divergence is rejected outright — inception is fully deterministic; two distinct s0 events for the same prefix indicates protocol-level corruption, not authority conflict.

The divergence invariant — combined with the proactive-ROR rule (`MAX_NON_REVEALING_EVENTS = MINIMUM_PAGE_SIZE - 2 = 62`) — guarantees:
- Exactly 2 events at the divergence serial `d`.
- At most 62 events on the adversary branch beyond `d` (proactive ROR caps non-revealing forks; an adversary without the recovery key cannot submit a recovery-revealing event to extend further).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

## Recovery (Rec)

Recovery resolves divergence by archiving adversary-authored events from serial `d = first_divergent_serial` forward, leaving the owner's authentic chain intact, then appending a `Rec` (and optionally a follow-up `Rot`).

### Builder pre-flight

`KeyEventBuilder::recover()` (also `contest()`, `rotate_recovery()`) runs two pre-flight checks before constructing the dual-signed event:

- **`require_no_pending_for_repair`** — refuses with `PendingEventsBlockRepair` when the builder has a connected `kels_client` and `pending_events` is non-empty. Offline builders bypass this gate (tests/bench need to inspect pending on a client-less builder).
- **`verify_server_chain_pre_repair`** — calls `client.verify_key_events(prefix, ..., KelVerifier::new(prefix), ...)` and wraps verifier errors as `ChainHasUnverifiedEvents`. Defense-in-depth: a buggy/malicious server otherwise gets taken at its word when the builder extends from its `get_owner_tail`.

Owner's `Rec` chains from owner's local tip (`get_owner_tail`), not the divergence ancestor. The merge engine handles the boundary detection server-side via the discriminator.

### Conditional rot follow-up

`Rec` only rotates the signing key if it itself is not enough to escape adversary-known key material. Mapping:

| Owner rotated since divergence? | Adversary rotated? | Extra `Rot` after `Rec`? |
|---|---|---|
| No | No | No |
| No | Yes | **Yes** |
| Yes | Yes | No |
| Yes | No | No |

Logic: `needs_extra_rot = adversary_rotated && !owner_rotated`. The `Rec` reveals the rotation key the adversary may know (preimage of prior `rotation_hash`); if both parties have used it, owner needs one more `Rot` to escape to a key the adversary doesn't know.

### Pending events bundling

Pending events are owner-authored events that the builder staged and signed but hasn't successfully flushed (typically because the adversary's earlier `Rec` archived owner's chain server-side, or a network failure left the local builder ahead of the server). The builder's `find_missing_owner_events` walks owner's local tail backward, calling `event_exists` on the server until it finds the boundary, and resubmits the missing events as part of the recovery batch.

`recover()` ships `[missing..., Rec, ?Rot]`. The server processes the batch atomically: missing events land first (re-establishing owner's chain), then `Rec` (and optional `Rot`) chains from the new tip.

This mirrors SEL's repair flow (see [../sel/event-log.md](../sel/event-log.md#pending-events-bundling)).

### Server-side discriminator

`MergeTransaction::archive_adversary_chain` (`lib/kels/src/merge.rs`) discriminates owner from adversary events using a `Rec.previous` walkback. Two strategies based on whether owner has events at the divergence serial:

- **`collect_all_adversary_saids`** — owner has no events at serial `d`. All events at `serial >= d` not on the owner walkback are adversary.
- **`collect_adversary_chain_saids`** — owner has events at serial `d`. Walk backward from the adversary event at `d`, then forward-trace any extensions.

Both follow the same algorithmic shape as SEL's `truncate_and_replace`:

1. Detect recovery: any event in the batch has `kind = Rec` (or `Cnt` for contest).
2. Compute archive lower bound `L = diverged_at_serial`.
3. **Single page fetch**: events at `serial >= L` for the prefix, ordered `(serial ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`KelVerifier::resume(&prefix, &kel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and verifies each event's signatures against the establishment-declared keys. Verification failure aborts archival — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — owner's bundled missing events may be referenced by `Rec.previous`).
6. **Walkback**: starting at `Rec.previous`, follow `event.previous` links through the map, accumulating `owner_chain_saids` for every event with `serial >= L`. Stop when serial drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (proactive-ROR seal caps the walk well below this).
7. **Archive**: page events at `serial >= L` whose SAID is NOT in `owner_chain_saids`. Insert into `kels_archived_events` and create `RecoveryRecord` + `kels_recovery_events` link rows.
8. **Delete** archived events from `kels_key_events` by SAID (NOT by serial range — owner's events at the same serials must remain).
9. Insert the batch's new events: pending first, then `Rec` (+ optional `Rot`).

The page+resume-verify pattern is the round-10 backport from SEL: prior to the round-10 work, `archive_adversary_chain` issued one DB query per walk hop. The new shape is one DB round-trip plus in-memory traversal, identical in structure to SEL's `truncate_and_replace` discriminator. The cryptographic gate is signature verification on both sides — KEL verifies signatures directly attached to the events; SEL verifies signatures on the anchoring `ixn` events that policy resolution requires. Trust posture is the same.

### Bounds

Proactive-ROR rule caps the chain since the last `Rec`/`Ror`/`Dec`/`Cnt` to `MAX_NON_REVEALING_EVENTS = 62`. Recovery cannot truncate at or before any prior recovery-revealing event, so `d > last_recovery_revealing_serial` and the post-`d` window is at most 62 events combined. One page (limit 64) covers both branches and the bundled `[Rec, Rot]`; one DB round-trip; no per-hop queries.

## Contest (Cnt)

Contest is the terminal state for authority conflict — the recovery key has been revealed by an adversary, and the legitimate owner cannot recover (recovery would require revealing the same already-known key). `Cnt` is dual-signed and freezes the chain.

### Algorithmic trigger — `ContestRequired`

The merge engine returns `ContestRequired` when:
- The KEL is divergent.
- At least one event in the divergent chain reveals the recovery key (`Rec` / `Ror` / `Dec` / `Cnt` from the adversary's branch, OR a `Ror`/`Dec` on owner's side that pre-revealed proactively).
- The submitted batch is not a contest (i.e., does not contain `Cnt`).

The owner's only legitimate next event is `Cnt`. Any other submission — including `Rec` — is rejected with `ContestRequired`.

This mirrors SEL's `ContestRequired` shape: someone else used the privileged primitive (KEL: revealed the recovery key by submitting `Rec`/`Ror`/`Dec`/`Cnt`; SEL: advanced the seal by submitting `Sea`/`Rpr`), and safe normal-flow continuation is no longer possible. The trigger is structurally the same — "the privileged operation has been used, you can't safely follow with the same primitive" — instantiated against the chain's privileged primitive (recovery key for KEL, evaluation seal for SEL).

### Distinguishing from `RecoverRequired`

A merely-divergent chain (no recovery-revealing event yet) returns `RecoverRequired` for any non-`Rec` submission. Owner can recover, the discriminator preserves their chain. `ContestRequired` is specifically the recovery-revealed case.

### Cnt event

`KeyEventKind::Cnt`:
- `reveals_recovery_key() = true` (same gate as `Rec`/`Ror`/`Dec`).
- Cnt extends owner's authentic tip: `previous = owner_tip.said`, `serial = owner_tip.serial + 1`.
- Dual-signed: signing key (preimage of prior `rotation_hash`) + recovery key (preimage of prior `recovery_hash`).

`KeyEvent::create_contest(previous, public_key, recovery_key)` mirrors `create_decommission`. No future-key commitments — KEL ends.

#### Authorization symmetry vs. SEL `Cnt`

Both KEL and SEL `Cnt` require the chain's privileged primitive. The asymmetry of *mechanism* derives from the difference in primitives:

- KEL's signing key and recovery key are independent cryptographic primitives. Neither structurally encompasses the other; both must be exercised together to prove dual control. Hence dual signature.
- SEL's `governance_policy` is a *policy* — a composable predicate that can be crafted to be inclusive of `write_policy`. Hence SEL `Cnt` requires only governance satisfaction.

The symmetry of *intent* — terminal authority assertion — is preserved on both sides.

### Server semantics

- Verify `Cnt`'s structure, dual signatures against tracked commitments.
- Insert `Cnt`. **No archival** — the chain itself is the record (both branches preserved for forensic review).
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions rejected with `ContestedKel`.
- Effective SAID for a contested chain: `hash_effective_said("contested:{prefix}")` — deterministic, cross-node consistent.

### Builder

`KeyEventBuilder::contest()`:
- Pre-flight: `require_no_pending_for_repair` + `verify_server_chain_pre_repair`.
- Bundles missing owner events via `find_missing_owner_events` (the adversary's `Rec` may have archived owner's chain server-side).
- Builds `Cnt` extending the owner's tip; submits `[missing..., Cnt]`.
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
- Builds `Dec` extending owner's tip; submits `[missing..., Dec]`.

## Merge-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source-→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append at owner_tip+1 | non-terminal events | Append. `Accepted`, `diverged_at: None`. |
| Linear, overlap at earlier serial | non-recovery events | Insert forking event, freeze. `Diverged`, `diverged_at: Some(d)`. |
| Linear, overlap, recovery revealed in existing branch | non-`Cnt` events | `ContestRequired`. |
| Linear, overlap | batch ending in `Rec` | Discriminator-driven recovery. `Recovered`. |
| Divergent, no recovery revealed | non-`Rec` events | `RecoverRequired`. |
| Divergent, no recovery revealed | batch ending in `Rec` | Discriminator-driven recovery. `Recovered`. |
| Divergent, recovery revealed | non-`Cnt` events | `ContestRequired`. |
| Divergent, recovery revealed | batch ending in `Cnt` | Insert `Cnt`, mark contested. `Contested`. |
| Linear, no conflict | batch ending in `Dec` | Insert `Dec`, mark decommissioned. `Accepted`. |
| Contested | any submission | Rejected with `ContestedKel`. |
| Decommissioned | any submission | Rejected with `KelDecommissioned`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/kel/event.rs` — `KeyEventKind` enum (`Icp`/`Dip`/`Rot`/`Ixn`/`Rec`/`Ror`/`Dec`/`Cnt`); `validate_structure` enforces per-kind field rules (see [events.md](events.md)).
- `lib/kels/src/types/kel/verification.rs` — `KelVerifier` and `KelVerification`; surfaces `diverged_at_serial`, `is_contested`, `is_decommissioned`, `last_recovery_revealing_serial`. Enforces proactive-ROR (`events_since_last_revealing > MAX_NON_REVEALING_EVENTS` rejected).
- `lib/kels/src/builder.rs` — `KeyEventBuilder::recover()`, `contest()`, `rotate_recovery()`, `decommission()`. Each runs `require_no_pending_for_repair` + `verify_server_chain_pre_repair` pre-flight (round-10), then builds the appropriate dual-signed event and submits the bundled batch.
- `lib/kels/src/merge.rs` — `MergeTransaction::merge_events` (single entry point); `archive_adversary_chain` with `collect_all_adversary_saids` / `collect_adversary_chain_saids` strategies. The round-10 backport replaces per-hop DB queries with a single page fetch + resume-mode verifier trust gate + in-memory walkback (mirroring SEL's `truncate_and_replace` discriminator).
- Server submit handler (`services/kels/src/handlers.rs`) — calls `save_with_merge` which acquires advisory lock, constructs `MergeTransaction`, invokes `merge_events`. All routing is internal to the merge engine.

**Tests:**
- `archive_adversary_chain_aborts_on_tampered_page` — page-tamper test; the resume-verifier rejects the page (signature mismatch) and aborts the archival.
- Existing recovery/contest/archival tests stay green under the page+resume-verify shape.
- `recover_refuses_when_pending_nonempty_and_connected`, `contest_refuses_when_pending_nonempty_and_connected`, `rotate_recovery_refuses_when_pending_nonempty_and_connected` — pin the round-10 pending gate.
- `recover_bypasses_pending_gate_in_offline_mode` — pin the offline-mode bypass that tests/bench depend on.

## References

- [docs/design/kel/events.md](events.md) — Per-kind reference: event kinds, field rules, typical chain shapes.
- [docs/design/kel/reconciliation.md](reconciliation.md) — Multi-node correctness matrix. Exhaustive enumeration of state × submission × gossip combinations proving the design terminates correctly and converges across nodes.
- [docs/design/kel/merge.md](merge.md) — KEL merge engine; full routing taxonomy and `MergeTransaction` API.
- [docs/design/sel/event-log.md](../sel/event-log.md) — SEL counterpart; the discriminator algorithm and pending-bundling shape are mirrored on both sides.
- [docs/design/sel/events.md](../sel/events.md) — SEL per-kind reference.
- [docs/design/kel/recovery-workflow.md](recovery-workflow.md) — Operator-facing recovery workflow (federation context).
- [docs/design/policy.md](../policy.md) — `Delegate(delegator, delegate)` resolution for `Dip` events.
