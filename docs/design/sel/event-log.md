# SAD Event Log (SEL) — Lifecycle, Repair, Contest, Decommission

> Source-of-truth design doc for the SEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing and `truncate_and_replace` discriminator), and [verification.md](verification.md) (SelVerifier algorithm). For the SADStore service architecture (object store, custody, gossip), see [../sadstore.md](../sadstore.md).

The SAD Event Log (SEL) is a per-prefix chain of `SadEvent` records describing the evolving state of a SAD object (typically a publication, credential template, or other governance-managed artifact). Authority over the SEL is asserted by anchoring `ixn` events in one or more KELs identified by the chain's `write_policy` and `governance_policy`.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain of events, latest tip extends cleanly. | Yes — `Upd`, `Est`, `Sea`, `Rpr`, `Cnt`, `Dec` (per write_policy / governance_policy). |
| **Divergent** | Two events exist at some version `d`. Chain is frozen until repaired. | Only `Rpr` (governance_policy authorized). Bundled owner-pending events permitted in the same batch. |
| **Contested** | Chain has terminated due to authority conflict — at least one `Cnt` event in the chain. Forensic preservation. | None. All submissions rejected. |
| **Decommissioned** | Chain has terminated cleanly by owner action — at least one `Dec` event in the chain. | None. All submissions rejected. |

State is computed from the chain's events, never tracked as a separate flag. The `SelVerification` token surfaces:
- `diverged_at_version: Option<u64>` — first version with multiple events, or `None` if linear.
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `last_governance_version: Option<u64>` — version of the most recent `Sea`/`Rpr` (the "evaluation seal").

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). | `write_policy` (Icp.said anchored under the declared write_policy). | No |
| `Est` | Establishment of `governance_policy` (v1, optional). | `write_policy`. | No |
| `Upd` | Normal update. | `write_policy`. | No |
| `Sea` | Seal — governance evaluation; advances the seal, may evolve `write_policy`. | `governance_policy`. | No |
| `Rpr` | Repair — advances the seal AND resolves divergence (replaces adversary events at the divergence point). | `governance_policy`. | No |
| `Cnt` | Contest — terminal due to authority conflict. | `governance_policy`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governance_policy`. | **Yes** |

`Cnt` and `Dec` are both governance-authorized terminal events; the split is intentional: explicit kinds carry intent; reusing one kind for both clean-end and conflict-end loses information.

For per-kind field rules (which fields are required/optional/forbidden per kind), and typical chain shapes, see [events.md](events.md).

## Evaluation Seal and Anchor Non-Poisonability

The `last_governance_version` is the most recent version at which a `Sea` or `Rpr` landed. It is the chain's **evaluation seal** — repair must not truncate at or before it (handlers reject `from_version <= last_governance_version`).

**Once an evaluation lands, the governance satisfaction it proves is final.** Subsequent revocation or poisoning of any KEL anchor used by that evaluation's `governance_policy` does NOT retroactively unsatisfy the past evaluation. The seal locks in the policy state at that version.

This is an accepted security boundary. Without it, a chain's history could be invalidated retroactively by anyone with control over a single anchor — making the chain's terminal states (sealed, contested, decommissioned) unstable. The trade-off is that an anchor controller who later turns adversarial cannot undo their past contributions; only the going-forward effect of `rec`/`cnt` on their KEL applies.

**Caveat**: `rec` or `cnt` on an underlying KEL DOES invalidate that keyholder's authority **going forward** — future evaluations referencing that keyholder will fail. The non-poisonability rule applies only to evaluations already in the chain.

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain is frozen at that point: `save_batch` rejects all non-repair appends with the existing "Chain is divergent — repair required" path.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicates protocol-level corruption, not authority conflict).

The divergence invariant — combined with the proactive governance evaluation rule (`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`) — guarantees:
- Exactly 2 events at the divergence version `d`.
- At most 1 event at each version `> d` (the chain is frozen; only one branch can extend post-divergence, and only by way of pre-divergence pending that races in).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

## Repair (Rpr)

Repair resolves divergence by archiving adversary-authored events from version `L = first_divergent_version` forward, leaving the owner's authentic chain intact, then appending an `Rpr` that advances the seal.

### Builder boundary derivation

`SadEventBuilder::repair()` derives the boundary uniformly: `boundary = owner_tip.version`, regardless of A3-vs-linear-extension. The `Rpr` is built as `SadEvent::rpr(boundary, content)`, producing:
- `Rpr.previous = boundary.said`
- `Rpr.version = boundary.version + 1`

The whole point of repair is to sync server state to owner's chain — `Rpr.previous` is therefore always owner's authentic tip. There is no "A3 → d-1" special case; the same rule covers both pure linear-extension and post-divergence repair.

`NothingToRepair` fires when the chain is non-divergent AND `server_tip.version <= owner_tip.version`.

### Pending events bundling

Pending events (events the builder staged and signed but never successfully flushed — typically because an A3 server response rejected the batch) are owner-authored work that must be preserved. The cost of discarding pending may be substantial: a `governance_policy` aggregating endorsements from many KELs may have collected hundreds of `ixn` anchors at flush time, and re-collecting them is expensive.

`repair()` bundles pending events into the submission batch:
- The batch ships as `[pending..., Rpr]`.
- `Rpr` extends the LAST pending event (or the verified tip if pending is empty).
- The server processes the batch atomically — pending events land first, then `Rpr` adopts them as part of the post-repair chain.

This mirrors KEL's `contest()` flow (`builder.rs:465`) which already bundles `find_missing_owner_events()` for the analogous reason (adversary's `rec` may have archived owner's chain server-side).

> **Future work**: persist pending across CLI sessions so a crash mid-collection doesn't lose accumulated work. Out of scope for the initial implementation; the in-memory pending model suffices once bundling is correct.

### Server-side discriminator

`truncate_and_replace` discriminates owner from adversary events using the `Rpr.previous` walkback pattern (mirrors KEL's `archive_adversary_chain`):

1. Detect repair: any new event after dedup has `kind = Rpr`.
2. Compute archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
3. **Single page fetch**: events at `version >= L` for the prefix, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and `write_policy` (which resolves to `Endorse(KEL_PREFIX)` nodes — fetching and verifying the signed `ixn` anchors in the controlling KELs). Verification failure aborts repair — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — owner's bundled pending events may be referenced by `Rpr.previous`).
6. **Walkback**: starting at `Rpr.previous`, follow `event.previous` links through the map, accumulating `owner_chain_saids` for every event with `version >= L`. Stop when version drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (governance seal caps the walk well below this).
7. **Archive**: page events at `version >= L` whose SAID is NOT in `owner_chain_saids`. Insert into `sad_event_archives` and create `SelRepairEvent` link rows.
8. **Delete** archived events from `sad_events` by SAID (NOT by version range — owner's events at the same versions must remain).
9. Insert the batch's new events: pending first, then `Rpr`.

### Bounds

Governance evaluation rule caps owner's chain since the last `Sea`/`Rpr` to `MAX_NON_EVALUATION_EVENTS = 63`. Repair cannot truncate at or before the seal, so `d > last_seal_version` and `owner_tip.version - L <= 63`. The divergence invariant caps adversary contribution. One page (limit 64) covers both branches combined; one DB round-trip; no per-hop queries.

## Contest (Cnt)

Contest is the terminal state for authority conflict — someone with `governance_policy` authority advanced the seal past where another authorized party would naturally write, and the second party rejects that history rather than accept it.

### Algorithmic trigger — `ContestRequired`

The server returns `ContestRequired` when:
- A normal (non-Rpr/Cnt/Dec) event is submitted.
- The verifier confirms `write_policy` is satisfied for the submission.
- The submission's version is at or below `last_governance_version` — i.e., the proposed event would land at or before the evaluation seal.

This is server-observable and unambiguous: a write-authorized event cannot legally land at a sealed version, and the seal advanced past the submitter's view of the chain. The submitter has authority but cannot proceed via normal append; their options are to accept the chain's new state, contest it, or abandon.

This mirrors KEL's `ContestRequired` shape: someone else used the privileged primitive (KEL: revealed the recovery key by submitting `rec`/`ror`/`dec`/`cnt`; SEL: advanced the seal by submitting `Sea`/`Rpr`), and safe normal-flow continuation is no longer possible. The trigger is structurally the same — "the privileged operation has been used, you can't safely follow with the same primitive" — instantiated against the chain's privileged primitive (recovery key for KEL, evaluation seal for SEL).

### Distinguishing from `RepairRequired`

A merely-divergent chain (no `Rpr` has landed yet, seal still at `last_governance_version_before_d`) is NOT a contest situation — owner can repair, the discriminator preserves their chain. The server returns the existing divergence-required signal. `ContestRequired` is specifically the seal-advanced case.

### Cnt event

`SadEventKind::Cnt` (new):
- `evaluates_governance() = true` (same gate as `Rpr`).
- Cnt extends the current tip: `previous = tip.said`, `version = tip.version + 1`.
- `content` is preserved — equals `previous.content` (verifier-enforced; see [events.md](events.md#content-semantics) for the per-kind content rule).

`SadEvent::cnt(previous)` constructor mirrors `SadEvent::rpr`. No content parameter — the constructor reads `previous.content` and carries it forward.

#### Authorization asymmetry vs. KEL `cnt`

KEL's `cnt` requires **dual signatures** — both the controller's signing key and the recovery key. SEL's `Cnt` requires only `governance_policy` satisfaction (no separate `write_policy` check). The asymmetry is intentional and derives from the difference in primitives:

- KEL's signing key and recovery key are independent cryptographic primitives. Neither can structurally encompass the other; both must be exercised together to prove dual control.
- SEL's `governance_policy` is a *policy* — a composable predicate that can be crafted to be inclusive of `write_policy` (e.g., a governance policy `Endorse(A) AND Endorse(B)` where the write_policy is `Endorse(A)` is strictly stronger than write_policy alone). Requiring both governance AND write satisfaction in SEL would either be redundant (when governance includes write) or under-specified (when governance and write address disjoint authority sets — which is a chain-design error, not something the kind structure should defend against).

The symmetry of *intent* — terminal authority assertion — is preserved; the symmetry of *mechanism* differs because the underlying authority primitives differ.

### Server semantics

- Verify `Cnt`'s structure and that the resulting chain still satisfies `governance_policy`.
- Insert `Cnt`. **No archival** — terminal events don't displace or remove anything; the chain itself is the record.
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions (including additional Cnts) rejected with `ContestedSel`.
- Effective SAID for a contested chain: `hash_effective_said("contested:{prefix}")` — deterministic, cross-node consistent.

### Builder

`SadEventBuilder::contest()`:
- Mirrors `KeyEventBuilder::contest`: pre-flight verifies the server chain (defense-in-depth), bundles pending events into the batch, builds `Cnt` extending the pending tip (or verified tip). Cnt's content is read from the tip and carried forward (no content parameter).
- Submits `[pending..., Cnt]`.
- On success: builder transitions to a contested local state, refuses further staging.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated chain abandonment. Used when the chain is not under conflict but the owner wants to mark it ended (e.g., the underlying SAD object is retired, the credential template is superseded, the publication is withdrawn).

### Trigger

Owner-initiated. No algorithmic server trigger — the owner runs `SadEventBuilder::decommission()` and submits `Dec`. The server has no mechanism to require a Dec; it only enforces that one terminates the chain.

### Dec event

`SadEventKind::Dec` (new):
- `evaluates_governance() = true` (terminal authority assertion).
- Dec extends the current tip: `previous = tip.said`, `version = tip.version + 1`.
- `content` is preserved — equals `previous.content` (verifier-enforced; see [events.md](events.md#content-semantics) for the per-kind content rule).

### Server semantics

- Verify `Dec`'s structure and that the resulting chain still satisfies `governance_policy`.
- Insert `Dec`. No archival.
- Any `Dec` event in the chain → `is_decommissioned = true`. All future submissions rejected with `DecommissionedSel`.
- Effective SAID for a decommissioned chain: the `Dec` event's own SAID (mirrors KEL `dec`).

### Builder

`SadEventBuilder::decommission()`:
- Same pre-flight as `repair`/`contest`: verify server chain, bundle pending. Dec's content is read from the tip and carried forward (no content parameter).
- Submits `[pending..., Dec]`.

## Server-Observable Case Taxonomy

When the server processes a submitted batch:

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append at owner_tip+1 | non-terminal events | Append. `applied: true`. |
| Linear, normal event at version <= last_governance_version, write_policy satisfied | non-terminal events | `ContestRequired`. |
| Linear, normal event creating fork (overlap with existing event) | non-terminal events | Insert forking event, freeze. `applied: true, diverged_at: Some(v)`. |
| Divergent | non-Rpr events | Rejected (chain is divergent — repair required). |
| Divergent | batch ending in Rpr | Discriminator-driven repair. `applied: true`. |
| Linear, version sealed past submission | batch ending in Cnt | Insert Cnt, mark contested. `applied: true`. |
| Linear, no conflict | batch ending in Dec | Insert Dec, mark decommissioned. `applied: true`. |
| Contested | any submission | Rejected with `ContestedSel`. |
| Decommissioned | any submission | Rejected with `DecommissionedSel`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/sad/event.rs` — variants `SadEventKind::Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec` with topic strings per [events.md](events.md). Constructors `SadEvent::icp/est/upd/sea/rpr/cnt/dec`; `cnt(previous)` and `dec(previous)` take no content parameter (read `previous.content` and carry forward). `evaluates_governance` returns true for `Sea`/`Rpr`/`Cnt`/`Dec`. Predicates: `is_contest`, `is_decommission`. `validate_structure` enforces the per-kind field rules (forbid content on Icp/Est; require on Upd; etc.). The "must equal `previous.content`" rule for Sea/Rpr/Cnt/Dec is a chain-state check (verifier, not validate_structure).
- `lib/kels/src/types/sad/verification.rs` — add `is_contested: bool` and `is_decommissioned: bool` fields to `SelVerifier` and `SelVerification`. Set on observing `Cnt` / `Dec` during verification. Surface via accessors. Add the content-preservation check: every Sea/Rpr/Cnt/Dec must have `event.content == previous.content`; reject otherwise. Add the Icp anchoring check: every v0 must have Icp.said anchored under its declared `write_policy` (`PolicyChecker::evaluate_anchored_policy(event.write_policy, event.said)`). The branch's `tracked_write_policy` is seeded only after this check passes.
- `lib/kels/src/sad_builder.rs::repair()` — drop the A3 → d-1 boundary branch; uniform `boundary = owner_tip.version`. Bundle pending events into the batch. Remove the `require_no_pending_for_repair` gate.
- `lib/kels/src/sad_builder.rs` — add `contest()` and `decommission()` (no content arg) mirroring `repair`'s pre-flight + bundling shape. Each constructor reads the tip's content and carries it forward.
- `services/sadstore/src/repository.rs::truncate_and_replace` — replace blanket archive-from-`from_version` with discriminator-driven archive: single page fetch, resume-verifier trust gate, walkback from `Rpr.previous`, archive non-owner page events.
- `services/sadstore/src/handlers.rs` — add `ContestRequired` algorithmic trigger in the normal-event path (write_policy satisfied + version <= last_governance_version). Add `is_contest` / `is_decommission` branches paralleling `is_repair`. Add contested/decommissioned terminal-state rejection at the top of the submit handler.

The discriminator algorithm and the pending-bundling shape are mirrored on the KEL side; see [../kel/event-log.md](../kel/event-log.md) for the KEL implementation surface.

**Tests:**
- New SEL full-stack: `flush_repair_preserves_owner_chain_when_owner_authored_at_divergence` (B1: owner has owner_d, didn't extend); `flush_repair_preserves_owner_post_fork_chain` (B2: owner extended past owner_d).
- New SEL: `submit_normal_event_returns_contest_required_when_sealed`.
- New SEL: `contest_terminates_chain` and `decommission_terminates_chain`.
- New SEL: `submit_after_contest_rejects_all_kinds`; `submit_after_decommission_rejects_all_kinds`.
- New SEL: `repair_bundles_pending_events_into_batch`.
- New SEL: `verifier_rejects_sea_with_changed_content` (and analogous for Rpr / Cnt / Dec) — content-preservation rule is enforced.
- New SEL: `verifier_rejects_est_with_content` — Est content is now forbidden.
- Tamper: `truncate_and_replace_aborts_on_tampered_page` (resume verifier rejects, repair aborts).
- Existing: `flush_repair_heals_divergent_chain` and `flush_repair_heals_adversarially_extended_chain` stay green under the new uniform-boundary rule.
- KEL: `archive_adversary_chain_aborts_on_tampered_page` (parallel tamper test); existing recovery/contest/archival tests stay green.

## References

- [docs/design/sel/events.md](events.md) — Per-kind reference: event kinds, field rules, typical chain shapes.
- [docs/design/sadstore.md](../sadstore.md) — SADStore service architecture (points here for divergence/repair semantics).
- [docs/design/kel/event-log.md](../kel/event-log.md) — KEL counterpart for the privileged-primitive model and the `archive_adversary_chain` discriminator (mirrored here for SEL).
- [docs/design/kel/merge.md](../kel/merge.md) — KEL merge engine; `archive_adversary_chain` shape mirrored in SEL `truncate_and_replace`.
- [docs/design/policy.md](../policy.md) — `write_policy`, `governance_policy`, `Endorse(KEL_PREFIX)`, anchor verification.
