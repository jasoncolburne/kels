# SAD Event Log (SEL) — Lifecycle, Repair, Contest, Decommission

> Source-of-truth design doc for the SEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing and `truncate_and_replace` discriminator), and [verification.md](verification.md) (SelVerifier algorithm). For the SADStore service architecture (object store, custody, gossip), see [../sadstore.md](../sadstore.md).

The SAD Event Log (SEL) is a per-prefix chain of `SadEvent` records describing the evolving state of a SAD object (typically a publication, credential template, custody record, or other governance-managed artifact). SE chains are **identity-rooted** — every SE chain binds at inception to an Identity Event Log (IEL) and resolves its per-event authorization through specific IEL events. Authority over the chain is asserted by anchoring `ixn` events in KELs identified by the IEL's currently-tracked `auth_policy` (for `Upd`) or `governance_policy` (for `Sea`/`Rpr`/`Cnt`/`Dec`).

See [../iel/events.md](../iel/events.md) for the IEL primitive and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability) for the unified validation rules that govern the binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, latest tip extends cleanly. | Yes — `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec` (per IEL-resolved authorization). |
| **Divergent** | Two events at some version `d`. Chain is frozen until repaired. | Only `Rpr` (governance-authorized via IEL). Bundled owner-pending events permitted in the same batch. |
| **Contested** | Chain has terminated due to authority conflict — at least one `Cnt` event in the chain. Forensic preservation. | None. All submissions rejected. |
| **Decommissioned** | Chain has terminated cleanly by owner action — at least one `Dec` event in the chain. | None. All submissions rejected. |

State is computed from the chain's events, never tracked as a separate flag. The `SelVerification` token surfaces:
- `diverged_at_version: Option<u64>` — first version with multiple events, or `None` if linear.
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `last_governance_version: Option<u64>` — version of the most recent `Sea`/`Rpr` (the "evaluation seal").
- `last_identity_event: Option<Digest256>` — the highest IEL event (in IEL chain order) that any SE event has bound to. Ratchets forward; never decreases.

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `identity` (IEL prefix). Permissionless — deterministic prefix derivation; no auth gate. | None at v0; chain advances require IEL-resolved authorization at v1+. | No |
| `Upd` | Normal update — append content. | `auth_policy` resolved through `identity_event`. | No |
| `Sea` | Seal — governance evaluation; advances the seal and ratchets `last_identity_event`. No field evolution (policies live on IEL). | `governance_policy` resolved through `identity_event`. | No |
| `Rpr` | Repair — advances the seal AND resolves divergence (replaces adversary events at the divergence point). | `governance_policy` resolved through `identity_event`. | No |
| `Cnt` | Contest — terminal due to authority conflict. | `governance_policy` resolved through `identity_event`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governance_policy` resolved through `identity_event`. | **Yes** |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true`.

For per-kind field rules and typical chain shapes, see [events.md](events.md). SE has no `Est` kind — identity rooting eliminates the optional-governance-at-Icp dance.

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Upd` event at v1 in the same batch. SE Icp is permissionless (deterministic prefix derivation for lookup); paired with the v1 Upd, the chain is born with content, an `identity_event` binding, and the first policy-enforced event. See [events.md §Inception batch rule](events.md#inception-batch-rule).

## Authorization via IEL — and Why That's Enough

SE chains do not declare or evolve their own authorization policies. Every authorization decision routes through the IEL the chain is bound to:

- **`Upd`** is authorized iff anchored under the IEL's tracked `auth_policy` resolved through the SE event's `identity_event`.
- **`Sea` / `Rpr` / `Cnt` / `Dec`** is authorized iff anchored under the IEL's tracked `governance_policy` resolved through `identity_event`.

The IEL primitive is responsible for the immunity rule and the anchor-non-poisonability guarantees that today's SEL spent considerable design effort on. SE inherits stability for free: every IEL event referenced by an SE binding has its policy SAIDs immune (IEL submit and verification gates enforce this), so the policy contents are fixed for the lifetime of the chain. See [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability) and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability).

The cross-chain validation rules — same at submit, gossip, bootstrap, and re-verification — are documented at [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules). They include monotonic-on-SE-chain (the chain's `last_identity_event` ratchets in IEL chain order; no rebinding to stale IEL events).

## Trust Caveat — Recovered Anchoring KELs

The seal property and the anchoring model give *structural* guarantees against poisoning (via IEL's immunity rule) and gossip races (terminal states are deterministic across nodes). They give *partial* guarantees when a participating KEL is later recovered — because recovery archives the adversary branch, anchors made on that branch are removed from the live KEL.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the owner's branch stay (`rec` archives only the adversary branch); anchors on the now-archived adversary branch do not. This applies to anchors of any kind — SEL governance evaluations, SEL writes, IEL evolutions.

Implications for SE consumers:

- A past SE event whose authorizing anchor was placed on the owner's branch of the anchoring KEL: re-verifies cleanly post-`rec`.
- A past SE event whose authorizing anchor was placed on the adversary branch (now archived): may *fail* re-verification. The recovery mechanism has reverted what the adversary did to the underlying KEL, and that reversal propagates to dependent SE chains.

This is observable, not hidden — the chain mathematics make the post-`rec` state visible. The consumer's runtime trust judgement is: when a participating KEL has `rec` history, re-verify the SE chain (and the IEL it binds to) and treat past state with caution proportionate to what survives.

`Cnt` on a participating KEL is distinct in shape: a contested KEL is frozen but no events are archived, so adversary-placed anchors stay in the live chain alongside owner-placed ones. Past SE evaluations re-verify regardless. But `cnt` is itself evidence that the recovery key was exposed — the KEL is permanently terminal, and a consumer should treat past evaluations participating in such a KEL with comparable caution to (or more than) the rec case.

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain is frozen at that point: the merge engine rejects all non-repair appends with the existing "Chain is divergent — repair required" path.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

The divergence invariant — combined with the proactive governance evaluation rule (`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`) — guarantees:
- Exactly 2 events at the divergence version `d`.
- At most 1 event at each version `> d` (chain frozen post-divergence; only one branch can extend by way of pre-divergence pending that races in).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

### Why SE has Rpr (and IEL doesn't)

SE divergence happens at the auth-policy layer: multiple parties with auth (e.g., multiple endorsers in a `Threshold` policy) can race conflicting `Upd` submissions. The legitimate operator's branch is "owner"; the adversarial branch is "adversary." `Rpr` is governance-authorized — a higher-bar authority than the auth-authorized fork — and resolves the divergence by archiving the adversary branch.

IEL has no analog because every IEL event after Icp is governance-authorized; there is no auth-vs-governance asymmetry for `Rpr` to exploit. See [../iel/event-log.md §Why no `Rpr`](../iel/event-log.md#why-no-rpr).

## Repair (Rpr)

Repair resolves divergence by archiving adversary-authored events from version `L = first_divergent_version` forward, leaving the owner's authentic chain intact, then appending an `Rpr` that advances the seal.

### Builder boundary derivation

`SadEventBuilder::repair()` derives the boundary uniformly: `boundary = owner_tip.version`, regardless of whether the chain is divergent or merely behind. The `Rpr` is built as `SadEvent::rpr(boundary)`, producing:
- `Rpr.previous = boundary.said`
- `Rpr.version = boundary.version + 1`
- `Rpr.content = boundary.content` (preservation rule; Rpr does not mutate content)
- `Rpr.identity_event = current IEL governance-establishing event`

### Pending events bundling

Pending events (events the builder staged but never successfully flushed — typically because the server rejected the batch with "Chain is divergent — repair required") are owner-staged in-progress work. `repair()` bundles pending events into the submission batch:
- The batch ships as `[pending..., Rpr]`.
- `Rpr` extends the LAST pending event (or the verified tip if pending is empty).
- The server processes the batch atomically — pending events land first, then `Rpr` adopts them as part of the post-repair chain. Bundled pending events are verified server-side on submit like any other event.

Whenever pending is non-empty, the application SHOULD display it to the user. The library cannot algorithmically decide whether stale-looking pending should bundle or be discarded — that requires human inspection. The library bundles pending by default; the user-facing decision (bundle vs. discard vs. selectively-discard) is application-level.

KEL bundles symmetrically — its lifecycle ops (`recover`/`contest`/`rotate_recovery`/`decommission`) ride `[missing..., pending..., Rec/Cnt/Ror/Dec, ?Rot]`. See [../kel/event-log.md §Pending events bundling](../kel/event-log.md#pending-events-bundling).

> **Future work**: persist pending across CLI sessions so a crash mid-collection doesn't lose accumulated work. Out of scope for the initial implementation; the in-memory pending model suffices once bundling is correct.

### Server-side discriminator

`truncate_and_replace` discriminates owner from adversary events using the `Rpr.previous` walkback pattern (mirrors KEL's `archive_adversary_chain`):

1. Detect repair: any new event after dedup has `kind = Rpr`.
2. Compute archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
3. **Single page fetch**: events at `version >= L` for the prefix, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and IEL-resolved authorization (which fetches and verifies the signed `ixn` anchors in the controlling KELs). Verification failure aborts repair — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — owner's bundled pending events may be referenced by `Rpr.previous`).
6. **Walkback**: starting at `Rpr.previous`, follow `event.previous` links through the map, accumulating `owner_chain_saids` for every event with `version >= L`. Stop when version drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (governance seal caps the walk well below this).
7. **Archive**: page events at `version >= L` whose SAID is NOT in `owner_chain_saids`. Insert into `sad_event_archives` and create `SelRepairEvent` link rows.
8. **Delete** archived events from `sad_events` by SAID (NOT by version range — owner's events at the same versions must remain).
9. Insert the batch's new events: pending first, then `Rpr`.

### Bounds

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63` caps the chain since the last `Sea`/`Rpr`/`Cnt`/`Dec` to 63 non-evaluation events. Repair cannot truncate at or before the evaluation seal (`from_version <= last_governance_version` is rejected). One page (limit 64) covers both branches and the bundled `[pending..., Rpr]`.

## Contest (Cnt)

Contest is the terminal state for SE — the legitimate operator cannot defeat an adversary who has demonstrated `governance_policy` authority on the bound IEL (or the chain is otherwise unrecoverable). `Cnt` freezes the SE chain.

### Algorithmic trigger — `ContestRequired`

The merge engine returns `ContestRequired { reason }` when:
- The submitted event is non-terminal AND non-Rpr.
- The event's version is `<=  last_governance_version` (the submitter's view is at-or-before the evaluation seal — someone with governance authority advanced the seal past the submitter's view).
- The chain is not divergent (divergence routes to `RepairRequired` instead).

This mirrors KEL's `ContestRequired` shape: the privileged primitive (here, governance evaluation) has been used, and safe normal-flow continuation is no longer possible. See [../kel/event-log.md §Contest (Cnt)](../kel/event-log.md#contest-cnt) for the structural parallel.

### Server semantics

- Verify `Cnt`'s structure and IEL-resolved governance authorization.
- Insert `Cnt`. **No archival** — the chain itself is the record (both branches preserved if divergent).
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions rejected with `ContestedSel`.

### Builder

`SadEventBuilder::contest()`:
- Pre-flight: `verify_server_chain_pre_action` (full client-side server-chain re-verification).
- Bundles pending events into the batch.
- Builds `Cnt` extending the last bundled event (pending tail, or verified tip if pending empty); submits `[pending..., Cnt]`.
- On success: builder transitions to a contested local state, refuses further staging.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated chain abandonment. Same shape as `Cnt` but no authority conflict — owner explicitly ends the chain.

### Server semantics

- Verify `Dec`'s structure, governance authorization.
- Insert `Dec`. No archival.
- Any `Dec` in the chain → `is_decommissioned = true`. All future submissions rejected with `DecommissionedSel`.

### Builder

`SadEventBuilder::decommission()`:
- Same pre-flight as `contest()`.
- Bundles pending. Builds `Dec` extending the last bundled event; submits `[pending..., Dec]`.

## Server-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive matrix and multi-node correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | non-terminal events | Append. Seal advances on `Sea`/`Rpr`. |
| Linear, overlap (fork) | non-`Rpr`/`Cnt`/`Dec` | Insert single forking event, freeze. `Diverged`. |
| Divergent | `Rpr` | Discriminator-driven repair. `Repaired`. |
| Divergent | non-`Rpr`/`Cnt`/`Dec` | `RepairRequired`. Chain unchanged. |
| Linear, post-evaluation-seal | non-terminal event with valid auth | `ContestRequired { reason }`. |
| Any non-terminal | `Cnt` | Insert, mark contested. |
| Any non-terminal | `Dec` | Insert, mark decommissioned. |
| Contested | any | Rejected with `ContestedSel`. |
| Decommissioned | any | Rejected with `DecommissionedSel`. |
| Inception batch missing Upd at v1 | `[Icp]` alone, or `[Icp, Sea/Cnt/Dec]` | Rejected — inception batch rule (see events.md). |

## Implementation Map

**Code:**
- `lib/kels/src/types/sad/event.rs` — `SadEventKind` enum (`Icp`/`Upd`/`Sea`/`Rpr`/`Cnt`/`Dec`); `validate_structure` per per-kind field rules. Inception batch rule enforced at submit handler, not in `validate_structure` (which is per-event, not per-batch).
- `lib/kels/src/types/sad/verification.rs` — `SelVerifier`, `SelVerification`. Branch state holds `last_identity_event` (ratchet); no longer holds `tracked_write_policy` / `tracked_governance_policy` (those resolve through IEL on demand).
- `lib/kels/src/sad_builder.rs` — `SadEventBuilder` with `update()`, `seal()`, `repair()`, `contest()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification (factored helper `verify_server_chain_pre_action`).
- `services/sadstore/src/handlers.rs` — submit handler: structural + IEL-resolved-authorization gate, terminal-state gate, divergence routing, `ContestRequired` algorithmic trigger, inception-batch-rule enforcement.
- `services/sadstore/src/repository.rs` — `truncate_and_replace` discriminator (single-page fetch + resume-verify trust gate + walkback + archival).

**Notable changes from the dual-policy era:**
- No `Est` kind. No `write_policy` / `governance_policy` fields on SE events.
- No `tracked_write_policy` / `tracked_governance_policy` on branch state.
- No SE-side immunity rule (lives on IEL).
- New `identity_event` field on every v1+ event.
- New `last_identity_event` ratchet on branch state.
- New `[Icp, Upd]` minimum inception batch rule.

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/event-log.md](../iel/event-log.md) — IEL counterpart; SE chains bind to IEL events.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference.
- [../sadstore.md](../sadstore.md) — SADStore service architecture.
- [../policy.md](../policy.md) — Policy DSL, anchoring model.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
