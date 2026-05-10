# SAD Event Log (SEL) — Lifecycle, Repair, Contest, Decommission

> Source-of-truth design doc for the SEL lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing and `truncate_and_replace` discriminator), and [verification.md](verification.md) (SelVerifier algorithm). For the SADStore service architecture (object store, custody, gossip), see [../sadstore.md](../sadstore.md).

The SAD Event Log (SEL) is a per-prefix chain of `SadEvent` records describing the evolving state of a SAD object (typically a publication, credential template, custody record, or other governance-managed artifact). SELs are **identity-rooted** — every SEL binds at inception to an Identity Event Log (IEL) and resolves its per-event authorization through specific IEL events. Authority over the chain is asserted by anchoring `ixn` events in KELs identified by the IEL's currently-tracked `auth_policy` (for `Upd`) or `governance_policy` (for `Sea`/`Rpr`/`Cnt`/`Dec`).

See [../iel/events.md](../iel/events.md) for the IEL primitive and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability) for the unified validation rules that govern the binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, latest tip extends cleanly. | Yes — `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec` (per IEL-resolved authorization). |
| **Divergent (non-privileged)** | Two events at some version `d`, both non-privileged (e.g., `Upd`-`Upd` race). Chain is recoverable via `Rpr` (extends one branch tip and archives the other branch). | `Rpr` (resolves divergence by extending a tip at `v_{d+1}` and archiving the other branch); `Cnt` (joins divergent set at `v_d` via the upgrade rule, transitioning to Contested). Bundled pending events permitted in the same batch. |
| **Contested** | Chain has terminated due to a privileged event in a divergent set (privileged-divergence-is-terminal rule), or via an explicit `Cnt` extending `v_{tip-1}` on a linear chain (which creates fresh divergence at the tip's version, immediately privileged-divergent → contested). SEL privileged events: `Sea`, `Rpr`, `Cnt`, `Dec` (all governance-authorized). | None. All submissions rejected. |
| **Decommissioned** | Chain has terminated cleanly by operator action — at least one `Dec` event in the chain, no Cnt or privileged divergence. Decommission is unconditionally terminal. | None. All submissions rejected with `DecommissionedSel`. |

State is computed from the chain's events, never tracked as a separate flag. The `SelVerification` token surfaces:
- `diverged_at_version: Option<u64>` — first version with multiple events, or `None` if linear.
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `last_governance_version: Option<u64>` — version of the most recent `Sea`/`Rpr` (the "evaluation seal").
- `last_identity_event: Option<Digest256>` — derived aggregate: the highest IEL event (in IEL chain order) that any SEL event in the chain has bound to. Computed across all events; not used as a watermark gate. New event acceptance is gated by per-event parent-monotonic on `identity_event`, applied per branch (see [verification.md](verification.md) and [../iel/event-log.md §What parent-monotonic blocks](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt)).

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `identity` (IEL prefix). Permissionless — deterministic prefix derivation; no auth gate. | None at v0; chain advances require IEL-resolved authorization at v1+. | No |
| `Upd` | Normal update — append content. | `auth_policy` resolved through `identity_event`. | No |
| `Sea` | Seal — governance evaluation; advances the seal and (typically) advances its branch's tip `identity_event` to the IEL's current event, closing the stale-binding window for subsequent same-branch events. No field evolution (policies live on IEL). | `governance_policy` resolved through `identity_event`. | No |
| `Rpr` | Repair — advances the seal AND resolves non-privileged divergence. Mode 1: `Rpr.previous` is a branch tip at `v_d`, Rpr extends it at `v_{d+1}`, the other branch archived. Mode 2: `Rpr.previous = v_{d-1}.said`, Rpr lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). | `governance_policy` resolved through `identity_event`. | No |
| `Cnt` | Contest — terminal due to authority conflict. | `governance_policy` resolved through `identity_event`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governance_policy` resolved through `identity_event`. | **Yes** |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true`.

For per-kind field rules and typical chain shapes, see [events.md](events.md). SEL has no `Est` kind — identity rooting eliminates the optional-governance-at-Icp dance.

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Upd` event at v1 in the same batch. SEL Icp is permissionless (deterministic prefix derivation for lookup); paired with the v1 Upd, the chain is born with content, an `identity_event` binding, and the first policy-enforced event. See [events.md §Inception batch rule](events.md#inception-batch-rule).

## Authorization via IEL — and Why That's Enough

SELs do not declare or evolve their own authorization policies. Every authorization decision routes through the IEL the chain is bound to:

- **`Upd`** is authorized iff anchored under the IEL's tracked `auth_policy` resolved through the SEL event's `identity_event`.
- **`Sea` / `Rpr` / `Cnt` / `Dec`** is authorized iff anchored under the IEL's tracked `governance_policy` resolved through `identity_event`.

The IEL primitive is responsible for the immunity rule and the anchor-non-poisonability guarantees that today's SEL spent considerable design effort on. SEL inherits stability for free: every IEL event referenced by an SEL binding has its policy SAIDs immune (IEL submit and verification gates enforce this), so the policy contents are fixed for the lifetime of the chain. See [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability) and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability).

The cross-chain validation rules — same at submit, gossip, bootstrap, and re-verification — are documented at [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules). They include per-event parent-monotonic on `identity_event` applied per branch (each event's `identity_event` must be at-or-after its parent event's `identity_event` in IEL chain order; branches with different parent-chains do not constrain each other). This rule is SEL-specific — KEL and IEL have no separate field referencing another chain's authorization context, so no analog rule applies to them.

## Trust Caveat — Recovered or Contested Anchoring KELs

The seal property and the anchoring model give *structural* guarantees against poisoning (via IEL's immunity rule) and gossip races (terminal states are deterministic across nodes). They give *partial* guarantees when a participating KEL is later recovered, and *no* guarantees when a participating KEL has been contested.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the branch the Rec extends stay (`rec` archives only the other branch); anchors on the now-archived branch do not. This applies to anchors of any kind — SEL governance evaluations, SEL writes, IEL evolutions.

Implications for SEL consumers:

- A past SEL event whose authorizing anchor was placed on the surviving branch of the anchoring KEL: re-verifies cleanly post-`rec`.
- A past SEL event whose authorizing anchor was placed on the archived branch: may *fail* re-verification. The recovery mechanism has reverted that branch in the underlying KEL, and the reversal propagates to dependent SELs.

This is observable, not hidden — the chain mathematics make the post-`rec` state visible. The consumer's runtime trust judgement is: when a participating KEL has `rec` history, re-verify the SEL (and the IEL it binds to) and treat past state with caution proportionate to what survives.

**A contested anchoring KEL is whole-chain-suspect.** Once the participating KEL has been contested (any privileged-divergence on it, or explicit Cnt), no anchors anchored under it can ground new trust decisions. Past SEL evaluations that depend on a contested KEL lose their authorization basis; cascade-reincept applies (the dependent IEL and SEL must reincept against a different anchoring KEL).

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain transitions per the privileged-divergence rule:
- If the divergent set contains a privileged event (`Sea`/`Rpr`/`Cnt`/`Dec`) — directly to **Contested** (terminal).
- If the divergent set is non-privileged (only `Upd` events) — to **Divergent (non-privileged)**, recoverable via `Rpr`.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

**Race-vs-takeover framing.** Divergence on a SEL — two events at the same version — can arise from a federation race (two parties with valid `auth_policy` submitting concurrent `Upd`s, or two governance-authorized parties submitting concurrent `Sea`/`Rpr`) or a takeover (a second party whose access was acquired via threshold compromise). The chain shape records the divergence in the data; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; the trust model degrades uniformly.

**Concurrent extensions** (race, same-batch fork): two events with the same `previous` land at the same version. Divergence is created at the moment of submission. The proactive governance evaluation rule (`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`) bounds the post-`d` window for non-privileged-divergent chains to one page.

The divergence invariant guarantees:
- **Non-privileged divergent set** at version `d` (event kinds limited to `Upd`): max 2 events. Recoverable via `Rpr`.
- **Privileged divergent set** at version `d` (at least one event is governance-authorized — `Sea`/`Rpr`/`Cnt`/`Dec`): max 3 events (2 non-privileged that arrived first via concurrent `Upd` extension + 1 privileged that landed via the upgrade rule and triggered the contested transition; OR 2 events at least one of which is privileged from the start). Contested-terminal.
- The post-`d` window for non-privileged divergence is bounded by the proactive evaluation rule (one page).
- Every event lives at a version at-or-after the chain's last evaluation seal (parent version ≥ seal). The seal-cap keeps fork-creation in the post-seal window where the parent's auth context is current. Combined with per-event parent-monotonic on `identity_event` (each event's `identity_event` must be at-or-after its parent's), this prevents stale-IEL-policy holders from extending an existing branch with a regressed `identity_event`.

### Why SEL has Rpr (and IEL doesn't)

SEL divergence on `Upd` events happens at the auth-policy layer: multiple parties with auth (e.g., multiple endorsers in a `Threshold` policy) can race conflicting `Upd` submissions. `Rpr` is governance-authorized — a higher-bar authority than the auth-authorized fork — and resolves the divergence by archiving the branch not on `Rpr.previous`'s walkback. The asymmetry `Rpr` exploits is between auth and governance authority, not between protocol-distinguished operator and adversary.

IEL has no analog because every IEL event after Icp is governance-authorized; there is no auth-vs-governance asymmetry for `Rpr` to exploit. See [../iel/event-log.md §Why no `Rpr`](../iel/event-log.md#why-no-rpr).

## Repair (Rpr)

Repair resolves a non-privileged-divergent SEL by archiving all events at `version >= diverged_at` not on `Rpr.previous`'s walkback, then appending the `Rpr` (which advances the seal). `Rpr.previous` takes one of two shapes:

1. **`Rpr.previous` is a branch tip at `v_d`.** Rpr extends that branch at `v_{d+1}`. The discriminator's walkback from `Rpr.previous` reaches the surviving-branch tip at `v_d`; events on the other branch are archived. Use case: one of the two branches at `v_d` is the operator's legitimate content; the operator preserves it via Rpr.
2. **`Rpr.previous` is `v_{d-1}` (the divergence ancestor).** Rpr lands at `v_d`. The discriminator's walkback from `Rpr.previous` stops immediately (version drops below `diverged_at`); all events at `version >= d` (both branches) are archived. Rpr is the only event at `v_d` after the discriminator runs. Use case: both branches at `v_d` are adversary-planted (the operator's tip is still at `v_{d-1}`); the operator replaces `v_d` entirely with their own Rpr.

Both modes are handled uniformly by `truncate_and_replace` — the walkback structure determines which events get archived without a separate code path per mode.

The asymmetry between auth-only `Upd`s in the divergent set and the governance-authorized `Rpr` is what lets `Rpr` resolve the divergence (`governance_policy` is structurally a higher bar than `auth_policy`). Cnt shares the Mode-2 parent shape (`previous = v_{d-1}.said`, lands at `v_d`) but has a different effect: Cnt joins the existing divergent set as a 3rd event at `v_d` WITHOUT archival, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. The kind discriminator (Rpr vs Cnt) determines whether the chain repairs (archival) or terminates (no archival). See [§Contest (Cnt)](#contest-cnt).

### Builder boundary derivation

`SadEventBuilder::repair()` derives the boundary uniformly: `boundary = surviving_tip.version` (the tip the operator's `Rpr` will extend), regardless of whether the chain is divergent or merely behind. The `Rpr` is built as `SadEvent::rpr(boundary)`, producing:
- `Rpr.previous = boundary.said`
- `Rpr.version = boundary.version + 1`
- `Rpr.content = boundary.content` (preservation rule; Rpr does not mutate content)
- `Rpr.identity_event = current IEL governance-establishing event`

### Pending events bundling

Pending events (events the builder staged but never successfully flushed — typically because the server rejected the batch with "Chain is divergent — repair required") are operator-staged in-progress work. `repair()` bundles pending events into the submission batch:
- The batch ships as `[pending..., Rpr]`.
- `Rpr` extends the LAST pending event (or the verified tip if pending is empty).
- The server processes the batch atomically — pending events land first, then `Rpr` adopts them as part of the post-repair chain. Bundled pending events are verified server-side on submit like any other event.

Whenever pending is non-empty, the application SHOULD display it to the user. The library cannot algorithmically decide whether stale-looking pending should bundle or be discarded — that requires human inspection. The library bundles pending by default; the user-facing decision (bundle vs. discard vs. selectively-discard) is application-level.

KEL bundles symmetrically — its lifecycle ops (`recover`/`contest`/`rotate_recovery`/`decommission`) ride `[missing..., pending..., Rec/Cnt/Ror/Dec, ?Rot]`. See [../kel/event-log.md §Pending events bundling](../kel/event-log.md#pending-events-bundling).

> **Future work**: persist pending across CLI sessions so a crash mid-collection doesn't lose accumulated work. Out of scope for the initial implementation; the in-memory pending model suffices once bundling is correct.

### Server-side discriminator

`truncate_and_replace` discriminates the surviving branch (the one the Rpr extends) from the archived branch using the `Rpr.previous` walkback pattern (mirrors KEL's `archive_adversary_chain`):

1. Detect repair: any new event after dedup has `kind = Rpr`.
2. Compute archive lower bound `L = first_divergent_version(prefix).unwrap_or(Rpr.version)`.
3. **Single page fetch**: events at `version >= L` for the prefix, ordered `(version ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and IEL-resolved authorization (which fetches and verifies the signed `ixn` anchors in the controlling KELs). Verification failure aborts repair — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — bundled pending events may be referenced by `Rpr.previous`).
6. **Walkback**: starting at `Rpr.previous`, follow `event.previous` links through the map, accumulating the surviving-branch SAIDs for every event with `version >= L`. Stop when version drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (governance seal caps the walk well below this).
7. **Archive**: page events at `version >= L` whose SAID is NOT on the surviving-branch walkback. Insert into `sad_event_archives` and create `SelRepairEvent` link rows.
8. **Delete** archived events from `sad_events` by SAID (NOT by version range — surviving-branch events at the same versions must remain).
9. Insert the batch's new events: pending first, then `Rpr`.

### Bounds

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63` caps the chain since the last `Sea`/`Rpr`/`Cnt`/`Dec` to 63 non-evaluation events. Repair cannot truncate at or before the evaluation seal (`from_version <= last_governance_version` is rejected). One page (limit 64) covers both branches and the bundled `[pending..., Rpr]`.

## Contest (Cnt)

Contest is the terminal state for SEL — the operator cannot defeat a party who has demonstrated `governance_policy` authority on the bound IEL (or the chain is otherwise unrecoverable). `Cnt` freezes the SEL.

### Algorithmic trigger — `ContestRequired`

The merge engine returns `ContestRequired { reason }` when:
- The submitted event is non-terminal AND non-Rpr.
- The event's version is `<= last_governance_version` (the submitter's view is at-or-before the evaluation seal — someone with governance authority advanced the seal past the submitter's view).
- The chain is not divergent (divergence routes to `RepairRequired` instead).

This mirrors KEL's `ContestRequired` shape: the privileged primitive (here, governance evaluation) has been used, and safe normal-flow continuation is no longer possible. See [../kel/event-log.md §Contest (Cnt)](../kel/event-log.md#contest-cnt) for the structural parallel.

### Cnt placement

`Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain (creates fresh divergence at the tip's version), or `v_{d-1}` on a divergent chain (the divergence ancestor; freeze-on-divergence keeps the shorter branch single-event with its tip at `v_d`, so its `v_{tip-1}` is `v_{d-1}` — same `v_{tip-1}` rule, different chain shape). On a divergent chain, Cnt joins the existing divergent set as a third event at `v_d` via the upgrade rule. Cross-node propagation works because `v_{d-1}` is structurally shared (lands cleanly before any divergence).

Cnt is privileged (governance-authorized). Its presence in any divergent set triggers the privileged-divergence-is-terminal rule — the chain becomes contested-terminal.

**Distinction from Rpr.** Cnt and Rpr's Mode 2 (Rpr extending `v_{d-1}` at `v_d`) share the same parent shape but have different effects. Rpr.Mode-2 archives the existing events at `v_d` via the discriminator → chain becomes non-divergent with Rpr as the new `v_d` event (repair; chain continues). Cnt does NOT archive — it joins the existing divergent set as a 3rd event at `v_d`, privileged-divergence-is-terminal fires, chain becomes contested-terminal (chain ends). Submitting `Cnt` with `previous = v_{d-1}.said` is what creates a contest; submitting `Rpr` with `previous = v_{d-1}.said` is what creates a Mode-2 repair.

See [../security-invariant.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../security-invariant.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

Authorization is the same IEL-resolved `governance_policy` required to accept `v_{tip}` — i.e., the policy resolved through `v_{tip-1}`'s `identity_event` binding (which resolves to whichever IEL event was current when `v_{tip-1}` landed). Authorization failure is HARD — a `Cnt` whose anchor does not satisfy the resolved governance_policy is rejected by the verifier; the chain stays at its prior state. (The general invariant — any event with failed auth is rejected — applies.) Operator discipline (advancing the live branch's tip `identity_event` via `Sea` after IEL governance evolves) keeps the resolved policy current.

### Server semantics

- Verify `Cnt`'s structure and IEL-resolved governance authorization at `v_{tip-1}` (HARD).
- Insert `Cnt`. **No archival** — the chain itself is the record (existing events preserved alongside Cnt).
- Cnt is privileged → its presence in the divergent set triggers `is_contested = true` via the privileged-divergence-is-terminal rule. All future submissions rejected with `ContestedSel`.
- On a linear chain, Cnt's insertion creates fresh divergence at the tip's version (2 events at that version: existing tip + Cnt); privileged-divergence rule fires immediately. On an already-divergent chain, Cnt becomes the 3rd event at `v_d` via the upgrade rule.

### Builder

`SadEventBuilder::contest()`:
- Pre-flight: `verify_server_chain_pre_action` (full client-side server-chain re-verification).
- Bundles pending events into the batch.
- Builds `Cnt.previous = v_{tip-1}.said` (parent of linear tip; or `v_{d-1}` on a divergent chain — freeze-on-divergence keeps the shorter branch single-event so its `v_{tip-1}` is `v_{d-1}`, the divergence ancestor; same rule, different chain shape). The lower-SAID tip-selection logic is no longer needed — `v_{tip-1}` is well-defined.
- Resolves authorization via `v_{tip-1}`'s IEL-resolved governance policy and constructs the anchor accordingly.
- Submits `[pending..., Cnt]`.
- On success: builder transitions to a contested local state, refuses further staging.
- **No `contest_with_iel_event_said` override.** When the bound IEL has terminated, the SEL stays in its last state — there is no escape hatch to bind `Cnt` against a stale IEL event. Consumers judge the SEL's status via the IEL's terminal status; the operator's response is reincept the SEL under a new IEL.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated chain abandonment. Same shape as `Cnt` but no authority conflict — owner explicitly ends the chain.

### Server semantics

- Verify `Dec`'s structure, governance authorization.
- Insert `Dec`. No archival.
- Any `Dec` in the chain → `is_decommissioned = true`. All future submissions rejected with `DecommissionedSel` (Dec is privileged → seals immediately → seal-cap forbids any later fork → no Cnt can land after Dec).

### Builder

`SadEventBuilder::decommission()`:
- Same pre-flight as `contest()`.
- Bundles pending. Builds `Dec` extending the last bundled event; submits `[pending..., Dec]`.

## Server-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive matrix and multi-node correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

Sealed/unsealed predicate (used in the divergent rows): a chain is **sealed** iff `last_governance_version >= first_divergent_version`; otherwise **unsealed**.

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | non-terminal events | Append. Seal advances on `Sea`/`Rpr`. |
| Linear (active) | `Cnt` (`previous = v_{N-1}.said`) | Insert; creates divergence at `v_N` (existing tip + Cnt); privileged-divergence rule fires; chain becomes contested-terminal. |
| Linear, overlap (fork, non-privileged events) | concurrent `Upd` | Insert second event at `v_d`; chain becomes Divergent (non-privileged); recoverable via `Rpr`. |
| Linear, overlap (fork, includes privileged) | concurrent governance event | Insert second event at `v_d`; privileged-divergence rule fires; chain becomes contested-terminal. |
| Linear, post-evaluation-seal | non-terminal/non-`Rpr`/non-`Cnt` with valid kind-relevant auth | `ContestRequired { reason }` (algorithmic trigger). |
| Linear (any) | `Dec` | Insert at tip, mark decommissioned. |
| Divergent (non-privileged), unsealed | `Rpr` | Discriminator-driven repair. Rpr.Mode-1: `Rpr.previous` is a branch tip at `v_d`, Rpr extends it at `v_{d+1}`, the other branch archived. Rpr.Mode-2: `Rpr.previous = v_{d-1}.said`, Rpr lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). `Repaired`. |
| Divergent (non-privileged) | `Cnt` (`previous = v_{d-1}.said`, joins divergent set via upgrade rule) | Insert as 3rd event at `v_d`; chain becomes contested-terminal. |
| Divergent (non-privileged) | other events (`Upd`/`Sea`/`Dec`) | `RepairRequired`. Chain unchanged. |
| Contested | any | Rejected with `ContestedSel`. |
| Decommissioned | any | Rejected with `DecommissionedSel`. |
| Chain ends at Icp | `[Icp]` alone (no v1 `Upd`) | Rejected by the verifier (`SelVerifier::finish_internal` → `IncompleteInception`). |

The full sealed/unsealed × per-kind matrix (including `BadIdentityBinding` and `IelDivergent` cross-chain rejections) is in [reconciliation.md §Local Submissions Matrix](reconciliation.md#local-submissions-matrix).

## Implementation Map

**Code:**
- `lib/kels/src/types/sad/event.rs` — `SadEventKind` enum (`Icp`/`Upd`/`Sea`/`Rpr`/`Cnt`/`Dec`); `validate_structure` per per-kind field rules. The inception batch rule is a chain-validity rule lifted into the verifier (it is not per-event, so it has no place in `validate_structure`).
- `lib/kels/src/types/sad/verification.rs` — `SelVerifier`, `SelVerification`. Branch state holds the branch tip's `identity_event` for the per-event parent-monotonic check on the next event extending the branch; authorization policies are not tracked per branch (they resolve through IEL on demand). The chain-wide `last_identity_event` is a derived aggregate (max across branches), not a flowing watermark gate. `finish_internal` enforces the inception batch rule (`IncompleteInception` whenever any branch tip is `Icp`).
- `lib/kels/src/sad_builder.rs` — `SadEventBuilder` with `update()`, `seal()`, `repair()`, `contest()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification (factored helper `verify_server_chain_pre_action`).
- `services/sadstore/src/handlers.rs` — submit handler: structural + IEL-resolved-authorization gate, terminal-state gate, divergence routing, `ContestRequired` algorithmic trigger.
- `services/sadstore/src/repository.rs` — `truncate_and_replace` discriminator (single-page fetch + resume-verify trust gate + walkback + archival).

**Notable changes from the dual-policy era:**
- No `Est` kind. SEL events carry no first-class authorization-policy fields.
- No per-branch tracking of authorization policies on branch state.
- No SEL-side immunity rule (lives on IEL).
- New `identity_event` field on every v1+ event.
- Per-branch `identity_event` tracking (each branch's tip's `identity_event` for the per-event parent-monotonic check on the next event extending that branch); chain-wide `last_identity_event` is a derived aggregate.
- New `[Icp, Upd]` minimum inception batch rule.

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/event-log.md](../iel/event-log.md) — IEL counterpart; SELs bind to IEL events.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference.
- [../sadstore.md](../sadstore.md) — SADStore service architecture.
- [../policy.md](../policy.md) — Policy DSL, anchoring model.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
