# SAD Event Log (SEL) — Lifecycle, Repair, Contest, Decommission

> Source-of-truth design doc for the SEL lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing and `truncate_and_replace` discriminator), and [verification.md](verification.md) (SelVerifier algorithm). For the SADStore service architecture (object store, custody, gossip), see [../../infrastructure/sadstore.md](../../infrastructure/sadstore.md).

The SAD Event Log (SEL) is a per-prefix chain of `SadEvent` records describing the evolving state of a SAD object (typically a publication, credential template, custody record, or other governance-managed artifact). SELs are **identity-rooted** — every SEL binds at inception to an Identity Event Log (IEL) and resolves its per-event authorization through specific IEL events. Authority over the chain is asserted by anchoring `ixn` events in KELs identified by the IEL's currently-tracked `authPolicy` (for `Upd`) or `governancePolicy` (for `Sea`/`Rpr`/`Cnt`/`Dec`).

> **Read first.** SEL is identity-rooted, so the IEL-side rules govern much of its behavior. Before this doc, read [../iel/events.md](../iel/events.md) (IEL primitive) and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability) (the unified validation rules governing the binding).

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, latest tip extends cleanly. | Yes — at v=1 `Est`; at v=2+ `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec` (per IEL-resolved authorization). |
| **Divergent (non-privileged)** | Two events at serial `d`, both non-privileged (e.g., `Upd`-`Upd` at v ≥ 2, or `Est`-`Est` at v = 1). Recoverable via `Rpr`. | `Rpr` (archives one branch; chain resumes); `Cnt` (joins set at `v_d` via upgrade rule → Contested). Bundled pending permitted. See [§Repair (Rpr)](#repair-rpr) and [§Cnt mechanics](#cnt-mechanics). |
| **Contested** | Chain terminated — privileged event in a divergent set, or explicit `Cnt` on a linear chain. SEL privileged: `Sea`/`Rpr`/`Cnt`/`Dec`. See [§Cnt mechanics](#cnt-mechanics). | None. All submissions rejected. |
| **Decommissioned** | Chain terminated cleanly by operator — at least one `Dec`, no Cnt or privileged divergence. | Gossip-delivered `Cnt` → Contested per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec); all other submissions rejected with `DecommissionedSel`. |

State is computed from the chain's events, never tracked as a separate flag. The `SelVerification` token surfaces:
- `divergenceAncestor: Option<Digest256>` — SAID of `v_{d-1}` on a divergent chain (`None` on linear).
- `is_contested: bool` — any `Cnt` event in the chain.
- `is_decommissioned: bool` — any `Dec` event in the chain.
- `lastSealAdvancingEvent: Option<Digest256>` — SAID of the most recent `Sea`/`Rpr` (the "evaluation seal").
- `lastIelEvent: Option<Digest256>` — derived aggregate: the highest IEL event (in IEL chain order) that any SEL event in the chain has bound to. Computed across all events; not used as a watermark gate. New event acceptance is gated by per-event parent-monotonic on `ielEvent`, applied per branch (see [verification.md](verification.md) and [../iel/event-log.md §What parent-monotonic blocks](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt)).

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `identity` (IEL prefix). Permissionless — deterministic prefix derivation; no auth gate. | None at v0; chain advances require IEL-resolved authorization at v1+. | No |
| `Est` | Establishment (v1). The first authorization-gated event; carries `ielEvent` binding to the IEL plus the chain's first content. Tier-2 anchored per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation) — raises per-attempt cost on SEL camping. | `authPolicy` resolved through `ielEvent`. | No |
| `Upd` | Normal update (v2+) — append content. | `authPolicy` resolved through `ielEvent`. | No |
| `Sea` | Seal — governance evaluation; advances the seal and (typically) advances its branch's tip `ielEvent` to the IEL's current event, closing the stale-binding window for subsequent same-branch events. No field evolution (policies live on IEL). | `governancePolicy` resolved through `ielEvent`. | No |
| `Rpr` | Repair — advances the seal AND resolves non-privileged divergence. Two parent shapes (branch-tip-extending, divergence-ancestor-extending); see [§Repair (Rpr)](#repair-rpr) for the full algorithm. | `governancePolicy` resolved through `ielEvent`. | No |
| `Cnt` | Contest — terminal due to authority conflict. | `governancePolicy` resolved through `ielEvent`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governancePolicy` resolved through `ielEvent`. | **Yes** |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true`.

For per-kind field rules and typical chain shapes, see [events.md](events.md).

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Est` event at v1 in the same batch. SEL Icp is permissionless (deterministic prefix derivation for lookup); paired with the v1 `Est`, the chain is born with content, an `ielEvent` binding, and the first policy-enforced event. `Est` is tier-2 anchored per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation), raising per-attempt cost against SEL camping. See [events.md §Inception batch rule](events.md#inception-batch-rule).

## Authorization via IEL

SELs do not declare or evolve their own authorization policies. Every authorization decision routes through the IEL the chain is bound to:

- **`Est` / `Upd`** is authorized iff anchored under the IEL's tracked `authPolicy` resolved through the SEL event's `ielEvent`. (`Est` is the v=1 binding-establishment event and is tier-2 anchored per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation); `Upd` is the routine extension at v=2+ and is tier-1 anchored.)
- **`Sea` / `Rpr` / `Cnt` / `Dec`** is authorized iff anchored under the IEL's tracked `governancePolicy` resolved through `ielEvent`.

The IEL primitive carries the immunity rule and the anchor-non-poisonability guarantees SEL depends on; SEL inherits stability for free: every IEL event referenced by an SEL binding has its policy SAIDs immune (IEL submit and verification gates enforce this), so the policy contents are fixed for the lifetime of the chain. See [../iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../iel/event-log.md#evaluation-seal-and-anchor-non-poisonability) and [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability).

The cross-chain validation rules — same at submit, gossip, bootstrap, and re-verification — are documented at [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules). They include per-event parent-monotonic on `ielEvent` applied per branch (each event's `ielEvent` must be at-or-after its parent event's `ielEvent` in IEL chain order; branches with different parent-chains do not constrain each other). This rule is SEL-specific — KEL and IEL have no separate field referencing another chain's authorization context, so no analog rule applies to them.

## Trust Caveat — Recovered or Contested Anchoring KELs

The seal property and the anchoring model give *structural* guarantees against poisoning (via IEL's immunity rule) and gossip races (terminal states are deterministic across nodes). They give *partial* guarantees when a participating KEL is later recovered, and *no* guarantees when a participating KEL has been contested.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the branch the Rec extends stay (`rec` archives only the other branch); anchors on the now-archived branch do not. This applies to anchors of any kind — SEL governance evaluations, SEL writes, IEL evolutions.

Implications for SEL consumers:

- A past SEL event whose authorizing anchor was placed on the surviving branch of the anchoring KEL: re-verifies cleanly post-`rec`.
- A past SEL event whose authorizing anchor was placed on the archived branch: may *fail* re-verification. The recovery mechanism has reverted that branch in the underlying KEL, and the reversal propagates to dependent SELs.

This is observable, not hidden — the chain mathematics make the post-`rec` state visible. The consumer's runtime trust judgement is: when a participating KEL has `rec` history, re-verify the SEL (and the IEL it binds to) and treat past state with caution proportionate to what survives.

**A contested anchoring KEL is whole-chain-suspect.** Once a participating KEL has been contested (any privileged-divergence on it, or explicit Cnt), the anchors it produced cease to ground trust decisions. Whether dependent IEL/SEL events lose their authorization basis depends on (a) whether the contested KEL actually anchored events on those chains, and (b) whether the resolving policy has threshold redundancy that lets it evaluate as satisfied without the contested KEL's contribution. Threshold-redundant policies (`M > N` across distinct custodians) absorb single-member contest — past anchored events stay satisfied via the surviving members; the operator's forward response is governance evolution (`Evl` on the bound IEL) to rotate the contested KEL out of the policy. Cascade-reincept of the IEL or SEL is required only when the chain *itself* is contested, not transitively from a contested anchoring KEL. See [../../protocol-doctrine.md §Adversary Patience and Policy Redundancy](../../protocol-doctrine.md#adversary-patience-and-policy-redundancy).

## Divergence and Freeze

Divergence is detected when two events share the same `previous` SAID. The chain transitions per the privileged-divergence rule:
- If the divergent set contains a privileged event (`Sea`/`Rpr`/`Cnt`/`Dec`) — directly to **Contested** (terminal).
- If the divergent set is non-privileged (only `Upd` events at v ≥ 2, or only `Est` events at v = 1) — to **Divergent (non-privileged)**, recoverable via `Rpr`.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

**Race-vs-takeover framing.** Divergence on a SEL — two events at the same serial — can arise from a federation race (two parties with valid `authPolicy` submitting concurrent `Upd`s, or two governance-authorized parties submitting concurrent `Sea`/`Rpr`) or a takeover (a second party whose access was acquired via threshold compromise). The chain shape records the divergence in the data; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; the trust model degrades uniformly.

**Concurrent extensions** (race, same-batch fork): two events with the same `previous` land at the same serial. Divergence is created at the moment of submission. The proactive governance evaluation rule (`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`) bounds the post-`d` window for non-privileged-divergent chains to one page.

```
Non-privileged Upd-Upd divergence at v_d:

  v0       v1                 v_{d-1}             v_d  ← non-privileged divergent set
[Icp] → [Est] → [Upd] → ... → [Upd_{d-1}] ─┬─ [Upd_a]   previous = v_{d-1}.said
                                           └─ [Upd_b]   previous = v_{d-1}.said

Both events auth-authorized; neither privileged. Chain is non-privileged-divergent →
recoverable via Rpr (governance-authorized; archives one branch via discriminator).
Post-`d` window capped at MAX_NON_EVALUATION_EVENTS = 63 events on either branch.


Privileged divergence at v_d (e.g., Upd-Sea or Sea-Cnt):

  v0       v1                 v_{d-1}             v_d  ← privileged divergent set
[Icp] → [Est] → [Upd] → ... → [Upd_{d-1}] ─┬─ [Upd]            ┐
                                           └─ [Sea or Cnt]     ┴── contested-terminal
                                                                    (privileged-divergence rule)

Any privileged event in the set fires privileged-divergence-is-terminal at first
observation. Chain transitions to Contested. No further events accepted at v_d
or beyond — contested-state gate rejects subsequent submissions including gossip-
delivered events.
```

The divergence invariant guarantees:
- **Non-privileged divergent set** at serial `d` (event kinds limited to `Upd` at v ≥ 2, or `Est` at v = 1): max 2 events. Recoverable via `Rpr`.
- **Privileged divergent set** at serial `d` (at least one event is governance-authorized — `Sea`/`Rpr`/`Cnt`/`Dec`):
  - **3-event variant** — 2 non-privileged arrived first (concurrent `Upd` extension); the 3rd privileged event landed via the upgrade rule and triggered the contested transition.
  - **2-event variant** — at least one of the two events was privileged from the start.
  - Both: contested-terminal.
- The post-`d` window for non-privileged divergence is bounded by the proactive evaluation rule (one page).
- Every event lives at a serial at-or-after the chain's last evaluation seal (`event_serial >= seal_serial`; see [../../protocol-doctrine.md §Forks are Seal-Bounded](../../protocol-doctrine.md#forks-are-seal-bounded)). The seal-cap keeps fork-creation in the post-seal window where the parent's auth context is current. Combined with per-event parent-monotonic on `ielEvent` (each event's `ielEvent` must be at-or-after its parent's), this prevents stale-IEL-policy holders from extending an existing branch with a regressed `ielEvent`. Cnt joining a divergent set at v_d on a chain whose tip is itself the most recent privileged event (a `Sea`-tipped SEL) lands at `event_serial = d = seal_serial`; the seal-cap admits this parent-at-(seal − 1) boundary case (parent at v_{d-1}, event at v_d = seal).

### The asymmetry exploited by Rpr

SEL divergence on `Est`/`Upd` events happens at the auth-policy layer: multiple parties with auth (e.g., multiple endorsers in a `Threshold` policy) can race conflicting submissions — `Est`-`Est` at v=1 (the brand-new-chain race) or `Upd`-`Upd` at v ≥ 2.

`Rpr`'s asymmetry is purely auth-vs-governance: a higher-bar authority (governance) resolves a lower-bar fork (auth) via archival of the branch not on `Rpr.previous`'s walkback. The protocol does not distinguish "the legitimate operator" from "the adversary" — both branches were authorized under `authPolicy` when they landed; the discriminator is which branch the governance-authorized `Rpr` chose to preserve.

IEL has no analog. Every IEL event is governance-authorized (`Icp` is self-endorsed; `Evl`/`Sea`/`Cnt`/`Dec` resolve against the tracked `governancePolicy`), so there is no auth-vs-governance asymmetry for `Rpr` to exploit. See [../iel/event-log.md §Why no `Rpr`](../iel/event-log.md#why-no-rpr).

## Repair (Rpr)

Repair resolves a non-privileged-divergent SEL by archiving all events at `serial >= divergedAt` not on `Rpr.previous`'s walkback, then appending the `Rpr` (which advances the seal). `Rpr.previous` takes one of two shapes:

1. **Branch-tip-extending shape — `Rpr.previous` is a branch tip at `v_d`.** Rpr extends that branch at `v_{d+1}`. The discriminator's walkback from `Rpr.previous` reaches the surviving-branch tip at `v_d`; events on the other branch are archived. Use case: one of the two branches at `v_d` is the operator's legitimate content; the operator preserves it via Rpr.

   ```
   Pre-state (non-priv divergent at v_d):
       ... → v_{d-1} ─┬─ surviving-branch tip @ v_d
                      └─ other-branch tip     @ v_d

   Rpr construction: rpr.previous = surviving-branch tip's said
                     rpr.serial  = d + 1

   Post-state (linear, repaired):
       ... → v_{d-1} → surviving-branch tip @ v_d → rpr @ v_{d+1}
                     ↑
                     other branch archived
   ```

2. **Divergence-ancestor-extending shape — `Rpr.previous` is `v_{d-1}` (the divergence ancestor).** Rpr lands at `v_d`. The discriminator's walkback from `Rpr.previous` stops immediately (serial drops below `divergedAt`); all events at `serial >= d` (both branches) are archived. Rpr is the only event at `v_d` after the discriminator runs. Use case: both branches at `v_d` are adversary-planted (the operator's tip is still at `v_{d-1}`); the operator replaces `v_d` entirely with their own Rpr.

   ```
   Pre-state (non-priv divergent at v_d, both adversary-planted):
       ... → v_{d-1} ─┬─ adversary-branch-1 tip @ v_d
                      └─ adversary-branch-2 tip @ v_d

   Rpr construction: rpr.previous = v_{d-1}.said
                     rpr.serial  = d

   Post-state (linear, repaired, Rpr is the only event at v_d):
       ... → v_{d-1} → rpr @ v_d
                     ↑
                     both adversary branches archived
   ```

   The divergence-ancestor-extending shape's "both branches" archival is exhaustive by construction: a 3-event divergent set at `v_d` would imply a non-archiving privileged event has already joined via the upgrade rule, transitioning the chain to contested-terminal — Rpr is rejected by the contested-state gate. Rpr applies only to non-privileged 2-event divergent sets at `v_d`; the upgrade rule's privileged-event-joins-divergent-set path is mutually exclusive with the discriminator's archival path. (Symmetric with KEL Recovery — see [../kel/event-log.md §Recovery (Rec)](../kel/event-log.md#recovery-rec).)

Both shapes are handled uniformly by `truncate_and_replace` — the walkback structure determines which events get archived without a separate code path per shape.

The asymmetry between auth-only `Upd`s in the divergent set and the governance-authorized `Rpr` is what lets `Rpr` resolve the divergence (`governancePolicy` is structurally a higher bar than `authPolicy`). Cnt shares the divergence-ancestor-extending parent shape (`previous = v_{d-1}.said`, lands at `v_d`) but has a different effect: Cnt joins the existing divergent set as a 3rd event at `v_d` WITHOUT archival, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. The kind discriminator (Rpr vs Cnt) determines whether the chain repairs (archival) or terminates (no archival). See [§Contest (Cnt)](#contest-cnt).

### Builder boundary derivation

`SadEventBuilder::repair()` derives the boundary uniformly: `boundary = surviving_tip.serial` (the tip the operator's `Rpr` will extend), regardless of whether the chain is divergent or merely behind. The `Rpr` is built as `SadEvent::rpr(boundary)`, producing:
- `Rpr.previous = boundary.said`
- `Rpr.serial = boundary.serial + 1`
- `Rpr.content = boundary.content` (preservation rule; Rpr does not mutate content)
- `Rpr.ielEvent = current IEL governance-establishing event`

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
2. Compute archive lower bound `L = first_divergent_serial(prefix).unwrap_or(Rpr.serial)`.
3. **Single page fetch**: events at `serial >= L` for the prefix, ordered `(serial ASC, kind sort_priority ASC, said ASC)`, `limit = MINIMUM_PAGE_SIZE`. One round-trip.
4. **Trust gate**: feed the page through the resume-mode verifier (`SelVerifier::resume(&prefix, &sel_verification).verify_page(&page)`). The verifier checks SAID, prefix, chain linkage, and IEL-resolved authorization (which fetches and verifies the signed `ixn` anchors in the controlling KELs). Verification failure aborts repair — fail-secure on tampered DB rows.
5. Build a SAID-keyed in-memory map of the verified page (and of the batch's own new events not yet on the chain — bundled pending events may be referenced by `Rpr.previous`).
6. **Walkback**: starting at `Rpr.previous`, follow `event.previous` links through the map, accumulating the surviving-branch SAIDs for every event with `serial >= L`. Stop when serial drops below L or said not in map. Bounded by `MINIMUM_PAGE_SIZE` iterations (governance seal caps the walk well below this).
7. **Archive**: page events at `serial >= L` whose SAID is NOT on the surviving-branch walkback. Insert into `sad_event_archives` and create `SelRepairEvent` link rows.
8. **Delete** archived events from `sad_events` by SAID (NOT by serial range — surviving-branch events at the same serials must remain).
9. Insert the batch's new events: pending first, then `Rpr`.

### Bounds

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63` caps the chain since `lastSealAdvancingEvent` to 63 non-evaluation events. `Cnt`/`Dec` satisfy the cap by terminating the chain (no further events admitted; cap-counter rendered moot). Repair cannot truncate at or before the seal (a fork-point at-or-before `lastSealAdvancingEvent` in IEL chain order is rejected). One page (limit 64) covers both branches and the bundled `[pending..., Rpr]`.

## Contest (Cnt)

Contest is the terminal state for SEL — the operator cannot defeat a party who has demonstrated `governancePolicy` authority on the bound IEL (or the chain is otherwise unrecoverable). `Cnt` freezes the SEL.

### Algorithmic trigger — `ContestRequired`

The merge engine returns `ContestRequired { reason }` when:
- The submitted event is non-terminal AND non-Rpr.
- The event is at-or-before `lastSealAdvancingEvent` in chain order (the submitter's view is at-or-before the evaluation seal — someone with governance authority advanced the seal past the submitter's view).
- The chain is not divergent (divergence routes to `RepairRequired` instead).

This mirrors KEL's `ContestRequired` shape: the privileged primitive (here, governance evaluation) has been used, and safe normal-flow continuation is no longer possible. See [../kel/event-log.md §Contest (Cnt)](../kel/event-log.md#contest-cnt) for the structural parallel.

### Cnt mechanics

`Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain (creates fresh divergence at the tip's serial), or `v_{d-1}` on a divergent chain (the divergence ancestor; the new (divergence-causing) branch is single-event at `v_d` by freeze-on-divergence, so its `v_{tip-1}` is `v_{d-1}` — same `v_{tip-1}` rule, different chain shape). The pre-existing branch may have extended past `v_d` before divergence was detected (up to ~63 events per the proactive-evaluation cap), but Cnt's parent rule selects `v_{d-1}` (the new branch's `v_{tip-1}`) because `v_{d-1}` is structurally shared cross-node. On a divergent chain, Cnt joins the existing divergent set as a third event at `v_d` via the upgrade rule. Cross-node propagation works because `v_{d-1}` is structurally shared (lands cleanly before any divergence).

*Scenario 1 — Cnt on a linear chain.* Cnt extends `v_{d-1}` (one before the tip) and lands at `v_d` as sibling of the existing tip, creating fresh divergence. Cnt is privileged, so privileged-divergence-is-terminal fires immediately:

```
  Pre-state:        ... → v_{d-1} → Upd_v_d   (tip)

  Cnt construction: cnt.previous = v_{tip-1}.said = v_{d-1}.said
                    cnt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ Upd_v_d ┐
                                   └─ Cnt     ┴── contested
```

*Scenario 2 — Cnt on an already-divergent SEL.* A non-priv divergent set (e.g., Upd-Upd race) sits at `v_d`. Cnt extends `v_{d-1}` (the divergence ancestor, same as the new branch's `v_{tip-1}`) and joins the divergent set as a 3rd event via the upgrade rule; privileged-divergence-is-terminal fires:

```
  Pre-state:        ... → v_{d-1} ─┬─ Upd_a @ v_d
                                   └─ Upd_b @ v_d

  Cnt construction: cnt.previous = v_{d-1}.said
                    cnt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ Upd_a @ v_d ┐
                                   ├─ Upd_b @ v_d ├── contested
                                   └─ Cnt   @ v_d ┘
```

Cnt is privileged (governance-authorized). Its presence in any divergent set triggers the privileged-divergence-is-terminal rule — the chain becomes contested-terminal.

**Distinction from Rpr.** Cnt and the divergence-ancestor-extending Rpr shape (Rpr extending `v_{d-1}` at `v_d`) share the same parent shape but have different effects. The divergence-ancestor-extending Rpr archives the existing events at `v_d` via the discriminator → chain becomes non-divergent with Rpr as the new `v_d` event (repair; chain continues). Cnt does NOT archive — it joins the existing divergent set as a 3rd event at `v_d`, privileged-divergence-is-terminal fires, chain becomes contested-terminal (chain ends). Submitting `Cnt` with `previous = v_{d-1}.said` creates a contest; submitting `Rpr` with `previous = v_{d-1}.said` creates a divergence-ancestor-extending repair.

See [../../protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

Authorization is the same IEL-resolved `governancePolicy` required to accept `v_{tip}` — i.e., the policy resolved through `v_{tip-1}`'s `ielEvent` binding (which resolves to whichever IEL event was current when `v_{tip-1}` landed). Authorization failure is HARD — a `Cnt` whose anchor does not satisfy the resolved governancePolicy is rejected by the verifier; the chain stays at its prior state. Operator discipline (advancing the live branch's tip `ielEvent` via `Sea` after IEL governance evolves) keeps the resolved policy current.

### Server semantics

- Verify `Cnt`'s structure and IEL-resolved governance authorization at `v_{tip-1}` (HARD).
- Insert `Cnt`. **No archival** — the SEL itself is the record (existing events preserved alongside Cnt).
- Cnt is privileged → its presence in the divergent set triggers `is_contested = true` via the privileged-divergence-is-terminal rule. All future submissions rejected with `ContestedSel`.
- On a linear chain, Cnt's insertion creates fresh divergence at the tip's serial (2 events at that serial: existing tip + Cnt); privileged-divergence rule fires immediately. On an already-divergent chain, Cnt becomes the 3rd event at `v_d` via the upgrade rule.

### Builder

`SadEventBuilder::contest()`:
- Pre-flight: `verify_server_chain_pre_action` (full client-side server-chain re-verification).
- Bundles pending events into the batch.
- Builds `Cnt` per [§Cnt mechanics](#cnt-mechanics) above.
- Resolves authorization via `v_{tip-1}`'s IEL-resolved governance policy and constructs the anchor accordingly.
- Submits `[pending..., Cnt]`.
- On success: builder transitions to a contested local state, refuses further staging.
- **No `contest_with_iel_event_said` override.** When the bound IEL has terminated, the SEL stays in its last state — there is no escape hatch to bind `Cnt` against a stale IEL event. Consumers judge the SEL's status via the IEL's terminal status; the operator's response is reincept the SEL under a new IEL.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated chain abandonment. Same shape as `Cnt` but no authority conflict — owner explicitly ends the chain.

```
Clean lifecycle terminated by Dec:

  v0       v1                v_N    v_{N+1}
[Icp] → [Est] → ... → [Upd_v_N] → [Dec]   ← chain decommissioned at v_{N+1}

  Dec.previous = v_N.said   (extends tip directly; no fresh divergence)
  Dec.serial  = N + 1
```

Dec is privileged but terminal — it does not advance the seal on SEL (`lastSealAdvancingEvent` advances only on `Sea`/`Rpr`; see [../../protocol-doctrine.md §Forks are Seal-Bounded](../../protocol-doctrine.md#forks-are-seal-bounded)). A `Cnt` with `previous = v_{d-1}.said` lands at `v_d` under the override rule — `event_serial >= seal_serial` is satisfied because the seal sits at-or-before `v_{d-1}` (Dec didn't move it). See [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec). No archival — `Dec` remains on the chain as forensic record.

### Server semantics

- Verify `Dec`'s structure, governance authorization.
- Insert `Dec`. No archival.
- Any `Dec` in the chain → `is_decommissioned = true`. Subsequent submissions rejected with `DecommissionedSel`, with one exception: a `Cnt` with `previous = v_{d-1}.said` overrides Dec per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) and transitions the chain to Contested.

### Builder

`SadEventBuilder::decommission()`:
- Same pre-flight as `contest()`.
- Bundles pending. Builds `Dec` extending the last bundled event; submits `[pending..., Dec]`.

## Merge-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive matrix and multi-node correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

> **Sealed vs unsealed (used in the divergent rows of the table below):** a chain is **sealed** iff `lastSealAdvancingEvent` is at-or-after the divergence point in chain order (i.e., a `Sea`/`Rpr` landed at-or-after `v_d`); otherwise **unsealed**.

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | non-terminal events | Append. Seal advances on `Sea`/`Rpr`. |
| Linear (active) | `Cnt` (`previous = v_{d-1}.said`) | Insert; creates divergence at `v_d` (existing tip + Cnt); privileged-divergence rule fires; chain becomes contested-terminal. |
| Linear, overlap (fork, non-privileged events) | concurrent `Upd` (v ≥ 2) or concurrent `Est` (v = 1, brand-new-chain race) | Insert second event at `v_d`; chain becomes Divergent (non-privileged); recoverable via `Rpr`. |
| Linear, overlap (fork, includes privileged) | concurrent governance event | Insert second event at `v_d`; privileged-divergence rule fires; chain becomes contested-terminal. |
| Linear, post-evaluation-seal | non-terminal/non-`Rpr`/non-`Cnt` with valid kind-relevant auth | `ContestRequired { reason }` (algorithmic trigger). |
| Linear (any) | `Dec` | Insert at tip, mark decommissioned. |
| Divergent (non-privileged), unsealed | `Rpr` | Discriminator-driven repair. Branch-tip-extending Rpr: `Rpr.previous` is a branch tip at `v_d`, Rpr extends it at `v_{d+1}`, the other branch archived. Divergence-ancestor-extending Rpr: `Rpr.previous = v_{d-1}.said`, Rpr lands at `v_d`, both branches at `v_d` archived (used when both branches are adversary-planted). `Repaired`. |
| Divergent (non-privileged) | `Cnt` (`previous = v_{d-1}.said`, joins divergent set via upgrade rule) | Insert as 3rd event at `v_d`; chain becomes contested-terminal. |
| Divergent (non-privileged) | other events (`Upd`/`Sea`/`Dec`) | `RepairRequired`. Chain unchanged. |
| Contested | any | Rejected with `ContestedSel`. |
| Decommissioned | `Cnt` whose `previous` matches `v_{d-1}.said` of some in-chain event (Cnt creates or joins a divergent set at `v_d`) | Cnt overrides Dec per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec); privileged-divergence-is-terminal fires; chain becomes Contested. Two shapes converge: Case A — Cnt's "other event" at `v_d` is `Dec` itself; Case B — Cnt's "other event" is the pre-Dec tip at `v_d`, and Dec sits at `v_{d+1}` on the surviving branch. |
| Decommissioned | any other submission | Rejected with `DecommissionedSel`. |
| Chain ends at Icp | `[Icp]` alone (no v1 `Est`) | Rejected by the verifier (`SelVerifier::finish_internal` → `IncompleteInception`). |

The full sealed/unsealed × per-kind matrix (including `BadIdentityBinding` and `IelDivergent` cross-chain rejections) is in [reconciliation.md §Local Submissions Matrix](reconciliation.md#local-submissions-matrix).

## Implementation Map

**Code:**
- `lib/kels/src/types/sad/event.rs` — `SadEventKind` enum (`Icp`/`Est`/`Upd`/`Sea`/`Rpr`/`Cnt`/`Dec`); `validate_structure` per per-kind field rules. The inception batch rule is a chain-validity rule lifted into the verifier (it is not per-event, so it has no place in `validate_structure`).
- `lib/kels/src/types/sad/verification.rs` — `SelVerifier`, `SelVerification`. Branch state holds the branch tip's `ielEvent` for the per-event parent-monotonic check on the next event extending the branch; authorization policies are not tracked per branch (they resolve through IEL on demand). The chain-wide `lastIelEvent` is a derived aggregate (max across branches), not a flowing watermark gate. `finish_internal` enforces the inception batch rule (`IncompleteInception` whenever any branch tip is `Icp`).
- `lib/kels/src/sad_builder.rs` — `SadEventBuilder` with `update()`, `seal()`, `repair()`, `contest()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification (factored helper `verify_server_chain_pre_action`).
- `services/sadstore/src/handlers.rs` — submit handler: structural + IEL-resolved-authorization gate, terminal-state gate, divergence routing, `ContestRequired` algorithmic trigger.
- `services/sadstore/src/repository.rs` — `truncate_and_replace` discriminator (single-page fetch + resume-verify trust gate + walkback + archival).

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/event-log.md](../iel/event-log.md) — IEL counterpart; SELs bind to IEL events.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference.
- [../../infrastructure/sadstore.md](../../infrastructure/sadstore.md) — SADStore service architecture.
- [../../features/policy.md](../../features/policy.md) — Policy DSL, anchoring model.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
