# SEL Events: Per-Kind Reference

Pure structural reference for SAD Event Log (SEL) event kinds, per-kind field rules, and typical chain shapes. SELs are **identity-rooted**: every SEL binds at inception to an Identity Event Log (IEL) and resolves its authorization policies through that IEL — SEL has no `auth_policy` or `governance_policy` fields of its own (those live on IEL; see [../iel/events.md](../iel/events.md)).

**What this doc covers:** per-kind field rules, prefix derivation, the inception batch rule, camping defense, the cross-chain binding to IEL, content semantics, and the evaluation bound. For chain lifecycle (states, divergence, repair, contest, decommission), see [event-log.md](event-log.md); for storage and API, see [../../infrastructure/sadstore.md](../../infrastructure/sadstore.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/sel/v1/events/icp` | Inception (v0). Declares `identity`. Seeds prefix derivation via `(identity, topic)`. Permissionless — no authorization gate. |
| `Est` | `kels/sel/v1/events/est` | Establishment (v1). The first authorization-gated event; carries `iel_event` binding to the IEL plus the chain's first content. Tier-2 anchored per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation) — raises per-attempt cost on SEL camping. |
| `Upd` | `kels/sel/v1/events/upd` | Normal update (v2+) — append content to the chain. Routine, tier-1 anchored. |
| `Sea` | `kels/sel/v1/events/sea` | Seal — governance evaluation. Advances `last_seal_advancing_event`. No policy-field evolution (policies live on IEL); may advance `iel_event` to a newer IEL state. Back-to-back Sea allowed only when the new Sea **strictly advances** `iel_event` — see [../../protocol-doctrine.md §Shape constraints on Sea](../../protocol-doctrine.md#shape-constraints-on-sea). |
| `Rpr` | `kels/sel/v1/events/rpr` | Repair — resolves non-privileged divergence and seals. Extends a tip at `v_{d+1}`; discriminator-driven archival of the events on the branch not extended. |
| `Cnt` | `kels/sel/v1/events/cnt` | Contest — terminal due to authority conflict. No archival. |
| `Dec` | `kels/sel/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction (resolved through the bound IEL event). `Est` is `auth_policy`-gated (like `Upd`) but tier-2 anchored (unlike `Upd`).

## Per-Kind Field Rules

`SadEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top.

### Structural fields

| Kind | serial | previous | identity | topic | iel_event | content |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | forbidden | forbidden |
| `Est` | `== 1` | required | forbidden | **required** | **required** | **required** |
| `Upd` | `>= 2` | required | forbidden | **required** | **required** | **required** |
| `Sea` | `>= 2` | required | forbidden | **required** | **required** | preserved |
| `Rpr` | `>= 2` | required | forbidden | **required** | **required** | preserved |
| `Dec` | `>= 2` | required | forbidden | **required** | **required** | preserved |
| `Cnt` | `>= 2` | required | forbidden | **required** | **required** | preserved |

The `identity` field lives on `Icp` only; subsequent events inherit it from chain context. The chain's bound IEL is fixed at inception and cannot be changed. The `topic` field — present on every event — is the SAD content-kind namespace (e.g., `kels/sad/v1/keys/mlkem`) and seeds the SEL prefix derivation `(identity, topic) → prefix` on `Icp`; subsequent events carry the same topic, enforced by the verifier's Topic consistency check (see [verification.md §Per-Event Checks](verification.md#per-event-checks)).

### Authorization and anchor

| Kind | authorization | KEL anchor kind | sort_priority |
|---|---|---|---|
| `Icp` | none (permissionless) | none | 0 |
| `Est` | auth (via IEL) | `Rot` (tier 2) | 1 |
| `Upd` | auth (via IEL) | `Ixn` (tier 1) | 2 |
| `Sea` | governance (via IEL) | `Rot` (tier 2) | 3 |
| `Rpr` | governance (via IEL) | `Ror` (tier 3) | 4 |
| `Dec` | governance (via IEL) | `Ror` (tier 3) | 5 |
| `Cnt` | governance (via IEL) | `Ror` (tier 3) | 6 |

Authorization is resolved through the bound IEL via each event's `iel_event` field: "auth (via IEL)" means against the IEL-resolved `auth_policy` at the bound event; "governance (via IEL)" means against the IEL-resolved `governance_policy`. `Icp` is permissionless — no authorization gate; the prefix derives deterministically from `(identity, topic)` and `Icp` alone is rejected by the verifier (see §Inception batch rule below).

KEL anchor kinds follow [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation): tier-1 (`Ixn`) for routine extension (`Upd`); tier-2 (`Rot`) for binding establishment and seal advance (`Est`, `Sea`); tier-3 (`Ror`) for recovery and terminals (`Rpr`, `Cnt`, `Dec`).

`sort_priority` is used by the merge engine for deterministic ordering of events at the same serial.

### Satisfaction model

Authorization for v1+ SEL events is resolved through `iel_event` — a SAID reference to the specific IEL event whose declared/evolved policy authorizes the SEL event:

- **Icp** is **permissionless** and carries no `iel_event`, no content, and no authorization. Anyone can submit it; the prefix derives deterministically from `(identity, topic)` (with said+prefix blanked) and the SAID derives from the full event. Same Icp from any submitter produces the same SAID, so server-side dedup makes "adversary submits first" a no-op. The chain cannot be advanced past Icp without `Est`, so permissionless Icp grants no authority.
- **Est** (v1, inception batch's second event) must satisfy the IEL's tracked `auth_policy` resolved through `iel_event`. `Est` is the first authorization-gated event on every SEL — it carries the initial `iel_event` binding plus the chain's first content. Per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation), `Est` is tier-2 anchored (KEL `Rot` per contributing policy member) to raise per-attempt cost against SEL camping; SEL prefix is `(identity, topic)`-derived and therefore predictable, and the tier-2 anchor forces a rotation-tier burn on every camp attempt.
- **Upd** (v2+) must satisfy the IEL's tracked `auth_policy` resolved through `iel_event`. The Upd's anchors (KEL ixns) must be authorized under the policy that the bound IEL event declared/evolved. Routine extension; tier-1 anchored.
- **Sea / Rpr / Cnt / Dec** must satisfy the IEL's tracked `governance_policy` — the higher bar, also resolved through `iel_event`. They do NOT separately need to satisfy `auth_policy`: a properly-crafted `governance_policy` should subsume `auth_policy`. Per anchor elevation: `Sea` is tier-2 anchored; `Rpr` / `Cnt` / `Dec` are tier-3 anchored.

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Est` event at v1 in the same batch. The minimum inception batch is `[Icp, Est, ...]`.

Rationale: SEL Icp is permissionless — by itself, it would land an "exists but unused" chain with no policy enforcement, no binding to IEL, and no content. Forcing an `Est` in the same batch ensures the chain is born with all three: a policy-enforced event, an `iel_event` binding, and content. This eliminates a liminal state the security analysis would otherwise have to reason about.

The rule is enforced inside the verifier (`SelVerifier::finish_internal` returns `IncompleteInception` whenever any branch tip is still an `Icp`) so every consumer's verifier walk applies it — a tampered DB serving `[Icp]` alone is rejected at end-verification, not just at submit. Submit handlers do not duplicate the rule.

The Icp itself is still permissionless and still dedup-idempotent across submitters — the rule only governs whether the batch as a whole lands. If `[Icp, Est_A]` and `[Icp, Est_B]` race, the SAIDs of the Est events differ (different `iel_event` and/or content), so both Ests land at v1 forming a divergent set. The legitimate operator's `Rpr` resolves the divergence.

This rule is SEL-specific. IEL has no analogous rule — IEL Icp is itself policy-enforced (anchored under its declared `governance_policy`, since every IEL event is governance-authorized), so an IEL Icp alone is already a meaningful, authorized chain birth.

### Camping defense (Icp permissionless + Est tier-2 + inception batch required)

SEL's prefix derives from `(identity, topic)` — predictable and well-known. Any party can compute and race-incept SEL chains for tuples an operator might use. SEL's defense against this is structural and lives in three composed rules:

- **`Icp` is permissionless and dedup-idempotent.** Any submitter's `Icp` for the same `(identity, topic)` produces the same SAID; being first to submit gains nothing.
- **`Est` is tier-2 anchored.** Every camping attempt requires the camper's policy members to each produce a KEL `Rot`, making mass camping economically expensive. See [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation).
- **Inception batch required.** A bare `[Icp]` is rejected at end-verification (`IncompleteInception`). Camping attempts must submit `[Icp, Est_camper]`; the legitimate operator submits `[Icp, Est_operator]`. The SAIDs differ at `Est`, forming a divergent set at v1 which the operator's `Rpr` resolves under the higher-bar `governance_policy`.

The three rules compose: `Icp` permissionless preserves dedup-idempotency on the prefix-deterministic inception; `Est` tier-2 raises per-attempt camping cost; inception batch required closes the "lone `Icp` placeholder" gap. Together they make SEL camping expensive without sacrificing the structural properties (deterministic prefix, dedup-idempotent inception) that the rest of the system depends on.

### `identity` semantics

- `Icp`: required. The IEL prefix this SEL is bound to. Seeds the SEL prefix via `(identity, topic) → prefix`.
- All other kinds: forbidden as a field. The chain's identity is fixed at Icp; subsequent events inherit it from chain context (verifier reads it from Icp during chain replay).

The chain's identity cannot be changed after Icp. To migrate an SEL to a different identity, decommission the existing chain (`Dec`) and incept a new one bound to the new IEL.

### `iel_event` semantics

`iel_event: Digest256` references the SAID of the specific IEL event whose declared/evolved policy authorizes the SEL event:

- `Icp`: forbidden. (No authorization gate; no policy to bind to.)
- `Est` / `Upd`: required. References the IEL event whose `auth_policy` field is currently tracked at the time of submission — i.e., the most recent IEL `Icp` or `Evl` that evolved `auth_policy`. (Subsequent `Sea` or `Evl`-without-auth-change on IEL leave the tracked `auth_policy` unchanged.)
- `Sea` / `Rpr` / `Cnt` / `Dec`: required. References the IEL event whose `governance_policy` field is currently tracked at the time of submission — i.e., the most recent IEL `Icp` or `Evl` that evolved `governance_policy`. (Subsequent `Sea` or `Evl`-without-governance-change on IEL leave the tracked `governance_policy` unchanged.)

#### Why bind by SAID rather than serial

- **Unambiguous under IEL divergence.** A serial number on a divergent IEL is ambiguous (two branches at the same serial have different tracked policies); a SAID picks exactly one event on exactly one branch.
- **Robust against re-tracked policies.** If IEL evolves `A → B → A` (same policy SAID re-tracked), serial-binding would have to disambiguate which span you're claiming; SAID-binding pins the specific event.
- **Fast-eval shortcut.** Resolution is one IEL event fetch + one anchor check; no paginated walk required.

Given the SAID-binding rule, the validation rules below apply uniformly across submit, gossip, bootstrap, and re-verification:

#### Validation rules (path-agnostic — submit, gossip, bootstrap, re-verification)

The same rules apply across all ingestion paths. KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules.

For an SEL event at v1+:
- `iel_event` references an IEL event in the IEL's authentic chain (`prefix == SEL.identity`).
- That IEL event resolves to a tracked `auth_policy` (for `Est`/`Upd`) or `governance_policy` (for `Sea`/`Rpr`/`Cnt`/`Dec`) via the IEL's branch state at that event.
- **The bound IEL event is acceptable iff** the IEL is non-divergent, OR the IEL is divergent AND `bound_event.serial < first_divergent_serial` (the binding lives in the pre-divergence shared portion of the chain). A binding at-or-after `first_divergent_serial` is rejected with `IelDivergent` — the IEL has no single authoritative state at that point.

  > **Note: chain-validity ≠ consumer trust.** A pre-divergence binding to a contested IEL passes the verifier but is treated as suspect by consumers per the whole-chain-suspect rule (see [../iel/event-log.md §Effect on Bound SELs](../iel/event-log.md#effect-on-bound-sels)).
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `iel_event`** (SEL-specific): each event's `iel_event` is at-or-after its parent event's `iel_event` (parent via `previous` SAID) in IEL chain order, applied per branch independently. No rebinding to stale IEL events on a same-branch extension. Branches with different parent-chains do not constrain each other. KEL and IEL have no analog rule — they resolve authorization from commitments/policy intrinsic to their own chain at `v_{tip-1}`. Within-chain policy variation across SEL branches is bounded by the seal-cap (no fork at-or-before seal) and privileged-divergence-is-terminal (any `Sea`/`Rpr`/`Cnt`/`Dec` in the divergent set ends the chain).

Past SEL events stay verified forever: the bound IEL event is immutable (chain history is fixed), the policy it declared is immune (immunity rule on IEL — see [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement)), and the anchors (KEL ixns) are timeless.

#### Parent-monotonic gaps and consumer-side discipline

The full analysis of what parent-monotonic blocks (and the scenarios it doesn't — brand-new chain races, stale governance termination on an unratcheted branch, Cnt fork-contest with low iel_event), the operator-discipline mitigation (advance the live branch's tip `iel_event` via `Sea` after IEL governance evolution), and the consumer-side stale-binding detection rule lives in [../iel/event-log.md §What parent-monotonic blocks (and what it doesn't)](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt) and the surrounding sections. That doc is the canonical home for cross-chain validation prose; this section is a pointer to avoid drift.

### `content` semantics

`Est` and `Upd` are the content-mutating kinds (`Est` introduces the chain's first content at v1; `Upd` extends content at v2+). Every other kind that allows content (`Sea`, `Rpr`, `Cnt`, `Dec`) must carry forward the most recent `Est`-or-`Upd` content value — i.e., `event.content == previous.content`. The verifier enforces this as a chain-state check.

- `Icp`: forbidden — v0 has no content (keeps prefix derivation deterministic for lookup).
- `Est`: required — the chain's first content, declared in the inception batch.
- `Upd`: required — routine content extension.
- `Sea` / `Rpr` / `Cnt` / `Dec`: preserved — must equal `previous.content`.

This makes content evolution legible at a glance: scanning the chain, every content change corresponds to an `Est` or `Upd` event; every other kind operates on chain *state* (governance, divergence resolution, terminal lifecycle) without entangling content semantics.

### Evaluation bound

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`. After 63 non-evaluation events (`Icp`, `Est`, `Upd`), the next event must be `Sea` / `Rpr` / `Cnt` / `Dec`. This caps an adversary's fork to 63 events before they need to satisfy `governance_policy` (resolved through IEL).

### Policy immunity (lives on IEL)

SEL events do not declare policies, so the immunity rule has no SEL-side fields to gate. The structural guarantee that protects past SEL authorizations comes from the IEL: every policy SAID that any IEL ever tracks must be `immune: true`, enforced both at IEL submit time and at IEL verification time. See [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement).

The cross-chain effect: an SEL event bound to `IEL_event_X.said` resolves through that IEL event's policy SAID. As long as that policy SAID is immune (which IEL guarantees), the policy's content is fixed and the SEL event's anchor verification produces the same answer forever. See [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability).

### Cnt overrides Dec

See [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) for the doctrinal mechanic (a gossip-delivered `Cnt` with `previous = v_{d-1}.said` lands alongside an existing `Dec` at `v_d`; the chain transitions to contested). On SEL, the auth check for the overriding `Cnt` is the IEL-resolved `governance_policy` requirement (resolved via `Cnt.iel_event`).

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  identity=IEL_prefix, topic=kels/sad/v1/keys/mlkem
v1  kind=est  iel_event=IEL_v0_said, content=key_publication_said    ← inception batch Est; binds to IEL Icp's auth_policy; tier-2 anchored
v2  kind=upd  iel_event=IEL_v0_said, content=rotated_key_said        ← routine extension; tier-1 anchored
v3  kind=sea  iel_event=IEL_v0_said, content=rotated_key_said        ← preserved from v2; pure evaluation
```

If the IEL evolves (an `Evl`-with-auth-policy lands on IEL), subsequent SEL Upds bind to the new IEL `Evl`'s SAID rather than IEL Icp.

### Divergence resolved by repair

```
v0  kind=icp  identity=IEL_prefix
v1  kind=est  iel_event=IEL_v0_said, content=v1_content
v2a kind=upd  iel_event=IEL_v0_said, content=owner_v2_content      (owner)         ← fork
v2b kind=upd  iel_event=IEL_v0_said, content=adversary_v2_content  (adversary)
    — chain frozen, divergent —
v3  kind=rpr  iel_event=IEL_governance_event_said, previous=v2a.said, content=owner_v2_content
                                                                              ← Rpr extends owner's tip; v2b archived
```

The `Rpr` extends owner's authentic tip (v2a). Content equals v2a's content (preservation). The `iel_event` references the IEL event currently establishing `governance_policy` (typically IEL Icp, but could be a later IEL Evl if governance evolved on IEL).

### Contest after IEL governance compromise

Setup: a second governance-authorized party — authority acquired via threshold compromise on the bound IEL — submits `Evl` on the IEL evolving `auth_policy` / `governance_policy` in their favor. The operator detects the compromise and chooses to terminate the SEL rather than advance under the new IEL governance.

```
v0..v3   normal chain
v4       Sea       (advances last_seal_advancing_event to Sea_v4.said)
v4'      Cnt       previous=v_3.said, serial=4
                   iel_event = pre-compromise IEL governance event
                   — Cnt joins Sea_v4 at v_4 as a 2-event privileged
                     divergent set; chain contested-terminal —
```

Cnt's `previous = v_{tip-1}.said = v_3.said` puts authorization at `v_3`'s IEL-resolved `governance_policy` — the legitimate pre-compromise governance, which the operator still satisfies. Content is preserved from `v_3` per the content carry-forward rule. Cnt's land-serial `v_4 = seal_serial = Sea_v4.serial` satisfies `event_serial >= seal_serial` via the seal-cap's parent-at-(seal − 1) boundary: the parent sits at `seal − 1`, the new event itself lives at the seal (see [../../protocol-doctrine.md §Forks are Seal-Bounded](../../protocol-doctrine.md#forks-are-seal-bounded)).

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec   iel_event=current_IEL_governance_event_said    ← owner ends the chain cleanly
```

After `Cnt`, all submissions are rejected. After `Dec`, all submissions are rejected with one exception: a `Cnt` with `previous = v_{d-1}.said` (where `v_{d-1}` is `Dec`'s parent) overrides `Dec` and transitions the chain to contested per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec). See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference (the chain primitive SEL binds to).
- [../iel/event-log.md](../iel/event-log.md) — IEL chain lifecycle.
- [../../infrastructure/sadstore.md](../../infrastructure/sadstore.md) — SADStore service architecture.
- [../../features/policy.md](../../features/policy.md) — Policy DSL and anchoring model.
- [../kel/events.md](../kel/events.md) — KEL counterpart.
