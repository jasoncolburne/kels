# SEL Events: Per-Kind Reference

Pure structural reference for SAD Event Log (SEL) event kinds, per-kind field rules, and typical chain shapes.

SELs are **identity-rooted**: every SEL binds at inception to an Identity Event Log (IEL) and resolves its authorization policies through that IEL. SEL itself has no `auth_policy` or `governance_policy` fields — those live on the IEL primitive (see [../iel/events.md](../iel/events.md)).

For chain lifecycle (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For storage, API, gossip, and custody, see [../sadstore.md](../../infrastructure/sadstore.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/sad/v1/events/icp` | Inception (v0). Declares `identity`. Seeds prefix derivation via `(identity, topic)`. Permissionless — no authorization gate. |
| `Est` | `kels/sad/v1/events/est` | Establishment (v1). The first authorization-gated event; carries `identity_event` binding to the IEL plus the chain's first content. Tier-2 anchored per [§Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation) — raises per-attempt cost on SEL camping. |
| `Upd` | `kels/sad/v1/events/upd` | Normal update (v2+) — append content to the chain. Routine, tier-1 anchored. |
| `Sea` | `kels/sad/v1/events/sea` | Seal — governance evaluation. Advances `last_governance_event`. No field evolution (policies live on IEL). |
| `Rpr` | `kels/sad/v1/events/rpr` | Repair — resolves non-privileged divergence and seals. Extends a tip at `v_{d+1}`; discriminator-driven archival of the events on the branch not extended. |
| `Cnt` | `kels/sad/v1/events/cnt` | Contest — terminal due to authority conflict. No archival. |
| `Dec` | `kels/sad/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction (resolved through the bound IEL event). `Est` is `auth_policy`-gated (like `Upd`) but tier-2 anchored (unlike `Upd`).

## Per-Kind Field Rules

`SadEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top.

| Kind | version | previous | identity | identity_event | content | sort_priority | authorization | KEL anchor kind |
|---|---|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | forbidden | forbidden | 0 | none (permissionless) | none |
| `Upd` | `>= 2` | required | forbidden | **required** | **required** | 1 | auth (via IEL) | `Ixn` (tier 1) |
| `Est` | `== 1` | required | forbidden | **required** | **required** | 2 | auth (via IEL) | `Rot` (tier 2) |
| `Sea` | `>= 2` | required | forbidden | **required** | preserved | 3 | governance (via IEL) | `Rot` (tier 2) |
| `Rpr` | `>= 2` | required | forbidden | **required** | preserved | 4 | governance (via IEL) | `Ror` (tier 3) |
| `Dec` | `>= 2` | required | forbidden | **required** | preserved | 5 | governance (via IEL) | `Ror` (tier 3) |
| `Cnt` | `>= 2` | required | forbidden | **required** | preserved | 6 | governance (via IEL) | `Ror` (tier 3) |

The `identity` field lives on `Icp` only; subsequent events inherit it from chain context. The chain's bound IEL is fixed at inception and cannot be changed.

### Satisfaction model

Authorization for v1+ SEL events is resolved through `identity_event` — a SAID reference to the specific IEL event whose declared/evolved policy authorizes the SEL event:

- **Icp** is **permissionless** and carries no `identity_event`, no content, and no authorization. Anyone can submit it; the prefix derives deterministically from `(identity, topic)` (with said+prefix blanked) and the SAID derives from the full event. Same Icp from any submitter produces the same SAID, so server-side dedup makes "adversary submits first" a no-op. The chain cannot be advanced past Icp without `Est`, so permissionless Icp grants no authority.
- **Est** (v1, inception batch's second event) must satisfy the IEL's tracked `auth_policy` resolved through `identity_event`. `Est` is the first authorization-gated event on every SEL — it carries the initial `identity_event` binding plus the chain's first content. Per [§Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation), `Est` is tier-2 anchored (KEL `Rot` per contributing policy member) to raise per-attempt cost against SEL camping; SEL prefix is `(identity, topic)`-derived and therefore predictable, and the tier-2 anchor forces a rotation-tier burn on every camp attempt.
- **Upd** (v2+) must satisfy the IEL's tracked `auth_policy` resolved through `identity_event`. The Upd's anchors (KEL ixns) must be authorized under the policy that the bound IEL event declared/evolved. Routine extension; tier-1 anchored.
- **Sea / Rpr / Cnt / Dec** must satisfy the IEL's tracked `governance_policy` — the higher bar, also resolved through `identity_event`. They do NOT separately need to satisfy `auth_policy`: a properly-crafted `governance_policy` should subsume `auth_policy` (mirrors today's SEL rule). Per anchor elevation: `Sea` is tier-2 anchored; `Rpr` / `Cnt` / `Dec` are tier-3 anchored.

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Est` event at v1 in the same batch. The minimum inception batch is `[Icp, Est, ...]`.

Rationale: SEL Icp is permissionless — by itself, it would land an "exists but unused" chain with no policy enforcement, no binding to IEL, and no content. Forcing an `Est` in the same batch ensures the chain is born with all three: a policy-enforced event, an `identity_event` binding, and content. This eliminates a liminal state the security analysis would otherwise have to reason about.

`Est`'s tier-2 anchoring (KEL `Rot` per contributing policy member) further raises per-attempt cost on SEL camping — see [§Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation). The combination of "Icp permissionless + Est tier-2 + inception batch required" is what makes SEL camping expensive without sacrificing dedup-idempotency on the prefix-deterministic `Icp` itself.

The rule is enforced inside the verifier (`SelVerifier::finish_internal` returns `IncompleteInception` whenever any branch tip is still an `Icp`) so every consumer's verifier walk applies it — a tampered DB serving `[Icp]` alone is rejected at end-verification, not just at submit. Submit handlers do not duplicate the rule.

The Icp itself is still permissionless and still dedup-idempotent across submitters — the rule only governs whether the batch as a whole lands. If `[Icp, Est_A]` and `[Icp, Est_B]` race, the SAIDs of the Est events differ (different `identity_event` and/or content), so both Ests land at v1 forming a divergent set. The legitimate operator's `Rpr` resolves the divergence.

This rule is SEL-specific. IEL has no analogous rule — IEL Icp is itself policy-enforced (anchored under its declared `governance_policy`, since every IEL event is governance-authorized), so an IEL Icp alone is already a meaningful, authorized chain birth.

### `identity` semantics

- `Icp`: required. The IEL prefix this SEL is bound to. Seeds the SEL prefix via `(identity, topic) → prefix`.
- All other kinds: forbidden as a field. The chain's identity is fixed at Icp; subsequent events inherit it from chain context (verifier reads it from Icp during chain replay).

The chain's identity cannot be changed after Icp. To migrate an SEL to a different identity, decommission the existing chain (`Dec`) and incept a new one bound to the new IEL.

### `identity_event` semantics

`identity_event: Digest256` references the SAID of the specific IEL event whose declared/evolved policy authorizes the SEL event:

- `Icp`: forbidden. (No authorization gate; no policy to bind to.)
- `Est` / `Upd`: required. References the most recent IEL `Icp` or `Evl`-with-auth-policy at the time of submission — the IEL event that established the currently-tracked `auth_policy`.
- `Sea` / `Rpr` / `Cnt` / `Dec`: required. References the most recent IEL `Icp` or `Evl`-with-governance-policy — the IEL event that established the currently-tracked `governance_policy`.

#### Why bind by SAID rather than version

- **Unambiguous under IEL divergence.** A version number on a divergent IEL is ambiguous (two branches at the same version have different tracked policies); a SAID picks exactly one event on exactly one branch.
- **Robust against re-tracked policies.** If IEL evolves `A → B → A` (same policy SAID re-tracked), version-binding would have to disambiguate which span you're claiming; SAID-binding pins the specific event.
- **Fast-eval shortcut.** Resolution is one IEL event fetch + one anchor check; no paginated walk required.

#### Validation rules (path-agnostic — submit, gossip, bootstrap, re-verification)

The same rules apply across all ingestion paths. KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules.

For an SEL event at v1+:
- `identity_event` references an IEL event in the IEL's authentic chain (`prefix == SEL.identity`).
- That IEL event resolves to a tracked `auth_policy` (for `Est`/`Upd`) or `governance_policy` (for `Sea`/`Rpr`/`Cnt`/`Dec`) via the IEL's branch state at that event.
- **The bound IEL event is acceptable iff** (a) the IEL is non-divergent, OR (b) the IEL is divergent AND `bound_event.version < first_divergent_version` (the bound event lives in the pre-divergence shared portion of the chain, which both branches agree on). A bound IEL event whose version is at-or-after the IEL's `first_divergent_version` is rejected with `IelDivergent` because the IEL doesn't have a single authoritative state at that point.

  Note: chain-validity allowing the binding does not imply consumer trust. A pre-divergence binding to a contested IEL passes here at the verifier layer but is treated as suspect by consumers per the whole-chain-suspect rule (see [../iel/event-log.md §Effect on Bound SELs](../iel/event-log.md#effect-on-bound-sels)).
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `identity_event`** (SEL-specific): each event's `identity_event` is at-or-after its parent event's `identity_event` (parent via `previous` SAID) in IEL chain order, applied per branch independently. No rebinding to stale IEL events on a same-branch extension. Branches with different parent-chains do not constrain each other. KEL and IEL have no analog rule — they resolve authorization from commitments/policy intrinsic to their own chain at `v_{tip-1}`. Within-chain policy variation across SEL branches is bounded by the seal-cap (no fork at-or-before seal) and privileged-divergence-is-terminal (any `Sea`/`Rpr`/`Cnt`/`Dec` in the divergent set ends the chain).

Past SEL events stay verified forever: the bound IEL event is immutable (chain history is fixed), the policy it declared is immune (immunity rule on IEL — see [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement)), and the anchors (KEL ixns) are timeless.

#### Parent-monotonic gaps and consumer-side discipline

The full analysis of what parent-monotonic blocks (and the scenarios it doesn't — brand-new chain races, stale governance termination on an unratcheted branch, Cnt fork-contest with low identity_event), the operator-discipline mitigation (advance the live branch's tip `identity_event` via `Sea` after IEL governance evolution), and the consumer-side stale-binding detection rule lives in [../iel/event-log.md §What parent-monotonic blocks (and what it doesn't)](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt) and the surrounding sections. That doc is the canonical home for cross-chain validation prose; this section is a pointer to avoid drift.

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

The cross-chain effect: an SEL event bound to `IEL_event_X.said` resolves through that IEL event's policy SAID. As long as that policy SAID is immune (which IEL guarantees), the policy's content is fixed and the SEL event's anchor verification produces the same answer forever. See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability).

### Cnt overrides Dec

`Cnt` and `Dec` are both terminal kinds (at most one of each per log), but they are not mutually exclusive. When a `Cnt`-`Dec` race delivers each event to a different node, the doctrine in [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) governs the merge: a gossip-delivered `Cnt` (with `previous = v_{d-1}.said`) is accepted on a decommissioned chain and lands at `v_d` alongside the existing `Dec`, forming a `{Dec, Cnt}` divergent set; privileged-divergence-is-terminal fires; the chain becomes contested. The asymmetry is intentional — a gossip-delivered `Dec` is rejected on a contested chain. Per-kind implications:

- **`Cnt`** can extend a Dec'd chain via this override path. Its parent shape (`v_{tip-1}.said`, resolving to `v_{d-1}.said` when the submitting node's tip is `Dec`) and IEL-resolved governance-authorization requirement are unchanged.
- **`Dec`** can be followed by a single gossip-delivered `Cnt`. No other event kind extends a Dec'd chain.

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  identity=IEL_prefix, topic=kels/sad/v1/keys/mlkem
v1  kind=est  identity_event=IEL_v0_said, content=key_publication_said    ← inception batch Est; binds to IEL Icp's auth_policy; tier-2 anchored
v2  kind=upd  identity_event=IEL_v0_said, content=rotated_key_said        ← routine extension; tier-1 anchored
v3  kind=sea  identity_event=IEL_v0_said, content=rotated_key_said        ← preserved from v2; pure evaluation
```

If the IEL evolves (an `Evl`-with-auth-policy lands on IEL), subsequent SEL Upds bind to the new IEL `Evl`'s SAID rather than IEL Icp.

### Divergence resolved by repair

```
v0  kind=icp  identity=IEL_prefix
v1  kind=est  identity_event=IEL_v0_said, content=v1_content
v2a kind=upd  identity_event=IEL_v0_said, content=owner_v2_content      (owner)         ← fork
v2b kind=upd  identity_event=IEL_v0_said, content=adversary_v2_content  (adversary)
    — chain frozen, divergent —
v3  kind=rpr  identity_event=IEL_governance_event_said, previous=v2a.said, content=owner_v2_content
                                                                              ← Rpr extends owner's tip; v2b archived
```

The `Rpr` extends owner's authentic tip (v2a). Content equals v2a's content (preservation). The `identity_event` references the IEL event currently establishing `governance_policy` (typically IEL Icp, but could be a later IEL Evl if governance evolved on IEL).

### Contest after IEL governance compromise

```
v0..v3   normal chain
v4       kind=sea  Sea_v4 advances last_governance_event to Sea_v4.said (chain tip)
         (a second governance-authorized party — authority acquired via threshold
          compromise on the bound IEL — submits Evl on the IEL evolving
          auth_policy / governance_policy in their favor; operator detects the
          compromise on the IEL and chooses to terminate the SEL since they cannot
          safely advance under the new IEL governance)
v4'      kind=cnt  previous=v_3.said, version=4                       ← Cnt joins Sea_v4 in a 2-event
         identity_event = (IEL event whose governance_policy was in effect at v_3 —    privileged divergent set at v_4;
                          the legitimate pre-compromise IEL governance, which the      privileged-divergence-is-terminal
                          operator still satisfies)                                    fires; chain contested.
         content preserved from v_3                                                    (Cnt's land-version v_4 = seal_version
                                                                                       = Sea_v4.version; the seal-cap's
                                                                                       event_version >= seal_version rule
                                                                                       admits this parent-at-(seal − 1)
                                                                                       boundary — see protocol-doctrine.md
                                                                                       §Forks are Seal-Bounded.)
```

Contest is the operator's path when a second party has demonstrated authority on the bound IEL (and thus over the SEL) that the operator cannot defeat. Cnt's `previous = v_{tip-1}.said = v_3.said` puts authorization at v_3's IEL-resolved governance_policy — the legitimate pre-compromise governance — which the operator still satisfies. Cnt's parent-at-(seal − 1) shape works at the boundary because the seal-cap is on the new event's land-version, not on the parent-version (see [../protocol-doctrine.md §Forks are Seal-Bounded](../../protocol-doctrine.md#forks-are-seal-bounded)).

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec   identity_event=current_IEL_governance_event_said    ← owner ends the chain cleanly
```

After `Cnt`, all submissions are rejected. After `Dec`, all submissions are rejected with one exception: a gossip-delivered `Cnt` (with `previous = v_{d-1}.said`, where `v_{d-1}` is `Dec`'s parent) overrides `Dec` and transitions the chain to contested per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec). See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference (the chain primitive SEL binds to).
- [../iel/event-log.md](../iel/event-log.md) — IEL chain lifecycle.
- [../sadstore.md](../../infrastructure/sadstore.md) — SADStore service architecture.
- [../policy.md](../../features/policy.md) — Policy DSL and anchoring model.
- [../kel/events.md](../kel/events.md) — KEL counterpart.
