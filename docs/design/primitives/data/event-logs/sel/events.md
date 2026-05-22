# SEL Events: Per-Kind Reference

Pure structural reference for SAD Event Log (SEL) event kinds, per-kind field rules, and typical chain shapes. SELs are **identity-rooted**: every SEL binds at inception to an Identity Event Log (IEL) and resolves its authorization policies through that IEL — SEL has no `authPolicy` or `governancePolicy` fields of its own (those live on IEL; see [../iel/events.md](../iel/events.md)).

**What this doc covers:** per-kind field rules, prefix derivation, the inception batch rule, camping defense, the cross-chain binding to IEL, content semantics, and the evaluation bound. For chain lifecycle (states, divergence, repair, decommission), see [event-log.md](event-log.md); for storage and API, see [../../../../infrastructure/sadstore.md](../../../../infrastructure/sadstore.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/sel/v1/events/icp` | Inception (v0). Declares `identity`. Seeds prefix derivation via `(identity, topic)`. Permissionless — no authorization gate. |
| `Est` | `kels/sel/v1/events/est` | Establishment (v1). The first authorization-gated event; carries `ielEvent` binding to the IEL plus the chain's first content. Tier-2 anchored per [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation) — raises per-attempt cost on SEL camping. |
| `Upd` | `kels/sel/v1/events/upd` | Normal update (v2+) — append content to the chain. Routine, tier-1 anchored. |
| `Sea` | `kels/sel/v1/events/sea` | Seal — governance evaluation. Advances `lastSealAdvancingEvent`. No policy-field evolution (policies live on IEL); may advance `ielEvent` to a newer IEL state. Back-to-back Sea allowed only when the new Sea **strictly advances** `ielEvent` — see [../../../../protocol-doctrine.md §Shape constraints on SEL Sea](../../../../protocol-doctrine.md#shape-constraints-on-sel-sea). |
| `Rpr` | `kels/sel/v1/events/rpr` | Repair — resolves divergence and seals. Extends a tip at `v_{d+1}`; discriminator-driven archival of the events on the branch not extended. |
| `Dec` | `kels/sel/v1/events/dec` | Decommission — terminal event ending the chain. |

`Sea`, `Rpr`, `Dec` all return `evaluates_governance() = true` — each requires `governancePolicy` satisfaction (resolved through the bound IEL event). `Est` is `authPolicy`-gated (like `Upd`) but tier-2 anchored (unlike `Upd`).

## Per-Kind Field Rules

`SadEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top.

### Structural fields

| Kind | serial | previous | identity | topic | ielEvent | content |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | forbidden | forbidden |
| `Est` | `== 1` | required | forbidden | **required** | **required** | **required** |
| `Upd` | `>= 2` | required | forbidden | **required** | **required** | **required** |
| `Sea` | `>= 2` | required | forbidden | **required** | **required** | preserved |
| `Rpr` | `>= 2` | required | forbidden | **required** | **required** | preserved |
| `Dec` | `>= 2` | required | forbidden | **required** | **required** | preserved |

The `identity` field lives on `Icp` only; subsequent events inherit it from chain context. The chain's bound IEL is fixed at inception and cannot be changed. The `topic` field — present on every event — is the SAD content-kind namespace (e.g., `kels/sel/v1/keys/mlkem`) and seeds the SEL prefix derivation `(identity, topic) → prefix` on `Icp`; subsequent events carry the same topic, enforced by the verifier's Topic consistency check (see [verification.md §Per-Event Checks](verification.md#per-event-checks)).

### Authorization and anchor

| Kind | authorization | KEL anchor kind | sort_priority |
|---|---|---|---|
| `Icp` | none (permissionless) | none | 0 |
| `Est` | auth (via IEL) | `Rot` (tier 2) | 1 |
| `Upd` | auth (via IEL) | `Ixn` (tier 1) | 2 |
| `Sea` | governance (via IEL) | `Rot` (tier 2) | 3 |
| `Rpr` | governance (via IEL) | `Ror` (tier 3) | 4 |
| `Dec` | governance (via IEL) | `Ror` (tier 3) | 5 |

Authorization is resolved through the bound IEL via each event's `ielEvent` field: "auth (via IEL)" means against the IEL-resolved `authPolicy` at the bound event; "governance (via IEL)" means against the IEL-resolved `governancePolicy`. `Icp` is permissionless — no authorization gate; the prefix derives deterministically from `(identity, topic)` and `Icp` alone is rejected by the verifier (see §Inception batch rule below).

KEL anchor kinds follow [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation): tier-1 (`Ixn`) for routine extension (`Upd`); tier-2 (`Rot`) for binding establishment and seal advance (`Est`, `Sea`); tier-3 (`Ror`) for repair and termination (`Rpr`, `Dec`).

`sort_priority` is used by the merge engine for deterministic ordering of events at the same serial.

### Satisfaction model

Authorization for v1+ SEL events is resolved through `ielEvent` — a SAID reference to the specific IEL event whose declared/evolved policy authorizes the SEL event:

- **Icp** is **permissionless** and carries no `ielEvent`, no content, and no authorization. Anyone can submit it; the prefix derives deterministically from `(identity, topic)` (with said+prefix blanked) and the SAID derives from the full event. Same Icp from any submitter produces the same SAID, so server-side dedup makes "adversary submits first" a no-op. The chain cannot be advanced past Icp without `Est`, so permissionless Icp grants no authority.
- **Est** (v1, inception batch's second event) must satisfy the IEL's tracked `authPolicy` resolved through `ielEvent`. `Est` is the first authorization-gated event on every SEL — it carries the initial `ielEvent` binding plus the chain's first content. Per [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation), `Est` is tier-2 anchored (KEL `Rot` per contributing policy member) to raise per-attempt cost against SEL camping; SEL prefix is `(identity, topic)`-derived and therefore predictable, and the tier-2 anchor forces a rotation-tier burn on every camp attempt.
- **Upd** (v2+) must satisfy the IEL's tracked `authPolicy` resolved through `ielEvent`. The Upd's anchors (KEL ixns) must be authorized under the policy that the bound IEL event declared/evolved. Routine extension; tier-1 anchored.
- **Sea / Rpr / Dec** must satisfy the IEL's tracked `governancePolicy` — the higher bar, also resolved through `ielEvent`. They do NOT separately need to satisfy `authPolicy`: a properly-crafted `governancePolicy` should subsume `authPolicy`. Per anchor elevation: `Sea` is tier-2 anchored; `Rpr` / `Dec` are tier-3 anchored.

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Est` event at v1 in the same batch. The minimum inception batch is `[Icp, Est, ...]`.

Rationale: SEL Icp is permissionless — by itself, it would land an "exists but unused" chain with no policy enforcement, no binding to IEL, and no content. Forcing an `Est` in the same batch ensures the chain is born with all three: a policy-enforced event, an `ielEvent` binding, and content. This eliminates a liminal state the security analysis would otherwise have to reason about.

The rule is enforced inside the verifier (`SelVerifier::finish_internal` returns `IncompleteInception` whenever any branch tip is still an `Icp`) so every consumer's verifier walk applies it — a tampered DB serving `[Icp]` alone is rejected at end-verification, not just at submit. Submit handlers do not duplicate the rule.

The Icp itself is still permissionless and still dedup-idempotent across submitters — the rule only governs whether the batch as a whole lands. If `[Icp, Est_A]` and `[Icp, Est_B]` race, the SAIDs of the Est events differ (different `ielEvent` and/or content); whichever Est arrives first on a node lands, and the second is rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Cross-node disagreement surfaces via the irreconcilable-prefix table; reincept under a new `(identity, topic)` is the operator recourse.

This rule is SEL-specific. IEL has no analogous rule — IEL Icp is itself policy-enforced (anchored under its declared `governancePolicy`, since every IEL event is governance-authorized), so an IEL Icp alone is already a meaningful, authorized chain birth.

### Camping defense (Icp permissionless + Est tier-2 + inception batch required + Est-Est mutual destruction)

SEL's prefix derives from `(identity, topic)` — predictable and well-known. Any party can compute and race-incept SEL chains for tuples an operator might use. SEL's defense against this is structural and lives in four composed rules:

- **`Icp` is permissionless and dedup-idempotent.** Any submitter's `Icp` for the same `(identity, topic)` produces the same SAID; being first to submit gains nothing.
- **`Est` is tier-2 anchored.** Every camping attempt requires the camper's policy members to each produce a KEL `Rot`, making mass camping economically expensive. See [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation).
- **Inception batch required.** A bare `[Icp]` is rejected at end-verification (`IncompleteInception`). Camping attempts must submit `[Icp, Est_camper]`; the legitimate operator submits `[Icp, Est_operator]`.
- **`Est`-`Est` competition at v=1 is rejected at merge.** `Est` is privileged at tier 2; a second `Est` for the same `(identity, topic)` whose SAID differs from the locally-resident `Est` is rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Each node retains whichever `Est` arrived first locally. Cross-node disagreement surfaces via the irreconcilable-prefix table. Operator recourse against a successful camp is reincept under a new `(identity, topic)` tuple.

The four rules compose: `Icp` permissionless preserves dedup-idempotency on the prefix-deterministic inception; `Est` tier-2 raises per-attempt camping cost; inception batch required closes the "lone `Icp` placeholder" gap; uniform priv-rejection at merge means neither party can capture a working chain federation-wide. Together they make SEL camping expensive **and** unprofitable: the camper pays tier-2 cost but cannot displace the operator's `Est` on nodes where it arrived first, leaving the prefix in dispute rather than under either party's control.

#### Operator-facing mitigations alongside the structural defense

Race-incept is targeted, not opportunistic — adversaries pay the tier-2 anchor cost only against valuable identities. Defenses below bound the targeting surface and the per-target cost:

- **Well-designed bound IEL policy.** High thresholds, custody separation across distinct domains, and threshold redundancy (`M > N`) raise the cost of an adversary's `Est_camper` to threshold-many tier-2 anchors across independently-held key custodies. The structural defense holds even with a single-KEL IEL; threshold redundancy is what makes it economically prohibitive against high-value targets.
- **Choose the right primitive for the privacy level you need.** SEL content is replicated through gossip and is structurally readable by anyone who can fetch from any node — treat published SAD content as world-readable. Keep PII out of public SAD content. For private messaging, use [exchange](../../../../features/exchange.md) (ESSR envelopes — end-to-end encrypted, point-to-point, not on a publicly-replicated chain). For SADs that need restricted access, use SAD custody (access controls on the SAD body — the chain event referencing the SAD stays public; the body is access-gated). Reducing the identifying attributes exposed in public chains bounds the adversary's ability to single out a chain as a valuable camping target.

### `identity` semantics

- `Icp`: required. The IEL prefix this SEL is bound to. Seeds the SEL prefix via `(identity, topic) → prefix`.
- All other kinds: forbidden as a field. The chain's identity is fixed at Icp; subsequent events inherit it from chain context (verifier reads it from Icp during chain replay).

The chain's identity cannot be changed after Icp. To migrate an SEL to a different identity, decommission the existing chain (`Dec`) and incept a new one bound to the new IEL.

### `ielEvent` semantics

`ielEvent: Digest256` references the SAID of the specific IEL event whose declared/evolved policy authorizes the SEL event:

- `Icp`: forbidden. (No authorization gate; no policy to bind to.)
- `Est` / `Upd`: required. References the IEL event whose `authPolicy` field is currently tracked at the time of submission — i.e., the most recent IEL `Icp` or `Evl` that evolved `authPolicy`. (Subsequent `Sea` or `Evl`-without-auth-change on IEL leave the tracked `authPolicy` unchanged.)
- `Sea` / `Rpr` / `Dec`: required. References the IEL event whose `governancePolicy` field is currently tracked at the time of submission — i.e., the most recent IEL `Icp` or `Evl` that evolved `governancePolicy`. (Subsequent `Sea` or `Evl`-without-governance-change on IEL leave the tracked `governancePolicy` unchanged.)

#### Why bind by SAID rather than serial

- **Unambiguous under IEL divergence.** A serial number on a divergent IEL is ambiguous (two branches at the same serial have different tracked policies); a SAID picks exactly one event on exactly one branch.
- **Robust against re-tracked policies.** If IEL evolves `A → B → A` (same policy SAID re-tracked), serial-binding would have to disambiguate which span you're claiming; SAID-binding pins the specific event.
- **Fast-eval shortcut.** Resolution is one IEL event fetch + one anchor check; no paginated walk required.

Given the SAID-binding rule, the validation rules below apply uniformly across submit, gossip, bootstrap, and re-verification:

#### Validation rules (path-agnostic — submit, gossip, bootstrap, re-verification)

The same rules apply across all ingestion paths. KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules.

For an SEL event at v1+:
- `ielEvent` references an IEL event in the IEL's authentic chain (`prefix == SEL.identity`).
- That IEL event resolves to a tracked `authPolicy` (for `Est`/`Upd`) or `governancePolicy` (for `Sea`/`Rpr`/`Dec`) via the IEL's branch state at that event.
- **The bound IEL event is acceptable iff `bound_event.serial <= bound_iel.lastSealAdvancingEvent.serial`.** A binding above the IEL's `lastSealAdvancingEvent` is rejected with `IelDivergent` — events above the seal are not structurally trustworthy as authorization context per [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability). The seal-bound covers the federation-dispute case by construction: on an IEL where federation-level dispute is surfaced via the irreconcilable-prefix table, the local seal stays at the prior linear-portion advance, so a binding at-or-after a disputed serial is already above the seal and rejected.

  > **Note: chain-validity ≠ consumer trust.** An at-or-below-seal binding to a federation-disputed IEL passes the verifier and stays trust-evaluable for consumer queries — at-or-below-seal IEL events retain structural verifiability per [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability). The federation-disputed IEL is frozen for forward extension: a SEL that needs to advance its binding above the IEL's seal cannot, since above-seal IEL events are not structurally trustworthy; that's the case where the operator reincepts the SEL under a new IEL prefix (see [../iel/event-log.md §Effect on Bound SELs](../iel/event-log.md#effect-on-bound-sels)).
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `ielEvent`** (SEL-specific): each event's `ielEvent` is at-or-after its parent event's `ielEvent` (parent via `previous` SAID) in IEL chain order, applied per branch independently. No rebinding to stale IEL events on a same-branch extension. Branches with different parent-chains do not constrain each other. KEL and IEL have no analog rule — they resolve authorization from commitments/policy intrinsic to their own chain at the parent event. Within-chain policy variation across SEL branches is bounded by the seal-cap (no fork at-or-before seal) and [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal) (privileged events `Sea`/`Dec` that would create or join a divergent set are rejected at merge; `Rpr` routes through the discriminator and resolves divergence).

Past SEL events stay verified forever: the bound IEL event is immutable (chain history is fixed), the policy it referenced stays resolvable (per the IEL immunity rule — see [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement)), and the anchors (KEL ixns) are timeless.

#### Parent-monotonic gaps and consumer-side discipline

The full analysis of what parent-monotonic blocks (and the scenarios it doesn't — brand-new chain races, stale governance termination on an unratcheted branch, fork-contest with low ielEvent), the governance-evolution Sea ratchet (advance the live branch's tip `ielEvent` via `Sea` after IEL governance evolution), and the consumer-side stale-binding detection rule lives in [../iel/event-log.md §What parent-monotonic blocks (and what it doesn't)](../iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt) and the surrounding sections. That doc is the canonical home for cross-chain validation prose; this section is a pointer to avoid drift.

### `content` semantics

`Est` and `Upd` are the content-mutating kinds (`Est` introduces the chain's first content at v1; `Upd` extends content at v2+). Every other kind that allows content (`Sea`, `Rpr`, `Dec`) must carry forward the most recent `Est`-or-`Upd` content value — i.e., `event.content == previous.content`. The verifier enforces this as a chain-state check.

- `Icp`: forbidden — v0 has no content (keeps prefix derivation deterministic for lookup).
- `Est`: required — the chain's first content, declared in the inception batch.
- `Upd`: required — routine content extension.
- `Sea` / `Rpr` / `Dec`: preserved — must equal `previous.content`.

This makes content evolution legible at a glance: scanning the chain, every content change corresponds to an `Est` or `Upd` event; every other kind operates on chain *state* (governance, divergence resolution, terminal lifecycle) without entangling content semantics.

### Seal-advance cap

The seal-advance cap is `MINIMUM_PAGE_SIZE − 2 = 62`. After 62 non-seal-advancing events (`Icp`, `Upd`), the next event must be a seal-advancing kind (`Est` at v=1; `Sea` / `Rpr` thereafter; `Dec` enforces but does not advance). This caps an adversary's fork to 62 events before they need to satisfy `governancePolicy` (resolved through IEL).

The `− 2` headroom is sized for the worst-case atomic batch — a `[Rpr, Sea]` repair-and-resealing batch fitting in one `MINIMUM_PAGE_SIZE`-bounded page. `MINIMUM_PAGE_SIZE` is a protocol constant, not a per-deployment knob, so batches produced on any conformant node verify on every other conformant node.

The SEL seal-advance cap is structurally symmetric with KEL's seal-advance cap (`MINIMUM_PAGE_SIZE − 2 = 62`, advancing on `Rec`/`Ror`/`Rot`) — both leave 2-slot trailing room for the worst-case atomic recovery/repair batch (`[Rec, Rot]` on KEL; `[Rpr, Sea]` on SEL). See [../kel/events.md §Seal-advance cap](../kel/events.md#seal-advance-cap).

### Policy immunity (lives on IEL)

SEL events do not declare policies, so the immunity rule has no SEL-side fields to gate. The storage commitment that keeps past SEL authorizations resolvable lives on the IEL: every policy SAID that any IEL ever tracks must be `immune: true`, enforced both at IEL submit time and at IEL verification time. See [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement).

The cross-chain effect: an SEL event bound to `IEL_event_X.said` resolves through that IEL event's policy SAID. As long as that policy SAID is immune (which IEL guarantees), the policy stays resolvable and the SEL event's anchor verification produces the same answer forever. See [../iel/event-log.md §Cross-Chain Anchor Stability](../iel/event-log.md#cross-chain-anchor-stability).

### Terminal states are fully terminal

Once a `Dec` has landed cleanly on a linear chain, the chain accepts no further submissions of any kind. The seal-cap rejects every submission whose parent sits at-or-before `Dec`'s parent. Privileged events (`Sea`/`Dec`) that would create or join a divergent set are rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  identity=IEL_prefix, topic=kels/sel/v1/keys/mlkem
v1  kind=est  ielEvent=IEL_v0_said, content=key_publication_said    ← inception batch Est; binds to IEL Icp's authPolicy; tier-2 anchored
v2  kind=upd  ielEvent=IEL_v0_said, content=rotated_key_said        ← routine extension; tier-1 anchored
v3  kind=sea  ielEvent=IEL_v0_said, content=rotated_key_said        ← preserved from v2; pure evaluation
```

If the IEL evolves (an `Evl`-with-auth-policy lands on IEL), subsequent SEL Upds bind to the new IEL `Evl`'s SAID rather than IEL Icp.

### Divergence resolved by repair

```
v0  kind=icp  identity=IEL_prefix
v1  kind=est  ielEvent=IEL_v0_said, content=v1_content
v2a kind=upd  ielEvent=IEL_v0_said, content=v2a_content         ← fork
v2b kind=upd  ielEvent=IEL_v0_said, content=v2b_content         ← fork (races with v2a)
    — Divergent, recoverable via Rpr —
v3  kind=rpr  ielEvent=IEL_governance_event_said, previous=v2a.said, content=v2a_content
                                                                ← Rpr extends v2a (branch-tip-extending shape); v2b archived
```

The `Rpr` extends v2a (branch-tip-extending shape). Content equals v2a's content (preservation rule — Rpr does not mutate content). The `ielEvent` references the IEL event currently establishing `governancePolicy` (typically IEL Icp, but could be a later IEL Evl if governance evolved on IEL). Whoever currently satisfies the `governancePolicy` dictates which branch Rpr extends and which is archived.

### Concurrent privileged events producing federation-level non-convergence

Two governance-authorized parties — both satisfying the chain's IEL-resolved `governancePolicy` at `v_{d-1}` — submit concurrent privileged events extending the same parent `v_{d-1}` to different nodes. Each event lands as a clean linear extension on its submitting node; gossip then delivers each event to the other node, where the seal-cap rejects the late arrival.

```
v0..v3   normal linear chain (replicated to nodes A and B)
v4       Sea       previous=v_3.said, serial=4     ← party 1's Sea on node A
                                                     (lands cleanly; A's seal advances)
v4'      Dec       previous=v_3.said, serial=4     ← party 2's Dec on node B
                                                     (lands cleanly; B's seal advances)

    Gossip propagation:
      Node A receives Dec: parent_serial = 3 < seal_serial = 4
        → rejected by seal-cap. A's tip stays at Sea.
      Node B receives Sea: parent_serial = 3 < seal_serial = 4
        → rejected by seal-cap. B's tip stays at Dec.

    Cross-node: A and B do not converge at the protocol layer.
    Federation-level convergence is provided via the irreconcilable-prefix table.
```

The structural signature of "race" and "compromise" is identical from the chain's perspective. Both events satisfy the same `governancePolicy` at `v_3`; the chain layer cannot distinguish them. Federation-level convergence is handled at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

Operator recourse against compromise on a still-Active SEL is via IEL governance evolution: an `Evl` on the bound IEL that excludes the compromised governance member updates the SEL's resolved `governancePolicy` going forward. Subsequent SEL events bind to the new IEL state via a `Sea` ratchet — see [event-log.md §Authorization via IEL](event-log.md#authorization-via-iel).

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec   ielEvent=current_IEL_governance_event_said    ← clean chain end
```

After `Dec`, the chain is fully terminal. The seal-cap rejects every subsequent submission whose parent sits at-or-before `v_{d-1}`. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference (the chain primitive SEL binds to).
- [../iel/event-log.md](../iel/event-log.md) — IEL chain lifecycle.
- [../../../../infrastructure/sadstore.md](../../../../infrastructure/sadstore.md) — SADStore service architecture.
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL and anchoring model.
- [../kel/events.md](../kel/events.md) — KEL counterpart.
