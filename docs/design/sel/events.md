# SE Events: Per-Kind Reference

Pure structural reference for SAD Event Log (SEL) event kinds, per-kind field rules, and typical chain shapes.

SE chains are **identity-rooted**: every SE chain binds at inception to an Identity Event Log (IEL) and resolves its authorization policies through that IEL. SE itself has no `auth_policy` or `governance_policy` fields — those live on the IEL primitive (see [../iel/events.md](../iel/events.md)).

For chain lifecycle (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For storage, API, gossip, and custody, see [../sadstore.md](../sadstore.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/sad/v1/events/icp` | Inception (v0). Declares `identity`. Seeds prefix derivation via `(identity, topic)`. Permissionless — no authorization gate. |
| `Upd` | `kels/sad/v1/events/upd` | Normal update — append content to the chain. |
| `Sea` | `kels/sad/v1/events/sea` | Seal — governance evaluation. Advances `last_governance_version`. No field evolution (policies live on IEL). |
| `Rpr` | `kels/sad/v1/events/rpr` | Repair — resolves divergence and seals. Discriminator-driven archival of adversary events. |
| `Cnt` | `kels/sad/v1/events/cnt` | Contest — terminal due to authority conflict. No archival. |
| `Dec` | `kels/sad/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction (resolved through the bound IEL event).

SE has **no `Est` kind** — identity rooting eliminates the optional-governance-at-Icp dance. Both auth_policy and governance_policy are always declared at IEL Icp; SE chains inherit them from there.

## Per-Kind Field Rules

`SadEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top.

| Kind | version | previous | identity | identity_event | content | authorization |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | forbidden | forbidden | none (permissionless) |
| `Upd` | `>= 1` | required | forbidden | **required** | **required** | auth (via IEL) |
| `Sea` | `>= 1` | required | forbidden | **required** | preserved | governance (via IEL) |
| `Rpr` | `>= 1` | required | forbidden | **required** | preserved | governance (via IEL) |
| `Cnt` | `>= 1` | required | forbidden | **required** | preserved | governance (via IEL) |
| `Dec` | `>= 1` | required | forbidden | **required** | preserved | governance (via IEL) |

The `identity` field lives on `Icp` only; subsequent events inherit it from chain context. The chain's bound IEL is fixed at inception and cannot be changed.

### Satisfaction model

Authorization for v1+ SE events is resolved through `identity_event` — a SAID reference to the specific IEL event whose declared/evolved policy authorizes the SE event:

- **Icp** is **permissionless**. Anyone can submit it; the prefix derives deterministically from `(identity, topic)` (with said+prefix blanked) and the SAID derives from the full event. Same Icp from any submitter produces the same SAID, so server-side dedup makes "adversary submits first" a no-op. The chain cannot be advanced past Icp without satisfying the IEL's `auth_policy`, so permissionless Icp grants no authority. Today's SEL Icp authorization gate (anchored under declared `write_policy`) closed a phishing class — under identity rooting, the phishing class evaporates by construction because there are no policy fields on Icp to phish.
- **Upd** must satisfy the IEL's tracked `auth_policy` resolved through `identity_event`. The Upd's anchor (KEL ixn) must be authorized under the policy that the bound IEL event declared/evolved.
- **Sea / Rpr / Cnt / Dec** must satisfy the IEL's tracked `governance_policy` — the higher bar, also resolved through `identity_event`. They do NOT separately need to satisfy `auth_policy`: a properly-crafted `governance_policy` should subsume `auth_policy` (mirrors today's SEL rule).

### Inception batch rule

A submission containing an `Icp` event MUST also contain an `Upd` event at v1 in the same batch. The minimum inception batch is `[Icp, Upd, ...]`.

Rationale: SE Icp is permissionless — by itself, it would land an "exists but unused" chain with no policy enforcement, no binding to IEL, and no content. Forcing an Upd in the same batch ensures the chain is born with all three: a policy-enforced event, an `identity_event` binding, and content. This eliminates a liminal state the security analysis would otherwise have to reason about.

The Icp itself is still permissionless and still dedup-idempotent across submitters — the rule only governs whether the batch as a whole lands. If `[Icp, Upd_A]` and `[Icp, Upd_B]` race, the first batch lands; the second batch's Icp dedups, its Upd extends as v2 (subject to monotonic and authorization rules).

This rule is SE-specific. IEL has no analogous rule — IEL Icp is itself policy-enforced (anchored under its declared `auth_policy`), so an IEL Icp alone is already a meaningful, authorized chain birth.

### `identity` semantics

- `Icp`: required. The IEL prefix this SE chain is bound to. Seeds the SE prefix via `(identity, topic) → prefix`.
- All other kinds: forbidden as a field. The chain's identity is fixed at Icp; subsequent events inherit it from chain context (verifier reads it from Icp during chain replay).

The chain's identity cannot be changed after Icp. To migrate an SE chain to a different identity, decommission the existing chain (`Dec`) and incept a new one bound to the new IEL.

### `identity_event` semantics

`identity_event: Digest256` references the SAID of the specific IEL event whose declared/evolved policy authorizes the SE event:

- `Icp`: forbidden. (No authorization gate; no policy to bind to.)
- `Upd`: required. References the most recent IEL `Icp` or `Sea`-with-auth-policy at the time of submission — the IEL event that established the currently-tracked `auth_policy`.
- `Sea` / `Rpr` / `Cnt` / `Dec`: required. References the most recent IEL `Icp` or `Sea`-with-governance-policy — the IEL event that established the currently-tracked `governance_policy`.

#### Why bind by SAID rather than version

- **Unambiguous under IEL divergence.** A version number on a divergent IEL is ambiguous (two branches at the same version have different tracked policies); a SAID picks exactly one event on exactly one branch.
- **Robust against re-tracked policies.** If IEL evolves `A → B → A` (same policy SAID re-tracked), version-binding would have to disambiguate which span you're claiming; SAID-binding pins the specific event.
- **Fast-eval shortcut.** Resolution is one IEL event fetch + one anchor check; no paginated walk required.

#### Validation rules (path-agnostic — submit, gossip, bootstrap, re-verification)

The same rules apply across all ingestion paths. KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules.

For an SE event at v1+:
- `identity_event` references an IEL event in the IEL's authentic chain (`prefix == SE.identity`).
- That IEL event declared (`Icp`) or evolved (`Sea`) the relevant policy — `auth_policy` for `Upd`; `governance_policy` for `Sea`/`Rpr`/`Cnt`/`Dec`.
- The IEL is not divergent at the bound event's branch.
- SE.said is anchored under the resolved policy.
- **Monotonic on SE chain**: `identity_event` is at-or-after the SE chain's prior `last_identity_event` in IEL chain order. The chain ratchets forward; no rebinding to stale IEL events.

Past SE events stay verified forever: the bound IEL event is immutable (chain history is fixed), the policy it declared is immune (immunity rule on IEL — see [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement)), and the anchor (KEL ixn) is timeless.

#### What monotonicity blocks and what it doesn't

Monotonic-on-SE-chain prevents an adversary from "rolling back" the chain — once the chain is bound to IEL_v5, no new event can bind to anything earlier. On actively-maintained chains, the legitimate operator's recent events have ratcheted `last_identity_event` to a recent IEL state; an adversary with stale (revoked-since) authority cannot insert new events bound to their old IEL state.

Monotonic does NOT prevent:
- **Brand-new chain races.** Before `last_identity_event` is set, an adversary can submit `[Icp, Upd_stale]` first and establish the chain with stale binding. Recovery: legitimate operator's next Upd (with current binding) lands at v2 and ratchets `last_identity_event` forward; subsequent stale-bound events are rejected. Adversary's stale v1 event remains in chain history but is buried by subsequent Upds (consumer-side reads "latest content").
- **Stale governance termination.** An adversary with stale governance authority can submit `Cnt` or `Dec` if the chain hasn't been bound past their stale event. Mitigation: **operator discipline** — after IEL evolves governance, owner submits a `Sea` on each dependent SE chain to ratchet `last_identity_event` forward to the current IEL event. After ratchet, stale-bound `Cnt`/`Dec` fail monotonic and are rejected. The vulnerable window is "between IEL governance evolution and the SE Sea ratchets" — bounded by gossip latency plus operator reaction time.

#### Consumer-side discipline

A consumer reading the SE chain can detect stale-bound events by checking whether the bound IEL event's declared policy is still IEL's currently-tracked policy. If not, the SE event was authorized under a now-revoked policy — the consumer can filter, treat with caution, or reject per their use-case rules. The chain mathematics make this visible; no protocol change is required.

### `content` semantics

`Upd` is the only kind that introduces or changes `content`. Every other kind that allows content (`Sea`, `Rpr`, `Cnt`, `Dec`) must carry forward the most recent `Upd`'s content value — i.e., `event.content == previous.content`. The verifier enforces this as a chain-state check.

- `Icp`: forbidden — v0 has no content (keeps prefix derivation deterministic for lookup).
- `Upd`: required — the sole content-mutating kind.
- `Sea` / `Rpr` / `Cnt` / `Dec`: preserved — must equal `previous.content` (which is `None` if no `Upd` has landed yet).

This makes content evolution legible at a glance: scanning the chain, every content change corresponds to an `Upd` event; every other kind operates on chain *state* (governance, divergence resolution, terminal lifecycle) without entangling content semantics.

### Evaluation bound

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`. After 63 non-evaluation events (`Icp`, `Upd`), the next event must be `Sea` / `Rpr` / `Cnt` / `Dec`. This caps an adversary's fork to 63 events before they need to satisfy `governance_policy` (resolved through IEL).

### Policy immunity (lives on IEL)

SE events do not declare policies, so the immunity rule has no SE-side fields to gate. The structural guarantee that protects past SE authorizations comes from the IEL: every policy SAID that any IEL ever tracks must be `immune: true`, enforced both at IEL submit time and at IEL verification time. See [../iel/events.md §Policy immunity requirement](../iel/events.md#policy-immunity-requirement).

The cross-chain effect: an SE event bound to `IEL_event_X.said` resolves through that IEL event's policy SAID. As long as that policy SAID is immune (which IEL guarantees), the policy's content is fixed and the SE event's anchor verification produces the same answer forever. See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability).

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  identity=IEL_prefix, topic=kels/sad/v1/keys/mlkem
v1  kind=upd  identity_event=IEL_v0_said, content=key_publication_said    ← first Upd; binds to IEL Icp's auth_policy
v2  kind=upd  identity_event=IEL_v0_said, content=rotated_key_said
v3  kind=sea  identity_event=IEL_v0_said, content=rotated_key_said        ← preserved from v2; pure evaluation
```

If the IEL evolves (a Sea-with-auth-policy lands on IEL), subsequent SE Upds bind to the new IEL Sea's SAID rather than IEL Icp.

### Divergence resolved by repair

```
v0  kind=icp  identity=IEL_prefix
v1  kind=upd  identity_event=IEL_v0_said, content=v1_content
v2a kind=upd  identity_event=IEL_v0_said, content=owner_v2_content      (owner)         ← fork
v2b kind=upd  identity_event=IEL_v0_said, content=adversary_v2_content  (adversary)
    — chain frozen, divergent —
v3  kind=rpr  identity_event=IEL_governance_event_said, previous=v2a.said, content=owner_v2_content
                                                                              ← Rpr extends owner's tip; v2b archived
```

The `Rpr` extends owner's authentic tip (v2a). Content equals v2a's content (preservation). The `identity_event` references the IEL event currently establishing `governance_policy` (typically IEL Icp, but could be a later IEL Sea if governance evolved on IEL).

### Contest after IEL governance compromise

```
v0..v4   normal chain, last_governance_version=4 (Sea at v4)
         (an unauthorized actor submits Sea on IEL evolving auth_policy/governance_policy in their favor)
v5       owner Upd at v5 — would have to bind to the IEL's new authority event, which the owner doesn't satisfy
         → owner cannot safely continue normally; Cnt is the only legitimate path
v6       kind=cnt  identity_event=current_IEL_governance_event_said    ← chain becomes contested, terminal
                                                                              (Cnt's content preserved from v5)
```

Contest is the operator's path when an adversary has demonstrated authority on the IEL (and thus over the SE chain) that the legitimate holder cannot defeat.

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec   identity_event=current_IEL_governance_event_said    ← owner ends the chain cleanly
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## References

- [event-log.md](event-log.md) — Chain lifecycle and discriminator algorithm.
- [verification.md](verification.md) — `SelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference (the chain primitive SE binds to).
- [../iel/event-log.md](../iel/event-log.md) — IEL chain lifecycle.
- [../sadstore.md](../sadstore.md) — SADStore service architecture.
- [../policy.md](../policy.md) — Policy DSL and anchoring model.
- [../kel/events.md](../kel/events.md) — KEL counterpart.
