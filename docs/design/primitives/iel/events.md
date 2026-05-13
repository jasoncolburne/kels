# Identity Events: Per-Kind Reference

Pure structural reference for Identity Event Log (IEL) event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For the verifier algorithm, see [verification.md](verification.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/iel/v1/events/icp` | Inception (v0). Declares both `auth_policy` and `governance_policy`. Seeds prefix derivation via `(auth_policy, governance_policy, topic)`. |
| `Evl` | `kels/iel/v1/events/evl` | Evolve — governance evaluation. Advances `last_governance_event`. MUST evolve at least one of `auth_policy` / `governance_policy`; a no-op Evl is rejected as a structural error. |
| `Sea` | `kels/iel/v1/events/sea` | Seal advance — governance-authorized re-evaluation without policy evolution. Advances `last_governance_event`. Carries no policy fields. Closes the post-exclusion window per [§Exclusion Evolutions and the Seal Advance](../../protocol-doctrine.md#exclusion-evolutions-and-the-seal-advance). |
| `Cnt` | `kels/iel/v1/events/cnt` | Contest — terminal due to authority conflict (or divergence). No archival — both branches preserved as forensic record. |
| `Dec` | `kels/iel/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Evl`, `Sea`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires the branch's *tracked* `governance_policy` satisfaction. `Icp` is also governance-authorized but against the policy *declared at that event* (self-governance-endorsement), not against a previously-tracked policy; see [§Satisfaction model](#satisfaction-model) for the full per-kind rule.

IEL has **no `Upd` kind** — there is no "content" on identity chains. The chain's data is its tracked policy state, mutated only via `Evl`. IEL has **no `Est` kind** — both policies are required at `Icp`, since identity chains are not third-party-discoverable and don't need the optional-governance-at-Icp dance that SEL uses (SEL `Est` provides camping defense for SEL's well-known-tuple prefix; IEL has no analogous surface). IEL has **no `Rpr` kind** — divergence on IEL is immediately terminal (every IEL event is privileged, so any divergent set on IEL fires the privileged-divergence-is-terminal rule); there's no "preserve one branch, archive the other" shape because the protocol cannot adjudicate from chain data when both branches are governance-authorized. See [event-log.md §Divergence and Contest-Only Resolution](event-log.md#divergence-and-contest-only-resolution).

## Per-Kind Field Rules

`IdentityEvent::validate_structure()` enforces version and `previous` rules. Per-kind policy-field discipline (carry-forward vs. evolution vs. declaration) is enforced by the **verifier** — not by `validate_structure` — because the discipline depends on chain-state context (the previous event's policy values) which structural validation alone cannot see.

| Kind | version | previous | auth_policy | governance_policy | sort_priority | authorization | KEL anchor kind |
|---|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | declared (required) | declared (required) | 0 | self (governance_policy) | `Ixn` (tier 1) |
| `Evl` | `>= 1` | required | preserved or evolved | preserved or evolved (at least one of `auth_policy` / `governance_policy` MUST evolve) | 1 | governance | `Rot` (tier 2) |
| `Sea` | `>= 2` | required | forbidden | forbidden | 2 | governance | `Rot` (tier 2) |
| `Dec` | `>= 1` | required | forbidden | forbidden | 3 | governance | `Ror` (tier 3) |
| `Cnt` | `>= 1` | required | forbidden | forbidden | 4 | governance | `Ror` (tier 3) |

`auth_policy` and `governance_policy` are `Option<Digest256>` fields on `IdentityEvent`: present (non-`None`) on `Icp` and `Evl`, absent (`None`) on `Sea`, `Cnt`, and `Dec`. "Declared" applies at `Icp` where there is no predecessor — the inceptor declares both fields directly. "Preserved or evolved" applies on `Evl` — the field's value either equals the predecessor's value (preserved) or differs (evolved; the difference is what the verifier interprets as a policy evolution requiring governance authorization). "Forbidden" applies on `Sea`, `Cnt`, and `Dec`: `Sea` is the seal-advance-without-evolution event, and terminal events have no forward state to declare, so the field is absent and the verifier rejects any `Sea`/`Cnt`/`Dec` carrying a value. This mirrors KEL, where `rotation_hash` and `recovery_hash` are likewise forbidden on terminal kinds (`Dec`, `Cnt`) because the KEL ends — see [../kel/events.md §Forward-key commitments](../kel/events.md#forward-key-commitments). The doctrinal frame: the chain's tracked policy state lives in the verifier's branch state, advanced by `Icp`/`Evl`; `Sea` advances the seal without changing policy; terminal events end the chain and have no forward state to declare.

(No `content` field on any kind. IEL events do not carry content.)

### Per-Kind Policy Field Discipline

`Icp` and `Evl` carry `auth_policy` and `governance_policy`; `Sea`, `Cnt`, and `Dec` do not. The verifier checks the per-kind discipline as part of branch-state validation:

- **`Icp`**: declares both policies. The verifier records them as the chain's initial tracked auth and governance policies after confirming both are immune and Icp.said is anchored under the declared `governance_policy` (every IEL event is governance-authorized — see [§Satisfaction model](#satisfaction-model)).
- **`Evl`**: MUST evolve at least one of `auth_policy` / `governance_policy`. Either field can evolve independently; both can evolve in the same `Evl`. A no-op `Evl` (both fields identical to the predecessor) is rejected — `last_governance_event` is the chain's evaluation seal, not a heartbeat counter, so every `Evl` must be a real governance act. The verifier records the new tracked policies after confirming any new policy is immune and the Evl is anchored under the *previous* tracked governance_policy.
- **`Sea`**: both policy fields are absent (forbidden). `Sea` is the seal-advance event — its purpose is to advance `last_governance_event` without declaring policy evolution. Authorization resolves through the branch's tracked `governance_policy` (resolved at the predecessor). Shape constraints: `Sea`'s parent must not be `Icp` (a seal advance is meaningful only after a policy-evolution event opens a window), another `Sea` (IEL `Sea` carries no content fields, so back-to-back `Sea` is by definition identical-content — invalid per the doctrine's "no identical-content `Sea`-`Sea`" rule; SEL `Sea`-`Sea` with advancing `identity_event` is allowed there but not here), or `Cnt`/`Dec` (terminal events do not extend). See [§Exclusion Evolutions and the Seal Advance](../../protocol-doctrine.md#exclusion-evolutions-and-the-seal-advance).
- **`Cnt` / `Dec`**: both fields are absent (forbidden). Terminal events have no forward state to declare — the chain ends with the terminal, and the verifier's tracked policy state is what authorized acceptance of the terminal itself (resolved at the predecessor). The verifier rejects any Cnt/Dec carrying a non-`None` `auth_policy` or `governance_policy` as a structural error. Authorization for the terminal still resolves through the branch's `tracked_governance_policy` (set when the predecessor was processed) — see [§Satisfaction model](#satisfaction-model).

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event. **Every IEL event is governance-authorized**: IEL is the governance primitive, so even inception — the act of declaring the chain's policies — is itself a governance act. The chain's `auth_policy` is reserved for application-facing per-event authorization, consumed by SEL `Upd` events via `identity_event` binding (see [../sel/events.md](../sel/events.md)); it is never the gate that authorizes IEL events themselves.

- **Icp** must satisfy the `governance_policy` it declares. The inceptor proves membership in the governance policy they're naming by anchoring `Icp.said` under that policy. Identity chains aren't third-party-discoverable, so the prefix derivation `(auth_policy, governance_policy, topic) → prefix` is private to the inceptor — there's no phishing class equivalent to today's SEL Icp gate. The anchoring requirement is the structural authentication of the inceptor against the governance policy they declare.
- **Evl / Sea / Cnt / Dec** must satisfy the branch's tracked `governance_policy`. Same gate as Icp; same rule across the chain. They do NOT separately need to satisfy `auth_policy`: `auth_policy` is reserved for SEL `Est`/`Upd` authorization through the bound IEL event.

### `auth_policy` semantics

- `Icp`: declared as a **field** that seeds the IEL prefix (prefix = Blake3 of v0 template with said+prefix blanked). It does NOT authorize the Icp itself — Icp is governance-authorized (see [governance_policy semantics](#governance_policy-semantics) below). The `auth_policy` declared at Icp is consumed downstream by SEL `Upd` events that bind to this Icp via `identity_event`.
- `Evl`: present; preserved (== previous) or evolved (differs from previous; evaluated against the previous tracked `governance_policy`). At least one of `auth_policy` / `governance_policy` must evolve in any given `Evl` — an Evl preserving both is rejected.
- `Sea` / `Cnt` / `Dec`: **absent (forbidden)**. `Sea` is the seal-advance event; terminal events have no forward state to declare. The verifier rejects any `Sea`/`Cnt`/`Dec` carrying a value.

The verifier's branch state tracks the effective `auth_policy` — seeded from `Icp` and updated whenever an `Evl` carries a new value. Authorization for an SEL event that points at a specific IEL event SAID resolves through the tracked `auth_policy` at that IEL event's branch state.

### `governance_policy` semantics

- `Icp`: declared. Identity chains always declare governance at v0 (no Est dance). Also serves as the **authorization gate** (Icp.said must be anchored under the declared `governance_policy`) — every IEL event is a governance act.
- `Evl`: present; preserved or evolved (the latter evaluated against the *previous* tracked governance_policy). At least one of `auth_policy` / `governance_policy` must evolve per Evl.
- `Sea` / `Cnt` / `Dec`: **absent (forbidden)**. Authorization for these kinds resolves through the branch's `tracked_governance_policy` (set when the predecessor was processed); the kind itself declares nothing forward.

### Policy immunity requirement

Any policy referenced as a chain's `auth_policy` OR `governance_policy` — whether at `Icp` (v0) or via a `Evl` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification (hard reject; structural error). This is the structural enforcement of chain stability: IEL chains are time-ordered policy histories, and past authorizations (both auth and governance) must remain stable across the lifetime of the chain.

To revoke an endorser's authority, evolve the policy via `Evl` (issuing a new auth_policy or governance_policy SAID that excludes the endorser); do not attempt to poison past events. `Evl`-driven evolution is the canonical correction path.

This rule mirrors today's SEL immunity rule and serves the same purpose. With IEL, it becomes the cornerstone of cross-chain consistency: every SEL event binds to a specific IEL event SAID, and that IEL event's policy SAIDs must be immune so the binding remains verifiable for the lifetime of any dependent SEL.

See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the SEL-side implications.

### No `content` field

IEL events do not carry content. The chain's "data" is its tracked policy state, mutated via `Evl`. This is the structural contrast with SEL: SEL has `content` (mutated by `Upd`); IEL has policy state (mutated by `Evl`). The two primitives split policy-management from content-recording at the type level.

### Evaluation bound — not applicable

Today's SEL has `MAX_NON_EVALUATION_EVENTS = 63` to bound how long an adversary can fork before satisfying governance_policy. On IEL, **every event is governance-authorized** (`Icp`, `Evl`, `Sea`, `Cnt`, `Dec`). There are no "non-evaluation events" between governance evaluations — every event IS governance-authorized at submission time. The bound is implicit and need not be enforced.

(`last_governance_event` advances on `Evl` and `Sea` — Icp/Cnt/Dec do not advance the seal — but the governance authorization gate applies uniformly at all kinds. Only one Icp can land per chain, so the chain has at most one pre-Evl event.)

### Cnt overrides Dec

`Cnt` and `Dec` are both terminal kinds (at most one of each per log), but they are not mutually exclusive. When a `Cnt`-`Dec` race delivers each event to a different node, the doctrine in [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) governs the merge: a `Cnt` with `previous = v_{d-1}.said` is accepted on a decommissioned chain and lands at `v_d` alongside the existing `Dec`, forming a `{Dec, Cnt}` divergent set; privileged-divergence-is-terminal fires; the chain becomes contested. The asymmetry is intentional — `Dec` is rejected on a contested chain. Per-kind implications:

- **`Cnt`** can extend a Dec'd chain via this override path. Its parent shape (`v_{tip-1}.said`, resolving to `v_{d-1}.said` when the submitting node's tip is `Dec`) and governance-authorization requirement are unchanged.
- **`Dec`** can be followed by a single `Cnt` (with `previous = v_{d-1}.said`). No other event kind extends a Dec'd chain.

## Typical Chain Shapes

### Identity with policy evolution

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=evl  auth_policy=A1                              ← auth_policy evolved; governance_policy unchanged
v2  kind=evl  governance_policy=G1                        ← governance_policy evolved; auth_policy unchanged
```

Each `Evl` must evolve at least one policy — a no-op Evl (both fields preserved) is rejected as a structural error. There is no "pure-attestation" mode: `last_governance_event` is the evaluation seal, not a heartbeat counter, and key rotation on anchoring KELs is a layer-below concern that doesn't surface as IEL events.

### Divergence is contested-terminal

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=evl  auth_policy=A1
v2  kind=evl  previous=v1.said, auth_policy=A2_a            ← submission #1 (linear extension of tip v_1)
v2' kind=cnt  previous=v1.said                              ← submission #2 (operator's Cnt extending v_{tip-1}=v_1
                                                              on a node whose tip is already v_2 via gossip; lands
                                                              at v_2 alongside the existing v_2 event)
    — 2-event divergent set at v_2, both with previous = v_1.said.
      Every IEL event is privileged → privileged-divergence-is-terminal fires
      immediately; chain becomes contested-terminal as of v_2. —
```

The two events at `v_2` carry the same `previous = v_1.said` — each was accepted as a linear-chain extension on its submitting node at submission time, with the two extensions independently landing at `v_2`. Valid 2-event pairings on IEL are `Evl`-`Evl`, `Evl`-`Sea`, `Sea`-`Sea`, `Evl`-`Cnt`, and `Sea`-`Cnt` — every divergent set at `v_d` contains at least one seal-advancing event (`Evl` or `Sea`). `Cnt` is absolute and terminal (at most one per log; the contested-state gate locks after first acceptance), so `Cnt`-`Cnt` cannot form. `Dec` extends tip directly (`Dec.previous = tip.said`), so it lands only on linear chains and never appears in a divergent set — a `Dec` landing decommissions the chain. Every IEL event is privileged, so the divergent set transitions the chain to contested-terminal immediately by the privileged-divergence-is-terminal rule. **No 3rd event lands at `v_2`** — the contested-state gate rejects all subsequent submissions, including any further `Evl`, `Sea`, `Cnt`, or `Dec` arriving at v_2 via gossip. **Once divergence is observed, no Cnt is accepted on a divergent IEL** — Cnt acceptance is always a linear-chain extension on the submitting node's local chain; the 2-event divergent set is emergent (observed via gossip-merge of two independently-submitted linear-chain extensions, or as the post-acceptance state on a node whose tip is the gossip-delivered concurrent event when Cnt lands — see next example).

Both events stay in storage forever as forensic record. Operator re-incepts under a different prefix (different topic, or new IEL identity).

This is intentional: history is encoded in the data. We accept divergence and treat it as the chain's structural admission that governance is no longer single-authoritative. Termination is the honest answer; there is no `Rpr` to archive one branch in favor of the other (every branch is governance-authorized; the protocol has no grounds to declare one "the" branch).

### Contest after Cnt and Evl land in the same generation

```
v0..v3   normal linear chain (across the federation)
v4       kind=evl   advances last_governance_event to Evl_v4.said
v5       kind=evl   previous=v_4.said       ← compromised party's Evl_v5
v5'      kind=cnt   previous=v_4.said       ← operator's Cnt
    — 2-event divergent set at v_5: {Evl_v5, Cnt}. Privileged-divergence-
      is-terminal fires; chain contested-terminal as of v_5. —
```

Each submission is a linear-chain extension on its submitting node's local state at submission time. A second governance-authorized party — authority acquired via threshold compromise — submits Evl_v5 on their node (whose tip is v_4); Evl_v5 extends v_4 (= the submitter's tip) and lands at v_5 on their node. Gossip propagates Evl_v5 to the operator's node; the operator's tip advances to v_5. The operator, observing the unexpected v_5 event as evidence of compromise, submits Cnt; Cnt extends v_4 (= v_{tip-1} on the operator's node, where the tip is now Evl_v5) and lands at v_5 alongside Evl_v5 on the operator's node. Neither submission "knowingly joins a pre-existing divergent set" — each is a linear-chain extension on its node at submission time. The 2-event divergent set at v_5 is the post-acceptance state once Cnt lands on the operator's node (Evl_v5 already present from gossip), and the gossip-merged state on other nodes once both events propagate.

Cnt's `previous = v_4.said` is `v_{tip-1}` on the operator's node at submission, and `v_{d-1}` (the divergence ancestor — the parent shared with Evl_v5) once the divergent set is observable. Authorization resolves through `v_4`'s tracked `governance_policy` (the policy in effect when v_4 landed — the legitimate pre-compromise governance), which the operator still satisfies. The structural signature of "race" and "compromise" is identical from the chain's perspective; consumer-side judgment + out-of-band knowledge is what determines whether to treat this as accidental race or as intentional takeover. Either way, the chain is contested-terminal once the divergent set forms.

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec                                            ← owner ends the chain cleanly
```

After `Cnt`, all submissions are rejected. After `Dec`, all submissions are rejected with one exception: a `Cnt` with `previous = v_{d-1}.said` (where `v_{d-1}` is `Dec`'s parent) overrides `Dec` and transitions the chain to contested per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec). See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## Cross-chain binding from SEL to IEL

Every SEL event at v1+ carries `identity_event: Digest256` — the SAID of the IEL event whose declared/evolved policy authorizes the SEL event. Per-kind binding:

- SEL `Est` / `Upd` → binds to an IEL `Icp` or `Evl`-with-auth-policy event whose declared/evolved `auth_policy` authorizes the event's anchor.
- SEL `Sea` / `Rpr` / `Cnt` / `Dec` → binds to an IEL `Icp` or `Evl`-with-governance-policy event whose declared/evolved `governance_policy` authorizes the lifecycle event's anchor. (SEL retains its own `Sea` and `Rpr` kinds; the asymmetry is intentional — see [../sel/events.md](../sel/events.md) for the SEL kind set.)

Binding by SAID (not version) is unambiguous under IEL divergence, robust against re-tracked-same-policy patterns, and enables a fast-eval shortcut: one IEL event fetch + one anchor check, without paginating the full IEL chain.

The binding rule is **path-agnostic** — the same validation applies at submit, gossip ingestion, bootstrap, and re-verification. The protocol does not distinguish data by ingestion path. KELS data is data; pulling it from one node and putting it into another is no big deal. See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the unified rule and the operator-discipline corollary that handles governance-evolution races.

See [../sel/events.md §`identity_event` semantics](../sel/events.md#identity_event-semantics) for the SEL-side field rules.

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, anchor non-poisonability.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference (the chain primitive that binds to IEL events).
- [../policy.md](../../features/policy.md) — Policy DSL and anchoring model (immunity rule).
