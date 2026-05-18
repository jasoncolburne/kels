# Identity Events: Per-Kind Reference

Pure structural reference for Identity Event Log (IEL) event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, decommission, evaluation seal), see [event-log.md](event-log.md). For the verifier algorithm, see [verification.md](verification.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/iel/v1/events/icp` | Inception (v0). Declares both `authPolicy` and `governancePolicy`. Seeds prefix derivation via `(authPolicy, governancePolicy, nonce)`. |
| `Evl` | `kels/iel/v1/events/evl` | Evolve — governance evaluation. Advances `lastSealAdvancingEvent`. MUST evolve at least one of `authPolicy` / `governancePolicy`; a no-op Evl is rejected as a structural error. |
| `Sea` | `kels/iel/v1/events/sea` | Seal advance — governance-authorized re-evaluation without policy evolution. Advances `lastSealAdvancingEvent`. Carries no policy fields. Closes the post-exclusion window per [../../../../protocol-doctrine.md §Exclusion Evolutions and the Seal Advance](../../../../protocol-doctrine.md#exclusion-evolutions-and-the-seal-advance). |
| `Dec` | `kels/iel/v1/events/dec` | Decommission — terminal owner-initiated end. |

**Every IEL event is governance-authorized.** `Evl`, `Sea`, `Dec` all return `evaluates_governance() = true` — each requires the branch's *tracked* `governancePolicy` to be satisfied. `Icp` is also governance-authorized, but against the policy it *declares at that event* (self-governance-endorsement), not against a previously-tracked policy. See [§Satisfaction model](#satisfaction-model) for the full per-kind rule.

**Seal-advancing vs terminal.** Only `Evl` and `Sea` advance `lastSealAdvancingEvent` (the evaluation seal). `Dec` enforces the seal-cap gate but does not advance it.

**Kinds IEL does not have.** Four deliberate omissions distinguish IEL from KEL/SEL:

- **No `Upd`** — identity chains carry no "content"; the chain's data is its tracked policy state, mutated only via `Evl`.
- **No `Est`** — both policies are required at `Icp`. Identity chains have structurally unpredictable prefixes (the inception `nonce` makes the derived prefix unguessable from outside), so they don't need the optional-governance-at-Icp dance that SEL uses for camping defense. SEL `Est` provides camping defense for SEL's well-known-tuple prefix; IEL has no analogous surface.
- **No `Rpr`** — divergence on IEL is immediately terminal (every IEL event is privileged, so any divergent set fires the privileged-divergence-is-terminal rule). There's no "preserve one branch, archive the other" shape because the protocol cannot adjudicate from chain data when both branches are governance-authorized. See [event-log.md §Divergence and Contest-Only Resolution](event-log.md#divergence-and-contest-only-resolution).
- **No `Cnt`** — IEL `Cnt` is structurally redundant under the post-#202 doctrine and is dropped. On a compromised IEL the operator's recourse is a competing `Evl` under the still-current policy, which creates divergence and triggers privileged-divergence-is-terminal (every IEL event is privileged). Forensic owner-attribution after a contested IEL lives in out-of-band channels (operator publishes a signed statement under their KEL). See [../../../../protocol-doctrine.md §Privileged Divergence is Terminal §IEL repair-event absence](../../../../protocol-doctrine.md#privileged-divergence-is-terminal).

## Per-Kind Field Rules

`IdentityEvent::validate_structure()` enforces serial and `previous` rules. Per-kind policy-field discipline (carry-forward vs. evolution vs. declaration) is enforced by the **verifier** — not by `validate_structure` — because the discipline depends on chain-state context (the previous event's policy values) which structural validation alone cannot see.

### Structural fields

| Kind | serial | previous | authPolicy | governancePolicy | nonce |
|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | declared (required) | declared (required) | **required** |
| `Evl` | `>= 1` | required | preserved or evolved | preserved or evolved (at least one of `authPolicy` / `governancePolicy` MUST evolve) | forbidden |
| `Sea` | `>= 2` | required | forbidden | forbidden | forbidden |
| `Dec` | `>= 1` | required | forbidden | forbidden | forbidden |

`nonce` is a field on `Icp` only — opaque random bytes chosen by the inceptor that seed the prefix derivation `(authPolicy, governancePolicy, nonce) → prefix`. It makes the prefix structurally unpredictable from outside (defending against well-known-tuple camping, which IEL — unlike SEL — has no other structural defense against). The verifier rejects any non-`Icp` event carrying a non-`None` nonce: nonce reuse or replay outside Icp would dilute the prefix's unpredictability.

`authPolicy` and `governancePolicy` are `Option<Digest256>` fields on `IdentityEvent`: present (non-`None`) on `Icp` and `Evl`, absent (`None`) on `Sea` and `Dec`. The per-kind values in the table use three terms:

- **Declared** — applies at `Icp`. The inceptor declares both fields directly; no predecessor exists.
- **Preserved or evolved** — applies on `Evl`. The field's value either equals the predecessor's (preserved) or differs (evolved); the difference is what the verifier interprets as a policy evolution requiring governance authorization.
- **Forbidden** — applies on `Sea` and `Dec`. `Sea` is the seal-advance-without-evolution event; `Dec` is terminal and has no forward state to declare. The verifier rejects any `Sea`/`Dec` carrying a value.

This mirrors KEL: `rotationHash` and `recoveryHash` are likewise forbidden on terminal kinds (`Dec`, `Cnt` — KEL still has Cnt) because the KEL ends — see [../kel/events.md §Forward-key commitments](../kel/events.md#forward-key-commitments). The doctrinal frame: the chain's tracked policy state lives in the verifier's branch state, advanced by `Icp`/`Evl`; `Sea` advances the seal without changing policy; terminal events end the chain and have no forward state to declare.

(No `content` field on any kind. IEL events do not carry content.)

`Sea`'s `serial >= 2` constraint and the parent-kind constraint (`Sea`'s parent must be `Evl` — see §Per-Kind Policy Field Discipline) are co-implied: only `Evl` can land at v=1 on a non-terminal IEL chain (Icp is at v=0; Sea/Dec are forbidden at v=1 by serial rules or terminal semantics), so the parent of any `Sea` at v=2 is necessarily an `Evl`. The two constraints are stated independently for clarity but describe the same structural shape.

### Authorization and anchor

| Kind | authorization | KEL anchor kind | sort_priority |
|---|---|---|---|
| `Icp` | self (governancePolicy) | `Rot` (tier 2) | 0 |
| `Evl` | governance | `Rot` (tier 2) | 1 |
| `Sea` | governance | `Rot` (tier 2) | 2 |
| `Dec` | governance | `Ror` (tier 3) | 3 |

Authorization terminology: "self" means the event is governance-authorized against the policy it declares at the same event (Icp anchors `Icp.said` under the declared `governancePolicy`); "governance" means against the branch's tracked `governancePolicy` (resolved at the predecessor). Every IEL event is governance-authorized; see §Satisfaction model below.

The "KEL anchor kind" column reflects [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation): tier-2 (`Rot`) for `Icp`/`Evl`/`Sea` (governance acts — declaration, evolution, seal advance); tier-3 (`Ror`) for `Dec` (terminal). Each contributing KEL member's `governancePolicy` leaf must produce an anchor of the required kind on the IEL event's SAID.

`sort_priority` is used by the merge engine for deterministic ordering of events at the same serial (during divergent-set processing and gossip-merge). The values are decorative ordering hints, not authorization-relevant; lower priority sorts first.

### Per-Kind Policy Field Discipline

`Icp` and `Evl` carry `authPolicy` and `governancePolicy`; `Sea` and `Dec` do not. The verifier checks the per-kind discipline as part of branch-state validation:

- **`Icp`**: declares both policies. The verifier records them as the chain's initial tracked auth and governance policies after confirming both are immune and Icp.said is anchored under the declared `governancePolicy` (every IEL event is governance-authorized — see [§Satisfaction model](#satisfaction-model)).
- **`Evl`**: MUST evolve at least one of `authPolicy` / `governancePolicy`. Either field can evolve independently; both can evolve in the same `Evl`. A no-op `Evl` (both fields identical to the predecessor) is rejected — `lastSealAdvancingEvent` is the chain's evaluation seal, not a heartbeat counter, so every `Evl` must be a real governance act. The verifier records the new tracked policies after confirming any new policy is immune and the Evl is anchored under the *previous* tracked governancePolicy.
- **`Sea`**: both policy fields are absent (forbidden). `Sea` is the seal-advance event — its purpose is to advance `lastSealAdvancingEvent` without declaring policy evolution. Authorization resolves through the branch's tracked `governancePolicy` (resolved at the predecessor). Shape constraints: `Sea`'s parent must not be `Icp` (a seal advance is meaningful only after a policy-evolution event opens a window), another `Sea` (IEL `Sea` carries no content field, so a `Sea` extending another `Sea` would add no semantic information beyond the parent — invalid per the doctrine's prohibition on semantically-redundant consecutive Seas; SEL `Sea`-`Sea` is allowed there only when the new Sea strictly advances `ielEvent`, re-ratcheting the binding after the bound IEL evolves), or `Dec` (terminal events do not extend). See [../../../../protocol-doctrine.md §Exclusion Evolutions and the Seal Advance](../../../../protocol-doctrine.md#exclusion-evolutions-and-the-seal-advance). The parent-kind constraint is enforced by the verifier walk (see [verification.md §Per-Event Checks](verification.md#per-event-checks)) and complements the submit-time dedup pre-filter that catches byte-identical concurrent Sea-Sea pairings — both layers ensure the chain never carries a semantically-redundant consecutive Sea regardless of ingestion path (submit, gossip, restored backup, bootstrap).
- **`Dec`**: both fields are absent (forbidden). The chain ends with the terminal, and the verifier's tracked policy state is what authorized acceptance of the terminal itself (resolved at the predecessor). The verifier rejects any Dec carrying a non-`None` `authPolicy` or `governancePolicy` as a structural error. Authorization for the terminal still resolves through the branch's `trackedGovernancePolicy` (set when the predecessor was processed) — see [§Satisfaction model](#satisfaction-model).

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event. **Every IEL event is governance-authorized** — IEL is the governance primitive, so even inception is itself a governance act. The chain's `authPolicy` is reserved for application-facing per-event authorization consumed by SEL events via `ielEvent` binding; it is never the gate that authorizes IEL events themselves.

- **Icp** — gate: `governancePolicy` declared at this event (self-endorsement). Anchor: tier-2 (`Rot`) per contributing member. Why: the inceptor proves membership in the policy they're naming by anchoring `Icp.said` under that policy.
- **Evl / Sea / Dec** — gate: the branch's tracked `governancePolicy` (resolved at the predecessor). Anchor: tier-2 for `Evl`/`Sea`, tier-3 for `Dec`. Why: the chain's tracked policy is the authority that admits subsequent events. These kinds do NOT separately satisfy `authPolicy`; `authPolicy` is reserved for SEL `Est`/`Upd`.

**Note on Icp's tier-2 anchor.** The prefix derivation `(authPolicy, governancePolicy, nonce) → prefix` includes opaque random bytes chosen by the inceptor, making the prefix structurally unpredictable from outside (no phishing-class equivalent to SEL Icp). Tier-2 anchoring on Icp specifically prevents signing-key-only compromise of policy members from forging an `Icp` under stolen membership — see [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation).

### `authPolicy` semantics

- `Icp`: declared as a **field** that seeds the IEL prefix (prefix = Blake3 of v0 template with said+prefix blanked). It does NOT authorize the Icp itself — Icp is governance-authorized (see [governancePolicy semantics](#governancepolicy-semantics) below). The `authPolicy` declared at Icp is consumed downstream by SEL `Upd` events that bind to this Icp via `ielEvent`.
- `Evl`: present; preserved (== previous) or evolved (differs from previous; evaluated against the previous tracked `governancePolicy`). At least one of `authPolicy` / `governancePolicy` must evolve in any given `Evl` — an Evl preserving both is rejected.
- `Sea` / `Dec`: **absent (forbidden)**. `Sea` is the seal-advance event; terminal events have no forward state to declare. The verifier rejects any `Sea`/`Dec` carrying a value.

The verifier's branch state tracks the effective `authPolicy` — seeded from `Icp` and updated whenever an `Evl` carries a new value. Authorization for an SEL event that points at a specific IEL event SAID resolves through the tracked `authPolicy` at that IEL event's branch state.

### `governancePolicy` semantics

- `Icp`: declared. Identity chains always declare governance at v0 (no Est dance). Also serves as the **authorization gate** (Icp.said must be anchored under the declared `governancePolicy`) — every IEL event is a governance act.
- `Evl`: present; preserved or evolved (the latter evaluated against the *previous* tracked governancePolicy). At least one of `authPolicy` / `governancePolicy` must evolve per Evl.
- `Sea` / `Dec`: **absent (forbidden)**. Authorization for these kinds resolves through the branch's `trackedGovernancePolicy` (set when the predecessor was processed); the kind itself declares nothing forward.

### Policy immunity requirement

Any policy referenced as a chain's `authPolicy` OR `governancePolicy` — whether at `Icp` (v0) or via a `Evl` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification (hard reject; structural error). This is the structural enforcement of chain stability: IEL chains are time-ordered policy histories, and past authorizations (both auth and governance) must remain stable across the lifetime of the chain.

To revoke an endorser's authority, evolve the policy via `Evl` (issuing a new authPolicy or governancePolicy SAID that excludes the endorser); do not attempt to poison past events. `Evl`-driven evolution is the canonical correction path.

This rule mirrors SEL's immunity rule and serves the same purpose. With IEL, it becomes the cornerstone of cross-chain consistency: every SEL event binds to a specific IEL event SAID, and that IEL event's policy SAIDs must be immune so the binding remains verifiable for the lifetime of any dependent SEL.

See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the SEL-side implications.

### No `content` field

IEL events do not carry content. The chain's "data" is its tracked policy state, mutated via `Evl`. This is the structural contrast with SEL: SEL has `content` (mutated by `Upd`); IEL has policy state (mutated by `Evl`). The two primitives split policy-management from content-recording at the type level.

### Evaluation bound — not applicable

SEL has `MAX_NON_EVALUATION_EVENTS = 63` to bound how long an adversary can fork before satisfying governancePolicy. On IEL, **every event is governance-authorized** (`Icp`, `Evl`, `Sea`, `Dec`). There are no "non-evaluation events" between governance evaluations — every event IS governance-authorized at submission time. The bound is implicit and need not be enforced.

(`lastSealAdvancingEvent` advances on `Evl` and `Sea` — Icp/Dec do not advance the seal — but the governance authorization gate applies uniformly at all kinds. Only one Icp can land per chain, so the chain has at most one pre-Evl event.)

## Typical Chain Shapes

### Identity with policy evolution

```
v0  kind=icp  authPolicy=A0, governancePolicy=G0
v1  kind=evl  authPolicy=A1                              ← authPolicy evolved; governancePolicy unchanged
v2  kind=evl  governancePolicy=G1                        ← governancePolicy evolved; authPolicy unchanged
```

Each `Evl` must evolve at least one policy — a no-op Evl (both fields preserved) is rejected as a structural error. There is no "pure-attestation" mode: `lastSealAdvancingEvent` is the evaluation seal, not a heartbeat counter, and key rotation on anchoring KELs is a layer-below concern that doesn't surface as IEL events.

### Divergence is contested-terminal

```
v0  kind=icp   authPolicy=A0, governancePolicy=G0
v1  kind=evl   authPolicy=A1
v2  kind=evl   previous=v1.said, authPolicy=A2_a            ← submission #1 (linear extension of v_1)
v2' kind=evl   previous=v1.said, authPolicy=A2_b            ← submission #2 (concurrent linear extension on a
                                                              different node; lands at v_2 on its node)
    — 2-event divergent set at v_2 (gossip-merged), both with previous = v_1.said.
      Every IEL event is privileged → privileged-divergence-is-terminal fires
      immediately; chain becomes contested-terminal as of v_2. —
```

The two events at `v_2` carry the same `previous = v_1.said` — each was accepted as a linear-chain extension on its submitting node at submission time, with the two extensions independently landing at `v_2`. Valid 2-event pairings on IEL are `Evl`-`Evl`, `Evl`-`Sea`, and `Sea`-`Evl` — every divergent set at `v_d` contains at least one seal-advancing event by construction (Evl/Sea are the only non-terminal kinds available post-Icp). `Sea`-`Sea` cannot form: IEL `Sea` carries no content or policy fields, so two `Sea` events sharing `(previous, serial, prefix, kind)` are byte-identical → identical SAID → dedup at submit. `Dec` extends the chain's highest-serial event directly (`Dec.previous = parent.said`, where parent is the chain's max-serial event), so it lands only on linear chains and never appears in a divergent set — a `Dec` landing decommissions the chain. Every IEL event is privileged, so the divergent set transitions the chain to contested-terminal immediately by the privileged-divergence-is-terminal rule. **No 3rd event lands at `v_2`** — the contested-state gate rejects all subsequent submissions, including any further `Evl`, `Sea`, or `Dec` arriving at v_2 via gossip.

Both events stay in storage forever as forensic record. Operator re-incepts under a new prefix; the inception nonce is always fresh.

This is intentional: history is encoded in the data. Divergence is accepted as the chain's structural admission that governance is no longer single-authoritative. Termination is the honest answer; there is no `Rpr` to archive one branch in favor of the other (every branch is governance-authorized; the protocol has no grounds to declare one "the" branch).

### Operator recourse against a compromised IEL (competing Evl)

```
v0..v4   normal linear chain (across the federation)
v5       kind=evl   previous=v_4.said, authPolicy=A5_adv     ← compromised party's Evl (threshold-compromise),
                                                              lands at v_5 on adversary's submitting node
v5'      kind=evl   previous=v_4.said, authPolicy=A5_op      ← operator's competing Evl (still satisfying v_4's
                                                              tracked governancePolicy), lands at v_5 on
                                                              operator's submitting node
    — 2-event divergent set at v_5 once both propagate via gossip: {Evl_adv, Evl_op}.
      Privileged-divergence-is-terminal fires; chain contested-terminal as of v_5. —
```

Each submission is a linear-chain extension on its submitting node's local state at submission time. The compromised party — authority acquired via threshold compromise on the governance policy at `v_4` — submits `Evl_adv` on their node (whose local tip is v_4); `Evl_adv` extends v_4 and lands at v_5 on their node. The operator, observing the unexpected `Evl_adv` arriving via gossip, submits their own competing `Evl_op` under the same `v_4` governance authority (which the operator still satisfies — they were a member of the policy threshold before the compromise). `Evl_op` extends v_4 (= the operator's own pre-gossip tip) and lands at v_5 on the operator's node. Once gossip merges the two events, the divergent set at v_5 forms, privileged-divergence-is-terminal fires, and the chain becomes contested-terminal.

The structural signature of "race" and "compromise" is identical from the chain's perspective; consumer-side judgment plus out-of-band knowledge is what determines whether to treat this as accidental race or as intentional takeover. Either way, the chain is contested-terminal once the divergent set forms.

**Operator recourse on IEL is via competing Evl**, not Cnt (IEL has no Cnt — see [§Kinds IEL does not have](#event-kinds) above). The forensic "this IEL was compromised" attribution lives in out-of-band channels (a signed statement under the operator's KEL); the in-band signal is "the IEL went divergent → contested-terminal at v_5."

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec                                            ← owner ends the chain cleanly
```

After `Dec`, all submissions are rejected. Pre-Dec events retain trust under their original authorization (Dec is clean retirement; no compromise signaled). See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.

## Cross-chain binding from SEL to IEL

Every SEL event at v1+ carries `ielEvent: Digest256` — the SAID of an IEL event whose declared/evolved policy authorizes the SEL event. The per-kind binding rule (which IEL policy field gates which SEL kind) and the path-agnostic validation rules (submit, gossip, bootstrap, re-verification) are the canonical SEL-side concern; see [../sel/events.md §Validation rules](../sel/events.md#validation-rules-path-agnostic--submit-gossip-bootstrap-re-verification). For the IEL-side stability invariants that make this binding deterministic forever — immunity, anchor non-poisonability, and the resolution mechanism — see [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability).

Binding by SAID (not serial) is unambiguous under IEL divergence, robust against re-tracked-same-policy patterns, and enables a fast-eval shortcut: one IEL event fetch + one anchor check, without paginating the full IEL chain.

See [../sel/events.md §`ielEvent` semantics](../sel/events.md#ielevent-semantics) for the SEL-side field rules.

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, anchor non-poisonability.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference (the chain primitive that binds to IEL events).
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL and anchoring model (immunity rule).
