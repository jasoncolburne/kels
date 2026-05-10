# Identity Events: Per-Kind Reference

Pure structural reference for Identity Event Log (IEL) event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For the verifier algorithm, see [verification.md](verification.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/iel/v1/events/icp` | Inception (v0). Declares both `auth_policy` and `governance_policy`. Seeds prefix derivation via `(auth_policy, governance_policy, topic)`. |
| `Evl` | `kels/iel/v1/events/evl` | Evolve — governance evaluation. Advances `last_governance_event`. MUST evolve at least one of `auth_policy` / `governance_policy`; a no-op Evl is rejected as a structural error. |
| `Cnt` | `kels/iel/v1/events/cnt` | Contest — terminal due to authority conflict (or divergence). No archival — both branches preserved as forensic record. |
| `Dec` | `kels/iel/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Evl`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction.

IEL has **no `Upd` kind** — there is no "content" on identity chains. The chain's data is its tracked policy state, mutated only via `Evl`. IEL has **no `Est` kind** — both policies are required at `Icp`, since identity chains are not third-party-discoverable and don't need the optional-governance-at-Icp dance that today's SEL uses. IEL has **no `Rpr` kind** — divergence on IEL is immediately terminal (every IEL event is privileged, so any divergent set on IEL fires the privileged-divergence-is-terminal rule); there's no "preserve one branch, archive the other" shape because the protocol cannot adjudicate from chain data when both branches are governance-authorized. See [event-log.md §Divergence and Contest-Only Resolution](event-log.md#divergence-and-contest-only-resolution).

## Per-Kind Field Rules

`IdentityEvent::validate_structure()` enforces version and `previous` rules. Per-kind policy-field discipline (carry-forward vs. evolution vs. declaration) is enforced by the **verifier** — not by `validate_structure` — because the discipline depends on chain-state context (the previous event's policy values) which structural validation alone cannot see.

| Kind | version | previous | auth_policy | governance_policy | sort_priority | authorization |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | declared (required) | declared (required) | 0 | self (governance_policy) |
| `Evl` | `>= 1` | required | preserved or evolved | preserved or evolved (at least one of `auth_policy` / `governance_policy` MUST evolve) | 1 | governance |
| `Cnt` | `>= 1` | required | preserved (must equal previous) | preserved (must equal previous) | 2 | governance |
| `Dec` | `>= 1` | required | preserved (must equal previous) | preserved (must equal previous) | 3 | governance |

`auth_policy` and `governance_policy` are non-`Option` `Digest256` fields on every `IdentityEvent` — the chain's tracked policy state is always present in every event, never absent. "Preserved" means the field's value must equal the value on the predecessor event; "evolved" means it differs (and the difference is what the verifier interprets as a policy evolution requiring governance authorization). "Declared" applies only at `Icp` where there is no predecessor — the inceptor declares both fields directly.

(No `content` field on any kind. IEL events do not carry content.)

### Per-Kind Policy Field Discipline

Every IEL event carries `auth_policy` and `governance_policy`. The verifier checks the per-kind discipline as part of branch-state validation:

- **`Icp`**: declares both policies. The verifier records them as the chain's initial tracked auth and governance policies after confirming both are immune and Icp.said is anchored under the declared `governance_policy` (every IEL event is governance-authorized — see [§Satisfaction model](#satisfaction-model)).
- **`Evl`**: MUST evolve at least one of `auth_policy` / `governance_policy`. Either field can evolve independently; both can evolve in the same `Evl`. A no-op `Evl` (both fields identical to the predecessor) is rejected — `last_governance_event` is the chain's evaluation seal, not a heartbeat counter, so every `Evl` must be a real governance act. The verifier records the new tracked policies after confirming any new policy is immune and the Evl is anchored under the *previous* tracked governance_policy.
- **`Cnt` / `Dec`**: must carry the same values as the predecessor. The verifier rejects any Cnt/Dec whose `auth_policy` or `governance_policy` differs from the predecessor's as a structural-equivalent error (the design's "forbidden field on terminal kinds" rule, enforced at the verifier rather than at `validate_structure` because the predecessor's values are needed to make the comparison).

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event. **Every IEL event is governance-authorized**: IEL is the governance primitive, so even inception — the act of declaring the chain's policies — is itself a governance act. The chain's `auth_policy` is reserved for application-facing per-event authorization, consumed by SEL `Upd` events via `identity_event` binding (see [../sel/events.md](../sel/events.md)); it is never the gate that authorizes IEL events themselves.

- **Icp** must satisfy the `governance_policy` it declares. The inceptor proves membership in the governance policy they're naming by anchoring `Icp.said` under that policy. Identity chains aren't third-party-discoverable, so the prefix derivation `(auth_policy, governance_policy, topic) → prefix` is private to the inceptor — there's no phishing class equivalent to today's SEL Icp gate. The anchoring requirement is the structural authentication of the inceptor against the governance policy they declare.
- **Evl / Cnt / Dec** must satisfy the branch's tracked `governance_policy`. Same gate as Icp; same rule across the chain. They do NOT separately need to satisfy `auth_policy`: `auth_policy` is reserved for SEL Upd authorization through the bound IEL event.

### `auth_policy` semantics

- `Icp`: declared as a **field** that seeds the IEL prefix (prefix = Blake3 of v0 template with said+prefix blanked). It does NOT authorize the Icp itself — Icp is governance-authorized (see [governance_policy semantics](#governance_policy-semantics) below). The `auth_policy` declared at Icp is consumed downstream by SEL `Upd` events that bind to this Icp via `identity_event`.
- `Evl`: present on every event; preserved (== previous) or evolved (differs from previous; evaluated against the previous tracked `governance_policy`). At least one of `auth_policy` / `governance_policy` must evolve in any given `Evl` — an Evl preserving both is rejected.
- `Cnt` / `Dec`: present on every event; must be preserved (== previous). Verifier rejects evolution at terminal kinds.

The verifier's branch state tracks the effective `auth_policy` — seeded from `Icp` and updated whenever an `Evl` carries a new value. Authorization for an SEL event that points at a specific IEL event SAID resolves through the tracked `auth_policy` at that IEL event's branch state.

### `governance_policy` semantics

- `Icp`: declared. Identity chains always declare governance at v0 (no Est dance). Also serves as the **authorization gate** (Icp.said must be anchored under the declared `governance_policy`) — every IEL event is a governance act.
- `Evl`: present on every event; preserved or evolved (the latter evaluated against the *previous* tracked governance_policy). At least one of `auth_policy` / `governance_policy` must evolve per Evl.
- `Cnt` / `Dec`: present on every event; must be preserved.

### Policy immunity requirement

Any policy referenced as a chain's `auth_policy` OR `governance_policy` — whether at `Icp` (v0) or via a `Evl` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification (hard reject; structural error). This is the structural enforcement of chain stability: IEL chains are time-ordered policy histories, and past authorizations (both auth and governance) must remain stable across the lifetime of the chain.

To revoke an endorser's authority, evolve the policy via `Evl` (issuing a new auth_policy or governance_policy SAID that excludes the endorser); do not attempt to poison past events. `Evl`-driven evolution is the canonical correction path.

This rule mirrors today's SEL immunity rule and serves the same purpose. With IEL, it becomes the cornerstone of cross-chain consistency: every SEL event binds to a specific IEL event SAID, and that IEL event's policy SAIDs must be immune so the binding remains verifiable for the lifetime of any dependent SEL.

See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the SEL-side implications.

### No `content` field

IEL events do not carry content. The chain's "data" is its tracked policy state, mutated via `Evl`. This is the structural contrast with SEL: SEL has `content` (mutated by `Upd`); IEL has policy state (mutated by `Evl`). The two primitives split policy-management from content-recording at the type level.

### Evaluation bound — not applicable

Today's SEL has `MAX_NON_EVALUATION_EVENTS = 63` to bound how long an adversary can fork before satisfying governance_policy. On IEL, **every event is governance-authorized** (`Icp`, `Evl`, `Cnt`, `Dec`). There are no "non-evaluation events" between governance evaluations — every event IS governance-authorized at submission time. The bound is implicit and need not be enforced.

(`last_governance_event` advances only on `Evl` — Icp/Cnt/Dec do not advance the seal — but the governance authorization gate applies uniformly at all kinds. Only one Icp can land per chain, so the chain has at most one pre-Evl event.)

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
v2  kind=evl  previous=v1.said, auth_policy=A2_a            ← concurrent submission #1
v2' kind=cnt  previous=v1.said                              ← concurrent submission #2 (lands at v_2 alongside v_2)
    — 2-event divergent set at v_2, both with previous = v_1.said.
      Every IEL event is privileged → privileged-divergence-is-terminal fires
      immediately; chain becomes contested-terminal as of v_2. —
```

The two events at `v_2` carry the same `previous = v_1.said` (the `v_{tip-1}` rule applied to a chain whose tip is v_1). The 2-event set may be any combination of `Evl`/`Cnt` (and structurally any IEL kind, since every IEL event is governance-authorized — `Icp`, `Evl`, `Cnt`, `Dec` are all privileged); the outcome is the same. **No 3rd event lands at `v_2`** — the contested-state gate rejects all subsequent submissions, including any further `Evl`, `Cnt`, or `Dec` arriving at v_2 via gossip. **Once divergence is observed, no Cnt is accepted on a divergent IEL** — Cnt only lands as one of the events in the original 2-event divergent set, or as the linear-chain operator-initiated termination (see next example).

Both events stay in storage forever as forensic record. Operator re-incepts under a different prefix (different topic, or new IEL identity).

This is intentional: history is encoded in the data. We accept divergence and treat it as the chain's structural admission that governance is no longer single-authoritative. Termination is the honest answer; there is no `Rpr` to archive one branch in favor of the other (every branch is governance-authorized; the protocol has no grounds to declare one "the" branch).

### Contest joining a divergent set after governance compromise

```
v0..v3   normal chain
v4       kind=evl  Evl_v4 advances last_governance_event to Evl_v4.said
         (a second governance-authorized party — authority acquired via threshold compromise —
          submits Evl_v5 at v_5 with previous = v_4.said; lands first via gossip race)
v5'      kind=cnt  previous=v_4.said, version=5             ← operator's Cnt joins Evl_v5 in divergent set at v_5
    — 2-event divergent set at v_5: {Evl_v5 (other party), Cnt}. Privileged-divergence-is-
      terminal fires; chain contested-terminal as of v_5. —
```

Cnt's `previous = v_{tip-1}.said = v_4.said` is the divergence ancestor — the parent shared with Evl_v5. Authorization resolves through `v_4`'s tracked `governance_policy` (the policy in effect when v_4 landed — the legitimate pre-compromise governance), which the operator still satisfies. The structural signature of "race" and "compromise" is identical from the chain's perspective; consumer-side judgment + out-of-band knowledge is what determines whether to treat this as accidental race or as intentional takeover. Either way, the chain is contested-terminal once the divergent set forms.

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec                                            ← owner ends the chain cleanly
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## Cross-chain binding from SEL to IEL

Every SEL event at v1+ carries `identity_event: Digest256` — the SAID of the IEL event whose declared/evolved policy authorizes the SEL event. Per-kind binding:

- SEL `Upd` → binds to an IEL `Icp` or `Evl`-with-auth-policy event whose declared/evolved `auth_policy` authorizes the Upd's anchor.
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
- [../policy.md](../policy.md) — Policy DSL and anchoring model (immunity rule).
