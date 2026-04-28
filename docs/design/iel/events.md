# Identity Events: Per-Kind Reference

Pure structural reference for Identity Event Log (IEL) event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For the verifier algorithm, see [verification.md](verification.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/iel/v1/events/icp` | Inception (v0). Declares both `auth_policy` and `governance_policy`. Seeds prefix derivation via `(auth_policy, governance_policy, topic)`. |
| `Evl` | `kels/iel/v1/events/evl` | Evolve — governance evaluation. Advances `last_governance_version`; may evolve `auth_policy` and/or `governance_policy`. |
| `Cnt` | `kels/iel/v1/events/cnt` | Contest — terminal due to authority conflict (or divergence). No archival — both branches preserved as forensic record. |
| `Dec` | `kels/iel/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Evl`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction.

IEL has **no `Upd` kind** — there is no "content" on identity chains. The chain's data is its tracked policy state, mutated only via `Evl`. IEL has **no `Est` kind** — both policies are required at `Icp`, since identity chains are not third-party-discoverable and don't need the optional-governance-at-Icp dance that today's SEL uses. IEL has **no `Rpr` kind** — divergence on IEL is preserved (history is encoded in the data) and resolved by `Cnt` rather than repair; `Rpr`'s "preserve owner's branch, archive adversary's" semantics doesn't apply when both branches have governance authority. See [event-log.md §Divergence and Contest-Only Resolution](event-log.md#divergence-and-contest-only-resolution).

## Per-Kind Field Rules

`IdentityEvent::validate_structure()` enforces version and `previous` rules. Per-kind policy-field discipline (carry-forward vs. evolution vs. declaration) is enforced by the **verifier** — not by `validate_structure` — because the discipline depends on chain-state context (the previous event's policy values) which structural validation alone cannot see.

| Kind | version | previous | auth_policy | governance_policy | sort_priority | authorization |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | declared (required) | declared (required) | 0 | self (auth_policy) |
| `Evl` | `>= 1` | required | preserved or evolved | preserved or evolved | 1 | governance |
| `Cnt` | `>= 1` | required | preserved (must equal previous) | preserved (must equal previous) | 2 | governance |
| `Dec` | `>= 1` | required | preserved (must equal previous) | preserved (must equal previous) | 3 | governance |

`auth_policy` and `governance_policy` are non-`Option` `Digest256` fields on every `IdentityEvent` — the chain's tracked policy state is always present in every event, never absent. "Preserved" means the field's value must equal the value on the predecessor event; "evolved" means it differs (and the difference is what the verifier interprets as a policy evolution requiring governance authorization). "Declared" applies only at `Icp` where there is no predecessor — the inceptor declares both fields directly.

(No `content` field on any kind. IEL events do not carry content.)

### Per-Kind Policy Field Discipline

Every IEL event carries `auth_policy` and `governance_policy`. The verifier checks the per-kind discipline as part of branch-state validation:

- **`Icp`**: declares both policies. The verifier records them as the chain's initial tracked auth and governance policies after confirming both are immune and Icp.said is anchored under the declared `auth_policy`.
- **`Evl`**: may carry the same values as the predecessor (no evolution — `Evl` is a pure governance attestation that advances `last_governance_version` without changing tracked policies) OR may carry different values (an evolution; the verifier records the new tracked policies after confirming the new policy is immune and the Evl is anchored under the *previous* tracked governance_policy). Either field can evolve independently.
- **`Cnt` / `Dec`**: must carry the same values as the predecessor. The verifier rejects any Cnt/Dec whose `auth_policy` or `governance_policy` differs from the predecessor's as a structural-equivalent error (the design's "forbidden field on terminal kinds" rule, enforced at the verifier rather than at `validate_structure` because the predecessor's values are needed to make the comparison).

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event:

- **Icp** must satisfy the `auth_policy` it declares. The inceptor proves membership in the policy they're naming by anchoring `Icp.said` under that policy. Identity chains aren't third-party-discoverable, so the prefix derivation `(auth_policy, governance_policy, topic) → prefix` is private to the inceptor — there's no phishing class equivalent to today's SEL Icp gate. The anchoring requirement remains as a structural authentication of the inceptor against the policy they declare.
- **Evl / Cnt / Dec** must satisfy the branch's tracked `governance_policy` — the higher bar. They do NOT separately need to satisfy `auth_policy`: a properly-crafted `governance_policy` should subsume `auth_policy`. See [event-log.md §Authorization Asymmetry vs. KEL Cnt](event-log.md#authorization-asymmetry-vs-kel-cnt) for the rationale.

### `auth_policy` semantics

- `Icp`: declared as a **field** (seeds the IEL prefix — prefix = Blake3 of v0 template with said+prefix blanked) AND serves as the **authorization gate** (Icp.said must be anchored under the declared `auth_policy`).
- `Evl`: present on every event; preserved (== previous) or evolved (differs from previous; evaluated against the previous tracked `governance_policy`).
- `Cnt` / `Dec`: present on every event; must be preserved (== previous). Verifier rejects evolution at terminal kinds.

The verifier's branch state tracks the effective `auth_policy` — seeded from `Icp` and updated whenever an `Evl` carries a new value. Authorization for an SE event that points at a specific IEL event SAID resolves through the tracked `auth_policy` at that IEL event's branch state.

### `governance_policy` semantics

- `Icp`: declared. Identity chains always declare governance at v0 (no Est dance).
- `Evl`: present on every event; preserved or evolved (the latter evaluated against the *previous* tracked governance_policy).
- `Cnt` / `Dec`: present on every event; must be preserved.

### Policy immunity requirement

Any policy referenced as a chain's `auth_policy` OR `governance_policy` — whether at `Icp` (v0) or via a `Evl` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification (hard reject; structural error). This is the structural enforcement of chain stability: IEL chains are time-ordered policy histories, and past authorizations (both auth and governance) must remain stable across the lifetime of the chain.

To revoke an endorser's authority, evolve the policy via `Evl` (issuing a new auth_policy or governance_policy SAID that excludes the endorser); do not attempt to poison past events. `Evl`-driven evolution is the canonical correction path.

This rule mirrors today's SEL immunity rule and serves the same purpose. With IEL, it becomes the cornerstone of cross-chain consistency: every SE event binds to a specific IEL event SAID, and that IEL event's policy SAIDs must be immune so the binding remains verifiable for the lifetime of any dependent SE chain.

See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the SE-side implications.

### No `content` field

IEL events do not carry content. The chain's "data" is its tracked policy state, mutated via `Evl`. This is the structural contrast with SE: SE has `content` (mutated by `Upd`); IEL has policy state (mutated by `Evl`). The two primitives split policy-management from content-recording at the type level.

### Evaluation bound — not applicable

Today's SEL has `MAX_NON_EVALUATION_EVENTS = 63` to bound how long an adversary can fork before satisfying governance_policy. On IEL, **every event after Icp is governance-authorized** (`Evl`, `Cnt`, `Dec`). There are no "non-evaluation events" between governance evaluations — every event IS a governance evaluation. The bound is implicit and need not be enforced.

(Icp counts as a non-evaluation event in the SEL sense, but only one Icp can land per chain, so it doesn't introduce an unbounded run.)

## Typical Chain Shapes

### Identity with policy evolution

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=evl  auth_policy=A1                              ← auth_policy evolved; governance_policy unchanged
v2  kind=evl  governance_policy=G1                        ← governance_policy evolved; auth_policy unchanged
v3  kind=evl                                              ← pure attestation; no field evolution
```

Pure-attestation `Evl` is permitted — it advances `last_governance_version` without changing tracked policies. Useful as a periodic governance reattestation if no concrete evolution is needed.

### Divergence terminated by contest

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=evl  auth_policy=A1                                 (owner)
v1' kind=evl  auth_policy=A1_alternate                       (concurrent submission, gossip race)
    — both branches preserved; chain divergent —
v2  kind=cnt  previous=v1.said                               ← Cnt extends one branch; chain becomes contested
```

Both branches stay in storage forever as forensic record. The chain is terminal once `Cnt` lands. Owner re-incepts under a different prefix (different topic, or new IEL identity).

This is intentional: history is encoded in the data. We accept divergence and resolve via `Cnt`, rather than having an `Rpr` archive one branch in favor of the other. When two governance-authorized parties produce conflicting events, neither can be "the" branch under the other's authority — the chain has demonstrated that its governance is no longer single-authoritative, and termination is the honest answer.

### Contest after governance compromise

```
v0..v4   normal chain, last_governance_version=4 (Evl at v4)
         (an unauthorized actor submits Evl at v5 — racing the legitimate owner or simply substituting)
v6       owner submits Cnt extending current tip            ← chain becomes contested, terminal
```

Contest is the operator's path whenever the chain's governance integrity has broken — whether via gossip race or compromise. Same kind, same lifecycle.

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec                                            ← owner ends the chain cleanly
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## Cross-chain binding from SE to IEL

Every SE event at v1+ carries `identity_event: Digest256` — the SAID of the IEL event whose declared/evolved policy authorizes the SE event. Per-kind binding:

- SE `Upd` → binds to an IEL `Icp` or `Evl`-with-auth-policy event whose declared/evolved `auth_policy` authorizes the Upd's anchor.
- SE `Sea` / `Rpr` / `Cnt` / `Dec` → binds to an IEL `Icp` or `Evl`-with-governance-policy event whose declared/evolved `governance_policy` authorizes the lifecycle event's anchor. (SE retains its own `Sea` and `Rpr` kinds; the asymmetry is intentional — see [../sel/events.md](../sel/events.md) for the SE kind set.)

Binding by SAID (not version) is unambiguous under IEL divergence, robust against re-tracked-same-policy patterns, and enables a fast-eval shortcut: one IEL event fetch + one anchor check, without paginating the full IEL chain.

The binding rule is **path-agnostic** — the same validation applies at submit, gossip ingestion, bootstrap, and re-verification. The protocol does not distinguish data by ingestion path. KELS data is data; pulling it from one node and putting it into another is no big deal. See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the unified rule and the operator-discipline corollary that handles governance-evolution races.

See [../sel/events.md §`identity_event` semantics](../sel/events.md#identity_event-semantics) for the SE-side field rules.

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, anchor non-poisonability.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/events.md](../sel/events.md) — SE per-kind reference (the chain primitive that binds to IEL events).
- [../policy.md](../policy.md) — Policy DSL and anchoring model (immunity rule).
