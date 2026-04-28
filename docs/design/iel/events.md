# Identity Events: Per-Kind Reference

Pure structural reference for Identity Event Log (IEL) event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For the verifier algorithm, see [verification.md](verification.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/iel/v1/events/icp` | Inception (v0). Declares both `auth_policy` and `governance_policy`. Seeds prefix derivation via `(auth_policy, governance_policy, topic)`. |
| `Sea` | `kels/iel/v1/events/sea` | Seal — governance evaluation. Advances `last_governance_version`; may evolve `auth_policy` and/or `governance_policy`. |
| `Rpr` | `kels/iel/v1/events/rpr` | Repair — resolves divergence and seals. Discriminator-driven archival of adversary events. |
| `Cnt` | `kels/iel/v1/events/cnt` | Contest — terminal due to authority conflict. No archival — the chain itself is the record. |
| `Dec` | `kels/iel/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction.

IEL has **no `Upd` kind** — there is no "content" on identity chains. The chain's data is its tracked policy state, mutated only via `Sea`. IEL has **no `Est` kind** — both policies are required at `Icp`, since identity chains are not third-party-discoverable and don't need the optional-governance-at-Icp dance that today's SEL uses.

## Per-Kind Field Rules

`IdentityEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top (e.g., immunity check on every introduced/evolved policy).

| Kind | version | previous | auth_policy | governance_policy | authorization |
|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | self (auth_policy) |
| `Sea` | `>= 1` | required | optional | optional | governance |
| `Rpr` | `>= 1` | required | forbidden | forbidden | governance |
| `Cnt` | `>= 1` | required | forbidden | forbidden | governance |
| `Dec` | `>= 1` | required | forbidden | forbidden | governance |

(No `content` field on any kind. IEL events do not carry content.)

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event:

- **Icp** must satisfy the `auth_policy` it declares. The inceptor proves membership in the policy they're naming by anchoring `Icp.said` under that policy. Identity chains aren't third-party-discoverable, so the prefix derivation `(auth_policy, governance_policy, topic) → prefix` is private to the inceptor — there's no phishing class equivalent to today's SEL Icp gate (which guards against an adversary submitting an Icp on a public `(write_policy, topic)` pair). The anchoring requirement remains as a structural authentication of the inceptor against the policy they declare.
- **Sea / Rpr / Cnt / Dec** must satisfy the branch's tracked `governance_policy` — the higher bar. They do NOT separately need to satisfy `auth_policy`: a properly-crafted `governance_policy` should subsume `auth_policy`. See [event-log.md](event-log.md#authorization-asymmetry-vs-kel-cnt) for the rationale, which mirrors today's SEL.

### `auth_policy` semantics

- `Icp`: required as a **field** (seeds the IEL prefix — prefix = Blake3 of v0 template with said+prefix blanked) AND as the **authorization gate** (Icp.said must be anchored under the declared `auth_policy`).
- `Sea`: optional — present means policy evolution (evaluated against `governance_policy`, the higher bar). Absent means the policy is unchanged across the Sea.
- `Rpr` / `Cnt` / `Dec`: forbidden as a field. To evolve `auth_policy` after one of these, submit a separate `Sea` afterward.

The verifier's branch state tracks the effective `auth_policy` — seeded from `Icp` and updated whenever a `Sea` carries a new `auth_policy`. Authorization for an SE event that points at a specific IEL event SAID resolves through the tracked `auth_policy` at that IEL event's branch state.

### `governance_policy` semantics

- `Icp`: required. Identity chains always declare governance at v0 (no Est dance).
- `Sea`: optional — present means governance policy evolution (evaluated against the *previous* tracked governance_policy).
- `Rpr` / `Cnt` / `Dec`: forbidden as a field. To evolve governance_policy after one of these, submit a separate `Sea` afterward.

### Policy immunity requirement

Any policy referenced as a chain's `auth_policy` OR `governance_policy` — whether at `Icp` (v0) or via a `Sea` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification (hard reject; structural error). This is the structural enforcement of chain stability: IEL chains are time-ordered policy histories, and past authorizations (both auth and governance) must remain stable across the lifetime of the chain.

To revoke an endorser's authority, evolve the policy via `Sea` (issuing a new auth_policy or governance_policy SAID that excludes the endorser); do not attempt to poison past events. `Sea`-driven evolution is the canonical correction path.

This rule mirrors today's SEL immunity rule and serves the same purpose. With IEL, it becomes the cornerstone of cross-chain consistency: every SE event binds to a specific IEL event SAID, and that IEL event's policy SAIDs must be immune so the binding remains verifiable for the lifetime of any dependent SE chain.

See [event-log.md §Cross-Chain Anchor Stability](event-log.md#cross-chain-anchor-stability) for the SE-side implications.

### No `content` field

IEL events do not carry content. The chain's "data" is its tracked policy state, mutated via `Sea`. This is the structural contrast with SE: SE has `content` (mutated by `Upd`); IEL has policy state (mutated by `Sea`). The two primitives split policy-management from content-recording at the type level.

### Evaluation bound — not applicable

Today's SEL has `MAX_NON_EVALUATION_EVENTS = 63` to bound how long an adversary can fork before satisfying governance_policy. On IEL, **every event after Icp is governance-authorized** (Sea, Rpr, Cnt, Dec). There are no "non-evaluation events" between governance evaluations — every event IS a governance evaluation. The bound is implicit and need not be enforced.

(Icp counts as a non-evaluation event in the SEL sense, but only one Icp can land per chain, so it doesn't introduce an unbounded run.)

## Typical Chain Shapes

### Identity with policy evolution

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=sea  auth_policy=A1                              ← auth_policy evolved; governance_policy unchanged
v2  kind=sea  governance_policy=G1                        ← governance_policy evolved; auth_policy unchanged
v3  kind=sea                                              ← pure attestation; no field evolution
```

Pure-attestation Sea is permitted — it advances `last_governance_version` without changing tracked policies. Useful as a periodic governance reattestation if no concrete evolution is needed.

### Divergence resolved by repair

```
v0  kind=icp  auth_policy=A0, governance_policy=G0
v1  kind=sea  auth_policy=A1                                 (owner)
v1' kind=sea  auth_policy=A1_adversary                       (adversary races at v1)
    — chain frozen, divergent —
v2  kind=rpr  previous=v1.said                               ← Rpr extends owner's tip; v1' archived
```

The adversary's ability to fork is bounded by the governance_policy gate — they need governance authority even to create the fork. The fork resolution is via `Rpr`, identical in shape to SEL's repair.

### Contest after governance compromise

```
v0..v4   normal chain, last_governance_version=4 (Sea at v4)
         (an unauthorized Sea then lands at v5 advancing the seal to 5)
v6       owner submits Cnt extending current tip            ← chain becomes contested, terminal
```

Contest is the operator's path when an adversary has demonstrated governance authority that the legitimate holder cannot defeat.

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec                                            ← owner ends the chain cleanly
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.

## Cross-chain binding from SE to IEL

Every SE event at v1+ carries `identity_event: Digest256` — the SAID of the IEL event whose declared/evolved policy authorizes the SE event. Per-kind binding:

- SE `Upd` → binds to an IEL `Icp` or `Sea`-with-auth-policy event whose declared/evolved `auth_policy` authorizes the Upd's anchor.
- SE `Sea` / `Rpr` / `Cnt` / `Dec` → binds to an IEL `Icp` or `Sea`-with-governance-policy event whose declared/evolved `governance_policy` authorizes the lifecycle event's anchor.

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
