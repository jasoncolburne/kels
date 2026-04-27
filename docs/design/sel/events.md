# SAD Events: Per-Kind Reference

Pure structural reference for SAD event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, repair, contest, decommission, evaluation seal), see [event-log.md](event-log.md). For storage, API, gossip, and custody, see [../sadstore.md](../sadstore.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/sad/v1/events/icp` | Inception (v0). Seeds prefix derivation via `(write_policy, topic)`. |
| `Est` | `kels/sad/v1/events/est` | Establish `governance_policy` at v1, when v0 did not declare it. |
| `Upd` | `kels/sad/v1/events/upd` | Normal update — append content to the chain. |
| `Sea` | `kels/sad/v1/events/sea` | Seal — governance evaluation. Advances `last_governance_version`; may evolve `write_policy` / `governance_policy`. |
| `Rpr` | `kels/sad/v1/events/rpr` | Repair — resolves divergence and seals. Discriminator-driven archival of adversary events. |
| `Cnt` | `kels/sad/v1/events/cnt` | Contest — terminal due to authority conflict. No archival — the chain itself is the record. |
| `Dec` | `kels/sad/v1/events/dec` | Decommission — terminal owner-initiated end. |

`Sea`, `Rpr`, `Cnt`, `Dec` all return `evaluates_governance() = true` — each requires `governance_policy` satisfaction.

## Per-Kind Field Rules

`SadEvent::validate_structure()` enforces these. The verifier adds chain-state checks on top (e.g., Est rejected when governance_policy already established from v0; Upd/Sea/Rpr/Cnt/Dec rejected when no governance_policy established).

| Kind | version | previous | content | write_policy | governance_policy | authorization |
|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | forbidden | **required** | optional | write |
| `Est` | `== 1` | required | forbidden | forbidden | **required** | write |
| `Upd` | `>= 1` | required | **required** | forbidden | forbidden | write |
| `Sea` | `>= 1` | required | preserved | optional | optional | governance |
| `Rpr` | `>= 1` | required | preserved | forbidden | forbidden | governance |
| `Cnt` | `>= 1` | required | preserved | forbidden | forbidden | governance |
| `Dec` | `>= 1` | required | preserved | forbidden | forbidden | governance |

### Satisfaction model

The "authorization" column names which policy must be satisfied for the verifier to accept the event:

- **Icp** must satisfy the `write_policy` it declares. The inceptor proves membership in the policy they're naming by anchoring `Icp.said` under that policy. The SAID + prefix derivation provides chain identity (a colliding Icp with different declarations belongs to a different chain), but identity is not authorization — anchoring under the declared `write_policy` is. This is the SEL analog of KEL's "Icp signed by the declared `public_key`" rule: in both, v0 authenticates the inceptor against what v0 declares. Without this gate, an adversary could submit an Icp declaring an arbitrary `governance_policy` of their choosing for any public `(write_policy, topic)` pair — the resulting chain would have a different prefix, but the adversary could lure a write-authorized party into submitting an `Upd` to it (e.g., via a phishing prefix), then later use the adversary-controlled `governance_policy` to `Sea`-rotate `write_policy` and capture the chain. Anchoring Icp under `write_policy` closes this by ensuring only members of the declared policy can incept the chain.
- **Est / Upd** must also satisfy the branch's tracked `write_policy`. The verifier seeds `tracked_write_policy` from v0's declaration and updates it whenever a `Sea` carries a new `write_policy`. v1+ authorization checks against the tracked value, not the event's own field.
- **Sea / Rpr / Cnt / Dec** must satisfy `governance_policy` — the higher bar. They do NOT separately need to satisfy `write_policy`: a properly-crafted `governance_policy` should subsume `write_policy` (a chain whose governance authorizes a strictly disjoint set from its write authority is misconfigured, not a case the kind structure should defend against). See [event-log.md](event-log.md#authorization-asymmetry-vs-kel-cnt) for the rationale and the contrast with KEL's dual-signature model.

### `write_policy` semantics

- `Icp`: required as a **field** (seeds the SEL prefix — prefix = Blake3 of v0 template with said+prefix blanked) AND as the **authorization gate** (Icp.said must be anchored under the declared `write_policy`).
- `Sea`: optional — present means policy evolution (evaluated against `governance_policy`, the higher bar). Absent means pure evaluation.
- `Est` / `Upd` / `Rpr` / `Cnt` / `Dec`: forbidden as a field. Est declares governance_policy, not write_policy. Upd is content-only. Rpr/Cnt/Dec are governance-authorized lifecycle transitions; to evolve policy after repair, submit a separate `Sea` afterward.

The verifier's `SadBranchState` tracks the effective `tracked_write_policy` — seeded from v0 (Icp always carries it) and updated whenever a `Sea` event carries a new write_policy. v1+ events are authorized against `branch.tracked_write_policy`, not the event's own field. This prevents an adversary who satisfies the current write_policy from replacing the policy via an Upd-style event: policy replacement requires satisfying the stricter `governance_policy` too.

### `governance_policy` semantics

- `Icp`: optional. Declaring on v0 changes the SEL prefix derivation. Use only when the caller controls prefix computation; for discoverable chains, omit on v0 and declare via Est at v1.
- `Est`: required. v1 establishment when v0 omitted governance_policy.
- `Sea`: optional — present means governance policy evolution (evaluated against the *previous* tracked governance_policy).
- `Upd` / `Rpr` / `Cnt` / `Dec`: forbidden on the event. To evolve governance_policy after one of these, submit a separate `Sea`.

### Policy immunity requirement

Any policy referenced as a chain's `write_policy` OR `governance_policy` — whether at `Icp` (v0), `Est` (v1), or via a `Sea` evolution — MUST have `immune: true`. Non-immune policies are rejected at submit time and during verification. This is the structural enforcement of chain stability: SEL chains are time-ordered histories, and past authorizations (both write and governance) must remain stable across the lifetime of the chain. Immunity is structural, not behavioral; it does not depend on evaluator carve-outs.

To revoke an endorser's authority, evolve the policy via `Sea` (issuing a new write_policy or governance_policy SAID that excludes the endorser); do not attempt to poison past events. `Sea`-driven evolution is the canonical correction path. The forward-looking effect of policy evolution is what changes — past events stay authorized under the policy that was in effect when they landed. For compromise of an underlying anchoring KEL, the corrective mechanism is `rec` / `cnt` on that KEL (see [event-log.md §Trust Caveat — Recovered Anchoring KELs](event-log.md#trust-caveat--recovered-anchoring-kels)).

See [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability) for the full rationale and contrast with credential-side poison semantics (which stay current-state-aware).

### `content` semantics

`Upd` is the **only** kind that introduces or changes `content`. Every other kind that allows content (`Sea`, `Rpr`, `Cnt`, `Dec`) must carry forward the most recent `Upd`'s content value — i.e., `event.content == previous.content`. The verifier enforces this as a chain-state check.

- `Icp`: forbidden — v0 has no content (keeps prefix derivation deterministic).
- `Est`: forbidden — Est establishes governance_policy, not content. The first content lands at the first `Upd`.
- `Upd`: required — the sole content-mutating kind.
- `Sea` / `Rpr` / `Cnt` / `Dec`: preserved — must equal `previous.content` (which is `None` if no `Upd` has landed yet on the chain).

This tightening makes content evolution legible at a glance: scanning the chain, every content change corresponds to an `Upd` event, and every other kind operates on chain *state* (policy, divergence resolution, terminal lifecycle) without entangling content semantics.

### Evaluation bound

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`. After 63 non-evaluation events (i.e., events that aren't `Sea` / `Rpr` / `Cnt` / `Dec`), the next event must be a governance evaluation. This bound caps an adversary's fork to 63 events before they need to satisfy governance_policy. Est counts as a non-evaluation event toward this bound.

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  write_policy=endorse(kel_prefix), topic=kels/sad/v1/keys/mlkem
v1  kind=est  governance_policy=endorse(kel_prefix)            ← no content; Est establishes governance only
v2  kind=upd  content=key_publication_said                     ← first Upd introduces content
v3  kind=upd  content=rotated_key_said                         ← Upd mutates content
v4  kind=sea  content=rotated_key_said                         ← preserved from v3; pure evaluation
```

### Identity chain with policy evolution

```
v0  kind=icp  write_policy=policy_a_said, topic=kels/sad/v1/identity/chain
v1  kind=est  governance_policy=policy_a_said
v2  kind=sea  write_policy=policy_b_said                       ← policy evolution; content preserved (None)
v3  kind=sea                                                    ← pure evaluation; content preserved (None)
```

### Divergence resolved by repair

```
v0  kind=icp  governance_policy=gp_said
v1  kind=upd  content=v1_content
v2a kind=upd  content=owner_v2_content       (owner)           ← fork
v2b kind=upd  content=adversary_v2_content   (adversary)       ← fork (races with v2a)
    — chain frozen, divergent effective SAID —
v3  kind=rpr  previous=v2a.said, content=owner_v2_content      ← Rpr extends owner's tip; content preserved from v2a; v2b archived
```

The `Rpr` extends owner's authentic tip (v2a), not the pre-divergence ancestor. The server walks back from `Rpr.previous` to identify the owner's chain; v2b is archived. Content on the Rpr equals v2a's content (preservation); only an `Upd` after the repair would mutate content. See [event-log.md](event-log.md#repair-rpr) for the discriminator algorithm.

### Contest after seal capture

```
v0..v4   normal chain, last_governance_version=4 (Sea at v4)
v5       owner Upd at v5 → write_policy satisfied; v5 > seal=4 → lands; seal still 4
         (an unauthorized Sea then lands at v6 advancing the seal to 6)
v6       owner submits Upd extending their local v5 (proposed version=6)
            → write_policy satisfied, but v6 ≤ seal=6 → ContestRequired
v7       owner submits Cnt extending current tip                ← chain becomes contested, terminal
                                                                   (Cnt's content preserved from v6's content)
```

### Clean decommission

```
v0..vN   normal chain
vN+1     kind=dec   ← owner ends the chain cleanly
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and server-observable case taxonomy.
