# Identity Event Log (IEL) — Lifecycle, Divergence, Contest, Decommission

> Source-of-truth design doc for the IEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing), and [verification.md](verification.md) (IelVerifier algorithm).

The Identity Event Log (IEL) is a per-prefix chain of `IdentityEvent` records describing the evolving authorization state of an identity — its tracked `auth_policy` and `governance_policy`. Authority over the IEL is asserted by anchoring `ixn` events in one or more KELs identified by the chain's currently-tracked policies (mirrors SEL's anchoring model).

IEL is the authorization root for SE chains. Every SAD Event Log binds to a specific IEL by SAID at inception and resolves its per-event authorization through specific IEL events. See [../sel/events.md §`identity_event` semantics](../sel/events.md#identity_event-semantics) for the SE-side binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain of events, latest tip extends cleanly. | Yes — `Evl`, `Cnt`, `Dec` (per `governance_policy`). |
| **Divergent** | Two events exist at some version `d`. Both branches preserved as forensic record. | Only `Cnt` (governance authorized; terminates the chain). All other submissions return `ContestRequired`. |
| **Contested** | Chain has terminated due to authority conflict (or divergence) — at least one `Cnt` event in the chain. | None. All submissions rejected. |
| **Decommissioned** | Chain has terminated cleanly by owner action — at least one `Dec` event in the chain. | None. All submissions rejected. |

State is computed from the chain's events, never tracked as a separate flag. The `IelVerification` token surfaces:
- `diverged_at_version: Option<u64>`
- `is_contested: bool`
- `is_decommissioned: bool`
- `last_governance_version: Option<u64>` — version of the most recent `Evl` (the "evaluation seal").

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `auth_policy` and `governance_policy`. | `auth_policy` (Icp.said anchored under the declared auth_policy). | No |
| `Evl` | Evolve — governance evaluation; advances the seal, may evolve `auth_policy` and/or `governance_policy`. | `governance_policy`. | No |
| `Cnt` | Contest — terminal due to authority conflict or divergence. | `governance_policy`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governance_policy`. | **Yes** |

For per-kind field rules and typical chain shapes, see [events.md](events.md). **There is no `Rpr` kind on IEL.** Divergence is preserved as data and resolved by `Cnt` rather than archived by repair (see [§Divergence and Contest-Only Resolution](#divergence-and-contest-only-resolution)).

## Evaluation Seal and Anchor Non-Poisonability

The `last_governance_version` is the most recent version at which an `Evl` landed. It is the chain's **evaluation seal**.

**Once an evaluation lands, the governance satisfaction it proves is final.** This is enforced *structurally* via a constraint on policies introduced or evolved on the chain:

> **Policy immunity rule.** Any policy referenced as a chain's `auth_policy` or `governance_policy` MUST have `immune: true`. Both the merge engine (at submit time) and the verifier (at verification time) reject any `Icp` or `Evl` event that introduces or evolves a policy whose `immune` flag is not set. Both layers enforce because the verifier processes data from any source — gossip, peer pulls, restored backups, bootstrap — and cannot trust that the originating node enforced the rule (the "DB cannot be trusted" invariant; see [../security-invariant.md](../security-invariant.md)).

Since `immune: true` makes a policy impervious to poisoning in the evaluator (`evaluate_anchored_policy` skips poison checks for immune policies), the rule guarantees that no anchor used in any chain authorization (auth or governance) can ever be poisoned. Past `Evl` / `Cnt` / `Dec` evaluations stay satisfied by construction.

**Revocation via policy evolution, not poison.** To remove an endorser's authority going forward, evolve the policy via `Evl` (declaring a new `auth_policy` or `governance_policy` SAID that excludes the endorser); the new policy must itself be immune. Past events stay authorized under the policy in effect when they landed. For compromise of an underlying anchoring KEL, the corrective mechanism is `rec` / `cnt` on that KEL (see [§Trust Caveat below](#trust-caveat--recovered-anchoring-kels)).

## Divergence and Contest-Only Resolution

IEL has only one non-Icp event kind that does ongoing work — `Evl`, governance-authorized. Divergence on IEL therefore requires two governance-authorized events to land at the same version. There is no analog to today's SEL's auth-vs-governance asymmetry that motivates `Rpr` (preserve owner's branch, archive adversary's): on IEL, both branches have governance authority, so neither is structurally "owner" or "adversary" in a way the protocol can adjudicate.

We accept divergence as data and resolve via `Cnt`:

- **Divergence is preserved.** Both branches stay in storage forever as forensic record. The chain mathematics make the divergence visible to consumers.
- **`Cnt` is the only resolution.** While divergent, the merge handler accepts `Cnt` (governance-authorized, terminates the chain) and rejects all other submissions with `ContestRequired`.
- **`Cnt` propagates normally.** Owner submits `Cnt` extending either branch's tip at any node. Server accepts (Cnt extends an existing tip); gossip propagates `Cnt` to other nodes, which already have both branches preserved. Each node validates `Cnt` against its known tips and marks the chain contested. Federation converges.
- **No `Rpr`.** No discriminator algorithm. No archive table. No repair link rows.

This is intentional: history is encoded in the data. When two governance-authorized events conflict, the chain has demonstrated that its governance is no longer single-authoritative. Termination is the honest outcome; the operator re-incepts under a new identity if continued operation is needed.

### What divergence means structurally

Divergence is detected when two IEL events share the same `previous` SAID. The chain is frozen at that point: the merge handler accepts only `Cnt` until terminal state lands.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

The divergence invariant — combined with every IEL event after Icp being governance-authorized — guarantees:
- Exactly 2 events at the divergence version `d`.
- At most 1 event at each version `> d` (chain frozen post-divergence; only `Cnt` extending one branch's tip lands).
- The combined post-`d` window fits in one `MINIMUM_PAGE_SIZE`-bounded page.

### Why no `Rpr`

`Rpr` on today's SEL exists because:
- SEL has many auth-authorized events (`Upd`) that an adversary could use to extend a divergent branch.
- The "preserve owner, archive adversary" framing makes sense because owner has the higher-bar governance authority and adversary has only auth.

On IEL, both branches require governance to exist at all. There's no asymmetry for `Rpr` to exploit. If two governance-authorized events conflict, we don't have grounds to declare one of them the "real" branch and archive the other — both are equally legitimate by the chain's own rules. The honest answer is `Cnt` (admit the conflict, terminate, re-incept).

## Cross-Chain Anchor Stability

IEL is the cornerstone of cross-chain consistency for the federation. Every SE event at v1+ binds to a specific IEL event by SAID via `identity_event`. The immunity rule on IEL is what makes this binding stable across time.

### Why IEL stability matters to SE

A SE event bound to `IEL_event_X.said` resolves authorization through:
1. Look up `IEL_event_X` in the IEL's authentic chain.
2. Read the policy declared (`Icp`) or evolved (`Evl`) at that event.
3. Verify SE.said is anchored under that policy.

For this resolution to remain deterministic forever:
- `IEL_event_X` must remain in IEL's authentic chain (never archived) — guaranteed by chain immutability and the no-`Rpr` rule (we never archive on IEL).
- The policy declared at `IEL_event_X` must have stable content (anchors don't move) — guaranteed by the IEL immunity rule.
- The KEL ixn anchoring SE.said must remain in its KEL — caveat: subject to KEL `rec` / `cnt` (see Trust Caveat).

The first two are structural. The third is a runtime trust concern that applies to all anchoring in the system.

### Path-agnostic validation rules

KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules for SE event bindings.

For an SE event at v1+, all paths (submit, gossip ingestion, bootstrap, re-verification) check:

- `identity_event` references an IEL event in IEL's authentic chain (`prefix == SE.identity`).
- That IEL event declared (`Icp`) or evolved (`Evl`) the relevant policy — `auth_policy` for SE `Upd`, `governance_policy` for SE `Sea`/`Rpr`/`Cnt`/`Dec`.
- IEL is not divergent at the bound event's branch.
- SE.said is anchored under the resolved policy.
- **Monotonic on SE chain**: `identity_event` is at-or-after the SE chain's prior `last_identity_event` in IEL chain order.

There is no separate "most recent at submit time" rule. Such a rule would create a path distinction (submit vs. gossip) that breaks data agnosticism, and would reject historical bindings during bootstrap.

### What monotonicity blocks (and what it doesn't)

Monotonic-on-SE-chain prevents an adversary from "rolling back" the chain — once the chain is bound to IEL_v5, no new event can bind to anything earlier. On actively-maintained chains, the legitimate operator's recent events have ratcheted `last_identity_event` forward; an adversary with stale (revoked-since) authority cannot insert new events bound to their old IEL state.

Monotonic does NOT prevent:

- **Brand-new chain races.** Before `last_identity_event` is set, an adversary can submit `[Icp, Upd_stale]` first and establish the chain with stale binding. Recovery: legitimate operator's next Upd (with current binding) ratchets `last_identity_event` forward; subsequent stale-bound events are rejected. The adversary's stale v1 entry remains in chain history but is buried by subsequent Upds (consumer-side reads "latest content"). The SE inception batch rule (`[Icp, Upd]` minimum) makes this race well-defined: every chain starts with both content and a binding.
- **Stale governance termination.** An adversary with stale governance authority can submit `Cnt` or `Dec` if the SE chain hasn't been bound past their stale event. Mitigation is **operator discipline**: after IEL evolves governance, the owner submits a `Sea` on each dependent SE chain to ratchet `last_identity_event` forward to the current IEL event. After the ratchet, stale-bound `Cnt`/`Dec` fail monotonic and are rejected. The vulnerable window is "between IEL governance evolution and the SE Sea ratchets" — bounded by gossip latency plus operator reaction time.

### Consumer-side discipline

Independent of any submit/verify gates, a consumer reading an SE chain can detect stale-bound events by checking whether the bound IEL event's declared policy is still IEL's currently-tracked policy. If not, the SE event was authorized under a now-revoked policy and the consumer can filter, treat with caution, or reject per their use-case rules. The chain mathematics make this visible without protocol modification.

### Operator-discipline corollary for governance evolution

When the IEL's `governance_policy` evolves (an `Evl` on IEL changes who has governance authority), the operator should immediately submit a `Sea` on each dependent SE chain to ratchet that chain's `last_identity_event` forward to the new IEL `Evl`. This closes the window in which an adversary with revoked governance could submit a stale-bound `Cnt`/`Dec` against an unmaintained SE chain.

This is an operator best practice, not a protocol-enforced rule. Future automation could auto-issue SE Seas on IEL governance evolution, but is out of scope for v1 of this design.

## Trust Caveat — Recovered Anchoring KELs

The seal property and the anchoring model give *structural* guarantees against poisoning (policy immunity rule) and gossip races (terminal states are deterministic across nodes). They give *partial* guarantees when a participating KEL is later recovered — because recovery archives the adversary branch, anchors made on that branch are removed from the live KEL.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the owner's branch stay (`rec` archives only the adversary branch); anchors on the now-archived adversary branch do not.

Implications for IEL consumers (and transitively SE consumers, since SE binds to IEL events):

- An IEL `Evl` / `Cnt` / `Dec` whose policy was satisfied entirely by owner-placed anchors: re-verifies cleanly across `rec`. Past evaluation stands. SE chains bound to that IEL event continue to verify under it.
- An IEL event whose satisfaction depended on adversary-placed anchors (now archived): may *fail* re-verification. SE chains bound to that IEL event may also fail re-verification, since the upstream authorization is no longer satisfied.

This is observable, not hidden — the chain mathematics make the post-rec state visible. The consumer's runtime trust judgement is: when an anchoring KEL has `rec` history, re-verify the IEL and any SE chains bound to it; treat past state with caution proportionate to what survives.

`Cnt` is distinct in shape: a contested KEL is frozen but no events are archived, so adversary-placed anchors stay in the live chain alongside owner-placed ones. Past IEL and SE evaluations re-verify regardless. But `cnt` is itself evidence that the recovery key was exposed — the KEL is permanently terminal, and a consumer should treat past evaluations participating in such a KEL with comparable caution to (or more than) the rec case.

The caveat applies to anchors of any kind — IEL events (governance), and transitively SE events that bind to them.

## Contest (Cnt)

Contest is the terminal state for IEL — reachable from divergence (any `Cnt` resolves a divergent chain to contested) or directly from active state (operator chooses to terminate).

### Server semantics

- Verify `Cnt`'s structure, governance authorization.
- Insert `Cnt`. **No archival** — both branches preserved if divergent; single branch preserved if linear.
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions rejected with `ContestedIel`.
- Effective SAID for a contested chain: deterministic, cross-node consistent.

### Builder

`IdentityEventBuilder::contest()`:
- Pre-flight: full chain re-verification.
- Bundles pending events into the batch (mirrors SEL).
- Builds `Cnt` extending the appropriate tip (or one of the divergent tips, if divergent).

### Cascading effect on dependent SE chains

A contested IEL freezes the IEL. SE chains bound to the contested IEL face ambiguous future authorization: the IEL has no path forward, so SE's tracked `auth_policy` and tracked `governance_policy` are effectively frozen at whatever was current when IEL contested.

Operator response per SE chain:
- **Migrate**: incept a new SE chain bound to a different IEL.
- **Decommission**: end the SE chain via `Dec`.
- **Contest**: if the SE chain itself is contested in the same incident, `Cnt` it.

These are operator decisions, not protocol-enforced. The federation continues operating: SE chains can still be read; they just cannot be advanced if the IEL is contested.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated identity end. Same shape as SEL `Dec` and same governance authorization.

### Cascading effect on dependent SE chains

Same as `Cnt`: SE chains bound to a decommissioned IEL face frozen authorization. Operator chooses migrate/decommission/contest per chain.

## Server-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | `Evl` | Append. Seal advances. |
| Linear, overlap (fork) | non-`Cnt`/`Dec` | Insert single forking event, freeze. `Diverged`. |
| Divergent | `Cnt` | Insert, mark contested. |
| Divergent | non-`Cnt`/`Dec` | `ContestRequired`. Chain unchanged. |
| Linear, post-evaluation-seal | `Evl` extending pre-seal version with valid governance | `ContestRequired { reason }` (mirrors SEL). |
| Any non-terminal | `Cnt` | Insert, mark contested. |
| Any non-terminal | `Dec` | Insert, mark decommissioned. |
| Contested | any | Rejected with `ContestedIel`. |
| Decommissioned | any | Rejected with `IelDecommissioned`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/iel/event.rs` — `IdentityEventKind` enum (`Icp`/`Evl`/`Cnt`/`Dec`); `validate_structure` per per-kind field rules.
- `lib/kels/src/types/iel/verification.rs` — `IelVerifier`, `IelVerification`, branch state with tracked `auth_policy` and tracked `governance_policy`.
- `lib/kels/src/identity_builder.rs` — `IdentityEventBuilder` with `evolve()`, `contest()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification.
- Server submit handler — terminal gate, immunity gate, divergent-rejection routing (returns `ContestRequired` for non-`Cnt` events on divergent chains), algorithmic `ContestRequired` trigger for events at-or-before evaluation seal.
- Storage — `iel_events` table. **No archive table** (no `Rpr` to archive into).

**Notable simplifications vs. SEL:**
- No `Rpr` kind, no `truncate_and_replace` discriminator algorithm, no archive tables, no repair-link rows.
- IelVerifier still tracks branches (max 2 per the divergence invariant) but never reconciles — divergent stays divergent until `Cnt`.
- `MAX_NON_EVALUATION_EVENTS` proactive bound doesn't apply (every IEL event after Icp is governance-authorized; no fork window to bound).

**Tests:**
- Submit / verifier / builder coverage; gossip-race convergence on contested state.

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; SE chains bind to IEL events.
- [../sel/events.md](../sel/events.md) — SE per-kind reference.
- [../policy.md](../policy.md) — Policy DSL, anchoring model, immunity rule.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
