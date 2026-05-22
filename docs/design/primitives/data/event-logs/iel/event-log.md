# Identity Event Log (IEL) — Lifecycle, Divergence, Decommission

> Source-of-truth design doc for the IEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing), and [verification.md](verification.md) (IelVerifier algorithm).

The Identity Event Log (IEL) is a per-prefix chain of `IdentityEvent` records describing the evolving authorization state of an identity — its tracked `authPolicy` and `governancePolicy`. Authority over the IEL is asserted by anchoring `ixn` events in one or more KELs identified by the chain's currently-tracked governance policy.

An IEL is the authorization root for a SEL. Every Credential, SEL, or generally identifying/owned document binds to a specific IEL — SELs in particular by prefix at inception, resolving per-event authorization through specific IEL event SAIDs. See [../sel/events.md §`ielEvent` semantics](../sel/events.md#ielevent-semantics) for the SEL-side binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, max-serial event extends cleanly. | Yes — `Evl`, `Dec` (per `governancePolicy`, subject to the seal-cap). |
| **Decommissioned** | Chain ended cleanly via `Dec` — exactly one `Dec`, ending a clean linear chain. | None. All submissions rejected with `IelDecommissioned`. |

IEL has no Divergent state. Every IEL event is privileged, so any second event at the same serial would create a divergent set containing a privileged event — which the merge layer rejects per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Divergent sets cannot form locally on IEL. Cross-node priv-vs-priv races (each `Evl`/`Dec` landing cleanly on its submitting node, gossip-arriving competing event rejected by the seal-cap) surface at the federation layer via the irreconcilable-prefix table.

State is computed from the chain's events, never tracked as a separate flag. The `IelVerification` token surfaces:
- `is_decommissioned: bool` — `true` when the linear chain tip is a `Dec` event.
- `lastSealAdvancingEvent: Option<Digest256>` — SAID of the most recent `Evl` that landed cleanly on the linear chain (the "evaluation seal"). The seal never forks: privileged events that would create or join a divergent set are rejected at merge, so seal-advancing landings are linear-chain extensions by construction.

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `authPolicy` and `governancePolicy`. | `governancePolicy` (Icp.said anchored under the declared governancePolicy — every IEL event is a governance act). | No |
| `Evl` | Evolve — governance evaluation; advances the seal. MUST evolve at least one of `authPolicy` / `governancePolicy` (a no-op Evl is rejected as a structural error). | `governancePolicy`. | No |
| `Dec` | Decommission — terminal event ending the chain. | `governancePolicy`. | **Yes** |

For per-kind field rules and typical chain shapes, see [events.md](events.md). **IEL has no `Rpr` kind** — divergent sets cannot form locally on IEL, so there is nothing for `Rpr` to repair. Every IEL event is privileged, so a second event at the same serial is always privileged; the merge layer rejects it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). See [§Privileged-event merge-layer rejection](#privileged-event-merge-layer-rejection) for the structural argument and [§Operator recourse against compromise](#operator-recourse-against-compromise) for the recourse paths.

## Evaluation Seal and Policy Immunity

The `lastSealAdvancingEvent` is the SAID of the most recent `Evl` event that landed cleanly on the linear chain. It is the chain's **evaluation seal**. The seal never forks: privileged events that would create or join a divergent set are rejected at the merge layer per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The seal-cap and locked-portion bound at the protocol layer structurally block stale-authority chain rearrangement.

> **Policy immunity rule.** Any policy referenced as a chain's `authPolicy` or `governancePolicy` MUST have `immune: true`. Both the merge engine (at submit time) and the verifier (at verification time) reject any `Icp` or `Evl` event that introduces or evolves a policy whose `immune` flag is not set. Both layers enforce because the verifier processes data from any source — gossip, peer pulls, restored backups, bootstrap — and cannot trust that the originating node enforced the rule (the "DB cannot be trusted" invariant; see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)).

**Why the rule exists.** Immunity is a storage-layer commitment: a referenced policy must remain resolvable for the lifetime of any chain that references it. Without it, a referenced policy can become unresolvable (storage GC, propagation gap, lost data), and a consumer verifying any event under that policy sees `policy_satisfied = false` — structurally indistinguishable from "the event's anchors don't satisfy the policy's threshold." Past authorizations would collapse into authorization failures from the consumer's perspective. Enforcing the rule at both submit and verification keeps the storage commitment a protocol invariant — authorization-affecting state lives in the schema, not in emergent storage behavior. The full rationale lives at [events.md §Policy immunity requirement](events.md#policy-immunity-requirement).

**Revocation is via policy evolution.** To remove an endorser's authority going forward, evolve the policy via `Evl` — declare a new `authPolicy` or `governancePolicy` SAID that excludes the endorser. The new policy must itself be immune. Past events stay authorized under the policy in effect when they landed. For compromise of an underlying anchoring KEL, the corrective mechanism is `Rec` on that KEL (see [§Trust Caveat below](#trust-caveat--recovered-anchoring-kels)).

**Every `Evl` must be a real evolution.** A no-op `Evl` (both `authPolicy` and `governancePolicy` identical to the predecessor) is rejected as a structural error. Every IEL event therefore changes chain state — `Icp` declares policy, `Evl` evolves policy, `Dec` terminates the chain.

## Privileged-event merge-layer rejection

IEL has only one non-Icp, non-terminal event kind that does ongoing work — `Evl`, governance-authorized. Every IEL event (`Icp`, `Evl`, `Dec`) is privileged. A second event at the same serial would therefore always be privileged, and the merge layer rejects it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal): its acceptance would create a divergent set containing a privileged event.

**Divergent sets cannot form locally on IEL.** The chain state machine reduces to `{Active, Decommissioned}`. There is no analog to SEL's auth-vs-governance asymmetry that motivates `Rpr` (preserve one branch, archive the other): on IEL, both candidates for a divergent set would have governance authority, and the protocol cannot adjudicate which side is the rightful operator from chain data alone — so the structural answer is to reject the second event at merge and require operator-level reconciliation.

**Race-vs-takeover framing.** Two competing `Evl`/`Dec` events at the same serial — landing on different federation nodes via concurrent submission — can arise from a federation race (two legitimately-current governance-authorized parties submitting concurrently) or a takeover (a party holding currently-authorized governance forking against the other party who also holds it). The chain data records the per-node first-receive; the protocol cannot structurally distinguish race from takeover. Cross-node disagreement surfaces at the federation layer via the irreconcilable-prefix table (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). Consumer trust degrades uniformly post-dispute regardless of cause.

**Distinction from KEL Rec / SEL Rpr.** KEL Rec and SEL Rpr resolve divergence by archiving events via the discriminator. They take two parent shapes: branch-tip-extending (`previous = v_d.said` for one of the two branch tips, lands at `v_{d+1}`, archives the other branch) and divergence-ancestor-extending (`previous = v_{d-1}.said`, lands at `v_d`, archives both branches at `v_d`). IEL has no recovery primitive — there is no archival path on IEL, and no divergent set forms locally. When two governance-authorized events arrive at the same node, the second is rejected at merge; when they land on different nodes, federation-level disagreement is surfaced via the irreconcilable-prefix table.

- **No divergent sets in storage.** Each node retains its locally-landed first-receive; the rejected event never enters live storage. No forensic divergent-set record.
- **No repair primitive.** No discriminator algorithm. No archive table. No repair link rows.

This is intentional: when a governance-authorized event would conflict with one already accepted, there is no way to determine which submitter is the rightful operator from chain data alone. Merge-layer rejection is the honest outcome; the federation surfaces the cross-node disagreement; the operator re-incepts under a new identity if continued operation is needed and the federation-level dispute cannot be reconciled out-of-band.

### Operator recourse against compromise

Recourse on a compromised IEL depends on whether the operator still satisfies the chain's tracked `governancePolicy`.

- **Linear governance evolution** — if the operator still satisfies governance, submit a linear `Evl` extending the current tip that evolves the policy to exclude the compromised member. The chain stays Active under the new policy; the compromised member loses governance authority going forward.
- **Rotate the IEL out of parent policies** — if the governance threshold has been breached and the operator cannot satisfy the policy, the structural recourse is to rotate the IEL identity out of parent policies that bind to it (out-of-band coordination with chains that anchor to this IEL prefix). There is no in-band protocol primitive that re-grants authority to a party who no longer satisfies the chain's tracked policy.
- **Clean shutdown** — `Dec` terminates the chain cleanly when the operator wants to end it; not a compromise-specific recourse but listed for completeness as a chain-termination path.

If the chain has been disrupted at the federation layer (concurrent priv-vs-priv race surfaced via the irreconcilable-prefix table; the federation cannot extend forward under either branch without operator-level reconciliation), the path forward is reincept under a new prefix — see [§Effect on Bound SELs](#effect-on-bound-sels) for the cascade implications.

Forensic 'this IEL was compromised' attribution lives out-of-band as a signed statement under the operator's KEL.

Federation-race convergence — when two governance-authorized parties submit competing privileged events concurrently to different nodes — is handled at the infrastructure layer rather than the protocol layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

### Why divergent sets cannot form locally on IEL

Every IEL event is privileged (`Icp`, `Evl`, `Dec` are all governance-authorized). A second event at the same serial would always be privileged, and the merge layer rejects it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). The chain stays linear locally.

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

The shapes that would produce divergent sets on KEL/SEL but are rejected on IEL:

- `Evl`-`Evl` — concurrent governance evolutions on an Active chain. Second `Evl` rejected at merge.
- `Evl`-`Dec`, `Dec`-`Evl` — one party submits the terminator while a second governance-authorized party submits an evolution extending the same parent. Second event rejected at merge.

Pairings that cannot form regardless (byte-identical → dedup at submit):

- `Dec`-`Dec` — `Dec` carries no content or policy fields, so two `Dec` events with the same `previous`, `serial`, `prefix`, and `kind` are byte-identical → identical SAID → dedup.

Cross-node priv-vs-priv races: when two governance-authorized parties submit competing `Evl`/`Dec` events to different nodes, each lands cleanly as a linear-chain extension on its submitting node and advances the local seal. Gossip then delivers each event to the other node, where the seal-cap rejects the late arrival (its parent sits in the locked portion behind the now-advanced seal). Each node retains its locally-landed first-receive; the federation does not converge at the protocol layer. Federation-level convergence is provided by the irreconcilable-prefix table at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

**Diagram.** The possible federation-race shape:

```
Concurrent extension at v_d on different nodes:

  v0      v1        v_d  ← Node A's tip
[Icp] → [Evl_{d-1}] → [Evl_A]

  v0      v1        v_d  ← Node B's tip
[Icp] → [Evl_{d-1}] → [Evl_B]   (distinct policy body from Evl_A)

Each event lands cleanly on its submitting node. Gossip delivers each to
the other; the seal-cap rejects the late arrival on each side. Per-node,
each chain stays linear (Active). Federation-level disagreement is
surfaced via the irreconcilable-prefix table; the operator re-incepts under a
new prefix to resume forward operation.
```

The chain-state invariants on IEL:
- **No divergent sets locally** — privileged events that would create or join a divergent set are rejected at merge. The chain is `{Active, Decommissioned}` per-node.
- Every event's parent sits at-or-after the chain's last seal (`parent_serial >= seal_serial` — the seal-cap rejects events whose parent is in the locked portion; see [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded)). Every non-terminal IEL event advances the seal (`Evl`), and the terminal kind (`Dec`) enforces but does not advance the seal. The seal therefore coincides with the chain's max-serial event on a linear IEL — within-window forks don't structurally exist on IEL.

### Why no Rpr

`Rpr` on SEL exists because:
- SEL has many auth-authorized events (`Upd`) that a second auth-holder could use to extend a divergent branch.
- The asymmetry between auth and governance authority is what `Rpr` exploits: governance is the higher-bar authority, so a governance-authorized `Rpr` resolves an auth-authorized fork by archiving the branch not on `Rpr.previous`'s walkback.

On IEL, every event is governance-authorized — there is no asymmetry for `Rpr` to exploit. A second governance-authorized event at the same serial as an existing one would create a divergent set containing a privileged event, which the merge layer rejects per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). Divergent sets cannot form locally on IEL, so there is nothing for `Rpr` to repair. Cross-node priv-vs-priv races surface at the federation layer rather than as a per-node divergent set. Operator recourse against compromise on a still-Active chain is described in [§Operator recourse against compromise](#operator-recourse-against-compromise) above. The [../../../../protocol-doctrine.md §No dedicated termination-by-contest event](../../../../protocol-doctrine.md#no-dedicated-termination-by-contest-event) section covers the protocol-wide framing, including the pre-emptive-suspicion gap (a submitter who wants to mark an IEL as compromised pre-emptively uses `Evl`-rotate / `Dec` / out-of-band rather than a protocol-level compromise signal).

## Federation Disputes and the Trust Layer

A federation-level dispute on an IEL chain — two governance-authorized events at the same serial landing on different nodes — can arise from two real failure modes:

1. **Federation race.** Two parties with valid governance authority submit `Evl` events near-concurrently to different nodes. Each lands cleanly as a linear-chain extension on its submitting node; the seal-cap rejects the gossip-arriving competing event on each side. The irreconcilable-prefix table surfaces the disagreement federation-wide.
2. **Threshold compromise.** A second governance-authorized party (one whose authority was acquired via threshold compromise) submits a competing `Evl`. The federation-level signal is identical to the federation-race case.

The verifier accepts each per-node chain as structurally valid in either case — the local first-receive landed under valid auth checks. The trust layer (not the verifier) decides the consumer response based on the federation-level signal.

> **Race and threshold-compromise are not chain-distinguishable.** The federation signal produced by a race is identical to the signal produced by threshold compromise — same per-node tips, same federation-level disagreement. Only out-of-band context (operator intent, monitoring signals, who held what keys when) lets consumers separate the two. The protocol cannot — and does not try.

The security dials differ by cause: against compromise, threshold height (high enough that controlling the threshold is hard-to-impossible) is the operator's mechanism. Against race, application-layer coordination above the protocol bounds the window — see [§Multi-Party Governance Synchronization](#multi-party-governance-synchronization). The protocol-level response is the same regardless of cause: federation-level disagreement surfaces via the irreconcilable-prefix table → operator either reconciles out-of-band or reincepts under a new identity.

### Chain validity vs consumer trust

The IEL verifier and downstream consumers operate on different questions:

- **Chain validity** (the verifier's job). "Is this chain shape structurally authentic?" — events exist, cryptography is correct, chain linkages are correct, immunity rule satisfied, structural integrity intact. Per-node, every IEL chain is linear (Active or Decommissioned).
- **Consumer trust** (the auth/policy layer's job). "Should I trust authorization claims from this chain?" — handled via `policy_satisfied`, federation-level dispute signal, and per-event `satisfied_saids` (see [verification.md §Caller-bounded SAID querying](verification.md#caller-bounded-said-querying)).

**Trust model split**:
- **Active linear chain (no federation-level dispute)**: events trusted under their original authorization.
- **Active linear chain with federation-level dispute** (surfaced via the irreconcilable-prefix table): events at-or-below `lastSealAdvancingEvent` at the time of dispute onset retain structural verifiability — at-or-below-seal anchors stay anchored, credentials issued against at-or-below-seal IEL state remain checkable, SEL bindings pinned to at-or-below-seal `ielEvent` stay trust-evaluable per [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability). Above-seal events on either party's per-node chain are tier-1-equivalent in the absence of cross-node consensus and not structurally trustworthy. Consumers cannot anchor new authorization in above-seal chain content while the dispute is open.
- **Decommissioned chain** (`Dec` landed cleanly, no federation-level dispute): pre-Dec events retain trust under their original authorization. `Dec` is the operator's clean-retirement signal.

The "divergent" state in KEL/SEL has no IEL analog — every IEL event is privileged, so divergent sets cannot form locally on IEL.

The verifier's job is to make chain authenticity unambiguous; the consumer's job is to apply the trust layer on top of that verified-authentic data plus the federation-level dispute signal.

### Effect on Bound SELs

When the IEL has been disrupted at the federation layer (e.g., concurrent `Evl`s on different nodes surfaced via the irreconcilable-prefix table), SELs whose binding sits at-or-below the IEL's `lastSealAdvancingEvent` (per the `IelDivergent` rule on SEL events) remain trust-evaluable: their `ielEvent` references the structurally-final at-or-below-seal segment, which the seal-cap permanently freezes. The seal-bound captures the federation-dispute case by construction — the local seal stays at the prior linear-portion advance, strictly below any disputed serial. SELs that would forward-extend their binding against the IEL — by issuing a new `Est` or `Sea` referencing an above-seal `ielEvent` — face the freeze. Above-seal `ielEvent`s are not structurally trustworthy under federation-level dispute. The protocol provides no policy state for above-seal bindings to resolve against. Operator's recourse for the SELs that needed to advance forward is to reincept the SEL under a new IEL prefix and rebind dependent chains forward to the new identity. See [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability).

When the IEL is decommissioned (`Dec` landed, no federation-level dispute), bound SELs continue to verify cleanly — pre-Dec IEL events stay authoritative under their original auth. `Dec` is a clean-retirement signal; the operator simply isn't using the IEL going forward. New SEL submissions that reference a decommissioned IEL fail (the IEL accepts no new events to ratchet against), but existing SEL events bound to pre-Dec IEL events keep their meaning.

This split between federation-disputed and decommissioned IELs is the operator's recovery surface. Cascade-reincept is the operational reality for forward extension when an IEL is federation-disputed and cannot be reconciled: every dependent SEL that needs to extend its binding past the disputed IEL state must reincept under a new IEL. **Operators should design identity hierarchies with this cascade in mind** — anchoring everything to a single root means root disruption costs the forward operation of the entire dependent tree. Partition the dependency graph so a single disruption has a bounded blast radius.

## Multi-Party Governance Synchronization

When more than one party can satisfy an IEL's `authPolicy` or `governancePolicy`, concurrent submissions can produce two `Evl` events landing on different federation nodes at the same serial — federation-level dispute surfaced via the irreconcilable-prefix table; forward extension blocked under both parties' branches until reconciled out-of-band or reincept under a new prefix. Operators must serialize governance submissions above the protocol (designated submitter, leader election, or any other out-of-band serialization mechanism). This is load-bearing for high-stakes IEL identities (federation root, identity-hierarchy roots, anything whose reincept would cascade widely) — not optional. Synchronization defends against accidental races; threshold compromise is a separate concern handled by operational hardening + threshold redundancy. Full operator guidance: [../../../../../operations/multi-party-governance.md](../../../../../operations/multi-party-governance.md).

## Cross-Chain Anchor Stability

IEL is the cornerstone of cross-chain consistency for the federation. Every SEL event at v1+ binds to a specific IEL event by SAID via `ielEvent`. The immunity rule on IEL is what makes this binding stable across time.

### Why IEL stability matters to SEL

A SEL event bound to `IEL_event_X.said` resolves authorization through:
1. Look up `IEL_event_X` in the IEL's authentic chain.
2. Read the policy declared (`Icp`) or evolved (`Evl`) at that event.
3. Verify SEL.said is anchored under that policy.

For this resolution to remain deterministic forever:
- `IEL_event_X` must remain in IEL's authentic chain (never archived) — guaranteed by chain immutability and the no-`Rpr` rule (no archival on IEL).
- The policy referenced at `IEL_event_X` must remain resolvable so consumers can evaluate it — guaranteed by the IEL immunity rule.
- The KEL ixns anchoring SEL.said must remain in their KELs — caveat: subject to KEL `rec` (see Trust Caveat).

The first two are structural. The third is a runtime trust concern that applies to all anchoring in the system.

```
SEL→IEL authorization resolution for a SEL Upd at v1+:

  SEL Upd                                    IEL chain
  ───────                                    ─────────
  ielEvent = X.said  ────────────►  IEL_event_X (Icp or Evl)
                                                │
                                                ├─ declares / evolves
                                                │   auth_policy_X
                                                │
                                                ▼
  SEL.said anchored        ──────────►   policy_X.evaluate(anchor)?
  in a KEL ixn under                            │
  the policies in policy_X                      ├─►  YES → SEL Upd accepted
                                                └─►  NO  → SEL Upd rejected

The same shape applies for SEL Sea/Rpr/Dec — they resolve through
governancePolicy rather than authPolicy at the same IEL event. See
[../sel/events.md §Validation rules](../sel/events.md#validation-rules-path-agnostic--submit-gossip-bootstrap-re-verification)
for the canonical per-kind binding rule.
```

### Path-agnostic validation rules

KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules for SEL event bindings.

For an SEL event at v1+, all paths (submit, gossip ingestion, bootstrap, re-verification) check:

- `ielEvent` references an IEL event in IEL's authentic chain (`prefix == SEL.identity`).
- That IEL event declared (`Icp`) or evolved (`Evl`) the relevant policy — `authPolicy` for SEL `Est`/`Upd`, `governancePolicy` for SEL `Sea`/`Rpr`/`Dec`.
- The bound IEL event sits at-or-below the IEL's `lastSealAdvancingEvent` (`IelDivergent` rejection if above the seal — see [../sel/events.md §Validation rules](../sel/events.md#validation-rules-path-agnostic--submit-gossip-bootstrap-re-verification)).
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `ielEvent`** (SEL-specific): each SEL event's `ielEvent` must be at-or-after its parent event's `ielEvent` in IEL chain order, where "parent" is the event referenced by `previous` SAID. The check is applied per branch — the verifier walks each branch independently, comparing each event's `ielEvent` against the previous event's on the same branch. Branches with different parent-chains do not constrain each other's `ielEvent` values.

This rule is unique to the SEL↔IEL cross-chain binding. SEL is the only primitive whose authorization is referenced via a separate field pointing at another chain; KEL and IEL resolve authorization from commitments/policy intrinsic to their own chain at the event's parent (`previous`), and have no analog rule.

There is no chain-wide watermark gate. The chain's `lastIelEvent` (the highest `ielEvent` observed across all events in the chain) is a derived aggregate, computed after the fact, used by consumers to query "what's the highest IEL binding this SEL has reached" — not used to gate new event acceptance. New event acceptance is gated by the per-event parent-monotonic check on the branch the event extends.

**Consequence for divergent SEL chains**: branches may reference different IEL events at the same SEL serial, and may resolve to different governance/auth policies on each branch. This within-chain policy variation is bounded structurally by SEL's seal-cap (no fork at-or-before the seal — caps how far back branches can diverge) and by privileged-divergence-is-terminal (any privileged event in the divergent set ends the chain — caps how long the chain can stay in a divergent state). KEL and IEL never have within-chain policy variation.

There is no separate "most recent at submit time" rule. Such a rule would create a path distinction (submit vs. gossip) that breaks data agnosticism, and would reject historical bindings during bootstrap.

### What parent-monotonic blocks (and what it doesn't)

Parent-monotonic prevents an adversary from extending a branch with a regressed `ielEvent` — once a branch's tip is bound to IEL_v5, no further event extending that same branch can bind to anything earlier than v5. On actively-maintained chains, the legitimate operator's recent events on the live branch have advanced `ielEvent` forward; an adversary with stale (revoked-since) authority cannot insert new events on that same branch bound to their old IEL state.

Parent-monotonic does NOT prevent three scenarios. None breaks the system: each has a structural mitigation covered in [§Consumer-side discipline](#consumer-side-discipline), [§Governance-evolution ratchet via Sea](#governance-evolution-ratchet-via-sea), or [§Application-developer enrollment patterns](#application-developer-enrollment-patterns). The three are worth understanding when designing enrollment flows and operator routines.

#### Brand-new chain races (merge-layer rejection — federation-level dispute at v=1)

Before any legitimate v1+ event lands, a party with `authPolicy` authority on the bound IEL can submit `[Icp, Est_camper]` to a federation node, establishing the chain with their content at v1 on that node. The legitimate operator's enrollment-time response is `[Icp, Est_operator]` — `Icp` dedups (same content, same SAID across submitters); `Est_operator` lands at v=1 with `parent = Icp.said` (extending `Icp` via dedup-equivalence per [../../../../protocol-doctrine.md §Extension Discipline](../../../../protocol-doctrine.md#extension-discipline); operators never extend adversary events).

`Est` is privileged at tier 2. When the second `Est` arrives at a node where the first `Est` has already landed, the merge layer rejects it per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal): its acceptance would create a divergent set containing a privileged event. Each node retains whichever `Est` arrived first locally. Cross-node disagreement surfaces via the irreconcilable-prefix table; the federation cannot extend the chain forward under either branch without operator-level reconciliation. Operator recourse is reincept under a new `(identity, topic)` tuple.

Camping is federation-wide unprofitable: the camper pays tier-2 anchor cost (per contributing policy member) to land their `Est` on at least one node, but cannot dislodge the legitimate operator's `Est` from nodes where the operator's `Est` landed first. The disagreement surfaces in the irreconcilable-prefix table; consumers see the prefix as in-dispute rather than as a working chain. Mass camping is economically unprofitable; single-target camping yields nothing federation-wide usable to the camper. Enrollment patterns bound the targeting surface by keeping new `(identity, topic)` tuples unobservable until the operator's submission lands — see [§Application-developer enrollment patterns](#application-developer-enrollment-patterns).

```
Step 1 — Adversary submits [Icp, Est_camper] on Node A first:

  Node A: [Icp_v0] → [Est_camper @ v=1, ielEvent=IEL_camper]   (chain tip)

Step 2 — Operator submits [Icp, Est_operator] with Est_operator.previous =
Icp.said (extending Icp via dedup-equivalence; never extending Est_camper).
Two cases:

  Case A (same node — Node A):
    Icp dedups. Est_operator would land at v=1 alongside Est_camper,
    creating a 2-event divergent set containing a privileged event.
    Merge layer rejects per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal).
    Node A's chain stays at [Icp, Est_camper].

  Case B (different node — Node B, before Est_camper's gossip arrives):
    Node B's chain is born with [Icp, Est_operator] at v=1. Once
    Est_camper arrives via gossip, the seal-cap rejects it.
    Node B's chain stays at [Icp, Est_operator].

Step 3 — Cross-node state:

  Node A: [Icp, Est_camper]      (effective SAID = Est_camper.said)
  Node B: [Icp, Est_operator]    (effective SAID = Est_operator.said)

  Federation surfaces the disagreement via the irreconcilable-prefix table.

Step 4 — Operator recourse: reincept under a new (identity, topic) tuple.
```

#### Stale governance termination on unratcheted branches (not blocked)

A party holding stale governance authority can submit a privileged event (`Sea` or `Dec`) extending a branch tip whose `ielEvent` is still at the stale event. Mitigation is the governance-evolution Sea ratchet (see [§Governance-evolution ratchet via Sea](#governance-evolution-ratchet-via-sea) below): after IEL evolves governance, submit a `Sea` on each dependent SEL to advance the branch tip's `ielEvent` forward to the current IEL event. After this advancement, a stale-bound `Sea`/`Dec` extending the new tip fails parent-monotonic on its own branch (its `ielEvent` would regress relative to its parent) and is rejected. The vulnerable window is between IEL governance evolution and the SEL Sea ratchet — bounded by gossip latency plus the ratchet's submission cadence.

```
IEL evolves governance:
  IEL: [Icp] → [Evl_old] → [Evl_new]

Vulnerable window (SEL tip not yet ratcheted):
  SEL: [Icp] → ... → [Upd_v_N, ielEvent=Evl_old.said]   (tip)
                                          ↑
                                    adversary with stale gov_old
                                    authority can submit:

    Dec_stale.previous = Upd_v_N.said       (extends tip)
    Dec_stale.ielEvent = Evl_old.said       (stale binding)

    Per-event parent-monotonic check:
      parent's ielEvent = Evl_old.said
      Dec_stale's        = Evl_old.said
      Evl_old ≥ Evl_old → SATISFIED → accepted; chain decommissioned.

After governance-evolution Sea ratchet (post-Sea state):
  SEL: ... → [Upd_v_N] → [Sea_v_{N+1}, ielEvent=Evl_new.said]  (tip)

Same adversary tries again:
    Dec_stale.previous = Sea_v_{N+1}.said
    Dec_stale.ielEvent = Evl_old.said

    Per-event parent-monotonic check:
      parent's ielEvent = Evl_new.said
      Dec_stale's        = Evl_old.said
      Evl_old < Evl_new → REGRESS → HARD-fail rejection.
```

#### Fork-contest with low ielEvent (not blocked)

A privileged event (`Sea` or `Dec`) that forks from `v_{d-1}` (forming its own singleton branch at `v_d`) need only satisfy `event.ielEvent >= v_{d-1}.ielEvent`. It does not need to satisfy any constraint relative to the existing diverged branches — those are structurally independent branches.

This is intentional. Chain-wide watermark would otherwise reject scenarios where a long divergent branch already sits at higher SEL serials with lower `ielEvent`s than the submission's binding. The per-branch framing is what makes per-event parent-monotonic work — each branch's `ielEvent` constraint is independent of the others. The merge layer's separate rule that rejects privileged events whose landing would create or join a divergent set (per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)) is what keeps privileged events from extending into divergent state; it operates independently from the parent-monotonic check.

```
Pre-state (existing divergent at v_d with high SEL serials but
low ielEvent on the diverged branches):

  SEL: [Icp] → ... → [Upd_{d-1}, ielEvent=IEL_v3] ─┬─ Upd_a @ v_d  ┐
                                                    └─ Upd_b @ v_d  ┘
                                                    (both bound to IEL_v3)

A stale-governance holder (bound to IEL_v3 — past authority) attempts a
non-privileged event (Upd) extending v_{d-1} as a fresh singleton branch:

  evt.kind     = Upd
  evt.previous = v_{d-1}.said      (parent is divergence ancestor)
  evt.serial   = d
  evt.ielEvent = IEL_v3.said       (stale binding)

Per-event parent-monotonic check (per branch, against THIS branch's
parent — v_{d-1}, NOT against Upd_a/Upd_b which are on independent
branches):
  parent's ielEvent = IEL_v3.said
  evt's              = IEL_v3.said
  IEL_v3 ≥ IEL_v3 → SATISFIED → evt admitted as a 3rd non-priv event
  at v_d (assuming the divergence-invariant cap permits — see
  [../../../../protocol-doctrine.md §One Divergent Generation at a Time](../../../../protocol-doctrine.md#one-divergent-generation-at-a-time)).

evt's binding is unrelated to Upd_a/Upd_b's `ielEvent` because they're on
structurally independent branches. Chain-wide watermark would block this —
rightly understood as overconstraining. (A privileged event reaching this
shape — Sea/Dec extending v_{d-1} when an existing divergent set is at v_d —
is rejected separately by the merge layer per
[../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal),
independent of the parent-monotonic check.)
```

### Consumer-side discipline

Independent of any submit/verify gates, a consumer reading an SEL can detect stale-bound events by checking whether the bound IEL event's declared policy is still IEL's currently-tracked policy. If not, the SEL event was authorized under a now-revoked policy and the consumer can filter, treat with caution, or reject per their use-case rules. The chain mathematics make this visible without protocol modification.

### Governance-evolution ratchet via Sea

When the IEL's `governancePolicy` evolves (an `Evl` on IEL changes who has governance authority), the operator should immediately submit a `Sea` on each dependent SEL to advance the live branch's tip `ielEvent` forward to the new IEL `Evl`. This closes the window in which an adversary with revoked governance could submit a stale-bound `Sea`/`Dec` extending the new branch tip — once the tip's `ielEvent` is at the new Evl, any subsequent same-branch event must bind at-or-after the new Evl, so a regressed-binding event on that branch fails parent-monotonic.

This is an operator best practice, not a protocol-enforced rule. Future automation could auto-issue SEL Seas on IEL governance evolution, but is out of scope for v1 of this design.

### Application-developer enrollment patterns

The brand-new chain race described above is defused by enrollment-time discipline on the application-developer side: register all required SEL topics atomically, detect and `Rpr`-resolve prior chain content (the bound IEL's current `governancePolicy` outranks the auth-only racing party), and treat the user as inactive until enrollment completes (no consumers honor authorizations rooted in in-progress chains during the inactive window). The pattern eliminates the race as an authorization-bearing concern. Full developer guidance: [../../../../../development/enrollment.md](../../../../../development/enrollment.md).

## Trust Caveat — Recovered Anchoring KELs or Federation-Disputed Anchoring KELs

Beyond the structural guarantees above, IEL trust degrades for consumers when anchoring KELs are recovered or federation-disputed. The seal-cap and locked-portion bound structurally block stale-authority chain rearrangement; the policy-immunity rule keeps every referenced policy resolvable for the chain's lifetime; gossip races resolve to deterministic outcomes (per-node convergence at the protocol layer, or federation-layer dispute via the irreconcilable-prefix table). These structural guarantees are *partial* when a participating KEL is later recovered, and provide *no* guarantees when a participating KEL has been disputed at the federation layer.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the branch the Rec extends stay (`rec` archives only the other branch); anchors on the now-archived branch do not.

Implications for IEL consumers (and transitively SEL consumers, since SEL binds to IEL events):

- An IEL `Evl` / `Dec` whose policy was satisfied entirely by anchors on the surviving branch: re-verifies cleanly across `rec`. Past evaluation stands. SELs bound to that IEL event continue to verify under it.
- An IEL event whose satisfaction depended on anchors on the archived branch: may *fail* re-verification. SELs bound to that IEL event may also fail re-verification, since the upstream authorization is no longer satisfied.

This is observable, not hidden — the chain mathematics make the post-rec state visible. The consumer's runtime trust judgement is: when an anchoring KEL has `rec` history, re-verify the IEL and any SELs bound to it; treat past state with caution proportionate to what survives.

**A federation-disputed KEL is frozen at the federation layer.** When a KEL has been surfaced as in-dispute via the irreconcilable-prefix table (e.g., concurrent priv-vs-priv race between federation nodes; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races)), anchors it produced at-or-below its `lastSealAdvancingEvent` retain validity per [../../../../protocol-doctrine.md §Pre-seal verifiability](../../../../protocol-doctrine.md#pre-seal-verifiability) — consumer queries against dependent IEL/SEL events whose authorization traced through those anchors continue to return `policy_satisfied = true`. Above-seal anchors are not structurally trustworthy (tier-1-only auth, indistinguishable from signing-key-only adversary capture); they do not ground new trust decisions. The disputed KEL cannot produce fresh anchors that consumers will accept federation-wide. Whether a dependent IEL/SEL event still evaluates as satisfied for forward consumer trust depends on whether the resolving policy has threshold redundancy that lets it evaluate as satisfied without the disputed KEL's contribution. Threshold-redundant policies (`M > N` across distinct custodians) absorb single-member disputes — at-or-below-seal events stay satisfied via the surviving members, and the operator's forward response is governance evolution (`Evl`) to rotate the disputed KEL out of the policy. Cascade-reincept of the IEL or its dependent SELs is required only when the IEL *itself* is structurally blocked at the federation layer, not transitively from a disputed anchoring KEL. See [../../../../protocol-doctrine.md §Adversary Patience and Policy Redundancy](../../../../protocol-doctrine.md#adversary-patience-and-policy-redundancy).

The caveat applies to anchors of any kind — IEL events (governance), and transitively SEL events that bind to them.

## Decommission (Dec)

Decommission is the clean terminal state — `Dec` lands on a linear chain and ends it. Same shape as SEL `Dec` and same governance authorization (single-policy gate against the branch's tracked `governancePolicy`).

### Server semantics

- Verify `Dec`'s structure and governance authorization.
- Insert `Dec`. The chain transitions to Decommissioned.
- Any `Dec` event in the chain → `is_decommissioned = true`. All submissions rejected with `IelDecommissioned` (Decommissioned is fully terminal under universal locking; the seal-cap rejects any submission whose parent sits at-or-before `v_{d-1}`).
- Effective SAID for a decommissioned IEL: the `Dec` event's own SAID. Federation races between concurrent competing privileged submissions do not structurally converge at the protocol layer; convergence is provided at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

### Cascading effect on dependent SELs

SELs bound to a decommissioned IEL have their IEL-resolved `authPolicy` and `governancePolicy` (resolved through each SEL event's `ielEvent` binding) anchored at whatever IEL state was current when `Dec` landed. The IEL cannot evolve forward, so dependent SEL authorization stays at that resolved state.

Operator response per SEL:
- **Migrate**: incept a new SEL bound to a different IEL.
- **Decommission**: end the SEL via `Dec`.

These are operator decisions, not protocol-enforced. The federation continues operating: SELs can still be read; they just cannot be advanced if the IEL is decommissioned.

## Merge-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | `Evl` (clean linear extension of the current tip) | Append. Seal advances. |
| Linear, overlap | competing `Evl` or `Dec` extending `v_{d-1}` while an event exists at `v_d` | Rejected at merge per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal). `ParentLocked`. Cross-node priv-vs-priv races surface via the irreconcilable-prefix table (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). |
| Linear, post-evaluation-seal | `Evl` extending pre-seal serial | Rejected by seal-cap (cannot fork at or before the seal). |
| Any non-terminal, clean linear | `Dec` extending the current tip | Append at chain max-serial; mark decommissioned. |
| Decommissioned | any submission | Rejected with `IelDecommissioned`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/iel/event.rs` — `IdentityEventKind` enum (`Icp`/`Evl`/`Dec`); `validate_structure` per per-kind field rules.
- `lib/kels/src/types/iel/verification.rs` — `IelVerifier`, `IelVerification`, branch state with tracked `authPolicy` and tracked `governancePolicy`. Surfaces `is_decommissioned`, `lastSealAdvancingEvent`.
- `lib/kels/src/identity_builder.rs` — `IdentityEventBuilder` with `evolve()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification.
- Server submit handler — terminal gate (`IelDecommissioned`), immunity gate, privileged-event merge-layer rejection (a priv `Evl`/`Dec` whose landing would create or join a divergent set is rejected with `ParentLocked` per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal)), algorithmic `ParentLocked` trigger for events at-or-before evaluation seal on linear chains.
- Storage — `iel_events` table. **No archive table** (no `Rpr` to archive into).

**Notable simplifications vs. SEL:**
- No `Rpr` kind, no `truncate_and_replace` discriminator algorithm, no archive tables, no repair-link rows.
- IelVerifier never sees a divergent set: every IEL chain is linear per-node (Active or Decommissioned). The branch-state machinery is single-branch in practice.
- The SEL seal-advance cap has no IEL analog (every IEL event is governance-authorized; no fork window to bound).

**Tests:** Submit / verifier / builder coverage; cross-node federation-race surfacing via the irreconcilable-prefix table.

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; SELs bind to IEL events.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference.
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL, anchoring model, immunity rule.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
