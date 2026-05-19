# Identity Event Log (IEL) — Lifecycle, Divergence, Decommission

> Source-of-truth design doc for the IEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing), and [verification.md](verification.md) (IelVerifier algorithm).

The Identity Event Log (IEL) is a per-prefix chain of `IdentityEvent` records describing the evolving authorization state of an identity — its tracked `authPolicy` and `governancePolicy`. Authority over the IEL is asserted by anchoring `ixn` events in one or more KELs identified by the chain's currently-tracked governance policy.

An IEL is the authorization root for a SEL. Every Credential, SEL, or generally identifying/owned document binds to a specific IEL — SELs in particular by prefix at inception, resolving per-event authorization through specific IEL event SAIDs. See [../sel/events.md §`ielEvent` semantics](../sel/events.md#ielevent-semantics) for the SEL-side binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain, max-serial event extends cleanly. | Yes — `Evl`, `Dec` (per `governancePolicy`). |
| **Contested** | Chain terminated by divergent set — every IEL event is privileged, so privileged-divergence-is-terminal fires at first 2-event observation (see [§Divergence is Contested-Terminal](#divergence-is-contested-terminal)). Both branches preserved as forensic record. | None. All submissions rejected. |
| **Decommissioned** | Chain ended cleanly via `Dec` — exactly one `Dec`, ending a clean linear chain. | None. All submissions rejected with `IelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `IelVerification` token surfaces:
- `divergenceAncestor: Option<Digest256>` — SAID of `v_{d-1}` on a divergent chain (`None` on linear)
- `is_contested: bool` — true when a divergent set exists (set by the verifier on any IEL divergence, since every IEL event is privileged)
- `is_decommissioned: bool`
- `lastSealAdvancingEvent: Option<Digest256>` — SAID of the most recent `Evl` (the "evaluation seal").

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `authPolicy` and `governancePolicy`. | `governancePolicy` (Icp.said anchored under the declared governancePolicy — every IEL event is a governance act). | No |
| `Evl` | Evolve — governance evaluation; advances the seal. MUST evolve at least one of `authPolicy` / `governancePolicy` (a no-op Evl is rejected as a structural error). | `governancePolicy`. | No |
| `Dec` | Decommission — terminal event ending the chain. | `governancePolicy`. | **Yes** |

For per-kind field rules and typical chain shapes, see [events.md](events.md). **IEL has no `Rpr` kind** — divergence is preserved as data, and the chain becomes contested-terminal immediately on any divergence (every IEL event is privileged → privileged-divergence-is-terminal fires). See [§Divergence is Contested-Terminal](#divergence-is-contested-terminal) for the structural argument and [§Operator recourse against compromise](#operator-recourse-against-compromise) for the recourse paths.

## Evaluation Seal and Policy Immunity

The `lastSealAdvancingEvent` is the SAID of the most recent `Evl` event. It is the chain's **evaluation seal**. The seal-cap and locked-portion bound at the protocol layer structurally block stale-authority chain rearrangement — see [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal).

> **Policy immunity rule.** Any policy referenced as a chain's `authPolicy` or `governancePolicy` MUST have `immune: true`. Both the merge engine (at submit time) and the verifier (at verification time) reject any `Icp` or `Evl` event that introduces or evolves a policy whose `immune` flag is not set. Both layers enforce because the verifier processes data from any source — gossip, peer pulls, restored backups, bootstrap — and cannot trust that the originating node enforced the rule (the "DB cannot be trusted" invariant; see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)).

**Why the rule exists.** Immunity is a storage-layer commitment: a referenced policy must remain resolvable for the lifetime of any chain that references it. Without it, a referenced policy can become unresolvable (storage GC, propagation gap, lost data), and a consumer verifying any event under that policy sees `policy_satisfied = false` — structurally indistinguishable from "the event's anchors don't satisfy the policy's threshold." Past authorizations would collapse into authorization failures from the consumer's perspective. Enforcing the rule at both submit and verification keeps the storage commitment a protocol invariant — authorization-affecting state lives in the schema, not in emergent storage behavior. The full rationale lives at [events.md §Policy immunity requirement](events.md#policy-immunity-requirement).

**Revocation is via policy evolution.** To remove an endorser's authority going forward, evolve the policy via `Evl` — declare a new `authPolicy` or `governancePolicy` SAID that excludes the endorser. The new policy must itself be immune. Past events stay authorized under the policy in effect when they landed. For compromise of an underlying anchoring KEL, the corrective mechanism is `Rec` on that KEL (see [§Trust Caveat below](#trust-caveat--recovered-anchoring-kels)).

**Every `Evl` must be a real evolution.** A no-op `Evl` (both `authPolicy` and `governancePolicy` identical to the predecessor) is rejected as a structural error. Every IEL event therefore changes chain state — `Icp` declares policy, `Evl` evolves policy, `Dec` terminates the chain.

## Divergence is Contested-Terminal

IEL has only one non-Icp, non-terminal event kind that does ongoing work — `Evl`, governance-authorized. Divergence on IEL therefore requires two governance-authorized events to land at the same serial. There is no analog to SEL's auth-vs-governance asymmetry that motivates `Rpr` (preserve one branch, archive the other): on IEL, both branches have governance authority, and the protocol cannot adjudicate which side is the rightful operator from chain data alone.

**Privileged-divergence-is-terminal applies trivially on IEL.** The privileged event set on IEL includes every event kind: `Icp`, `Evl`, `Dec` are all governance-authorized. (The chain cannot be contested before its inception; the rule is structurally vacuous at `Icp` itself but applies uniformly to any divergence post-inception.) Any divergent set on an IEL therefore contains a privileged event by definition, and the chain transitions to contested-terminal immediately. There is no separate "explicit termination" step needed for IEL divergence — divergence IS termination, structurally.

**Race-vs-takeover framing.** Divergence on IEL — two events at the same serial — can arise from a federation race (two legitimately-current governance-authorized parties submitting concurrently) or a takeover (a party holding currently-authorized governance forking against the other party who also holds it). The chain data records the divergence; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; consumer trust degrades uniformly post-divergence regardless of cause.

**Distinction from KEL Rec / SEL Rpr.** KEL Rec and SEL Rpr resolve divergence by archiving events via the discriminator. They take two parent shapes: branch-tip-extending (`previous = v_d.said` for one of the two branch tips, lands at `v_{d+1}`, archives the other branch) and divergence-ancestor-extending (`previous = v_{d-1}.said`, lands at `v_d`, archives both branches at `v_d`). IEL has no recovery primitive — there is no archival path on IEL. When two governance-authorized events conflict, the chain is contested-terminal.

- **Divergence is preserved.** Both branches stay in storage forever as forensic record. The divergence is visible to consumers.
- **No repair primitive.** No discriminator algorithm. No archive table. No repair link rows.

This is intentional: history is encoded in the data. When a governance-authorized event diverges, there is no way to determine if the divergent event was created by an adversary or legitimate operator. Termination is the honest outcome; the operator re-incepts under a new identity if continued operation is needed.

### Operator recourse against compromise

Recourse on a compromised IEL depends on whether the operator still satisfies the chain's tracked `governancePolicy`.

- **Linear governance evolution** — if the operator still satisfies governance, submit a linear `Evl` extending the current tip that evolves the policy to exclude the compromised member. The chain stays Active under the new policy; the compromised member loses governance authority going forward.
- **Rotate the IEL out of parent policies** — if the governance threshold has been breached and the operator cannot satisfy the policy, the structural recourse is to rotate the IEL identity out of parent policies that bind to it (out-of-band coordination with chains that anchor to this IEL prefix). There is no in-band protocol primitive that re-grants authority to a party who no longer satisfies the chain's tracked policy.
- **Clean shutdown** — `Dec` terminates the chain cleanly when the operator wants to end it; not a compromise-specific recourse but listed for completeness as a chain-termination path.

If the chain has already transitioned to Contested (any divergent set on IEL fires privileged-divergence-is-terminal), the path forward is reincept under a new prefix — see [§Effect on Bound SELs](#effect-on-bound-sels) for the cascade implications.

Forensic 'this IEL was compromised' attribution lives out-of-band as a signed statement under the operator's KEL.

Federation-race convergence — when two governance-authorized parties submit competing privileged events concurrently to different nodes — is handled at the infrastructure layer rather than the protocol layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

### How divergence is detected and why it's terminal on IEL

Divergence is detected when two IEL events share the same `previous` SAID. The chain becomes contested-terminal immediately by the privileged-divergence rule (every IEL event is governance-authorized, so any divergent set on IEL is privileged).

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

The route that creates divergence on an IEL chain:

**Concurrent extensions** producing a 2-event divergent set at `v_d` (both events extending `v_{d-1}`, landing on different nodes via concurrent submission and merging via gossip). Possible pairings:

- `Evl`-`Evl` — concurrent governance evolutions on an Active chain (distinct policy bodies → distinct SAIDs at the same serial).
- `Evl`-`Dec`, `Dec`-`Evl` — one party submits the terminator while a second governance-authorized party submits an evolution extending the same parent.

Pairings that cannot form (byte-identical → dedup at submit):

- `Dec`-`Dec` — `Dec` carries no content or policy fields, so two `Dec` events with the same `previous`, `serial`, `prefix`, and `kind` are byte-identical → identical SAID → dedup.

Note: under the seal-cap rule (`parent_serial >= seal_serial`), once any IEL event lands at `v_d` on a node, that node's seal advances and gossip-arriving competing events extending `v_{d-1}` are rejected. Divergent sets therefore form only when both events arrive at the same node before either has advanced the seal — typically via simultaneous gossip-merge of independent submissions. Cross-node federation races resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)).

Every IEL divergent set at `v_d` transitions the chain to contested-terminal immediately by the privileged-divergence-is-terminal rule (every IEL event is privileged). The transition is Active → Contested. No third event lands at `v_d` — the contested-state gate rejects all subsequent submissions, including any further `Evl`/`Dec` arriving via gossip.

**Diagram.** The possible shapes look like:

```
Concurrent extension at v_d:

  v0      v1        v2     ← divergent set at v2; chain immediately contested-terminal
[Icp] → [Evl] ─┬─ [Evl_A]
               └─ [Evl_B]  (distinct policy body from Evl_A)

Both branches preserved as forensic record. The chain is contested as of v2;
no further events land at v2 — subsequent submissions, including
gossip-delivered Evl/Dec at v2, are rejected by the contested-state gate.
```

The divergence invariant guarantees:
- **Maximum 2 events at the divergence serial `d`** — every IEL event is privileged, so no non-privileged divergent set can form, and the upgrade-rule path doesn't exist on IEL (the general "max 3 at `v_d`" rule applies to KEL and SEL only). The chain transitions to contested-terminal at first observation of 2-event divergence, and the contested-state gate rejects all subsequent submissions (including any further `Evl` or `Dec` arriving via gossip at `v_d`).
- No events at serials > `d` — the chain is contested-terminal as of `d`.
- Every event's parent sits at-or-after the chain's last seal (`parent_serial >= seal_serial` — the seal-cap rejects events whose parent is in the locked portion; see [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded)). Every non-terminal IEL event advances the seal (`Evl`), and the terminal kind (`Dec`) enforces but does not advance the seal. The seal therefore coincides with the chain's max-serial event on linear IEL — within-window forks don't structurally exist on IEL, and the only divergence path is simultaneous gossip-merge of independent submissions before either has advanced the seal locally.
- **Bounded verifier processing at the divergent generation.** When the verifier walks a chain whose v_d generation holds two events (any 2-event subset observable after gossip-merge of concurrent linear-chain extensions on different nodes), it processes them as siblings of the same generation under the inline chain walk: branch state from processing `v_{d-1}` holds the tracked governancePolicy, and both events at `v_d` are verified consuming that same `v_{d-1}` governance context. Total verifier work at the v_d generation is bounded by single-event verification cost regardless of chain length.

### Why no Rpr

`Rpr` on SEL exists because:
- SEL has many auth-authorized events (`Upd`) that a second auth-holder could use to extend a divergent branch.
- The asymmetry between auth and governance authority is what `Rpr` exploits: governance is the higher-bar authority, so a governance-authorized `Rpr` resolves an auth-authorized fork by archiving the branch not on `Rpr.previous`'s walkback.

On IEL, both branches require governance to exist at all. There's no asymmetry for `Rpr` to exploit. If two governance-authorized events conflict, the protocol has no grounds to declare one of them the "real" branch and archive the other — both are equally legitimate by the chain's own rules. The honest answer is to let the privileged-divergence rule terminate the chain (admit the conflict). Operator recourse against compromise on a still-Active chain is described in [§Operator recourse against compromise](#operator-recourse-against-compromise) above. The [../../../../protocol-doctrine.md §No dedicated termination-by-contest event](../../../../protocol-doctrine.md#no-dedicated-termination-by-contest-event) section covers the protocol-wide framing, including the pre-emptive-suspicion gap (a submitter who wants to mark an IEL as compromised pre-emptively uses `Evl`-rotate / `Dec` / out-of-band rather than a protocol-level compromise signal).

## Divergence, Contestation, and the Trust Layer

A divergent IEL chain — two governance-authorized events at the same serial — can arise from two real failure modes the protocol surfaces in-data:

1. **Federation race.** Two parties with valid governance authority submit `Evl` events near-concurrently to different nodes. Both land legitimately; gossip propagates; both nodes eventually see both events at the same serial. The chain shape records the race in the data.
2. **Threshold compromise.** A second governance-authorized party (one whose authority was acquired via threshold compromise) submits a competing `Evl`. The chain shape records the compromise in the data; the structural signature is identical to the federation-race case.

The verifier accepts the divergent chain shape as structurally valid in either case — the events landed under valid auth checks at the time they were processed. The trust layer (not the verifier) decides the consumer response.

> **Race and threshold-compromise are not chain-distinguishable.** The chain shape produced by a federation race is identical to the chain shape produced by threshold compromise — same events, same SAIDs, same divergent set. Only out-of-band context (operator intent, monitoring signals, who held what keys when) lets consumers separate the two. The protocol cannot — and does not try.

The security dials differ by cause: against compromise, threshold height (high enough that controlling the threshold is hard-to-impossible) is the operator's mechanism. Against race, application-layer coordination above the protocol bounds the window — see [§Multi-Party Governance Synchronization](#multi-party-governance-synchronization). The protocol-level response is the same regardless of cause: divergence in the data → chain becomes contested-terminal → operator reincepts under a new identity.

### Chain validity vs consumer trust

The IEL verifier and downstream consumers operate on different questions:

- **Chain validity** (the verifier's job). "Is this chain shape structurally authentic?" — events exist, cryptography is correct, chain linkages are correct, immunity rule satisfied, structural integrity intact. The verifier accepts a divergent chain as valid because the divergent shape IS what the chain authentically experienced. Both branches verify independently. Contested chains stay structurally valid; events on the chain remain readable.
- **Consumer trust** (the auth/policy layer's job). "Should I trust authorization claims from this chain?" — handled via `policy_satisfied`, divergent-chain handling, and per-event `satisfied_saids` (see [verification.md §Caller-bounded SAID querying](verification.md#caller-bounded-said-querying)).

**Trust model split**:
- **Active linear chain**: events trusted under their original authorization.
- **Contested chain** (any divergent set on IEL — always immediately contested by the privileged-divergence rule): **whole-chain-suspect**. Pre-divergence events do not retain authorization grounding for new trust decisions. The reasoning is structural: when divergence occurs, the protocol cannot determine whether the divergence was race or takeover, and it cannot determine which event in the divergent set was authored legitimately. Consumers cannot anchor any new authorization on the chain's content; the chain is forensic-readable only. See [../../../../protocol-doctrine.md §Trust Model on Contested Chains](../../../../protocol-doctrine.md#trust-model-on-contested-chains) for the full reasoning.
- **Decommissioned chain** (Dec landed, no divergence): pre-Dec events retain trust under their original authorization. Dec is the operator's clean-retirement signal.

The "divergent non-privileged" state in KEL/SEL has no IEL analog — every IEL event is privileged, so any divergence is immediately contested.

The verifier's job is to make chain authenticity unambiguous; the consumer's job is to apply the trust layer on top of that verified-authentic data.

### Effect on Bound SELs

When the IEL is contested (divergence has occurred — always immediately contested since every IEL event is privileged), **all** SELs bound to any event in the IEL chain lose their authorization basis. The whole-chain-suspect rule applies uniformly: consumers cannot tell from chain data which IEL event was authored legitimately, so they cannot ground SEL trust in any IEL event from that chain. Operator's recourse is to reincept the SEL under a new IEL prefix and rebind dependent chains forward to the new identity.

When the IEL is decommissioned (Dec landed, no divergence), bound SELs continue to verify cleanly — pre-Dec IEL events stay authoritative under their original auth. Dec is a clean-retirement signal; the operator simply isn't using the IEL going forward. New SEL submissions that reference a decommissioned IEL fail (the IEL accepts no new events to ratchet against), but existing SEL events bound to pre-Dec IEL events keep their meaning.

This split between contested and decommissioned IELs is the operator's recovery surface. Cascade-reincept is the operational reality when an IEL fails: every dependent SEL must reincept under a new IEL. **Operators should design identity hierarchies with this cascade in mind** — anchoring everything to a single root means root compromise costs the entire dependent tree. Partition the dependency graph so a single compromise has a bounded blast radius.

## Multi-Party Governance Synchronization

When more than one party can satisfy an IEL's `authPolicy` or `governancePolicy`, concurrent submissions can produce two `Evl` events at the same serial — divergence on IEL → contested-terminal immediately. Operators must serialize governance submissions above the protocol (designated submitter, leader election, or any other out-of-band serialization mechanism). This is load-bearing for high-stakes IEL identities (federation root, identity-hierarchy roots, anything whose reincept would cascade widely) — not optional. Synchronization defends against accidental races; threshold compromise is a separate concern handled by operational hardening + threshold redundancy. Full operator guidance: [../../../../../operations/multi-party-governance.md](../../../../../operations/multi-party-governance.md).

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
- IEL is not divergent at the bound event's branch.
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `ielEvent`** (SEL-specific): each SEL event's `ielEvent` must be at-or-after its parent event's `ielEvent` in IEL chain order, where "parent" is the event referenced by `previous` SAID. The check is applied per branch — the verifier walks each branch independently, comparing each event's `ielEvent` against the previous event's on the same branch. Branches with different parent-chains do not constrain each other's `ielEvent` values.

This rule is unique to the SEL↔IEL cross-chain binding. SEL is the only primitive whose authorization is referenced via a separate field pointing at another chain; KEL and IEL resolve authorization from commitments/policy intrinsic to their own chain at the event's parent (`previous`), and have no analog rule.

There is no chain-wide watermark gate. The chain's `lastIelEvent` (the highest `ielEvent` observed across all events in the chain) is a derived aggregate, computed after the fact, used by consumers to query "what's the highest IEL binding this SEL has reached" — not used to gate new event acceptance. New event acceptance is gated by the per-event parent-monotonic check on the branch the event extends.

**Consequence for divergent SEL chains**: branches may reference different IEL events at the same SEL serial, and may resolve to different governance/auth policies on each branch. This within-chain policy variation is bounded structurally by SEL's seal-cap (no fork at-or-before the seal — caps how far back branches can diverge) and by privileged-divergence-is-terminal (any privileged event in the divergent set ends the chain — caps how long the chain can stay in a divergent state). KEL and IEL never have within-chain policy variation.

There is no separate "most recent at submit time" rule. Such a rule would create a path distinction (submit vs. gossip) that breaks data agnosticism, and would reject historical bindings during bootstrap.

### What parent-monotonic blocks (and what it doesn't)

Parent-monotonic prevents an adversary from extending a branch with a regressed `ielEvent` — once a branch's tip is bound to IEL_v5, no further event extending that same branch can bind to anything earlier than v5. On actively-maintained chains, the legitimate operator's recent events on the live branch have advanced `ielEvent` forward; an adversary with stale (revoked-since) authority cannot insert new events on that same branch bound to their old IEL state.

Parent-monotonic does NOT prevent three scenarios. None breaks the system: each has a structural mitigation covered in [§Consumer-side discipline](#consumer-side-discipline), [§Governance-evolution ratchet via Sea](#governance-evolution-ratchet-via-sea), or [§Application-developer enrollment patterns](#application-developer-enrollment-patterns). The three are worth understanding when designing enrollment flows and operator routines.

#### Brand-new chain races (not blocked)

Before any legitimate v1+ event lands, a party with `authPolicy` authority on the bound IEL can submit `[Icp, Est_stale]` first, establishing the chain with their content at v1. The legitimate operator's enrollment-time response is `[Icp, Est_legit]` — `Icp` dedups (same content, same SAID across submitters); `Est_legit` lands at v=1 with `parent = Icp.said` (extending `Icp` via dedup-equivalence per [../../../../protocol-doctrine.md §Extension Discipline](../../../../protocol-doctrine.md#extension-discipline); operators never extend adversary events). This creates a non-privileged divergent set with `Est_stale` — both auth-authorized; Est-Est race shape.

The operator then submits `Rpr` (governance-authorized via the bound IEL's current `governancePolicy`) extending their `Est_legit` branch. `Rpr` archives `Est_stale` and the chain becomes the operator's. The race is bounded by the user's enrollment window: until enrollment completes (including any `Rpr` cleanup), the user is treated as inactive in the system, and no consumers honor authorizations rooted in the in-progress chain — see [§Application-developer enrollment patterns](#application-developer-enrollment-patterns). The SEL inception batch rule (`[Icp, Est]` minimum) makes this race well-defined: every chain starts with both content and a binding.

```
Step 1 — Adversary submits [Icp, Est_stale] first; chain born at v_1:

  [Icp_v0] → [Est_stale @ v_1, ielEvent=IEL_v_old]   (chain tip)

Step 2 — Operator submits [Icp, Est_legit] with Est_legit.previous =
Icp.said (extending Icp via dedup-equivalence; never extending Est_stale):

  Icp dedups (deterministic prefix + SAID across submitters).
  Est_legit lands at v_1 alongside Est_stale:

  [Icp_v0] ─┬─ [Est_stale @ v_1, ielEvent=IEL_v_old]
            └─ [Est_legit @ v_1, ielEvent=IEL_v_current]

  Both auth-authorized; neither privileged → non-privileged divergent.

Step 3 — Operator submits Rpr extending Est_legit at v_2 (branch-tip-
extending shape):

  Rpr.previous = Est_legit.said,  Rpr.serial = 2

  Discriminator archives Est_stale's branch:

  [Icp_v0] → [Est_legit @ v_1] → [Rpr @ v_2]   (linear, repaired)
                                     ↑
                                     Est_stale archived (forensic;
                                                         not on live chain)
```

#### Stale governance termination on unratcheted branches (not blocked)

A party holding stale governance authority can submit a non-archiving privileged event (`Sea` or `Dec`) extending a branch tip whose `ielEvent` is still at the stale event. Mitigation is the governance-evolution Sea ratchet (see [§Governance-evolution ratchet via Sea](#governance-evolution-ratchet-via-sea) below): after IEL evolves governance, submit a `Sea` on each dependent SEL to advance the branch tip's `ielEvent` forward to the current IEL event. After this advancement, a stale-bound `Sea`/`Dec` extending the new tip fails parent-monotonic on its own branch (its `ielEvent` would regress relative to its parent) and is rejected. The vulnerable window is between IEL governance evolution and the SEL Sea ratchet — bounded by gossip latency plus the ratchet's submission cadence.

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

A non-archiving privileged event (`Sea` or `Dec`) that forks from `v_{d-1}` (forming its own singleton branch at `v_d`) need only satisfy `event.ielEvent >= v_{d-1}.ielEvent`. It does not need to satisfy any constraint relative to the existing diverged branches — those are structurally independent branches.

This is intentional. Chain-wide watermark would otherwise reject fork-contest scenarios where a long divergent branch already sits at higher SEL serials with lower `ielEvent`s than the contesting submission's binding. The per-branch framing is what makes fork-contest work — the structural admission of a non-archiving privileged event extending `v_{d-1}` is independent of the diverged branches' bindings, so the upgrade rule (priv event joining a non-privileged divergent set at `v_d` → Contested) fires uniformly even when the live branches are stale.

```
Pre-state (existing non-priv divergent at v_d with high SEL serials but
low ielEvent on the diverged branches):

  SEL: [Icp] → ... → [Upd_{d-1}, ielEvent=IEL_v3] ─┬─ Upd_a @ v_d  ┐
                                                    └─ Upd_b @ v_d  ┘
                                                    (both bound to IEL_v3)

Operator (with current governance, bound to IEL_v5) submits a non-
archiving privileged event (Sea or Dec) extending v_{d-1} as a singleton
branch at v_d:

  evt.previous = v_{d-1}.said      (parent is divergence ancestor)
  evt.serial   = d
  evt.ielEvent = IEL_v5.said       (current binding)

Per-event parent-monotonic check (per branch, against THIS branch's
parent — v_{d-1}, NOT against Upd_a/Upd_b which are on independent
branches):
  parent's ielEvent = IEL_v3.said
  evt's              = IEL_v5.said
  IEL_v5 ≥ IEL_v3 → SATISFIED → evt joins the divergent set as a
  3rd event at v_d via upgrade rule → privileged-divergence-is-terminal
  fires → chain becomes contested-terminal.

evt's binding is unrelated to Upd_a/Upd_b's `ielEvent` because
they're on structurally independent branches from evt's. Chain-wide
watermark would block this — rightly understood as overconstraining.
```

### Consumer-side discipline

Independent of any submit/verify gates, a consumer reading an SEL can detect stale-bound events by checking whether the bound IEL event's declared policy is still IEL's currently-tracked policy. If not, the SEL event was authorized under a now-revoked policy and the consumer can filter, treat with caution, or reject per their use-case rules. The chain mathematics make this visible without protocol modification.

### Governance-evolution ratchet via Sea

When the IEL's `governancePolicy` evolves (an `Evl` on IEL changes who has governance authority), the operator should immediately submit a `Sea` on each dependent SEL to advance the live branch's tip `ielEvent` forward to the new IEL `Evl`. This closes the window in which an adversary with revoked governance could submit a stale-bound `Sea`/`Dec` extending the new branch tip — once the tip's `ielEvent` is at the new Evl, any subsequent same-branch event must bind at-or-after the new Evl, so a regressed-binding event on that branch fails parent-monotonic.

This is an operator best practice, not a protocol-enforced rule. Future automation could auto-issue SEL Seas on IEL governance evolution, but is out of scope for v1 of this design.

### Application-developer enrollment patterns

The brand-new chain race described above is defused by enrollment-time discipline on the application-developer side: register all required SEL topics atomically, detect and `Rpr`-resolve prior chain content (the bound IEL's current `governancePolicy` outranks the auth-only racing party), and treat the user as inactive until enrollment completes (no consumers honor authorizations rooted in in-progress chains during the inactive window). The pattern eliminates the race as an authorization-bearing concern. Full developer guidance: [../../../../../development/enrollment.md](../../../../../development/enrollment.md).

## Trust Caveat — Recovered or Contested Anchoring KELs

Beyond the structural guarantees above, IEL trust degrades for consumers when anchoring KELs are recovered or contested. The seal-cap and locked-portion bound structurally block stale-authority chain rearrangement; the policy-immunity rule keeps every referenced policy resolvable for the chain's lifetime; gossip races resolve to deterministic terminal states. These structural guarantees are *partial* when a participating KEL is later recovered, and provide *no* guarantees when a participating KEL has been contested.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the branch the Rec extends stay (`rec` archives only the other branch); anchors on the now-archived branch do not.

Implications for IEL consumers (and transitively SEL consumers, since SEL binds to IEL events):

- An IEL `Evl` / `Dec` whose policy was satisfied entirely by anchors on the surviving branch: re-verifies cleanly across `rec`. Past evaluation stands. SELs bound to that IEL event continue to verify under it.
- An IEL event whose satisfaction depended on anchors on the archived branch: may *fail* re-verification. SELs bound to that IEL event may also fail re-verification, since the upstream authorization is no longer satisfied.

This is observable, not hidden — the chain mathematics make the post-rec state visible. The consumer's runtime trust judgement is: when an anchoring KEL has `rec` history, re-verify the IEL and any SELs bound to it; treat past state with caution proportionate to what survives.

**A contested KEL is whole-chain-suspect.** Once a KEL has been contested (privileged-divergence-is-terminal has fired), the anchors it produced cease to ground trust decisions. This is stronger than the recovery case: under recovery, anchors on the surviving branch remain authoritative; under contest, the chain mathematics cannot tell which side is the rightful operator and consumers must treat all anchors the contested KEL produced as suspect. Whether dependent IEL/SEL events lose their authorization basis depends on (a) whether the contested KEL actually anchored events on those chains, and (b) whether the resolving policy has threshold redundancy that lets it evaluate as satisfied without the contested KEL's contribution. Threshold-redundant policies (`M > N` across distinct custodians) absorb single-member contest — past events stay satisfied via the surviving members, and the operator's forward response is governance evolution (`Evl`) to rotate the contested KEL out of the policy. Cascade-reincept of the IEL or its dependent SELs is required only when the chain *itself* is contested, not transitively from a contested anchoring KEL. See [../../../../protocol-doctrine.md §Adversary Patience and Policy Redundancy](../../../../protocol-doctrine.md#adversary-patience-and-policy-redundancy).

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
| Linear, normal append | `Evl` | Append. Seal advances. |
| Linear, overlap (fork) | concurrent `Evl` (two governance-authorized submissions at the same serial via gossip-merge with distinct policy bodies) | Insert second event at `v_d`; chain becomes contested-terminal (every IEL event is privileged → privileged-divergence rule fires). Valid divergent pairing: `Evl`-`Evl` (and `Evl`-`Dec` / `Dec`-`Evl`). No 3rd event lands at `v_d` (IEL has no upgrade rule per [../../../../protocol-doctrine.md §Privileged Divergence is Terminal](../../../../protocol-doctrine.md#privileged-divergence-is-terminal); divergent IEL is contested-terminal at first 2-event observation). |
| Linear, post-evaluation-seal | `Evl` extending pre-seal serial | Rejected by seal-cap (cannot fork at or before the seal). |
| Any non-terminal | `Dec` | Append at chain max-serial; mark decommissioned. |
| Contested (post-divergence) | any submission, including further `Evl`/`Dec` via gossip at `v_d` or beyond | Rejected with `ContestedIel`. |
| Decommissioned | any submission | Rejected with `IelDecommissioned`. |

## Implementation Map

**Code:**
- `lib/kels/src/types/iel/event.rs` — `IdentityEventKind` enum (`Icp`/`Evl`/`Dec`); `validate_structure` per per-kind field rules.
- `lib/kels/src/types/iel/verification.rs` — `IelVerifier`, `IelVerification`, branch state with tracked `authPolicy` and tracked `governancePolicy`. `is_contested = true` is a verifier-side flag derived from observing any divergent set (every IEL event is privileged).
- `lib/kels/src/identity_builder.rs` — `IdentityEventBuilder` with `evolve()`, `decommission()`; pending-events bundling; pre-flight server-chain re-verification.
- Server submit handler — terminal gate, immunity gate, divergent-rejection routing (returns `ContestedIel` for any submission to a divergent chain — divergent IEL is contested-terminal by privileged-divergence-is-terminal, with no repair primitive), algorithmic `ContestRequired` trigger for events at-or-before evaluation seal on linear chains.
- Storage — `iel_events` table. **No archive table** (no `Rpr` to archive into).

**Notable simplifications vs. SEL:**
- No `Rpr` kind, no `truncate_and_replace` discriminator algorithm, no archive tables, no repair-link rows.
- IelVerifier still tracks branches (max 2 per the divergence invariant) but never reconciles — divergent stays divergent until the chain is reincepted under a new prefix.
- `MAX_NON_EVALUATION_EVENTS` proactive bound doesn't apply (every IEL event is governance-authorized; no fork window to bound).

**Tests:** Submit / verifier / builder coverage; gossip-race convergence on contested state.

## References

- [events.md](events.md) — Per-kind reference.
- [verification.md](verification.md) — `IelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; SELs bind to IEL events.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference.
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL, anchoring model, immunity rule.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
