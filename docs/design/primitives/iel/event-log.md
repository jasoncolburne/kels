# Identity Event Log (IEL) — Lifecycle, Divergence, Contest, Decommission

> Source-of-truth design doc for the IEL chain lifecycle. Pairs with [reconciliation.md](reconciliation.md) (multi-node correctness proof matrix), [merge.md](merge.md) (submit-handler routing), and [verification.md](verification.md) (IelVerifier algorithm).

The Identity Event Log (IEL) is a per-prefix chain of `IdentityEvent` records describing the evolving authorization state of an identity — its tracked `auth_policy` and `governance_policy`. Authority over the IEL is asserted by anchoring `ixn` events in one or more KELs identified by the chain's currently-tracked governance policy.

An IEL is the authorization root for a SEL. Every Credential, SEL, or generally identifying/owned document binds to a specific IEL — SELs in particular by prefix at inception, resolving per-event authorization through specific IEL event SAIDs. See [../sel/events.md §`identity_event` semantics](../sel/events.md#identity_event-semantics) for the SEL-side binding.

## Chain States

| State | Description | Accepts new events? |
|---|---|---|
| **Active** | Linear chain of events, latest tip extends cleanly. | Yes — `Evl`, `Cnt`, `Dec` (per `governance_policy`). |
| **Divergent** | Two events exist at some version `d`. Both branches preserved as forensic record. **On IEL, divergence is always immediately contested** — every IEL event is governance-authorized (Icp/Evl/Cnt/Dec all privileged), so any divergent set on IEL contains a privileged event by definition, and the privileged-divergence rule fires (see [../security-invariant.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../security-invariant.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly)). The "Divergent" state is structurally vacuous on IEL; divergence transitions directly to Contested. | Treated as Contested from the moment divergence is observed. |
| **Contested** | Chain has terminated due to divergence (any divergent set on IEL), or via an explicit `Cnt` extending `v_{tip-1}` on a linear chain (which creates fresh divergence at the tip's version, immediately privileged-divergent → contested). Once contested, no further events land. | None. All submissions rejected. |
| **Decommissioned** | Chain has terminated cleanly by operator action — at least one `Dec` event in the chain, no Cnt or divergence. Decommission is unconditionally terminal. | None. All submissions rejected with `IelDecommissioned`. |

State is computed from the chain's events, never tracked as a separate flag. The `IelVerification` token surfaces:
- `divergence_ancestor: Option<Digest256>` — SAID of `v_{d-1}` on a divergent chain (`None` on linear)
- `is_contested: bool`
- `is_decommissioned: bool`
- `last_governance_event: Option<Digest256>` — SAID of the most recent `Evl` (the "evaluation seal").

## Event Kinds

| Kind | Purpose | Authorization | Terminal? |
|---|---|---|---|
| `Icp` | Inception (v0). Declares `auth_policy` and `governance_policy`. | `governance_policy` (Icp.said anchored under the declared governance_policy — every IEL event is a governance act). | No |
| `Evl` | Evolve — governance evaluation; advances the seal. MUST evolve at least one of `auth_policy` / `governance_policy` (a no-op Evl is rejected as a structural error). | `governance_policy`. | No |
| `Cnt` | Contest — terminal due to authority conflict or divergence. | `governance_policy`. | **Yes** |
| `Dec` | Decommission — terminal owner-initiated end. | `governance_policy`. | **Yes** |

For per-kind field rules and typical chain shapes, see [events.md](events.md). **There is no `Rpr` kind on IEL.** Divergence is preserved as data and resolved by `Cnt` rather than archived by repair (see [§Divergence and Contest-Only Resolution](#divergence-and-contest-only-resolution)).

## Evaluation Seal and Anchor Non-Poisonability

The `last_governance_event` is the SAID of the most recent `Evl` event. It is the chain's **evaluation seal**.

**Every `Evl` must be a real evolution.** A no-op `Evl` (both `auth_policy` and `governance_policy` identical to the predecessor) is rejected as a structural error. This keeps `last_governance_event` meaningful as the evaluation seal — it advances only when the auth/governance state actually moves, not on heartbeat extensions. There is no use case for a periodic re-attestation: IEL has no repair primitive that would need governance "exercise," and key rotation lives at the KEL layer below (anchoring KELs rotate independently; IEL doesn't need to mirror them).

**Once an IEL event lands, the governance satisfaction it proves is final.** This is enforced *structurally* via a constraint on policies introduced or evolved on the chain:

> **Policy immunity rule.** Any policy referenced as a chain's `auth_policy` or `governance_policy` MUST have `immune: true`. Both the merge engine (at submit time) and the verifier (at verification time) reject any `Icp` or `Evl` event that introduces or evolves a policy whose `immune` flag is not set. Both layers enforce because the verifier processes data from any source — gossip, peer pulls, restored backups, bootstrap — and cannot trust that the originating node enforced the rule (the "DB cannot be trusted" invariant; see [../security-invariant.md](../../security-invariant.md)).

Since `immune: true` makes a policy impervious to poisoning in the evaluator (`evaluate_anchored_policy` skips poison checks for immune policies), the rule guarantees that no anchor used in any chain authorization (auth or governance) can ever be poisoned. Past `Evl` / `Cnt` / `Dec` evaluations stay satisfied by construction.

**Revocation via policy evolution, not poison.** To remove an endorser's authority going forward, evolve the policy via `Evl` (declaring a new `auth_policy` or `governance_policy` SAID that excludes the endorser); the new policy must itself be immune. Past events stay authorized under the policy in effect when they landed. For compromise of an underlying anchoring KEL, the corrective mechanism is `rec` / `cnt` on that KEL (see [§Trust Caveat below](#trust-caveat--recovered-anchoring-kels)).

## Divergence and Contest-Only Resolution

IEL has only one non-Icp event kind that does ongoing work — `Evl`, governance-authorized. Divergence on IEL therefore requires two governance-authorized events to land at the same version. There is no analog to today's SEL's auth-vs-governance asymmetry that motivates `Rpr` (preserve one branch, archive the other): on IEL, both branches have governance authority, and the protocol cannot adjudicate which side is the rightful operator from chain data alone.

**Privileged-divergence-is-terminal applies trivially on IEL.** The privileged event set on IEL includes every event kind: `Icp`, `Evl`, `Cnt`, `Dec` are all governance-authorized. (The chain cannot be contested before its inception; the rule is structurally vacuous at `Icp` itself but applies uniformly to any divergence post-inception.) Any divergent set on an IEL therefore contains a privileged event by definition, and the chain transitions to contested-terminal immediately. There is no separate "explicit Cnt resolution" step needed for IEL divergence — divergence IS contest, structurally.

**Race-vs-takeover framing.** Divergence on IEL — two events at the same version — can arise from a federation race (two legitimately-current governance-authorized parties submitting concurrently) or a takeover (a party holding currently-authorized governance forking against the other party who also holds it). The chain data records the divergence; the protocol cannot structurally distinguish race from takeover. The verifier accepts both as structurally valid; consumer trust degrades uniformly post-divergence regardless of cause. The operator response in either case is reincept under a new prefix — `Cnt` is available as an explicit termination signal but is not required for IEL because divergence is already terminal.

**`Cnt` on IEL** is the operator's protocol-level explicit-termination event, used when the chain is linear and the operator wants to terminate (compromise detected; voluntary abandonment-via-contest rather than -via-Dec).

As in all cases, `Cnt.previous = v_{tip-1}.said` (parent of current tip on linear, which creates fresh divergence at `v_N` for an IEL). See [../security-invariant.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../security-invariant.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

Cnt is invalid on an already divergent IEL, which is by definition contested.

**Distinction from KEL Rec / SEL Rpr.** KEL Rec and SEL Rpr resolve divergence by archiving events via the discriminator. They take two parent shapes: branch-tip-extending (`previous = v_d.said` for one of the two branch tips, lands at `v_{d+1}`, archives the other branch) and divergence-ancestor-extending (`previous = v_{d-1}.said`, lands at `v_d`, archives both branches at `v_d`). Cnt does NOT archive - it joins the existing (non-privileged) divergent set as a 3rd event at `v_d` (parent = `v_{d-1}`), privileged-divergence-is-terminal fires, the chain transitions to contested-terminal. The kind discriminator determines whether the chain recovers (Rec/Rpr; archival) or terminates (Cnt; no archival). IEL has no Rec/Rpr equivalent — there is no recovery primitive, only termination.

- **Divergence is preserved.** Both branches stay in storage forever as forensic record. The divergence is visible to consumers.
- **No `Rpr`.** No discriminator algorithm. No archive table. No repair link rows.

This is intentional: history is encoded in the data. When a governance-authorized event diverges, there is no way to determine if the governance authorized event was created by an adversary or legitimate operator. Termination is the honest outcome; the operator re-incepts under a new identity if continued operation is needed.

### What divergence means structurally

Divergence is detected when two IEL events share the same `previous` SAID. The chain becomes contested-terminal immediately by the privileged-divergence rule (every IEL event is governance-authorized, so any divergent set on IEL is privileged).

v0 divergence is rejected outright (inception is fully deterministic — two distinct v0 events for the same prefix indicate protocol-level corruption, not authority conflict).

The route that creates divergence on an IEL chain:

**Concurrent extensions** (race, same-batch fork): two events (any combination of `Evl` and `Cnt`, since both kinds extend with `previous = v_{d-1}.said`) land at the same version. Divergence is created at the moment of submission; the chain transitions to contested-terminal immediately by the privileged-divergence-is-terminal rule (every IEL event is privileged). No third event lands at `v_d` — the contested-state gate rejects all subsequent submissions, including any further `Evl`, `Cnt`, or `Dec` arriving via gossip.

**Diagrams.** The possible shapes look like:

```
Concurrent extension (any 2 of Evl/Cnt at v_d):

  v0      v1        v2     ← divergent set at v2; chain immediately contested-terminal
[Icp] → [Evl] ─┬─ [event_A]    one of {Evl, Cnt}
               └─ [event_B]    the other one (must differ in content)

Both branches preserved as forensic record. The chain is contested as of v2;
no further events land at v2 — subsequent submissions, including
gossip-delivered Evl/Cnt/Dec at v2, are rejected by the contested-state gate.

Linear-chain operator-initiated Cnt (Cnt extends v_{tip-1}, creating fresh
divergence at v_tip's version):

before:   [Icp] → [Evl_v1] → [Evl_v2]

operator submits Cnt with previous = Evl_v1.said, version = 2

after:    [Icp] → [Evl_v1] ─┬─ [Evl_v2]
                            └─ [Cnt]   ← privileged-divergence rule fires:
                                          chain contested at v2 (2 events at v_d)
```

The divergence invariant guarantees:
- **Maximum 2 events at the divergence version `d`** — IEL-specific. The general "max 3 at `v_d`" rule that applies to KEL and SEL (where the upgrade rule allows a privileged event to land as a third event after a non-privileged divergent set forms) does not apply on IEL: every IEL event is privileged → no non-privileged divergent set can form on IEL → upgrade-rule path does not exist. The chain transitions to contested-terminal at first observation of 2-event divergence, and the contested-state gate rejects all subsequent submissions (including any further `Evl`, `Cnt`, or `Dec` arriving via gossip at `v_d`).
- No events at versions > `d` — the chain is contested-terminal as of `d`.
- Every event lives at a version at-or-after the chain's last seal (`event_version >= seal_version` — the seal-cap rejects events landing strictly before the seal; see [../security-invariant.md §Forks are Seal-Bounded](../../security-invariant.md#forks-are-seal-bounded)). Combined with the rule that every IEL event advances the seal (Evl) or terminates (Cnt/Dec), the seal coincides with the tip on IEL — within-window forks structurally don't exist on IEL. A linear-chain Cnt on IEL — extending `v_{tip-1}` on a chain where seal coincides with tip — lands at `event_version = d = seal_version`; this is the parent-at-(seal − 1) boundary case the seal-cap explicitly admits (Cnt's parent `v_{d-1}` sits at seal − 1, the new event itself lives at the seal).
- **Bounded verifier processing at the divergent generation.** When the verifier walks a chain whose v_d generation holds two events (the linear tip and the linear-chain Cnt that extended `v_{tip-1}` on the submitting node, or any 2-event subset observable after gossip-merge with a concurrent submission on another node), it processes them as siblings of the same generation under the inline chain walk (verifier-merge unification, [#181](https://github.com/jasoncolburne/kels/issues/181)): branch state from processing `v_{d-1}` holds the tracked governance_policy, and both events at `v_d` are verified consuming that same `v_{d-1}` governance context. Total verifier work at the v_d generation is bounded by single-event verification cost regardless of chain length.

### Why no `Rpr`

`Rpr` on today's SEL exists because:
- SEL has many auth-authorized events (`Upd`) that a second auth-holder could use to extend a divergent branch.
- The asymmetry between auth and governance authority is what `Rpr` exploits: governance is the higher-bar authority, so a governance-authorized `Rpr` resolves an auth-authorized fork by archiving the branch not on `Rpr.previous`'s walkback.

On IEL, both branches require governance to exist at all. There's no asymmetry for `Rpr` to exploit. If two governance-authorized events conflict, we don't have grounds to declare one of them the "real" branch and archive the other — both are equally legitimate by the chain's own rules. The honest answer is to let the privileged-divergence rule terminate the chain immediately (admit the conflict, reincept under a new identity).

## Divergence, Contestation, and the Trust Layer

A divergent IEL chain — two governance-authorized events at the same version — can arise from two real failure modes the protocol surfaces in-data:

1. **Federation race.** Two parties with valid governance authority submit `Evl` events near-concurrently to different nodes. Both land legitimately; gossip propagates; both nodes eventually see both events at the same version. The chain shape records the race in the data.
2. **Threshold compromise.** A second governance-authorized party (one whose authority was acquired via threshold compromise) submits a competing `Evl`. The chain shape records the compromise in the data; the structural signature is identical to the federation-race case.

The verifier accepts the divergent chain shape as structurally valid in either case — the events landed under valid auth checks at the time they were processed. **The trust layer (not the verifier) decides the consumer response.** Note: race and threshold-compromise are not chain-distinguishable; only out-of-band context separates them.

The security dials differ by cause: against compromise, threshold height (high enough that controlling the threshold is hard-to-impossible) is the operator's mechanism. Against race, application-layer coordination above the protocol bounds the window — see [§Multi-Party Governance Synchronization](#multi-party-governance-synchronization). The protocol-level response is the same regardless of cause: divergence in the data → chain becomes contested-terminal → operator reincepts under a new identity.

### Cnt: Operator Contestation Primitive

`Cnt` is the operator's protocol-level explicit-termination event. On IEL specifically, `Cnt` is rarely strictly required for chain state — every IEL event is governance-authorized, so any divergence is immediately terminal by the privileged-divergence rule. `Cnt` exists for the linear case (no divergence yet, but operator wants to terminate proactively because they've detected compromise).

`Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain. On IEL this is Cnt's only valid acceptance shape: a node accepts Cnt only as a linear-chain extension of its own tip with `previous = v_{tip-1}.said`, landing the Cnt at `v_N`. All auth checks resolve against the node's linear-chain state at submission time. Acceptance creates fresh 2-event divergence at `v_N` (the existing linear tip + the new Cnt, both extending `v_{tip-1}`); the privileged-divergence-is-terminal rule fires and the chain transitions to contested-terminal. Whatever shape other nodes converge on after gossip — same 2-event set, or a different 2-event set produced by a concurrent `Evl`/`Cnt` submission on another node and locked in by that node's contested-state gate before Cnt arrives via gossip — is emergent from gossip-merge, not part of the acceptance rule. A Cnt arriving via gossip to a node that has already observed 2-event divergence at `v_d` is rejected by the contested-state gate. Cross-node propagation of a linear-chain Cnt works because `v_{tip-1}` is `v_{d-1}` (with `d = N`), and `v_{d-1}` is structurally shared — it lands cleanly before any divergence — so Cnt with `previous = v_{tip-1}.said` validates uniformly across nodes.

Authorization satisfies the same `governance_policy` required to accept `v_{tip}` — i.e., the policy declared at `v_{tip-1}` for events that extend it. Authorization failure is HARD: a Cnt whose anchor does not satisfy that policy is rejected by the verifier and the chain stays at its prior state. The same HARD rule applies to all events — the general invariant is "any event with failed auth is rejected."

**Distinction from KEL Rec / SEL Rpr.** KEL Rec and SEL Rpr resolve divergence by archiving events via the discriminator. They take two parent shapes: branch-tip-extending (`previous = v_d.said` for one of the two branch tips, lands at `v_{d+1}`, archives the other branch) and divergence-ancestor-extending (`previous = v_{d-1}.said`, lands at `v_d`, archives both branches at `v_d`). Cnt does NOT archive — it joins the existing divergent set as a 3rd event at `v_d` (parent = `v_{d-1}`), the privileged-divergence-is-terminal rule fires, the chain transitions to contested-terminal. IEL has no Rec/Rpr — there is no recovery primitive on IEL.

See [../security-invariant.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../security-invariant.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

In all cases:

- `Cnt` makes divergence permanent (already permanent on IEL by virtue of privileged-divergence-is-terminal; Cnt is an explicit marker).
- `Cnt` does NOT pick a winning branch — both branches stay in storage as forensic record.
- The chain becomes terminal-contested; no further events can land.
- IEL has no `Rpr` — divergence is structurally terminal regardless of whether `Cnt` lands.

### Chain Validity vs Consumer Trust

The IEL verifier and downstream consumers operate on different questions:

- **Chain validity** (the verifier's job). "Is this chain shape structurally authentic?" — events exist, cryptography is correct, chain linkages are correct, immunity rule satisfied, structural integrity intact. The verifier accepts a divergent chain as valid because the divergent shape IS what the chain authentically experienced. Both branches verify independently. Contested chains stay structurally valid; events on the chain remain readable.
- **Consumer trust** (the auth/policy layer's job). "Should I trust authorization claims from this chain?" — handled via `policy_satisfied`, divergent-chain handling, and per-event `satisfied_saids` (see [verification.md §Caller-bounded SAID querying](verification.md#caller-bounded-said-querying)).

**Trust model split**:
- **Active linear chain**: events trusted under their original authorization.
- **Divergent (non-privileged) chain** — does not arise on IEL since every IEL event is privileged; included here for parallel structure with KEL/SEL.
- **Contested chain** (any divergent set on IEL — always immediately contested — or chain has Cnt): **whole-chain-suspect**. Pre-Cnt events do not retain authorization grounding for new trust decisions. The reasoning is structural: when divergence occurs (or Cnt lands), the protocol cannot determine whether the divergence was race or takeover, and it cannot determine which event in the divergent set (if any) was authored legitimately. Consumers cannot anchor any new authorization on the chain's content; the chain is forensic-readable only. See [../security-invariant.md §Trust Model on Contested Chains](../../security-invariant.md#trust-model-on-contested-chains) for the full reasoning.
- **Decommissioned chain** (Dec landed, no Cnt): pre-Dec events retain trust under their original authorization. Dec is the operator's clean-retirement signal.

The verifier's job is to make chain authenticity unambiguous; the consumer's job is to apply the trust layer on top of that verified-authentic data.

### Effect on Bound SELs

When the IEL is contested (divergence has occurred, with or without explicit Cnt), **all** SELs bound to any event in the IEL chain lose their authorization basis. The whole-chain-suspect rule applies uniformly: consumers cannot tell from chain data which IEL event was authored legitimately, so they cannot ground SEL trust in any IEL event from that chain. Operator's recourse is to reincept the SEL under a new IEL prefix and rebind dependent chains forward to the new identity.

When the IEL is decommissioned (Dec landed, no Cnt or divergence), bound SELs continue to verify cleanly — pre-Dec IEL events stay authoritative under their original auth. Dec is a clean-retirement signal; the operator simply isn't using the IEL going forward. New SEL submissions that reference a decommissioned IEL fail (the IEL accepts no new events to ratchet against), but existing SEL events bound to pre-Dec IEL events keep their meaning.

This split between contested and decommissioned IELs is the operator's recovery surface. Cascade-reincept is the operational reality when an IEL fails: every dependent SEL must reincept under a new IEL. **Operators should design identity hierarchies with this cascade in mind** — anchoring everything to a single root means root compromise costs the entire dependent tree. Partition the dependency graph so a single compromise has a bounded blast radius.

## Cross-Chain Anchor Stability

IEL is the cornerstone of cross-chain consistency for the federation. Every SEL event at v1+ binds to a specific IEL event by SAID via `identity_event`. The immunity rule on IEL is what makes this binding stable across time.

### Why IEL stability matters to SEL

A SEL event bound to `IEL_event_X.said` resolves authorization through:
1. Look up `IEL_event_X` in the IEL's authentic chain.
2. Read the policy declared (`Icp`) or evolved (`Evl`) at that event.
3. Verify SEL.said is anchored under that policy.

For this resolution to remain deterministic forever:
- `IEL_event_X` must remain in IEL's authentic chain (never archived) — guaranteed by chain immutability and the no-`Rpr` rule (we never archive on IEL).
- The policy declared at `IEL_event_X` must have stable content (anchors don't move) — guaranteed by the IEL immunity rule.
- The KEL ixn anchoring SEL.said must remain in its KEL — caveat: subject to KEL `rec` / `cnt` (see Trust Caveat).

The first two are structural. The third is a runtime trust concern that applies to all anchoring in the system.

```
SEL→IEL authorization resolution for a SEL Upd at v1+:

  SEL Upd                                    IEL chain
  ───────                                    ─────────
  identity_event = X.said  ────────────►  IEL_event_X (Icp or Evl)
                                                │
                                                ├─ declares / evolves
                                                │   auth_policy_X
                                                │
                                                ▼
  SEL.said anchored        ──────────►   policy_X.evaluate(anchor)?
  in a KEL ixn under                            │
  the policies in policy_X                      ├─►  YES → SEL Upd accepted
                                                └─►  NO  → SEL Upd rejected

The same shape applies for SEL Sea/Rpr/Cnt/Dec — they resolve through
governance_policy rather than auth_policy at the same IEL event.
```

### Path-agnostic validation rules

KELS data is path-agnostic: an event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. The submit handler and the verifier enforce identical rules for SEL event bindings.

For an SEL event at v1+, all paths (submit, gossip ingestion, bootstrap, re-verification) check:

- `identity_event` references an IEL event in IEL's authentic chain (`prefix == SEL.identity`).
- That IEL event declared (`Icp`) or evolved (`Evl`) the relevant policy — `auth_policy` for SEL `Upd`, `governance_policy` for SEL `Sea`/`Rpr`/`Cnt`/`Dec`.
- IEL is not divergent at the bound event's branch.
- SEL.said is anchored under the resolved policy.
- **Per-event parent-monotonic on `identity_event`** (SEL-specific): each SEL event's `identity_event` must be at-or-after its parent event's `identity_event` in IEL chain order, where "parent" is the event referenced by `previous` SAID. The check is applied per branch — the verifier walks each branch independently, comparing each event's `identity_event` against the previous event's on the same branch. Branches with different parent-chains do not constrain each other's `identity_event` values.

This rule is unique to the SEL↔IEL cross-chain binding. SEL is the only primitive whose authorization is referenced via a separate field pointing at another chain; KEL and IEL resolve authorization from commitments/policy intrinsic to their own chain at `v_{tip-1}` and have no analog rule.

There is no chain-wide watermark gate. The chain's `last_identity_event` (the highest `identity_event` observed across all events in the chain) is a derived aggregate, computed after the fact, used by consumers to query "what's the highest IEL binding this SEL has reached" — not used to gate new event acceptance. New event acceptance is gated by the per-event parent-monotonic check on the branch the event extends.

**Consequence for divergent SEL chains**: branches may reference different IEL events at the same SEL version, and may resolve to different governance/auth policies on each branch. This within-chain policy variation is bounded structurally by SEL's seal-cap (no fork at-or-before the seal — caps how far back branches can diverge) and by privileged-divergence-is-terminal (any privileged event in the divergent set ends the chain — caps how long the chain can stay in a divergent state). KEL and IEL never have within-chain policy variation.

There is no separate "most recent at submit time" rule. Such a rule would create a path distinction (submit vs. gossip) that breaks data agnosticism, and would reject historical bindings during bootstrap.

### What parent-monotonic blocks (and what it doesn't)

Parent-monotonic prevents an adversary from extending a branch with a regressed `identity_event` — once a branch's tip is bound to IEL_v5, no further event extending that same branch can bind to anything earlier than v5. On actively-maintained chains, the legitimate operator's recent events on the live branch have advanced `identity_event` forward; an adversary with stale (revoked-since) authority cannot insert new events on that same branch bound to their old IEL state.

Parent-monotonic does NOT prevent:

- **Brand-new SEL chain races.** Before any legitimate v1+ event lands, a party with `auth_policy` authority on the bound IEL can submit `[Icp, Upd_stale]` first, establishing the chain with their content at v1. The legitimate operator's enrollment-time response is `[Icp, Upd_legit]` — Icp dedups (same content, same SAID across submitters); `Upd_legit` lands at v=1 with parent=Icp.said (extending `Icp` via dedup-equivalence, per [../security-invariant.md §Extension Discipline](../../security-invariant.md#extension-discipline) — operators never extend adversary events), creating a non-privileged divergent set with `Upd_stale` (both auth-authorized; Upd-Upd race shape). The operator then submits `Rpr` (governance-authorized via the bound IEL's current `governance_policy`) extending their `Upd_legit` branch; `Rpr` archives `Upd_stale` and the chain becomes the operator's. The race is bounded by the user's enrollment window: until enrollment completes (including any `Rpr` cleanup), the user is treated as inactive in the system, and no consumers honor authorizations rooted in the in-progress chain. See [§Application-developer enrollment patterns](#application-developer-enrollment-patterns) below. The SEL inception batch rule (`[Icp, Upd]` minimum) makes this race well-defined: every chain starts with both content and a binding.

  ```
  Step 1 — Adversary submits [Icp, Upd_stale] first; chain born at v_1:

    [Icp_v0] → [Upd_stale @ v_1, identity_event=IEL_v_old]   (chain tip)

  Step 2 — Operator submits [Icp, Upd_legit] with Upd_legit.previous =
  Icp.said (extending Icp via dedup-equivalence; never extending Upd_stale):

    Icp dedups (deterministic prefix + SAID across submitters).
    Upd_legit lands at v_1 alongside Upd_stale:

    [Icp_v0] ─┬─ [Upd_stale @ v_1, identity_event=IEL_v_old]
              └─ [Upd_legit @ v_1, identity_event=IEL_v_current]

    Both auth-authorized; neither privileged → non-privileged divergent.

  Step 3 — Operator submits Rpr extending Upd_legit at v_2 (branch-tip-
  extending shape):

    Rpr.previous = Upd_legit.said,  Rpr.version = 2

    Discriminator archives Upd_stale's branch:

    [Icp_v0] → [Upd_legit @ v_1] → [Rpr @ v_2]   (linear, repaired)
                                       ↑
                                       Upd_stale archived (forensic;
                                                           not on live chain)
  ```
- **Stale governance termination on an unratcheted branch.** An adversary with stale governance authority can submit `Cnt` or `Dec` extending a branch tip whose `identity_event` is still at the adversary's stale event. Mitigation is **operator discipline**: after IEL evolves governance, the operator submits a `Sea` on each dependent SEL to advance the branch tip's `identity_event` forward to the current IEL event. After this advancement, an adversary's stale-bound `Cnt`/`Dec` extending the new tip fails parent-monotonic on its own branch (its `identity_event` would regress relative to its parent) and is rejected. The vulnerable window is "between IEL governance evolution and the SEL Sea advancement" — bounded by gossip latency plus operator reaction time.

  ```
  IEL evolves governance:
    IEL: [Icp] → [Evl_old] → [Evl_new]

  Vulnerable window (SEL tip not yet ratcheted):
    SEL: [Icp] → ... → [Upd_v_N, identity_event=Evl_old.said]   (tip)
                                            ↑
                                      adversary with stale gov_old
                                      authority can submit:

      Cnt_stale.previous       = Upd_v_N.said       (extends tip)
      Cnt_stale.identity_event = Evl_old.said       (stale binding)

      Per-event parent-monotonic check:
        parent's identity_event = Evl_old.said
        Cnt_stale's             = Evl_old.said
        Evl_old ≥ Evl_old → SATISFIED → accepted; chain terminates.

  After operator-discipline Sea ratchet (post-Sea state):
    SEL: ... → [Upd_v_N] → [Sea_v_{N+1}, identity_event=Evl_new.said]  (tip)

  Same adversary tries again:
      Cnt_stale.previous       = Sea_v_{N+1}.said
      Cnt_stale.identity_event = Evl_old.said

      Per-event parent-monotonic check:
        parent's identity_event = Evl_new.said
        Cnt_stale's             = Evl_old.said
        Evl_old < Evl_new → REGRESS → HARD-fail rejection.
  ```

- **Cnt fork-contest with low identity_event.** A Cnt that forks from `v_{d-1}` (forming its own singleton branch at `v_d`) need only satisfy `Cnt.identity_event >= v_{d-1}.identity_event`. It does not need to satisfy any constraint relative to the existing diverged branches — those are structurally independent branches from this Cnt's branch. This is intentional: chain-wide watermark would otherwise reject Cnt fork-contest scenarios where a long divergent branch already sits at higher SEL versions with lower `identity_event`s than the Cnt's binding.

  ```
  Pre-state (existing non-priv divergent at v_d with high SEL versions but
  low identity_event on the diverged branches):

    SEL: [Icp] → ... → [Upd_{d-1}, identity_event=IEL_v3] ─┬─ Upd_a @ v_d  ┐
                                                          └─ Upd_b @ v_d  ┘
                                                          (both bound to IEL_v3)

  Operator (with current governance, bound to IEL_v5) submits Cnt that
  forks from v_{d-1} as a new singleton branch at v_d:

    Cnt.previous       = v_{d-1}.said      (parent is divergence ancestor)
    Cnt.version        = d
    Cnt.identity_event = IEL_v5.said       (operator's current binding)

  Per-event parent-monotonic check (per branch, against THIS branch's
  parent — v_{d-1}, NOT against Upd_a/Upd_b which are on independent
  branches):
    parent's identity_event = IEL_v3.said
    Cnt's                   = IEL_v5.said
    IEL_v5 ≥ IEL_v3 → SATISFIED → Cnt joins the divergent set as a
    3rd event at v_d via upgrade rule → privileged-divergence-is-terminal
    fires → chain becomes contested-terminal.

  Cnt's binding is unrelated to Upd_a/Upd_b's `identity_event` because
  they're on structurally independent branches from Cnt's. Chain-wide
  watermark would block this — rightly understood as overconstraining.
  ```

### Consumer-side discipline

Independent of any submit/verify gates, a consumer reading an SEL can detect stale-bound events by checking whether the bound IEL event's declared policy is still IEL's currently-tracked policy. If not, the SEL event was authorized under a now-revoked policy and the consumer can filter, treat with caution, or reject per their use-case rules. The chain mathematics make this visible without protocol modification.

### Operator-discipline corollary for governance evolution

When the IEL's `governance_policy` evolves (an `Evl` on IEL changes who has governance authority), the operator should immediately submit a `Sea` on each dependent SEL to advance the live branch's tip `identity_event` forward to the new IEL `Evl`. This closes the window in which an adversary with revoked governance could submit a stale-bound `Cnt`/`Dec` extending the new branch tip — once the tip's `identity_event` is at the new Evl, any subsequent same-branch event must bind at-or-after the new Evl, so a regressed-binding event on that branch fails parent-monotonic.

This is an operator best practice, not a protocol-enforced rule. Future automation could auto-issue SEL Seas on IEL governance evolution, but is out of scope for v1 of this design.

### Application-developer enrollment patterns

Operationally, the brand-new SEL chain race (above, under §What parent-monotonic blocks) is bounded by enrollment: until a user has finished registering all required well-known SEL topics for their identity, the system treats them as inactive, and no consumers honor authorizations rooted in their in-progress chains. Application developers must structure enrollment to take advantage of this:

- **Register all required well-known SEL topics atomically.** Submit one batch per topic, with all topics together within the enrollment flow; do not partially-enroll a user.
- **For each topic, detect and resolve prior chain content.** If the chain at the derived prefix already exists with content the operator didn't author (a competing party with `auth_policy` authority on the bound IEL submitted `[Icp, Upd_stale]` first), enrollment submits `Rpr` (governance-authorized via the bound IEL's current `governance_policy`) extending the operator's legitimate `Upd`. `Rpr` archives the competing branch and the chain becomes the operator's. `Rpr` resolves the divergence cleanly because `governance_policy` is structurally a higher bar than `auth_policy` — the operator's current governance authority outranks any auth-only competing submission.
- **Treat the user as inactive until enrollment completes** (including any `Rpr` cleanup). During the inactive enrollment window, no consumers honor authorizations rooted in the in-progress chains; the user's chains gain trust grounding only after enrollment finishes.

This pattern eliminates the brand-new chain race as an authorization-bearing concern: a competing party's race-won v1 has no consumers honoring it during the inactive window, and `Rpr` archives it before the user becomes active.

## Multi-Party Governance Synchronization

For IEL chains with multi-party governance — an `auth_policy` or `governance_policy` that multiple parties can satisfy — races between concurrent submissions create divergence even when all parties are legitimately authorized. Two operators independently signing and submitting `Evl` events without coordination produces two events at the same version: divergence on IEL → contested-terminal immediately (every IEL event is privileged, so any divergent set on IEL fires the privileged-divergence rule).

**Synchronization above the protocol is load-bearing for high-stakes IEL identities.** For a federation's root identity that issues credentials to many nodes, an identity hierarchy's root, or any identity whose reincept would cascade through many dependent chains, accidental divergence kills the identity and forces operational reincept. Without synchronization, any race takes the identity offline. This is not an optional optimization for these cases — it's an operator-facing requirement.

Mitigation is a mechanism that serializes governance submissions so two parties don't reach the chain concurrently. Concrete options:

- **Designated submitter**: one party assembles signatures from the other governance parties offline, then submits the assembled event. Other parties don't submit directly.
- **Leader election among governance parties**: a primary submitter is designated; leadership transfers via out-of-band coordination when needed.
- **Sequential signing rounds**: parties sign in turn; the final signer submits.
- **Consensus protocol (e.g., Raft) over the registry**: the KELS reference federation deployment uses the Raft registry for this purpose. The registry's commit log serializes governance submissions to the federation's identity chain, so two operators committing concurrently are serialized by Raft before reaching the chain. See [../../registry.md](../../infrastructure/registry.md) for the registry architecture.

The choice of synchronization mechanism is operational, not protocol-level — the IEL's protocol rules apply uniformly regardless of how submissions are serialized. The pattern is **required for high-stakes IEL identities** and **strongly recommended for any IEL whose governance involves more than a single submitter**.

Note that synchronization protects against **accidental** races, not against **compromise**. A second governance-authorized party who acquired authority via threshold compromise can author submissions regardless of any synchronization mechanism — that threat is the same with or without synchronization. Defense against threshold compromise is operational hardening: high thresholds, geographic and organizational distribution of operators, custody discipline, monitoring for unexpected governance activity.

**Threshold redundancy** is the operator's per-anchor recovery option for partial compromise: an anchored policy with `M > N` identities tolerates loss of `M − N` while remaining satisfiable, and a new anchor using a different threshold-satisfying subset re-establishes authorization without changing the policy itself (see [../policy.md §Threshold Redundancy](../../features/policy.md#threshold-redundancy)).

## Trust Caveat — Recovered or Contested Anchoring KELs

The seal property and the anchoring model give *structural* guarantees against poisoning (policy immunity rule) and gossip races (terminal states are deterministic across nodes). They give *partial* guarantees when a participating KEL is later recovered, and *no* guarantees when a participating KEL has been contested.

`Rec` (recovery-after-divergence; distinct from proactive `Ror`) is by design evidence that the prior signing key was compromised. After `rec`, anchors made under that key **may or may not** survive: anchors on the branch the Rec extends stay (`rec` archives only the other branch); anchors on the now-archived branch do not.

Implications for IEL consumers (and transitively SEL consumers, since SEL binds to IEL events):

- An IEL `Evl` / `Cnt` / `Dec` whose policy was satisfied entirely by anchors on the surviving branch: re-verifies cleanly across `rec`. Past evaluation stands. SELs bound to that IEL event continue to verify under it.
- An IEL event whose satisfaction depended on anchors on the archived branch: may *fail* re-verification. SELs bound to that IEL event may also fail re-verification, since the upstream authorization is no longer satisfied.

This is observable, not hidden — the chain mathematics make the post-rec state visible. The consumer's runtime trust judgement is: when an anchoring KEL has `rec` history, re-verify the IEL and any SELs bound to it; treat past state with caution proportionate to what survives.

**A contested KEL is whole-chain-suspect.** Once a KEL has been contested (any privileged-divergence on it, or explicit Cnt), no anchors anchored under it can ground new trust decisions. This is stronger than the recovery case: under recovery, anchors on the surviving branch remain authoritative; under contest, the chain mathematics cannot tell which side is the rightful operator and consumers must treat all anchors on the chain as suspect. Past IEL and SEL evaluations that depend on a contested KEL lose their authorization basis. Cascade-reincept applies: the dependent IEL (and its dependent SELs) must reincept against a different anchoring KEL.

The caveat applies to anchors of any kind — IEL events (governance), and transitively SEL events that bind to them.

## Contest (Cnt)

Contest is the terminal state for IEL — reachable from divergence (any `Cnt` resolves a divergent chain to contested) or directly from active state (operator chooses to terminate).

### Authorization Asymmetry vs. KEL Cnt

KEL `Cnt` requires **dual signatures** — both signing key (preimage of prior `rotation_hash`) and recovery key (preimage of prior `recovery_hash`). IEL `Cnt` requires only `governance_policy` satisfaction; it does NOT separately require `auth_policy`. The asymmetry is structural, not arbitrary:

- KEL's signing key and recovery key are **independent cryptographic primitives**. Neither structurally encompasses the other; both must be exercised together to prove dual control. Hence dual-signature on terminal events.
- IEL's `governance_policy` is a **policy** — a composable predicate that can be crafted to be inclusive of `auth_policy`. A properly-designed IEL has `governance_policy` that subsumes `auth_policy` (any party who could satisfy `auth_policy` can also satisfy `governance_policy`, but not vice versa). Hence single-policy gate on terminal events: governance is the higher bar and inclusion of auth is a chain-design property.

If an IEL is misconfigured such that `governance_policy` does NOT subsume `auth_policy` (i.e., a party authorized to write under `auth_policy` cannot terminate under `governance_policy`), that's a chain-design error — not a case the kind structure should defend against. The design assumes the immunity rule plus a sane policy hierarchy; chains that violate that hierarchy are operating outside the supported model.

The symmetry of *intent* — terminal authority assertion — is preserved on both sides. The mechanism differs because the underlying primitives differ. Same logic applies to SEL `Cnt` (see [../sel/events.md](../sel/events.md)).

### Server semantics

- Verify `Cnt`'s structure, governance authorization.
- Insert `Cnt`. **No archival** — both branches preserved if divergent; single branch preserved if linear.
- Any `Cnt` event in the chain → `is_contested = true`. All future submissions rejected with `ContestedIel`.
- Effective SAID for a contested chain: deterministic, cross-node consistent.

### Builder

`IdentityEventBuilder::contest()`:
- Pre-flight: full chain re-verification.
- Bundles pending events into the batch (mirrors SEL).
- Builds `Cnt.previous = v_{tip-1}.said` — the parent of the chain's current tip on a linear chain (creates fresh divergence at `v_N`), or `v_{d-1}` on a divergent chain (the divergence ancestor; on IEL both divergent branches are single-event at `v_d` by construction, so each branch's `v_{tip-1}` is `v_{d-1}`; same rule, different chain shape). The lower-SAID tip-selection logic is no longer needed — `v_{tip-1}` is well-defined: there is one parent of the linear-chain tip, and one shared ancestor of any divergent set.
- Resolves authorization via `v_{tip-1}`'s `governance_policy` and constructs the anchor accordingly.

### Cascading effect on dependent SELs

A contested IEL freezes the IEL. SELs bound to the contested IEL face ambiguous future authorization: the IEL has no path forward, so SEL's tracked `auth_policy` and tracked `governance_policy` are effectively frozen at whatever was current when IEL contested.

Operator response per SEL:
- **Migrate**: incept a new SEL bound to a different IEL.
- **Decommission**: end the SEL via `Dec`.
- **Contest**: if the SEL itself is contested in the same incident, `Cnt` it.

These are operator decisions, not protocol-enforced. The federation continues operating: SELs can still be read; they just cannot be advanced if the IEL is contested.

## Decommission (Dec)

Decommission is the clean terminal state for owner-initiated identity end. Same shape as SEL `Dec` and same governance authorization.

### Cascading effect on dependent SELs

Same as `Cnt`: SELs bound to a decommissioned IEL face frozen authorization. Operator chooses migrate/decommission/contest per chain.

## Server-Observable Case Taxonomy

When the merge engine processes a submitted batch (full routing logic in [merge.md](merge.md); the exhaustive per-state × per-kind matrix and the multi-node source→sink correctness proof are in [reconciliation.md](reconciliation.md); summarized here for lifecycle correlation):

| State observed | Batch content | Outcome |
|---|---|---|
| Linear, normal append | `Evl` | Append. Seal advances. |
| Linear (active) | `Cnt` (`previous = v_{N-1}.said`) | Insert; creates divergence at `v_N` (existing tip + Cnt); privileged-divergence rule fires; chain becomes contested-terminal. |
| Linear, overlap (fork) | concurrent `Evl` | Insert second event at `v_d`; chain becomes contested-terminal (every IEL event is privileged → privileged-divergence rule fires). |
| Divergent | `Cnt` (`previous = v_{d-1}.said`, joins divergent set via upgrade rule) | Insert as 3rd event at `v_d`; chain stays contested-terminal. |
| Divergent | any other event | Rejected; chain is contested-terminal. |
| Linear, post-evaluation-seal | `Evl` extending pre-seal version | Rejected by seal-cap (cannot fork at or before the seal). |
| Any non-terminal | `Dec` | Append at tip; mark decommissioned. |
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
- [../sel/event-log.md](../sel/event-log.md) — SEL counterpart; SELs bind to IEL events.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference.
- [../policy.md](../../features/policy.md) — Policy DSL, anchoring model, immunity rule.
- [../kel/event-log.md](../kel/event-log.md) — KEL counterpart.
