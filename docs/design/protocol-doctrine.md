# Protocol Doctrine

The structural rules that govern KELS — security invariants, cross-cutting doctrines, and verification mechanics. Each part below is load-bearing for protocol correctness; per-primitive design docs cross-reference these as the upstream source rather than re-deriving them.

**[Part 1 — Security Invariants](#part-1-security-invariants):**
- [Terminology](#terminology) — Locked, Chain states (Active/Divergent/Decommissioned/Contested), Cross-chain anchor satisfaction.
- [Operation Categories](#operation-categories)
- [Compromise is Permanent](#compromise-is-permanent) — the doctrine, and the structural mechanisms that enforce it:
  - [Forks are Seal-Bounded](#forks-are-seal-bounded)
  - [Per-Event Parent-Monotonic Ratchet (SEL-specific)](#per-event-parent-monotonic-ratchet-sel-specific)
  - [Privileged Divergence is Terminal](#privileged-divergence-is-terminal)
  - [One Divergent Generation at a Time](#one-divergent-generation-at-a-time)
  - [Anchor Tier Elevation](#anchor-tier-elevation)
  - [Trust Model on Contested Chains](#trust-model-on-contested-chains)
  - [Limit of the Doctrine](#limit-of-the-doctrine)

**[Part 2 — Cross-Cutting Doctrines](#part-2-cross-cutting-doctrines):**
- [Ordering Without Timestamps](#ordering-without-timestamps)
- [Federation Convergence](#federation-convergence)
- [Extension Discipline](#extension-discipline)

**[Part 3 — Verification Mechanics](#part-3-verification-mechanics):**
- [Verification tokens as proof of verification](#verification-tokens-as-proof-of-verification)
- [Streaming](#streaming)
- [Merge Verification](#merge-verification)
- [Inline reference checking](#inline-reference-checking)
- [Verifier and merge are distinct treatments](#verifier-and-merge-are-distinct-treatments)
- [policy_satisfied](#policy_satisfied)
- [Advisory Locking](#advisory-locking)
- [Effective-SAID synthetic comparison](#effective-said-synthetic-comparison)

---

## Part 1: Security Invariants

The invariants below are load-bearing for KELS security. They are stated structurally rather than statistically: the protocol's safety claims hold *by construction*, not by observation. Verifier implementations enforce them on every walk; an event or chain state that violates them is rejected, regardless of source.

### Terminology

Structural concepts referenced throughout the doctrine. Distinct senses; not interchangeable.

- **Locked**: the portion of a chain before its most recent privileged event. **Within-chain rule.** Locked events are structurally immutable within their own chain — `Rec` (KEL) and `Rpr` (SEL) on this chain cannot target them, and within-chain historical authorizations are not retroactively unsatisfiable. The privileged event ratchets the lock forward. This subsumes the historical-immutability sense used elsewhere in the corpus (e.g., "the chain's history at that serial is locked") — both phrasings describe the same boundary from different angles.
- **Chain states**: a chain is in exactly one of four states. State names are used precisely throughout the doctrine.
  - **Active** — linear chain; accepts linear extension.
  - **Divergent** (non-privileged divergence only) — multiple branches at the same serial; the divergent set contains only non-privileged events (Ixn-Ixn on KEL; Upd-Upd on SEL). Recoverable via `Rec` (KEL) / `Rpr` (SEL) — returns to Active. A joining privileged event upgrades the chain to Contested.
  - **Decommissioned** — linear `Dec` has landed. Fully terminal: accepts no submissions of any kind. Federation-race convergence with concurrent competing privileged events is handled at the infrastructure layer (see [§Limit of the doctrine — concurrent privileged event races](#concurrent-privileged-event-races)).
  - **Contested** — privileged-divergence-is-terminal has fired (a divergent set contains a privileged event). Fully final — no event of any kind lands.
- **Cross-chain anchor satisfaction**: an IEL/SEL event's policy satisfaction at consumer-query time is structurally checked against contributing KEL anchors. If a contributing KEL `Rec` lands and archives the event that carried the anchor, the KEL verifier reports the SAID as not-anchored on the canonical branch; the IEL/SEL's `policy_satisfied` flips false. **Distinct from within-chain state** — locked IEL/SEL events remain structurally locked within their own chains; cross-chain anchor satisfaction is a structural verification concern handled by composition redundancy (anchor count above exact threshold). See [§Anchor Tier Elevation §Threshold Composition](#threshold-composition).

### Operation Categories

The database cannot be trusted — it may have been altered. All operations on chain data (KEL, IEL, SEL) fall into three categories:

#### 1. Serving

Returning data to a client or peer. **No verification needed** — the receiver is responsible for verifying what they get.

Examples: `GET` endpoints serving event pages (per-primitive: `kel/:prefix`, `iel/:prefix`, `sel/:prefix`), effective-SAID lookups, paginated event reads.

#### 2. Consuming

Using data for security decisions (anchoring, key extraction, divergence routing, merge decisions). **MUST verify the full chain first.** The only way to access consumed data is through the corresponding verification token (`KelVerification`, `IelVerification`, `SelVerification`), which can only be obtained via that primitive's verifier (`KelVerifier`, `IelVerifier`, `SelVerifier`). This eliminates TOCTOU vulnerabilities — verification and data access happen in the same pass.

Examples: peer signature verification on a KEL, anchor checking on a KEL, governance-policy resolution on an IEL at a given serial, SEL `ielEvent` resolution, submit-handler routing decisions on any primitive.

#### 3. Resolving

Comparing state to decide whether to sync. A wrong answer triggers an unnecessary sync (which itself verifies), not a security hole. Standalone functions are acceptable here without full verification.

Examples: effective-SAID endpoints (per-primitive), anti-entropy comparison, KEL proactive-rotation prechecks (`should_add_rot_with_recover()`).

### Compromise is Permanent

The protocol grants authority **only to the chain's current state** (and the chain's most-recent shared pre-divergence state, where divergence has occurred). Past keys, past policies, past endorsers — anything that was once authorized but has since been rotated, revoked, or evolved out — has zero structural ability to act on the chain. Per primitive:

- **KEL:** a key compromised in 2023 cannot `Dec` the chain in 2026 — or extend it at all — even if the adversary still holds the key material.
- **IEL:** a `governancePolicy` participant revoked via `Evl` cannot land further governance acts on the chain after their revocation.
- **SEL:** an SEL bound to a stale IEL event whose governance has since rotated cannot be `Dec`'d by the rotated-out parties — subject to operator-side ratcheting via `Sea` to advance the SEL's tracked `ielEvent` to the post-rotation IEL state.

This closes the **stale-state kill-switch problem**. Without this rule, every party who ever held authority over a chain would retain protocol-level kill-switch authority over it forever, and any past compromise would become a permanent vulnerability. With this rule, past compromise is structurally a non-event for protocol authority.

#### Forks are Seal-Bounded

The structural mechanism that enforces "current-state-only authority" is the chain's evaluation/recovery seal:

Each primitive tracks `lastSealAdvancingEvent` — the SAID of the chain's most recent privileged-or-archiving non-terminal event. The advancing kinds differ:

- **KEL**: `Rec`/`Ror`/`Rot`.
- **IEL**: `Evl`.
- **SEL**: `Sea`/`Rpr`.

The terminal kind (`Dec` everywhere) enforces the seal but does not advance it.

KEL additionally tracks `lastRecoveryRevealingEvent` (`Rec`/`Ror`/`Dec`) for the spent-key / immunity rule and for the Ror cap. This is a distinct concept from the seal — the seal-advancing kinds (`Rec`/`Ror`/`Rot`) bound chain-state changes, while the recovery-revealing kinds (`Rec`/`Ror`/`Dec`) bound how stale a tracked recovery-key commitment can become. See [primitives/data/event-logs/kel/event-log.md §Seal and Key Non-Poisonability](primitives/data/event-logs/kel/event-log.md#seal-and-key-immunity).

A new event's parent MUST sit at-or-after the seal (`parent_serial >= seal_serial`). Since `event_serial = parent_serial + 1`, this is equivalently `event_serial > seal_serial` — the event lands strictly after the seal-defining event. Any submission whose parent sits in the locked portion (`parent_serial < seal_serial`) is rejected (`"Cannot extend serial V — parent in locked portion behind seal at serial S"`). This guarantees the auth context resolved at the event's parent is the chain's currently-tracked policy / key state — not a stale one, and that no event lands at the seal-defining event's own serial.

**Bounds on the post-seal window per primitive:**

- **KEL**: two parallel caps. The **seal-advance cap** bounds the chain at `MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events between privileged-or-archiving events (`Rec`/`Ror`/`Rot`). The independent **Ror cap** bounds at 512 events between recovery-revealing events (`Rec`/`Ror`/`Dec`), holding recovery-key-preimage staleness in check. Both numbers are protocol constants — `MINIMUM_PAGE_SIZE` is a deployment floor, not a per-deployment knob, so a recovery batch produced on any conformant deployment fits in any other's single page. See [primitives/data/event-logs/kel/events.md §Two parallel caps](primitives/data/event-logs/kel/events.md#two-parallel-caps).
- **IEL**: no protocol cap — every non-terminal IEL event advances the seal, so the seal coincides with the tip on linear chains and within-window forks don't structurally exist. The "how stale can authority become" bound is operator-side discipline.
- **SEL**: protocol-bounded at `MINIMUM_PAGE_SIZE − 2 = 62` non-seal-advancing events via the **seal-advance cap** (`Est` at v=1; `Sea` or `Rpr` thereafter). Combined with SEL's per-event parent-monotonic ratchet on `ielEvent`, this prevents stale-IEL-policy holders from extending an existing branch with a regressed binding. The `− 2` headroom accommodates a `[Rpr, Sea]` atomic repair-and-resealing batch in one `MINIMUM_PAGE_SIZE`-bounded page on every conformant deployment.

The SEL-specific ratchet that the bound composes with lives at [§Per-Event Parent-Monotonic Ratchet (SEL-specific)](#per-event-parent-monotonic-ratchet-sel-specific) below.

#### Per-Event Parent-Monotonic Ratchet (SEL-specific)

SEL is the only primitive where authorization context is referenced via a separate field (`ielEvent`) pointing at another chain. KEL and IEL have no analog — they resolve authorization from commitments/policy intrinsic to their own chain at the event's parent (`previous`), so there's nothing for a per-event monotonic check to compare across.

Each SEL event's `ielEvent` must be at-or-after its parent event's `ielEvent` in IEL chain order, applied per branch independently. A new branch's `ielEvent` is constrained only by its branch parent (the divergence ancestor on a fork-contest); branches with different parent-chains don't constrain each other.

**Consequence on divergent SEL chains.** Branches may reference different IEL events at the same SEL serial, and thus may resolve to different governance/auth policies on each branch. This within-chain policy variation is bounded by two rules: the seal-cap bounds where divergence can occur, and privileged-divergence-is-terminal bounds what state divergence can resolve to (any privileged event in the divergent set forces contested-terminal). KEL and IEL never have within-chain policy variation — KEL's authorization is intrinsic to its own commitments, and every IEL event is governance-authorized so any divergence is immediately contested.

#### Privileged Divergence is Terminal

The protocol's terminal-authority mechanism is three composable rules. Read them in order: rule 1 defines what "privileged divergence" means and when the chain terminates; rule 2 specifies the structural conditions on repair events (`Rec`/`Rpr`); rule 3 ensures cross-node consistency when privileged events land via gossip.

**1. Privileged-divergence-is-terminal.** Divergence at a serial where the divergent set contains at least one privileged event makes the chain immediately and terminally contested. Privileged events differ per primitive:

- **KEL privileged-or-archiving**: `Rot`, `Rec`, `Ror`, `Dec`. The privileged subset (`Rot`, `Ror`, `Dec`) triggers privileged-divergence-is-terminal; the archiving event (`Rec`) routes through the discriminator. The recovery-revealing sub-class (`Rec`, `Ror`, `Dec`) is dual-signed and gates the Ror cap; `Rot` is single-signed and seal-advancing but not recovery-revealing.
- **IEL privileged**: every event kind — `Icp`, `Evl`, `Dec` (all governance-authorized including `Icp`). The chain cannot be contested before its inception; the rule is structurally vacuous at `Icp` itself but applies uniformly to any divergence post-inception.
- **SEL privileged-or-archiving**: `Est`, `Sea`, `Rpr`, `Dec`. The privileged subset (`Est`, `Sea`, `Dec`) triggers privileged-divergence-is-terminal; the archiving event (`Rpr`) routes through the discriminator. `Est` is privileged at v=1 (tier-2 anchored, governance-authorized seal-advance — see [§Anchor Tier Elevation](#anchor-tier-elevation)).

The privileged-divergence-is-terminal transition is reachable by any privileged event landing in a divergent set; there is no protocol-level termination event distinct from the rest of the privileged set. Archiving events (`Rec`/`Rpr`) route through the discriminator before any divergent-set check fires — they resolve rather than create divergence.

**2. Repair-event conditions.** Two structural conditions apply to repair events — `Rec` (KEL), `Rpr` (SEL) — at the merge layer. They are data-driven (no receiver-state dependency), uniform across primitives with per-primitive instantiations.

2a. **Hard auth at landing.** Governance / signature check hard-fails on rejection at the merge layer; no soft-fail.
   - **KEL Rec**: dual-signed. `publicKey` preimage matches the parent's `rotationHash`; `recoveryKey` preimage matches the parent's `recoveryHash`. Both signatures verify; both digest commitments match.
   - **SEL Rpr**: governance evaluation against the bound IEL event's tracked `governancePolicy` hard-passes threshold. Repair-event SAID is anchored by a tier-3 KEL `Ror` per contributing governance member.
   - Authority concurrence is a moment-in-time question; "submit and satisfy later" does not generalize from cross-chain content references (which can resolve later because content is fetchable) to authority-tier checks.

2b. **Repair-event `previous` must not be in the locked portion.** `previous.serial ≥` the serial of the most recent seal-advancing event on the chain (any branch — privileged or archiving). The repair event's own serial = `previous.serial + 1`.
   - **KEL**: seal-advancing events are `Rot`, `Rec`, `Ror`, `Dec`. Subject to the bound: `Rec`.
   - **SEL**: seal-advancing events are `Est`, `Sea`, `Rpr`, `Dec`. Subject to the bound: `Rpr`.
   - **IEL**: no repair events exist on IEL (no `Rec`/`Rpr`). The bound is vacuous on IEL.
   - If no privileged event has landed (only `Icp` + non-privileged events), the bound holds vacuously — the repair event's `previous` can be any chain event including `Icp`.

**Semantic intent.** The honest construction of a repair event extends its submitter's local tip. A legitimate submitter wouldn't insert events into their own stream from anywhere else, and wouldn't accept adversarial events into their stream and append on top of those (that would imply trust in the adversary's events). Chain data cannot identify a submitter or distinguish "honest extension of submitter's tip" from "adversarial extension of an injected fake-tip" — the protocol has no notion of identity at the chain layer. Condition 2b restricts allowed constructions to those that *could* be honest tip-extensions: anything with `previous` in the chain's locked portion is structurally incompatible with extending a current legitimate tip and is denied.

The bound prevents revival attacks: a party holding stale authority (e.g., a recovery preimage revealed by an earlier `Rec`/`Ror`, or a revoked governance member whose old policy SAID remains immune-resolvable) cannot construct a repair event against an old authority position to rearrange the chain. Only current authority gates repair events. See [§Terminology](#terminology) for the locked-portion concept.

When a repair event's `previous` is the divergence ancestor (`v_{d-1}`), `Rec`/`Rpr` land at `v_d`. This shape is cross-node-validatable: `v_{d-1}` is structurally shared across all nodes (it lands cleanly before any divergence), so the repair event validates uniformly regardless of which divergent contents each node received. This is what solves the cross-node propagation problem that breaks tip-extension and combined-digest approaches.

**3. Upgrade rule (cross-node consistency).** Applies to privileged events with `previous = v_{d-1}.said`: `Rot`, `Ror`, `Dec` on KEL; `Est`, `Sea`, `Dec` on SEL; n/a on IEL (every event is privileged, so no non-privileged divergent set can form to upgrade). When a node has a non-privileged divergent set at `v_d` and gossip delivers such a privileged event for that same `v_d`, the node accepts the privileged event as a third event in the divergent set. Local state transitions from non-privileged-divergent (recoverable) to contested (terminal). Without this rule, different nodes that received different subsets of concurrent submissions would converge on different chain states.

The divergence invariant relaxes to allow up to 3 events at `v_d` when **exactly one** is privileged — the upgrade event. **3 events with 2+ privileged is structurally unreachable**: any privileged event in the original 2-event divergent set triggers privileged-divergence-is-terminal immediately, and the contested-state gate rejects any subsequent submission. Only when the original 2 events are both non-privileged does the upgrade-rule path open to add a 3rd privileged event.

##### Two parent shapes for archiving recovery events

KEL `Rec` and SEL `Rpr` resolve divergence by archiving events via the discriminator. They each take two parent shapes, named by what `previous` points at:

- **Branch-tip-extending shape** — `Rec.previous` / `Rpr.previous` is a branch tip at `v_d`. Rec/Rpr extends that branch at `v_{d+1}`; the other branch is archived.
- **Divergence-ancestor-extending shape** — `Rec.previous` / `Rpr.previous` is `v_{d-1}`, the divergence ancestor. Rec/Rpr lands at `v_d`; ALL events at `serial >= d` (both branches) are archived. Rec/Rpr is the only event at `v_d` after the discriminator runs.

##### Privileged and archiving event classes

Privileged events route by kind in the merge engine, so the upgrade rule's scope is well-defined and the rules above don't conflict with one another:

- **Archiving kinds** — `Rec` (KEL), `Rpr` (SEL). Go through the discriminator's archival path. Either parent shape (branch-tip-extending or divergence-ancestor-extending — see preceding subsection) bypasses the upgrade rule, since the discriminator removes the divergent set before any divergent-set check fires.
- **Privileged kinds** — `Rot`, `Ror`, `Dec` on KEL; `Est`, `Sea`, `Dec` on SEL. Do not archive. When their parent is `v_{d-1}.said` (the divergence ancestor) and a non-privileged divergent set already exists at `v_d`, they join the divergent set as a third event via the upgrade rule, triggering contested via rule 1. They reach this shape when the submitter's local tip is at `v_{d-1}` and they extend it directly with `previous = tip.said`; the event lands at `v_d`.

The verifier rule simplifies to:
- Divergent at `v_d`?
  - No → linear (active or terminal-via-Dec).
  - Yes → privileged event in the divergent set?
    - Yes → contested (terminal).
    - No → divergent (recoverable via Rec on KEL or Rpr on SEL; no recovery primitive on IEL — divergent IEL is auto-contested because every IEL event is privileged).

##### Worked scenarios — contested-state creation

A privileged event (`Rot`/`Ror`/`Dec` on KEL; `Est`/`Sea`/`Dec` on SEL) landing in a divergent set fires privileged-divergence-is-terminal. The submitter constructs the event with `previous = v_{d-1}.said` and `serial = d`; the event lands at `v_d`. Cross-node propagation works because `v_{d-1}` is structurally shared (it lands cleanly before any divergence). Three scenarios cover the common space.

*Scenario 1 — Privileged event on a linear chain.* Submitter's local tip is at `v_{d-1}`; the existing chain's highest-serial event is `v_d`. Submitter constructs a privileged event with `previous = v_{d-1}.said` and `serial = d`; the event lands at `v_d` as a sibling of the existing event:

```
  Pre-state:        ... → v_{d-1} → v_d  (existing event at v_d)

  Construction:     evt.previous = v_{d-1}.said
                    evt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ existing @ v_d  ┐
                                   └─ evt      @ v_d  ┴── contested (evt privileged)
```

*Scenario 2 — Privileged event joins an already-divergent set.* A non-privileged divergent set exists at `v_d` (e.g., ixn-ixn race on KEL). The pre-existing branch may have extended past `v_d` before divergence was observed (KEL: ≤62 events per the seal-advance cap; SEL: ≤62 per the seal-advance cap; IEL: never — divergence is contested-terminal at first observation). The new (divergence-causing) branch is always single-event at `v_d`. The submitter's event extends `v_{d-1}` (the unique parent at `serial − 1`, shared cross-node by chain validity):

```
  Pre-state:        ... → v_{d-1} ─┬─ ixn_a @ v_d → ixn_a' @ v_{d+1} → …  (pre-existing; may extend)
                                   └─ ixn_b @ v_d                         (new; single event on the divergent branch)

  Construction:     evt.previous = v_{d-1}.said
                    evt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ ixn_a @ v_d → ixn_a' @ v_{d+1} → …  ┐
                                   ├─ ixn_b @ v_d                         ├── contested
                                   └─ evt   @ v_d                         ┘
```

*Scenario 3 — Sequential post-event contest.* An `ixn_a` lands at `v_d` on Node A. Gossip propagates `ixn_a` to Node C; Node C's chain now has `ixn_a` at `v_d`. Node C's submitter, whose local view of the tip was still at `v_{d-1}` (or who chooses to extend the divergence ancestor), constructs a privileged event with `previous = v_{d-1}.said` and `serial = d`:

```
  Final state on Node C:
                    ... → v_{d-1} ─┬─ ixn_a @ v_d  ┐
                                   └─ evt   @ v_d  ┴── contested
```

In every scenario: the event's `previous` is the divergence-ancestor `v_{d-1}` (the unique parent at `serial − 1` — shared cross-node by chain validity), and the event lands at `v_d`. The repair-event bound (condition 2b) applies to `Rec`/`Rpr` and is enforced on KEL/SEL by the seal-cap; privileged events reach the `v_{d-1}`-extending shape when the submitter's local tip is at `v_{d-1}` and they extend it directly with `previous = tip.said`.

##### Repair-event authorization

Authorization for a repair event (`Rec` on KEL, `Rpr` on SEL) resolves through the commitments at the event's parent (`previous`).

- **KEL.** The dual signature is produced under the private signing and recovery keys whose public-key preimages are committed by the parent event's `rotationHash` and `recoveryHash`. Revealing the public-key preimage via a prior event landing at the parent's child serial does not yield the corresponding private key; signing capability remains submitter-held.
- **SEL.** The IEL-resolved governance policy at the SEL's `ielEvent` binding for the parent event (`Rpr.previous`).
- **IEL.** No repair events on IEL — see §Repair-event absence below.

Repair-event authorization is **HARD** at the merge layer per condition 2a. **General invariant: any event with failed auth is rejected.** A repair event (or `Dec`) whose dual-signature, governance-anchor, or IEL-resolved-policy check fails is rejected by the merge handler; the chain stays at its prior state. The DB-cannot-be-trusted invariant requires this — an unauthorized terminal must not advance the chain locally. See [§Verifier and merge are distinct treatments](#verifier-and-merge-are-distinct-treatments) for how the verifier's soft-fail composition is hardened at the merge layer.

**Recourse against signing-key-only Rot takeover (KEL specifically)**: an adversary holding the signing key plus the rotation-key preimage at `v_N` (revealing their `Rot` at `v_N`) does not hold the recovery-key preimage committed by the prior establishment's `recoveryHash`. A `Rec` (branch-tip-extending on a divergent chain, or divergence-ancestor-extending where the divergence ancestor's commitments are still legitimate) — subject to the locked-portion bound (condition 2b) — resolves dual-sig against the parent's commitments; the legitimate party's recovery-key preimage satisfies, the adversary's does not. See [primitives/data/event-logs/kel/event-log.md §Recourse against signing-key-only Rot takeover](primitives/data/event-logs/kel/event-log.md#recourse-against-signing-key-only-rot-takeover) for the key-state walkthrough.

From the moment a contested transition occurs (a privileged event lands in a divergent set), no further events on this chain are accepted.

##### No dedicated termination-by-contest event

No primitive has a dedicated termination-by-contest event distinct from the rest of the privileged set. The event taxonomies are:

- **KEL**: `Icp`, `Dip`, `Rot`, `Ixn`, `Rec`, `Ror`, `Dec`.
- **SEL**: `Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Dec`.
- **IEL**: `Icp`, `Evl`, `Dec`.

Structural reasoning: chain data alone cannot distinguish a legitimate submitter from an adversary with equivalent authority. A protocol primitive justified by reference to submitter intent ("the legitimate operator's terminate-with-prejudice signal") is structurally incoherent — chain layer has no identity concept, so identity framing cannot land in a primitive. The only structurally valid question is whether a dedicated termination event creates a chain-state effect that no other event produces. It does not: the contested-state transition (privileged divergence at `parent.serial + 1` → contested via privileged-divergence-is-terminal) is reachable by any privileged event landing in a divergent set.

**Chain lifecycle paths:**

- **Termination via clean shutdown**: `Dec`.
- **Termination via contested transition**: any privileged event (`Rot`/`Ror`/`Dec` on KEL; `Est`/`Sea`/`Dec` on SEL; `Evl`/`Dec` on IEL) landing in a divergent set fires privileged-divergence-is-terminal. See §Worked scenarios above.
- **Recovery from non-privileged divergence**: `Rec` (KEL) or `Rpr` (SEL).
- **Recovery from privileged divergence**: impossible per privileged-divergence-is-terminal; chain is Contested.

On IEL specifically, every event is privileged so the contested chain state is equivalent to the divergent chain state — `is_contested ⇔ is_divergent`; any IEL divergence is contested-terminal by construction. The full structural argument lives in [primitives/data/event-logs/iel/event-log.md §Divergence is Contested-Terminal](primitives/data/event-logs/iel/event-log.md#divergence-is-contested-terminal).

**Pre-emptive-suspicion gap (acknowledged).** A submitter who detects compromise pre-emptively (e.g., a contributing KEL was breached) and wants to mark a chain as suspect without retiring it has no protocol-level "compromise signal." Available paths: rotate out the compromised key via `Rot` (KEL) or `Evl` (IEL) (chain stays alive, no compromise signal); `Dec` (clean retirement — semantically misleading when compromise is the actual cause); out-of-band attestation under a separate KEL (requires a parallel discovery channel). This trade-off is accepted; the protocol's terminal and recourse paths remain intact.

<a id="concurrent-privileged-event-races"></a>

##### Limit of the doctrine — concurrent privileged event races

Concurrent privileged event races between federation peers do not structurally converge at the protocol layer. This covers all shapes — between archiving repair events (`Rec` on KEL, `Rpr` on SEL), between privileged events (`Rot`/`Ror`/`Dec` on KEL, `Est`/`Sea`/`Dec` on SEL, `Evl`/`Dec` on IEL), and mixed (`Dec`-vs-`Ror`, `Dec`-vs-`Rot`, etc.). Once a privileged event lands at `v_d` on a node, that node's seal advances and any competing submission whose parent sits at-or-before `v_{d-1}` is rejected by the seal-cap. Different nodes that received different "first" submissions end up on different terminal SAIDs.

Federation-level convergence for these races is provided at the infrastructure layer via a contested-prefix table that nodes maintain and gossip-sync; see [#205](https://github.com/jasoncolburne/kels/issues/205) for the design.

This is a deliberate trade-off. The seal-cap and locked-portion bound prevent stale-authority chain rearrangement: a party holding past-position private keys must not be able to land an event targeting the locked portion at any future time. Relaxing the bounds to admit competing privileged events at a sealed serial would re-open that long-tail killswitch surface. The bounds stay unconditional; federation-race non-convergence for concurrent privileged submissions is accepted as a residual and resolved out-of-protocol.

If an adversary compromises all three key tiers on a KEL (signing + rotation + recovery), or compromises threshold-many full-tier KELs on an IEL governance policy, the chain is structurally owned by the adversary and the protocol provides no recovery primitive. Defense lives in policy composition — IEL governance policies should require threshold-many distinct custody domains, so full compromise of any one domain leaves the policy threshold intact. See [§Limit of the Doctrine](#limit-of-the-doctrine) for the broader treatment of current-state compromise.

##### Pre-divergence verifiability survives contestation

A contested chain preserves the structural verifiability of every event at-or-below `lastSealAdvancingEvent` on the chain's pre-divergence linear portion at the time of contestation. The seal-cap and locked-portion bound prevent any event — on any branch, at any future point — from rearranging or invalidating events at-or-below that seal serial. The pre-seal portion is permanently final.

This means a contested chain remains useful as a verification surface for everything sealed before the contest fired:

- **Anchors hosted at-or-below the seal** stay anchored. A KEL `Ixn` that anchored an IEL event below the seal stays a valid attestation. A tier-1 (`Ixn`) anchor hosted between the seal and the divergence point is NOT durable — it could have been authored under captured signing-key capability and is not structurally distinguishable from adversary work. Such anchors become durable only when a subsequent privileged event seals them.
- **Credentials issued under an IEL state at-or-below the seal** remain verifiable. An issuance pinned to an IEL event that sits at-or-below the IEL's `lastSealAdvancingEvent` can still be checked against the IEL state at that event — the chain segment used for verification is structurally immutable.
- **SELs bound to a pre-seal `ielEvent`** stay trust-evaluable for their bound IEL state. The `IelDivergent` rule (per [primitives/data/event-logs/sel/events.md](primitives/data/event-logs/sel/events.md)) enforces this by accepting only bindings where `bound_event.serial <= bound_iel.lastSealAdvancingEvent.serial` AND `bound_event.serial < first_divergent_serial` — both conditions must hold.
- **Audit and forensic queries** on a contested chain produce truthful, structurally-grounded answers about state at-or-below the seal. Above-seal-below-divergence events appear in the forensic record but are not structurally trustworthy.

**Why the boundary is the seal, not the divergence point.** A tier-1-only extension between `lastSealAdvancingEvent` and the divergence point could be authored under captured signing-key capability without legitimate auth context. Events at-or-below the seal were authored under at-least-tier-2 auth (each seal advance is privileged or archiving — both classes require tier-2 or tier-3 capability), which the protocol accepts as structurally valid sealing-level auth regardless of submitter. Events above the seal have only tier-1 auth context, which is not structurally distinguishable from adversary capture. The seal is the boundary the protocol can defend; the divergence point is observationally later but not structurally stronger.

This is the consumer-side complement of [§Compromise is Permanent](#compromise-is-permanent). The "past authority cannot act" rule + the locked-portion bound together mean: once a chain segment sits at-or-below the seal, it is final — for the chain itself (no further events target it) AND for consumers (they can verify against it indefinitely).

The verifier signals this via `policy_satisfied`: queries against SAIDs anchored at-or-below the seal AND below `first_divergent_serial` return `policy_satisfied = true` even on contested chains; queries against SAIDs above the seal — whether below the divergence point or post-divergence — return `policy_satisfied = false`. The boundary is the seal at the time of contestation, not the divergence point.

#### Event-class taxonomy

The protocol's events fall into orthogonal axes: **class** (chain-state effect when landing in a divergent set) and **tier** (key material required to forge the anchor). The table below names every event kind across all three primitives; the structural pattern that emerges is cited from elsewhere in the doctrine.

| Chain | Event | Class | Tier | Anchor relationship |
|-------|-------|-------|------|---------------------|
| KEL | `Ixn` | content | 1 | hosts tier-1 anchors |
| KEL | `Rot` | privileged | 2 | hosts tier-2 anchors |
| KEL | `Ror` | privileged | 3 | hosts tier-3 anchors |
| KEL | `Rec` | archiving | 3 | — |
| KEL | `Dec` | privileged | 3 | — |
| IEL | `Icp` | privileged | 2 | requires `Rot` per member |
| IEL | `Evl` | privileged | 2 | requires `Rot` per member |
| IEL | `Dec` | privileged | 3 | requires `Ror` per member |
| SEL | `Icp` | content | — | unanchored (permissionless) |
| SEL | `Est` | privileged | 2 | requires `Rot` per member |
| SEL | `Upd` | content | 1 | requires `Ixn` per member |
| SEL | `Sea` | privileged | 2 | requires `Rot` per member |
| SEL | `Rpr` | archiving | 3 | requires `Ror` per member |
| SEL | `Dec` | privileged | 3 | requires `Ror` per member |

**Legend.**

- **Class.** Chain-state effect on the event's own chain.
  - **Content** — does not advance the seal; landing in a divergent set leaves the chain in a non-privileged-divergent state recoverable via the chain's archiving primitive (`Rec` on KEL, `Rpr` on SEL).
  - **Privileged** — advances the seal; landing in a divergent set fires privileged-divergence-is-terminal (contested-terminal).
  - **Archiving** — advances the seal AND archives the discriminator-losing branch when landing in a divergent set. The archiving-precedence rule fires the discriminator BEFORE the divergent-set check, so archiving events resolve rather than create divergence.
- **Tier.** Key material required to forge.
  - For KEL events: which preimages the event reveals (1: signing key only; 2: + rotation preimage; 3: + recovery preimage; tier-3 KEL events are dual-signed).
  - For IEL/SEL events: tier of KEL anchor required per contributing policy member.
- **SEL `Icp`** is the only unanchored event — permissionless, dedup-equivalent across submitters; the v=1 `Est` in the same inception batch carries the actual binding and authorization.

**Structural pattern.**

- All **privileged** events sit at tier 2 or 3.
- All **archiving** events sit at tier 3 (exclusively).
- All **content** events sit at tier 1 (or unanchored for SEL `Icp`).

Tier 1 is content exclusively. Tier 2 is privileged exclusively. Tier 3 is mixed (privileged + archiving). The pattern reflects two facts: lower tiers don't carry chain-state-effecting authority, and archival operations cryptographically require the recovery preimage (tier 3).

**Tier and class are independent axes** — the table's cell population happens to align (tier-1 always content, tier-2 always privileged, tier-3 mixed) but the axes describe distinct properties. Tier describes "what key material was required"; class describes "what happens to the chain when the event lands in a divergent set." See [§Anchor Tier Elevation](#anchor-tier-elevation) for tier semantics and the durability property derived from this taxonomy.

#### One Divergent Generation at a Time

The protocol bounds divergence to **one unresolved generation at a time** on any given chain. Within a generation, the divergent set at `v_d` carries 2 events when all non-privileged (recoverable via `Rec` on KEL / `Rpr` on SEL) or 3 events when the upgrade rule has added a privileged event (transition to contested-terminal; the 3rd event is the upgrade event). Beyond `v_d`, the divergence invariant caps each branch at 1 event per serial (the post-divergence linear-extension cap, applied per branch).

Two unresolved generations cannot coexist on the same chain. A second divergent generation at some `v_{d'} > d` would necessarily place 2 events at `v_{d'}` (one per branch on the second divergence), violating the first generation's post-divergence cap. The structural rules forbid stacking.

**Implication for the verifier walker.** An archiving event (`Rec` on KEL, `Rpr` on SEL) resolves a divergent generation; its archival must be applied to the walker's running state before any subsequent walk step that could introduce a new divergence. Without inline normalization, the chain would carry a stale divergent set into post-resolution state, structurally forbidding any further divergence even after semantic resolution. Per-primitive implementation invariants in [primitives/data/event-logs/kel/merge.md §Key Invariants](primitives/data/event-logs/kel/merge.md#key-invariants) and [primitives/data/event-logs/sel/merge.md §Key Invariants](primitives/data/event-logs/sel/merge.md#key-invariants).

#### Anchor Tier Elevation

Three operation classes, three key-tier requirements. Privileged IEL and SEL events anchor in higher-tier KEL events, not in routine `Ixn`. The elevation closes the signing-key-only adversarial pathway to forging governance acts, binding establishments, and terminal events on the chains that root other chains' authority.

KEL closes this surface intrinsically: KEL `Rec`/`Ror`/`Dec` are dual-signed (signing + recovery), already requiring tier-3 key material to forge. IEL and SEL have no analogous intrinsic mechanism — they piggyback on KEL's tier hierarchy by requiring privileged IEL/SEL events to anchor in KEL events of the matching tier. The per-tier mapping:

**Three-tier mapping.** Each operation class anchors in the KEL event kind that reveals the required key tier:

| Tier | Operation class | KEL anchor kind | Key material required per contributing KEL |
|------|----------------|-----------------|-----------------------------------------------|
| 1 | Routine extension | `Ixn` | Current signing key (already known/active; 0 hidden preimages) |
| 2 | Governance declaration or evolution; binding establishment; seal advance | `Rot` | Rotation-key preimage (1 hidden preimage; committed by prior establishment) |
| 3 | Recovery; terminal | `Ror` | Rotation-key preimage AND recovery-key preimage (2 hidden preimages; both committed by prior establishment) |

**Per-primitive anchor rules.**

| IEL Event | Anchor kind | Tier |
|-----------|-------------|------|
| `Icp` | `Rot` | 2 |
| `Evl` | `Rot` | 2 |
| `Dec` | `Ror` | 3 |

| SEL Event | Anchor kind | Tier |
|-----------|-------------|------|
| `Icp` | (none) | n/a — permissionless, no authorization, no anchor |
| `Est` | `Rot` | 2 (binding establishment; camping defense) |
| `Upd` | `Ixn` | 1 |
| `Sea` | `Rot` | 2 |
| `Rpr` | `Ror` | 3 |
| `Dec` | `Ror` | 3 |

**Policy satisfaction under elevation.** The policy DSL has leaf nodes (`Endorse(prefix)`, `Delegate(delegator)`) that test anchor presence and internal nodes (`Weighted`, nested `Policy`) that compose leaf results. Under anchor elevation, the leaf-level anchor check requires the hosting KEL event to be of the kind specified by the event's tier (`Ixn` for tier 1, `Rot` for tier 2, `Ror` for tier 3); a leaf that finds an anchor of the wrong kind evaluates as unsatisfied. DSL composition is unchanged — `Weighted` still sums satisfied-child weights against the minimum; `Policy` still recursively resolves and evaluates; `Delegate` still requires a delegate's anchor on the SAID, where the delegate is in turn delegated by the delegator named in the policy (the specific delegate is discovered at evaluation time, which is what allows operator-side fleet scaling). The verifier accepts the event when the top-level policy evaluates as satisfied, where satisfaction is computed against the tier-appropriate anchor check at every leaf.

**Strict event-kind anchor.** The tables name a single anchor kind per tier (`Rot` for tier 2, `Ror` for tier 3), not a tier-membership set. `Rot` reveals only the rotation tier; `Ror` reveals both rotation and recovery in one event. Each is the minimum-burn anchor for its tier. Operators whose KEL is divergent must first submit `Rec` to return the chain to a linear state; anchor emission lives on forward-extension events (`Ixn`/`Rot`/`Ror`), not on the recovery primitive (`Rec`) or the terminal `Dec` — the protocol keeps event semantics explicit and non-conflated; see [primitives/data/event-logs/kel/events.md §Anchor on Rot and Ror](primitives/data/event-logs/kel/events.md#anchor-on-rot-and-ror). The extra `Rec` carries no security cost — pre-rotation makes each revealing event commit a fresh `recoveryHash`, so the v_{N-1} preimage revealed by `Rec` is dead authority once `Rec` lands.

**Tier-2 anchor durability.** Tier-2 and tier-3 anchors are both structurally durable against `Rec` archival — both are seal-advancing classes (tier-2 via `Rot`, tier-3 via `Ror`), so a `Rec` cannot truncate at-or-before their serial (the seal-cap rejects). The difference between tier-2 and tier-3 is **forging difficulty only** — tier-2 requires the rotation-key preimage; tier-3 additionally requires the recovery-key preimage. The two-axis property of tier (forging difficulty + archivability) collapses to a single-axis property: forging difficulty. Tier-1 anchors (on `Ixn`) carry no such durability — a subsequent `Rec` can archive them. See [§Event-class taxonomy](#event-class-taxonomy) for the orthogonality framing.

**SEL `Est` and camping defense.** SEL prefix derives from `(identity, topic)` — predictable and well-known. An adversary can race-incept SEL chains for any tuple an operator might use. SEL `Icp` is permissionless and dedup-equivalent: any party's `Icp` for the same tuple produces the same SAID and lands once regardless of who submits it. The actual binding and authorization happen at the next event — `Est` — which carries `ielEvent` (binding to an IEL policy state) and is authorized under the IEL-resolved `authPolicy`. Elevating `Est` to tier 2 makes it privileged at v=1: any `Est`-`Est` divergent set at v=1 fires privileged-divergence-is-terminal at first observation; the chain becomes contested-terminal. Camping defense is **mutually destructive**: the camper pays tier-2 anchor cost (per contributing policy member) to deny the operator a tuple, but neither party gets a working chain at the contested `(identity, topic)`. Operator recourse against a successful camp is reincept under a new `(identity, topic)` tuple. The structural defense composes four rules: `Icp` permissionless + dedup-idempotent; `Est` tier-2 raises per-attempt cost; the inception batch rule rejects bare `[Icp]`; `Est`-`Est` mutual destruction means neither party wins. Mass camping becomes economically unprofitable; single-target camping remains possible but yields nothing usable to the camper. See [primitives/data/event-logs/sel/events.md §Camping defense](primitives/data/event-logs/sel/events.md#camping-defense-icp-permissionless--est-tier-2--inception-batch-required--est-est-mutual-destruction) for the operator-facing mitigation list (policy design, PII hygiene, exchange/custody for private data).

IEL has no `Est` counterpart because IEL `Icp` is itself the binding event — policies are declared inline at inception, authorized by the founding governance threshold. IEL prefix derives from `(authPolicy, governancePolicy, nonce)` where `nonce` is opaque random bytes chosen by the inceptor; the resulting prefix is structurally unpredictable from outside, so the well-known-tuple camping surface doesn't exist. IEL `Icp` is tier-2 anchored: the founding governance act is the same kind of act as `Evl`, and tier-2 (rotation-key preimage per contributing member) prevents signing-only compromise from creating fake-but-validly-governed IELs under stolen policy membership.

**Cross-chain anchor symmetry.** KEL achieves tier-3 intrinsically via dual-signature against `rotationHash` and `recoveryHash` preimages. IEL/SEL achieve it via anchor on KEL `Ror`. Both require the same cryptographic key material; the mechanism differs because IEL/SEL have no intrinsic key state to elevate against. KEL `Dec` is unchanged by anchor elevation — it does not anchor in another chain.

**What anchor elevation defends.**

- **Signing-key-only adversarial governance takeover.** Without elevation, an adversary with signing-only compromise of policy members could forge tier-1-anchored events. Under elevation, IEL `Icp`/`Evl` and SEL `Est`/`Sea` require `Rot` per contributing member; `Rot` requires the pre-committed rotation-key preimage, which signing-only compromise does not yield. Governance acts (declaration, evolution, seal advance), SEL binding camping, and fake-IEL creation via signing-only compromise are all closed.
- **Adversarial terminal events without recovery-key compromise.** `Dec` requires `Ror` per contributing member; `Ror` requires the rotation-key preimage AND the recovery-key preimage (both committed by prior establishment events, neither yet revealed). An adversary lacking the recovery-key preimage for any contributing member cannot forge tier-3-anchored `Dec`. Rotation-key compromise alone is insufficient.
- **Rotated-out kill-switch.** A rotated-out party who could in principle land `Dec` under the parent-event policy now needs `Ror` per contributing member — possession of both rotation-key and recovery-key preimages across the contributing policy members, not signing-key access. The structural authority of the parent's policy persists; the bar to exploit it is raised from tier 1 to tier 3.

**What anchor elevation does not defend.**

- **Recovery-key compromise.** A party holding both rotation- and recovery-key preimages (the tier-3 preimage pair) for enough policy members to satisfy the threshold can forge any IEL/SEL event class up to and including terminal events. They are structurally indistinguishable from the legitimate operator. Operational defenses (custody separation, threshold redundancy, monitoring) remain the only mitigation.
- **Fractured governance.** A rotated-out party convincing other policy members to voluntarily participate in a contesting event satisfies anchor checks legitimately. The protocol cannot distinguish "legitimate threshold coalition" from "rotated-out party plus current-state members." This is social, not adversarial.
- **Custody-degraded members.** Elevation's marginal value scales with per-member key-tier custody separation. A reference implementation that holds all three tiers on a single device gets no marginal protection — full-device compromise yields all three. The protocol is custody-agnostic; trait implementations can provide stronger custody options (HSM separation, geographic split, ceremony-gated reveal). Custody hygiene is a trait/integration concern, not a protocol one.

Anchor tier elevation is a **verifier-side rule**. The verifier walks each IEL/SEL event and checks anchor presence of the required kind in candidate policy members' KELs as part of computing threshold satisfaction. Submit handlers invoke the verifier; consumers reading gossip-received, replicated, or bootstrapped data enforce the same check. No submit-handler-only carve-out exists.

##### Threshold Composition

The anchor tier mapping (tier-1 `Ixn`, tier-2 `Rot`, tier-3 `Ror`) is structurally only as strong as the composition of contributing KELs. Locking events on IEL/SEL require anchors per contributing governance-policy member; an adversary landing a malicious locking event must compromise the relevant tier on **threshold-many distinct custody boundaries**.

- **Tier-2-anchored locking events on IEL (`Evl`) require rotation-tier compromise on threshold-many KELs.** An adversary at rotation-tier on threshold-many KELs can land a policy-evolving `Evl`, effectively taking over the IEL.
- **Tier-3-anchored locking events (`Rpr`, `Dec` on SEL; `Dec` on IEL) require recovery-tier compromise on threshold-many KELs.** Strictly harder; recovery preimages are by construction held separately from active signing keys.
- **Threshold > 1 is the load-bearing structural mitigation.** A single-KEL governance policy collapses to "rotation-tier compromise = full IEL takeover" — structurally valid but operationally fragile. Node gossip identities are documented as `degenerate single-KEL identity` configurations per [../infrastructure/federation.md](../infrastructure/federation.md); they serve narrow bootstrap roles. The federation IEL itself uses N-of-M.
- **Distinct custody boundaries matter.** Two KEL prefixes under the same operator's hardware compose to effective threshold 1 against an adversary who breaches that hardware. Policy composition must span genuine custody separation.
- **Cross-chain anchor satisfaction redundancy.** Composing with anchor count above exact threshold (`M > N` for N-of-M) protects against single-KEL recovery invalidating IEL/SEL anchors. Without redundancy, any contributing KEL's `Rec` archiving the anchoring event drops the IEL/SEL anchor below threshold and flips `policy_satisfied = false` for consumers (see [§policy_satisfied](#policy_satisfied)).
- **Federation IEL pattern is the canonical safe shape.** N-of-M across distinct federation members with redundancy ensures threshold-many rotation-tier compromises are infeasible without breaching multiple independent custody domains.

Composition fragility is a structural property of the policy itself, derivable by any consumer from chain data alone. The policy DSL is verifier-readable; `M` (total members) and `N` (threshold) are inspectable on every event whose authorization traces through the policy. A consumer computes the threshold buffer (`M − N`) and the per-member custody attestations available out-of-band, then degrades trust accordingly.

The verifier itself accepts any threshold ≥ 1: single-KEL policies are protocol-valid, and remain useful for narrow roles where a single custody domain is the deployment shape (e.g., the degenerate single-KEL identity used for node gossip bootstrap). They simply have a threshold buffer of zero and produce `policy_satisfied = false` for any IEL/SEL event whose contributing KEL has been recovered or contested. The chain mathematics surface this; consumers act on it.

#### Sea-after-Upd ratchet (application pattern)

This is an **application-protocol convention, not a protocol invariant** — the verifier does not require `Sea`-trailing structure. Applications that want the properties below enforce the convention at their construction layer.

An application protocol can require trailing SEL `Upd`s be followed by `Sea`, batching `[Upd..., Sea]` as the atomic application operation. Plain `Upd`-tailed chains are application-invalid by construction — conforming tooling never produces them, and consumers reject any chain whose tip is an unsealed `Upd`.

`Sea` is tier-2 anchored — it must anchor in a KEL `Rot`. So the pattern forces a key rotation on every sealed batch. Three layered properties result:

- **Exposure-window bounding (cryptographic).** Each operating signing key is exposed to operations for at most one batch. Pre-rotation hides the next key behind its hash until `Rot` reveals it: the next public key is structurally unreachable from cryptanalysis on the current key (offline signature analysis, side-channel observation, harvest-now-decrypt-later quantum attacks against the signature stream all operate on the current key's public bytes; the next key's bytes have not been observed). By the time the current key would be vulnerable, the chain has already rotated to a key the adversary has never seen. The property holds independent of custody arrangement — pre-rotation defends through *exposure surface*, not through where the keys are stored.
- **Policy-layer separation (when `authPolicy ≠ governancePolicy`).** `Sea` is governance-authorized. An auth-key-only holder can produce `Upd`s but not `Sea`. Multi-device or otherwise composed identities get real cryptographic separation between "auth-set wrote this" and "governance-set sealed this."
- **Consumer-visibility.** Conforming tooling batches `[Upd..., Sea]` atomically, so an Upd-tailed chain is structurally invalid under the convention — not a legitimate intermediate state. Consumers that observe an unsealed `Upd` at the tip detect a convention violation (tooling bypass, buggy producer, or a producer that cannot produce the `Sea`) and reject the chain.

The exposure-window property is the load-bearing one and applies even to degenerate single-KEL IELs where `authPolicy = governancePolicy`. KERI's entire security story leans on pre-rotation for the same reason; KELS inherits it and the Sea-after-Upd ratchet makes the rotation cadence application-driven rather than operator-paced.

**Where it applies:** any IEL+SEL composition where the operator wants exposure-window bounding on durable state, or where governance and auth need to be cryptographically separated, or where governance-aware consumers need a chain-completeness signal. For peer-address SELs on degenerate gossip-service IELs, exposure-window bounding is the primary motivation.

**Operational cost:** every sealed batch forces a `Rot`. The operator's rotation cadence is set by application traffic, not by an operator-defined schedule. For peer addresses where updates are infrequent, this is cheap; for high-frequency SEL traffic, the rotation overhead is non-trivial and the operator should batch `Upd`s aggressively before sealing.

#### Trust Model on Contested Chains

A chain that has transitioned to contested (via privileged-divergence-is-terminal) is **forward-terminal**: it cannot extend with any further events, and post-divergence events on it are submitter-indistinguishable on the chain mathematics. Events at-or-below `lastSealAdvancingEvent` at the time of contestation retain structural verifiability per [§Pre-divergence verifiability survives contestation](#pre-divergence-verifiability-survives-contestation) — anchors at-or-below the seal stay anchored, credentials issued against IEL states at-or-below the seal remain checkable, SEL bindings to at-or-below-seal IEL state stay trust-evaluable. Dependent chains whose bindings reach at-or-below-seal chain state stay authorized; chains that would forward-extend their binding against the contested chain face the freeze and require operator reincept under a new prefix.

The reasoning is structural, not statistical. Contested transitions fire when a privileged event lands in a divergent set. Both a legitimate submitter and an adversary (if they hold current authority) can produce events satisfying that authorization — "who actually has current authority" is exactly what's in question when compromise is suspected. The signatures and anchors on the events in the divergent set satisfy the same policy regardless of submitter; consumers have no protocol-observable way to determine which party submitted which post-divergence event.

After the contested transition, the only way to identify which post-divergence events were authored legitimately would be an out-of-band claim from the legitimate party — "post-divergence event A was mine; event B was the adversary's." The protocol has no trusted way to bring such a claim into the chain. The chain is forward-terminal: no further events can carry signed attestations. Verification tokens cannot be augmented with claims that originated outside the chain. Consumers relying on protocol-trusted information have nothing to distinguish "this post-divergence event was authored legitimately" from "this event may have been adversarial."

The conservative — and only protocol-grounded — response is to treat post-divergence events as submitter-indistinguishable. Events at-or-below the seal sit on the structurally-final at-or-below-seal segment and ground trust decisions normally; events above the seal (whether below or at-or-above the divergence point) stay readable as forensic record but do not ground new trust decisions. Consumers may apply out-of-band judgment about specific above-seal events if they have it (their own observation history; an external attestation through a different channel) but the protocol cannot make those judgments for them.

Contrast with **Decommission** (Dec): when `Dec` lands cleanly on a linear chain (not in a divergent set), it is a clean-retirement signal — no compromise indicated. Pre-Dec events retain trust under their original authorization. Once `Dec` lands the chain is fully terminal — no further events of any kind are accepted, and the seal-cap rejects any competing submission whose parent sits at-or-before `v_{d-1}`. Past content keeps its meaning. `Dec` is itself a privileged event, so when `Dec` lands in a pre-existing divergent set (rather than on a linear chain) it triggers the contested transition directly — see [§No dedicated termination-by-contest event](#no-dedicated-termination-by-contest-event) for the chain-state-effect distinction. Federation-race convergence between a `Dec` and a concurrent competing privileged submission is handled at the infrastructure layer (see [§Limit of the doctrine — concurrent privileged event races](#concurrent-privileged-event-races)).

For a chain that is divergent but not yet contested — non-privileged divergence (e.g., ixn-ixn on KEL or upd-upd on SEL) — events at-or-below `lastSealAdvancingEvent` keep their trust grounding (the at-or-below-seal portion is structurally final). Events above the seal (whether below the divergence point or at-or-above it) are flagged as untrusted in the verifier's output but stay in storage. This intermediate state resolves either by a privileged event upgrading the divergent set (chain transitions to contested — forward-terminal; above-seal events stay above-seal and submitter-indistinguishable while at-or-below-seal events retain verifiability) or by recovery / repair (KEL `Rec`, SEL `Rpr` — chain returns to active trusted state with the discriminator-archived branch removed from live storage, and the `Rec`/`Rpr` itself advances the seal forward).

##### Cases that all look identical to a consumer

A worked enumeration to make the indistinguishability concrete. In each case the resulting chain shape is the same; the consumer can't tell which case actually happened from the chain alone.

1. **A legitimate party detects a second governance party's `Evl`, submits `Dec` on their own attested tip; `Dec` lands in the divergent set; chain contested.** Legitimate action; some prior events may have been adversary-authored.
2. **Adversary holds current governance, submits `Dec` (or `Ror` on KEL) as denial-of-service; lands in a divergent set; chain contested.** Adversary action; prior chain may or may not have been tainted.
3. **Adversary rotates governance away from the legitimate party via a legitimate-looking `Evl`, then submits `Dec` under the new authority.** Adversary action under freshly-rotated authority; no protocol recourse remains.
4. **Two legitimate parties race-extend (no compromise); one's submission is a privileged event that lands in the resulting divergent set.** Legitimate; no actual compromise; pre-contested events all legitimate.
5. **Adversary acquires keys briefly, submits a `Dec`/`Ror`/`Sea` that lands in a divergent set as a precautionary state-change.** Adversary action; past events may or may not have been compromised during the exposure window.

Same chain shape in every case. The protocol cannot distinguish them post-divergence. Treating post-divergence events as submitter-indistinguishable is the only response that fails secure across all five; at-or-below-seal verifiability survives all five per [§Pre-divergence verifiability survives contestation](#pre-divergence-verifiability-survives-contestation).

#### Limit of the Doctrine

The doctrine closes attacks rooted in **past** state. It does NOT defend against compromise of **current** state.

If an adversary acquires sufficient currently-controlling authority — current KEL signing+recovery keys; current IEL `governancePolicy` threshold; current SEL identity binding's authorizing IEL event — they ARE the chain's current state by every protocol-observable measure. They can:

- Submit governance-authorized events (KEL `Rot`/`Ror`, IEL `Evl`, SEL `Sea`) that legitimately rotate authority away from the prior operator.
- Subsequently submit `Dec` (or any other governance act) under the new authority.
- Lock the legitimate prior operator out of all protocol-level recourse.

There is no protocol mechanism to distinguish "legitimately current" from "compromise-acquired-current." There is a narrow detect-and-respond window before the rotation lands: if the legitimate operator detects compromise and acts under the still-current pre-rotation authority before the adversary's rotation event lands, the legitimate event wins. After the rotation, no protocol-level recourse remains.

**Defense for current-state compromise is operational**, not structural. Practices compose across both protocol layers (KEL's dual-signature requirement on `Rec`/`Ror`/`Dec` blocks signing/rotation-key compromise regardless of recovery-key custody; IEL policy composition handles total device compromise via `Evl` rotation of the lost device):

- **High thresholds** in IEL `governancePolicy` / `authPolicy` — raise the cost of accumulating sufficient policy-member authority.
- **Custody separation** sized to threat model — KEL-internal (recovery key in different custody from the signing key, e.g., HSM or ceremony-gated) hardens against coerced signing or partial-device compromise; IEL-level (policy members on distinct devices/locations/custodians) hardens against total device compromise.
- **Monitoring** for unexpected governance / rotation events — fire alerts before adversary completes rotation.
- **Fast operator response** — cut the detect-to-respond latency to within the gossip window.
- **Threshold redundancy** (`M > N`) — re-anchor via a different threshold-satisfying subset when one identity becomes contested (see [features/policy.md §Threshold Redundancy](features/policy.md#threshold-redundancy)).
- **Abandon-and-reincept** under a new prefix when current-state compromise is suspected and no ratchet-out path exists — start fresh with new keys/policies; existing dependent chains rebind forward to the new identity.

The trade the protocol makes is intentional: a narrow current-state-compromise vulnerability (high-friction, time-bounded, operationally mitigable) in exchange for closing the much broader past-state kill-switch surface (low-friction, time-unbounded, structurally unmitigable without this doctrine).

##### Tier-2 adversary terminal-contestation path

A second compromise path exists at the rotation tier specifically. An adversary holding the signing key plus the rotation-key preimage — but NOT the recovery-key preimage — can force a chain to contested-terminal by racing `Rot` against an honest concurrent `Rot`/`Ror`. Two privileged events extending the same `v_{d-1}` form a 2-event privileged divergent set; privileged-divergence-is-terminal fires; the chain dies.

The forging bar to terminally damage a KEL via this path is **rotation-tier compromise** (signing key + rotation-key preimage), not the full tier-3 compromise required to forge `Ror`/`Dec`. Mitigations: operator monitoring catches adversary `Rot` before the honest concurrent rotation; operational serialization on `Rot` issuance closes the race window; the contested-prefix table at the infrastructure layer (#205) surfaces the contested state for out-of-band convergence without recovering the chain.

The damage is bounded by [§Pre-divergence verifiability survives contestation](#pre-divergence-verifiability-survives-contestation): anchors, credentials, and SEL bindings at-or-below the last seal advance remain verifiable. The race freezes forward extension; it does not invalidate the chain's at-or-below-seal history. This is the structural damage bound the protocol provides against the tier-2 adversary. A tier-2 adversary extending the chain with tier-1 `Ixn`s between the last seal and the Rot race could pollute the above-seal-below-divergence range; those events are not structurally trustworthy under the seal-bound verifiability rule.

Accepted as the cost of separating routine sealing (`Rot`) from recovery-commitment advance (`Ror`). The tier-3 adversary path (signing + rotation + recovery preimage) — the full kill-switch — remains unchanged. See [../analysis/protocol-attack-surface.md §Key Compromise](../analysis/protocol-attack-surface.md#key-compromise-kel) for the worked threat scenarios.

##### Adversary Patience and Policy Redundancy

The detect-and-respond window above assumes the adversary acts as soon as they hold sufficient authority. A strategic adversary doesn't. They accumulate — compromise key 1, wait, compromise key 2, wait, compromise key 3, then act once they hold a satisfying combination of the current policy. The window the operator has to respond is bounded by the adversary's timeline (when they choose to act), not by the operator's observation (when they detect the first compromise). Compromise detection at the per-key level may produce no protocol-observable signal until the adversary's accumulation completes; by then the rotation event is already authorized to land.

This makes policy design a budget against strategic patience, not a checkbox:

- **High thresholds + custody separation** raise the cost of accumulating sufficient authority. Each additional independently-held key in the policy is an additional independent compromise the adversary must accomplish. Geographic, organizational, and supply-chain separation between key custodians multiplies the cost of accumulation.
- **Threshold redundancy** (`threshold(N, M)` with `M > N`) tolerates loss of `M − N` identities. The operator who detects partial compromise of a subset ratchets-out the compromised members via `Evl` (declaring a new policy that excludes them); the chain remains under operator authority. See [features/policy.md §Threshold Redundancy](features/policy.md#threshold-redundancy).
- **Hierarchical scope partitioning** (a root identity governs a fleet of subordinate identities; each subordinate anchors a narrower scope) bounds the blast radius. A compromise at a leaf doesn't compromise the root or its siblings; the operator's response is scoped to the affected leaf.

The operational stakes for getting policy design wrong are concrete. A chain whose policy permits no ratchet-out path — e.g., `threshold(N, N)` (a unanimous policy with no redundancy beyond the threshold) — loses to the first compromise that hits the threshold. The operator's only response is reincept under a new prefix, which propagates to every consumer of the identity: every service config, every anchor allowlist, every KEL-backed binding, every peer registry needs to be updated to the new prefix. At federation scale this is a coordinated, expensive rollout — colloquially the "truck-roll." Every consumer is touched; coordination across operators (especially across organizational boundaries) introduces wall-clock delays measured in days or weeks.

Policies designed for ratchet-out — high thresholds, redundancy beyond the threshold, hierarchical scope partitioning — keep the prefix stable across compromise events. **Survivable compromise instead of catastrophic reincept.** Design policies to survive compromise without truck-roll; treat reincept as the option of last resort, not the routine response.

The principle applies uniformly across KEL, IEL, and SEL. **KEL** uses the dual-signature requirement on `Rec`/`Ror`/`Dec` to block signing/rotation-key compromise (exfiltration, brute force, coerced signing, side channels) regardless of where the recovery key is custodied — a single-device deployment is first-class for threat models where signing-tier compromise wouldn't also expose the recovery key. Custody separation (different device, HSM, ceremony-gated) is an optional deployment hardening for threat shapes where signing and recovery would otherwise fall together (coerced signing especially). **IEL** uses `M > N` thresholds across distinct custodians plus hierarchical scope partitioning (root IEL → subordinate IELs scoped narrowly) to handle total device compromise — surviving members rotate the contested device out via `Evl` without losing the identity. **SEL** inherits both via its IEL binding — a well-designed IEL governance policy is the SEL's main defense against adversary patience. The choice between KEL-internal custody separation and IEL multi-device composition depends on the application's threat shape and operational model; the protocol supports either, and both can be combined.

##### Cascade-reincept honesty

Reincept is needed when the IEL or SEL *itself* is contested, not when a KEL it merely references is contested. A contested **IEL** preserves trust evaluability for SELs whose binding sits on at-or-below-seal IEL state (`bound_event.serial <= bound_iel.lastSealAdvancingEvent.serial` AND `bound_event.serial < first_divergent_serial` per the `IelDivergent` rule); SELs that would forward-extend their binding against the contested IEL — by issuing a new `Est` or `Sea` referencing an above-seal `ielEvent` — face the freeze and require operator reincept under a new prefix. A contested **SEL** is forward-terminal — at-or-below-seal content stays verifiable; the contest doesn't cascade beyond the SEL itself. A contested **KEL** is more nuanced: at-or-below-seal anchors it produced retain validity, and dependent IEL/SEL events whose authorization traced through those anchors continue to return `policy_satisfied = true`. For forward evaluations that would have relied on a fresh anchor from the contested KEL, the contested KEL is frozen and cannot contribute; whether the dependent IEL/SEL event still evaluates as satisfied depends on whether the resolving policy has threshold redundancy that lets it evaluate as satisfied without the contested KEL's contribution. Policies with `M > N` threshold redundancy across distinct custodians absorb a single member's contest — past at-or-below-seal anchored events stay satisfied via the surviving members' contributions, and the operator's forward response is governance evolution (`Evl`) to rotate the contested KEL out of the policy. No IEL reincept needed.

The expensive case is contesting an **IEL at the root of a dependency tree**: the contest cascades transitively to every SEL (and credential issuance, anchor allowlist, peer registry, etc.) bound to it. **Don't put your entire dependent tree under a single root IEL that, if contested, costs you everything.** Identity hierarchies should be designed with the cascade in mind — partition the dependency graph so any single IEL's contest has a bounded blast radius.

##### Shape constraints on SEL Sea

- Parent cannot be `Icp` — `Sea` is meaningful only after a binding-establishing event has landed; SEL `Sea` after `Icp` would re-anchor an IEL binding that hasn't yet been declared.
- Parent cannot be `Dec` — terminal events do not extend.
- **SEL Sea-Sea allowed only with strict-advance.** The new `Sea` must strictly advance `ielEvent` to a newer IEL state — re-ratcheting the binding after the bound IEL evolves. Equal `ielEvent` between consecutive Seas is rejected.

---

## Part 2: Cross-Cutting Doctrines

Properties that hold across all primitives and bind them into a coherent protocol. These are not security invariants in the narrow sense — they constrain how the protocol composes (across nodes, across event kinds, across time) rather than asserting an authorization rule. Doctrine rules in Part 1 lean on these for their cryptographic-soundness argument.

### Ordering Without Timestamps

KELS chain events (KEL, IEL, SEL) carry no wall-clock timestamp field. Ordering is by serial number + cryptographic chain linkage (`previous` SAID).

#### Why no event-level timestamps

Wall-clock timestamps on chain events would not be cryptographically meaningful for ordering or tiebreaking:

- An event author can write any timestamp they choose. The protocol can only verify that an event was *observed* at-or-before "now"; it cannot verify the event was crafted when its timestamp claims.
- Clock drift across federation nodes precludes timestamps as a reliable cross-node ordering signal. Different nodes' clocks may disagree; relying on them for "who was first" would let drift, not data, decide chain outcomes.
- Cryptographically verifiable ordering already exists via serial numbers and `previous` SAID linkage. Adding wall-clock timestamps to chain events would be redundant for ordering and unsound for tiebreaking — it would introduce an untrusted input as a protocol decision input.

Where timestamps DO appear in KELS, they serve narrow roles within a **single party's reference frame**, not chain ordering or cross-node consensus:

- **Peer-to-peer signed requests** carry a Unix timestamp + nonce; the receiving party verifies the timestamp against its own clock within a 60-second window and deduplicates via the nonce cache.
- **Exchange envelopes** carry `createdAt` and a per-envelope `nonce`; recipients evaluate freshness against their own clock at decryption time.
- **Mail nonce expiry** evicts cache entries older than a configured window.

In each case the timestamp is consumed by a single party using its own clock — drift across the federation doesn't affect correctness. None of these timestamps appear in chain events, and none influence chain ordering.

#### Application-layer time-of-creation evidence

Applications building on KELS may need time-of-creation evidence (audit trails, regulatory reporting, claim validity windows). The recommended pattern is to carry timestamps as application-layer fields on the *content* a chain event anchors, not on the chain event itself. KELS-provided application primitives already follow this pattern:

- **Credentials** carry `issuedAt` (required) and `expiresAt` (optional). The verifier checks `expiresAt` against its own clock at verification time. See [creds.md](features/creds.md).
- **Exchange envelopes** carry `createdAt`. See [exchange.md](features/exchange.md).

For applications that need third-party-attested timestamps (e.g., legal contexts where a notary's stamp is required), the right pattern is an external attestation: a notary signs `(content_said, timestamp)` as a separate object, which the application carries alongside the content. The KELS chain still anchors the content SAID; the notary's stamp lives in application metadata.

### Federation Convergence

KELS depends on **eventual cross-node convergence**: gossip propagation, paired with deterministic effective-SAID computation, ensures every chain resolves to the same semantic state on every node in a healthy federation.

The assumption has three components:

- **Gossip propagates events.** Anti-entropy and submission-time fan-out push new events to all nodes within a bounded propagation window. (The bound itself is operational and lives in [infrastructure/gossip.md](infrastructure/gossip.md); the doctrine asserts only the eventual property.)
- **Semantic state is a function of the events.** Each node's view of a chain (active / divergent / contested / decommissioned, with which events at which serials) is computed deterministically from the events that node holds; identical event sets yield identical state.
- **Effective-SAID determinism on terminal/divergent chains.** Where chain contents may differ across nodes (different surviving fork events, different forensic snapshots), `hash_effective_said` computes a deterministic SAID that depends only on chain semantic state, not byte-identical content. Anti-entropy compares effective SAIDs and reconciles mismatches.

Doctrine rules that lean on convergence as their cryptographic-soundness argument:
- [§Privileged Divergence is Terminal](#privileged-divergence-is-terminal)'s upgrade rule — restores convergence on privileged events arriving via gossip into a non-priv divergent set.
- **End-verifiability over data-from-any-source** — the verifier produces the same answer because the data is semantically the same (or effective-SAID-identical) across nodes.
- **Single-node-compromise mitigation** — depends on cross-node replication surfacing tampering as divergence.

Convergence is the load-bearing assumption that makes the protocol's cryptographic invariants behave equivalently from any node a consumer queries. **Single-node deployments forfeit this property** — they trade convergence-via-replication for operational simplicity, and accept the structural weakening of DB-tampering surfacing. See [../analysis/protocol-attack-surface.md §DB Compromise + Key Compromise](../analysis/protocol-attack-surface.md#db-compromise--key-compromise) for the carve-out.

Convergence is among gossip-participating nodes. **Permanent node loss before propagation completes** (a node going offline while it still holds events not yet seen by other peers) is a deployment-shape concern — replication factor, node uptime, backup procedures, and clean retirement workflows. It is not a doctrine concern: the protocol asserts what convergence *means* and how it's computed; operators bear responsibility for keeping enough nodes online long enough for it to occur in practice. Operational guidance lives in the operations docs.

Per-primitive proof matrices in [primitives/data/event-logs/kel/reconciliation.md](primitives/data/event-logs/kel/reconciliation.md), [primitives/data/event-logs/iel/reconciliation.md](primitives/data/event-logs/iel/reconciliation.md), and [primitives/data/event-logs/sel/reconciliation.md](primitives/data/event-logs/sel/reconciliation.md) demonstrate convergence holds for each primitive under all state × submission × gossip combinations.

#### Worked example: the federation IEL

The federation itself is an instance of the primitive that depends on convergence. A KELS federation is a single IEL — the *federation IEL* — whose `authPolicy` declares the set of member identities authorized to participate in the gossip mesh. On every node, the federation IEL is replicated to the local sadstore service and the supporting member KELs to the local kels service; gossip queries those local services as its sources of truth for federation state. Propagation uses the normal gossip mechanics — PlumTree announcement-driven primary path, dependency tracking for out-of-order arrivals, anti-entropy as fallback. The federation has no separate consensus algorithm and no central state machine.

Convergence is what makes this work:

- **Identical `authPolicy` view across nodes.** Every gossip node deterministically resolves the federation IEL's tip from the events it holds. If two nodes hold the same event set, they compute the same effective SAID and read the same current `authPolicy`. Anti-entropy converges any two nodes whose effective SAIDs differ.
- **Handshake authorization is path-agnostic.** A connecting peer's identity is checked against the federation IEL's current `authPolicy` via `evaluate_signed_policy`. Two nodes that both hold the federation IEL's authentic tip produce identical authorization decisions. The "which node did the handshake reach?" question doesn't change the answer.
- **Membership evolution converges.** A governance-authorized `Evl` event evolving `authPolicy` propagates via the standard IEL gossip channel. Two nodes that have both received the `Evl` see identical post-evolution policy.
- **Contested-terminal is also convergent.** If two governance-authorized `Evl`s land concurrently at the same serial, IEL divergence makes the chain contested-terminal across all nodes (per [§Privileged Divergence is Terminal](#privileged-divergence-is-terminal), trivially on IEL since every IEL event is privileged). The federation dies under that prefix; recovery is a fresh federation IEL inception, propagated again via gossip. The catastrophic outcome converges; convergence is not contingent on the chain's success.

The per-peer address SEL pattern is the resolution-side companion. Each member identity owns a SEL bound to its own IEL at a deterministic prefix (`compute_sel_prefix(peer_identity, "kels/sel/v1/peer/addresses")`); each peer publishes its current network endpoints there. Discovery on any node reads the federation IEL's `authPolicy`, enumerates the member identities, walks each peer's address SEL, and connects. Convergence applies twice: once to the federation IEL (members agree on who's authorized), once per peer's address SEL (everyone resolves the same current endpoints for each peer).

The federation IEL therefore relies on convergence for the same reason any IEL does — convergent identity state under gossip — but its operational role makes the dependency especially visible: a federation with divergent `authPolicy` views across nodes would have nodes accepting different sets of peers as "current members," and the gossip mesh would partition along those views. The protocol's convergence guarantee, combined with the IEL primitive's structural properties, prevents that partition from ever forming under healthy gossip.

Full design: [infrastructure/federation.md](infrastructure/federation.md).

### Extension Discipline

The protocol cannot — and does not — prevent any currently-authorized party from chaining a new event onto any existing chain event. `previous` validates against the structural parent (the event whose SAID is named), not against "who authored the parent." A current-authority holder can technically point `previous` at any prior event the verifier would accept as a parent.

The operator's design discipline closes the implicit-endorsement gap. The discipline splits by event semantics:

#### Extend only attested events

Every chain event structurally attests to its parent — signing with `previous = parent.said` declares the predecessor acceptable as the parent state. Extending an adversary's event would be semantically equivalent to endorsing it: the new signed event chains from, and carries forward, the adversary's content.

A submitter extends only:

- **Their own previously-signed events.** Any event the submitter authored is theirs to extend.
- **Attested-shared state.** Two structural shapes:
  - **The divergence ancestor `v_{d-1}`.** On a fork, `v_{d-1}` is the unique shared parent of all events at `v_d`. Every node accepts `v_{d-1}` as authentic; extending it (e.g., a divergence-ancestor-extending `Rec`/`Rpr`, or a privileged event that triggers contested via the upgrade rule) carries no implicit endorsement of either `v_d` branch.
  - **SEL `Icp` via dedup-equivalence.** SEL `Icp` is permissionless and deterministic — the prefix derives from `(identity, topic)` and `Icp.said` derives from the full event with `said`+`prefix` blanked. Any submitter's `Icp` for the same `(identity, topic)` produces the same SAID. The submitter's own `Icp` is therefore structurally indistinguishable from any other submitter's `Icp`; extending it is extending attested state, not the adversary's.

The submitter never points an event's `previous` at an adversary event. This is a construction rule applied at the builder layer — the verifier accepts any structurally-valid parent reference; the discipline closes the gap that the verifier structurally cannot.

**Adversary-extended linear chains.** If an adversary captures KEL signing-key material (or SEL `authPolicy` material) and extends the chain linearly (`v_N`, `v_{N+1}`, …, `v_M`), the legitimate party's local chain after gossip has `v_M` as its highest-serial event. The legitimate party has no protocol move that targets `v_M` without endorsing the adversary's events — any submission extending `v_M.said` would attest to it. The structurally available moves all extend `v_{N-1}` (the legitimate party's last attested event):

- A privileged event extending `v_{N-1}` lands at `v_N` as sibling of `v_N_adv` — creates a divergent set; privileged-divergence-is-terminal fires; chain contested.
- The chain cannot be recovered via `Rec`/`Rpr` from this position because the bound (condition 2b) requires the repair event's `previous` to be at-or-after the most recent privileged event; if the adversary's extension included any privileged event, `Rec`/`Rpr` extending `v_{N-1}` would violate the bound.

Practically: when the legitimate party can act under the still-current `v_{N-1}`-anchored authority, they have a contested-termination path; once the adversary has rotated authority forward (privileged events extending past `v_{N-1}`), no protocol-level recourse remains and the response is reincept.

#### Implications

- **SEL pre-Icp camping response.** When an adversary submits `[Icp, Est_camper]` first, the legitimate party's response is `[Icp, Est_operator]` with `Est_operator.previous = Icp.said` (extending `Icp` via dedup-equivalence), **not** `previous = Est_camper.said`. Pointing `Est_operator` at `Est_camper` would attest to `Est_camper`'s acceptability as a parent. The construction creates a 2-event privileged divergent set at v=1 (Est is privileged at tier 2); privileged-divergence-is-terminal fires at first observation; the chain becomes contested-terminal. Operator recourse against a successful camp is reincept under a new `(identity, topic)` tuple — no in-protocol `Rpr` resolution. The mutual-destruction outcome is what makes camping unprofitable: the camper pays tier-2 anchor cost to deny the operator a tuple they can both abandon.

- **KEL/SEL divergence resolution.** `Rec` (KEL) or `Rpr` (SEL) extends either the divergence ancestor `v_{d-1}` (attested-shared; divergence-ancestor-extending shape, lands at `v_d`) or the legitimate party's own branch tip at `v_d` (own attestation; branch-tip-extending shape, lands at `v_{d+1}`). The repair event never points at the other branch's tip. "Whoever holds the recovery/governance key dictates which branch survives" reduces to "the submitter extends their own branch or `v_{d-1}`."

- **Contested-state creation.** A privileged event (KEL `Rot`/`Ror`/`Dec`; SEL `Est`/`Sea`/`Dec`; IEL `Evl`/`Dec`) extends the submitter's own attested tip or `v_{d-1}`. If the local tip is at `v_{d-1}` (no divergence yet observed locally, or divergence at `v_d` with the legitimate party not recognizing either `v_d` branch), the event lands at `v_d` and creates or joins a divergent set; privileged-divergence-is-terminal fires.

- **No event extends adversary content.** This rule is structurally absolute. Where the legitimate party can act, the structurally valid construction always extends attested state (their own or `v_{d-1}`).

#### Cross-primitive symmetry

The discipline is structurally identical across the three primitives. The shapes of "own previous tip" and "attested-shared state" instantiate differently per primitive (KEL: `v_{d-1}` and own-branch tips; IEL: `v_{d-1}` only — every event is governance-authorized so there are no auth-only operator-extension paths; SEL: `v_{d-1}`, `Icp` via dedup, and own-branch tips), but the underlying principle — operators attest only to their own content or to genuinely shared state, with termination events following the structural parent rule unconditionally — applies without primitive-specific exception.

---

## Part 3: Verification Mechanics

The implementation invariants that make Part 1's security invariants enforceable. Verification tokens, advisory locks, and inline reference checking are the patterns by which "the database cannot be trusted" gets converted into safe operations — verification and use happen in the same pass, under the same lock, against the same trusted context.

### Verification tokens as proof of verification

Functions that consume chain data accept a verification token (`&KelVerification`, `&IelVerification`, `&SelVerification`) as a parameter. Holding the token proves the corresponding chain was verified. Token fields are private with no public constructor — the only way to obtain one is through the corresponding verifier (`KelVerifier`, `IelVerifier`, `SelVerifier`).

### Streaming

Chain verification streams events page by page rather than loading entire chains into memory. The pattern applies uniformly across KEL, IEL, and SEL; each primitive has parallel types — `{Kel,Iel,Sel}Verifier` for the walk, `{Kel,Iel,Sel}Verification` for the proof-of-verification token, and a primitive-specific `PageLoader` trait abstracting the storage backend (a `KelStore` reference, an advisory-locked transaction, etc.).

The verifier walks events in **generations** (all events at a given serial), tracking per-branch state; divergence forks per-branch state. `completed_verification(loader, prefix, page_size, max_pages, ...)` is the paginated helper — it drives the loader and calls `truncate_incomplete_generation()` at each page boundary so a generation whose events span two pages re-fetches on the next page rather than being processed half-observed. The helper returns the trusted verification token; `max_pages` caps resource use (default 64 pages ≈ 2K events).

Per-primitive specifics — constructors, branch-state shape, divergence semantics, `PageLoader` implementations — live in each primitive's `verification.md`.

### Merge Verification

When merging new events into an existing chain (submit handler), first verify the entire existing chain in the DB using the corresponding verifier with paginated reads under an advisory lock. Obtain a trusted verification token from the verifier and use that token's data as the context for verifying the new incoming events — never re-query the DB between verification and use. The pattern applies uniformly across KEL, IEL, and SEL submit paths.

### Inline reference checking

Each verifier supports registering SAIDs of interest before the walk so the walk records what it observed without separate DB queries. KEL registers anchor SAIDs (KEL ixns observed at IEL/SEL Icp time and similar binding points); IEL and SEL register caller-cared-about SAIDs for satisfaction tracking. Registration happens before the walk; results are available on the verification token. The pattern eliminates a second DB pass for SAID-presence questions.

### Verifier and merge are distinct treatments

The verifier and the merge layer share infrastructure — the same verifier walk produces the same `policy_satisfied` signal — but compose it differently.

- **Verifier (reads).** Walks already-landed events and reports trust state on a verification token. Authorization failures above the seal are **soft**: they flip `policy_satisfied = false` and the walk continues. The verifier's purpose is to walk authentic chain data and surface findings; erroring out on a chain that contains divergence or governance-failed events would prevent callers from reading the chain at all, including the at-or-below-seal portion they need for forensic and trust-evaluation purposes. Hard-fail is reserved for structural-integrity violations (SAID mismatch, prefix mismatch, broken chain linkage); chain validity stays separable from policy satisfaction.
- **Merge layer (gates writes).** The submit handler runs the same verifier under an advisory lock and uses the resulting `policy_satisfied` as a gate on the new batch: if false at the post-batch walk, the submission is rejected and the new events never enter storage. Failed governance → no write. The gate applies uniformly across event kinds — `Ixn`/`Upd` extension, `Sea`/`Rpr`/`Rec`/`Ror`, and `Dec` alike — with no per-kind carve-outs.

One signal, two compositions: the verifier reads through pathology to expose it, the merge layer reads `policy_satisfied` to gate against it. The signal's definition and walk-time pathology list are in [§policy_satisfied](#policy_satisfied) immediately below; the merge-layer hard-auth invariant for repair events is in [§Privileged Divergence is Terminal §Repair-event authorization](#privileged-divergence-is-terminal).

### policy_satisfied

The verifier produces a `policy_satisfied: bool` on its verification token. Definition: `policy_satisfied = true` iff no walk-time pathology has been observed during the walk. The flag is **monotonic-falsy**: once flipped false, it stays false for the rest of the walk's reporting.

On a non-divergent chain, all queried SAIDs anchored at-or-below `lastSealAdvancingEvent` are recorded in `satisfied_saids`; SAIDs above the seal stay in storage but are not recorded as satisfied unless and until a subsequent seal-advancing event seals them. On a divergent chain, only SAIDs observed at-or-below `lastSealAdvancingEvent` on the pre-divergence linear portion are recorded; once recorded, those entries are not retroactively invalidated by later pathology.

Walk-time pathologies that flip `policy_satisfied = false`:
- Divergence at or before the SAID's anchor observation (post-divergence anchoring).
- Governance / anchor check failures (`Icp` self-governance soft-fail, `Dec` governance soft-fail, post-divergence `Evl` soft-fail).
- Missing SAD-object dependencies in collect-mode walks.
- Other structural anomalies observed during the walk.

The locked-portion doctrine (see [§Privileged Divergence is Terminal §Repair-event conditions](#privileged-divergence-is-terminal)) means settled events — those whose anchors fell in a clean walk segment, in the locked portion — are immune to subsequent chain pathology. Once `policy_satisfied` is true for a SAID in the locked portion, it stays true regardless of subsequent chain events.

**Merge-layer composition.** A submission whose `policy_satisfied` is false at the post-batch verifier walk is rejected with 403 Forbidden. The new events would not anchor under the agreed-upon (clean walk segment, locked portion) chain interpretation. This is the gate that hard-fails governance-failed `Dec` submissions: the merge layer applies the same `policy_satisfied` check across all event kinds (including `Dec`/`Rpr`/`Rec`), without per-kind carve-outs. See [§Verifier and merge are distinct treatments](#verifier-and-merge-are-distinct-treatments) for the framing of why the verifier reports rather than rejects on the same pathology.

### Advisory Locking

All verify-then-write paths hold PostgreSQL advisory locks for the duration of both verification and write. Per-primitive locked-transaction types implement the corresponding `PageLoader` trait by reading under the advisory lock; the same transaction is then used for the write. This eliminates time-of-check-to-time-of-use vulnerabilities. Applies uniformly across KEL, IEL, and SEL submit paths.

### Effective-SAID synthetic comparison

The effective SAID is the canonical chain-tip representation across KEL, IEL, and SEL. It identifies the chain's current state and lets nodes recognize that state across the network without exchanging chain data.

**Concrete vs synthetic representations.** Normal-tip chains carry the tip event's real SAID as the effective SAID; decommissioned chains (where `Dec` is the terminal tip — IEL only) carry the `Dec` event's real SAID. Two states have synthetic representations:

- `hash_effective_said("divergent:{prefix}")` — chain has competing branches at some serial (non-privileged divergent set; not yet contested).
- `hash_effective_said("contested:{prefix}")` — chain's divergent set contains a privileged event; privileged-divergence-is-terminal has fired; chain is Contested. No event of any kind lands.

The synthetic depends only on `(state, prefix)` — no chain history, no fork point, no serial. Any node observing or computing the effective SAID can recognize the state from the SAID alone.

**Cross-node coordination primitive.** Effective SAIDs travel on the wire — gossip announcements, sadstore 422 responses, `/effective-said` endpoints. Two nodes whose chain `P` is divergent (perhaps at different fork points) compute and exchange the same `hash_effective_said("divergent:P")`. This is what lets nodes recognize each other's chain state without exchanging the chains themselves. Encoding fork-point or serial into the synthetic would break this — node A and node B couldn't recognize each other's "divergent for P" state if their representations differed.

**State-detection algorithm.** Given an observed effective SAID for prefix `P`, a node tests:

1. `observed == hash_effective_said("divergent:{P}")` → chain is non-privileged divergent (recoverable via `Rec`/`Rpr`).
2. `observed == hash_effective_said("contested:{P}")` → chain is contested (privileged-divergence-is-terminal has fired; terminal).
3. Otherwise → chain has a real tip event SAID; the tip may be a normal extension event or a `Dec` (use per-event lookup to disambiguate).

States are mutually exclusive at any instant — at most one synthetic-match holds. Contested is terminal; divergent (non-privileged) is the recoverable intermediate.

A node observing an effective SAID for a prefix it has no local state for can still compute the synthetics: the function is `(state, prefix) → SAID` with no chain-history input. This is what lets a peer recognize "your chain `P` is contested" purely from the observed SAID, even on first contact.

The canonical helper is `hash_effective_said(input: &str)` in `lib/kels/src/types/sync.rs`. Inputs follow the `"<state>:{prefix-qb64}"` shape.

**Why divergence resolution doesn't need fork-point detail.** Differently-divergent chains across nodes are resolved through local privileged events (transitions to contested-terminal) or local `Rec`/`Rpr` (archiving repair). Cross-node sync of differently-divergent chains is intentionally not attempted — chains that can't be replayed deterministically must be resolved locally. The synthetic abstraction's prefix-only shape aligns with this design choice: a node receiving a divergent-effective-SAID from a peer learns "peer's chain is divergent" but cannot (and should not try to) reconcile against its own divergent state.
