# Protocol Doctrine

The structural rules that govern KELS — security invariants, cross-cutting doctrines, and verification mechanics. Each part below is load-bearing for protocol correctness; per-primitive design docs cross-reference these as the upstream source rather than re-deriving them.

The document is organized in three parts:

1. **[Security Invariants](#part-1-security-invariants)** — the database-untrusted operation categories, the compromise-is-permanent doctrine and the structural mechanisms that enforce it (seal-cap, privileged divergence, Cnt override, contested-chain trust model, limits).
2. **[Cross-Cutting Doctrines](#part-2-cross-cutting-doctrines)** — properties that govern how the protocol composes across nodes and across event kinds: ordering without timestamps, federation convergence, extension discipline.
3. **[Verification Mechanics](#part-3-verification-mechanics)** — the verification-token + advisory-lock pattern that makes the security invariants enforceable in practice.

---

## Part 1: Security Invariants

The invariants below are load-bearing for KELS security. They are stated structurally rather than statistically: the protocol's safety claims hold *by construction*, not by observation. Verifier implementations enforce them on every walk; an event or chain state that violates them is rejected, regardless of source.

### Operation Categories

The database cannot be trusted — it may have been altered. All operations on chain data (KEL, IEL, SEL) fall into three categories:

#### 1. Serving

Returning data to a client or peer. **No verification needed** — the receiver is responsible for verifying what they get.

Examples: `GET` endpoints serving event pages (per-primitive: `kel/:prefix`, `iel/:prefix`, `sel/:prefix`), effective-SAID lookups, paginated event reads.

#### 2. Consuming

Using data for security decisions (anchoring, key extraction, divergence routing, merge decisions). **MUST verify the full chain first.** The only way to access consumed data is through the corresponding verification token (`KelVerification`, `IelVerification`, `SelVerification`), which can only be obtained via that primitive's verifier (`KelVerifier`, `IelVerifier`, `SelVerifier`). This eliminates TOCTOU vulnerabilities — verification and data access happen in the same pass.

Examples: peer signature verification on a KEL, anchor checking on a KEL, governance-policy resolution on an IEL at a given version, SEL `identity_event` resolution, submit-handler routing decisions on any primitive.

#### 3. Resolving

Comparing state to decide whether to sync. A wrong answer triggers an unnecessary sync (which itself verifies), not a security hole. Standalone functions are acceptable here without full verification.

Examples: effective-SAID endpoints (per-primitive), anti-entropy comparison, KEL proactive-rotation prechecks (`should_add_rot_with_recover()`).

### Compromise is Permanent

The protocol grants authority **only to the chain's current state** (and the chain's most-recent shared pre-divergence state, where divergence has occurred). Past keys, past policies, past endorsers — anything that was once authorized but has since been rotated, revoked, or evolved out — has zero structural ability to act on the chain. A KEL key compromised in 2023 cannot Cnt the chain in 2026 even if the adversary still holds the key material; an IEL `governance_policy` participant who was revoked via `Evl` cannot Cnt the chain after their revocation; an SEL bound to a stale IEL event whose governance has since rotated cannot be Cnt'd by the rotated-out parties (subject to operator-side ratcheting via `Sea`).

This closes the **stale-state kill-switch problem**. Without this rule, every party who ever held authority over a chain would retain protocol-level kill-switch authority over it forever, and any past compromise would become a permanent vulnerability. With this rule, past compromise is structurally a non-event for protocol authority.

#### Forks are Seal-Bounded

The structural mechanism that enforces "current-state-only authority" is the chain's evaluation/recovery seal:

- **KEL**: `last_recovery_revealing_event` — the SAID of the most recent `Rec`/`Ror`/`Cnt`/`Dec`.
- **IEL**: `last_governance_event` — the SAID of the most recent `Evl`/`Sea` (Cnt/Dec are terminal and don't advance the seal but do enforce it).
- **SEL**: `last_governance_event` — the SAID of the most recent `Sea`/`Rpr` (Cnt/Dec terminal, don't advance the seal but do enforce it).

**Same concept, different per-primitive advance rules.** `last_recovery_revealing_event` (KEL) and `last_governance_event` (IEL, SEL) all express the same structural concept — the SAID of the chain's most recent privileged-but-non-terminal event, beyond which the chain cannot fork. The kinds that advance the seal differ because each primitive's privileged-non-terminal set differs: KEL on `Rec`/`Ror`, IEL on `Evl`/`Sea`, SEL on `Sea`/`Rpr`. Terminal kinds (`Cnt`/`Dec` everywhere) enforce the seal but do not advance it.

A new event's land-version MUST be at-or-after the seal (`event_version >= seal_version`). Any submission whose land-version is strictly before the seal is rejected (`"Cannot land at version V — sealed by evaluation/recovery at version S"`). This guarantees that any new event lives in the post-seal window, so the auth context resolved at the event's parent is the chain's currently-tracked policy / key state — not a stale one.

##### Parent-at-seal boundary case

The land-version framing matters at the parent-at-seal boundary. When the chain's tip is itself the most recent privileged event (always-true on linear IEL chains where every event advances the seal; sometimes-true on KEL when the tip is a `Rec` or `Ror` and on SEL when the tip is a `Sea`), a Cnt with `previous = v_{tip-1}.said` lands at v_tip = seal_version with `parent_version = seal_version − 1`. `event_version = seal_version` satisfies `>=`; the parent-at-(seal − 1) is admissible because the new event itself lives at the seal. Disallowing this boundary case would block Cnt on linear chains whose tip is a privileged event entirely — including all linear IEL chains.

**Only `Cnt` is admitted at `event_version = seal_version`.** The boundary carve-out is `Cnt`-specific by construction. Per-primitive reconciliation matrices show all other kinds either route to `ContestRequired` or are structurally `n/a`:

- **Non-priv events with submitter's local tip at v_{seal-1}** (honest-race `Ixn`/`Upd`/`Evl`/`Ror`/`Sea`/`Dec` landing at `v_seal`): rejected (`ContestRequired` on IEL/SEL `Active, sealed`). The operator's correct response is to rebuild against the new tip and resubmit, or to issue a `Cnt` if the seal-defining event is to be repudiated.
- **Recovery primitives in divergence-ancestor-extending shape** (`Rec` on KEL, `Rpr` on SEL with `previous = v_{seal-1}.said`): forbidden (`n/a` on SEL `Active, sealed`: "Rpr cannot truncate at-or-before the seal"; same applies to KEL Rec by symmetry). Their archival semantic would erase the seal-defining event at `v_seal`, breaking seal integrity. The recovery primitives' divergence-ancestor-extending shape is admissible only when the seal sits strictly before the divergence point (`seal_version < event_version`) — i.e., when the divergent set lives in the post-seal window. At the boundary, `Cnt` is the only legitimate response.

The asymmetry follows from semantics: `Cnt` is repudiation (it terminates without archival, leaving the seal-defining event in storage as forensic record); `Rec`/`Rpr` are recovery (they archive, which would destroy seal-defining state). Repudiation at the boundary is sound; recovery at the boundary is not.

**Bounds on the post-seal window per primitive**:
- **KEL**: protocol-bounded. `MAX_NON_REVEALING_EVENTS = 62` proactive-ROR rule caps the chain since the last recovery-revealing event to 62 non-revealing events; after that, the next event MUST be `Rec`/`Ror`/`Dec`/`Cnt`. The window in which past-but-not-yet-revealed keys could create new divergence is therefore bounded by ≤ 62 events.
- **IEL**: no protocol cap. Every non-terminal IEL event after `Icp` advances the seal (`Evl` and `Sea` are both governance-authorized and seal-advancing; `Cnt`/`Dec` are terminal and enforce but don't advance), so the seal coincides with the tip on linear chains — within-window forks structurally don't exist on IEL. The bound on "how stale can authority become before being supplanted" is purely operator-side: governance evolution discipline.
- **SEL**: protocol-bounded. `MAX_NON_EVALUATION_EVENTS = 63` rule caps the chain since the last `Sea`/`Rpr`/`Cnt`/`Dec` to 63 non-evaluation events. Combined with the **per-event parent-monotonic** check on `identity_event` (each SEL event's `identity_event` must be at-or-after its parent event's `identity_event` in IEL chain order, applied per branch independently), this prevents stale-IEL-policy holders from extending an existing branch with a regressed binding. A new branch's identity_event is constrained only by its branch parent (the divergence ancestor on a fork-contest); branches with different parent-chains don't constrain each other.

  **The per-branch parent-monotonic rule is SEL-specific.** SEL is the only primitive where authorization context is referenced via a separate field (`identity_event`) pointing at another chain. KEL and IEL have no analog — they resolve authorization from commitments/policy intrinsic to their own chain at `v_{tip-1}`, so there's nothing for a per-event monotonic check to compare across.

  **Consequence on divergent SEL chains**: branches may reference different IEL events at the same SEL version, and thus may resolve to different governance/auth policies on each branch. This within-chain policy variation is bounded structurally by two rules: the seal-cap (no fork at-or-before the seal) caps how far back branches can diverge; privileged-divergence-is-terminal (any `Sea`/`Rpr`/`Cnt`/`Dec` in the divergent set ends the chain) caps how long the chain can stay in a divergent state. KEL and IEL never have within-chain policy variation: KEL's authorization is intrinsic to its own commitments, and every IEL event is governance-authorized so any divergence is immediately contested.

#### Privileged Divergence is Terminal; Cnt Triggers It Uniformly

The protocol's terminal-authority mechanism is built on three composable rules:

**1. Cnt's parent is `v_{tip-1}`** — a unifying structural rule across linear and divergent chains. On a linear chain, `v_{tip-1}` is the parent of the chain's single tip; Cnt extending it creates fresh divergence at `v_{tip}`. On a divergent chain, the **new (divergence-causing) branch** is single-event at `v_d` — freeze-on-divergence blocks any further extension on that branch — so the new branch's `v_{tip-1}` is `v_{d-1}`, the divergence ancestor (the unique shared parent of all events at `v_d` by the divergence invariant). The **pre-existing branch** may have extended past `v_d` before divergence was detected: up to ~62 events on KEL per the proactive-ROR cap; up to ~63 events on SEL per the proactive-evaluation cap; never on IEL, where every event advances the seal so the chain transitions to contested-terminal at first 2-event divergence and the pre-existing branch cannot extend past `v_d` (both branches single-event by construction on IEL). The same `v_{tip-1}` rule applies in both linear and divergent shapes; Cnt's parent rule selects the **new branch's** `v_{tip-1}` = `v_{d-1}` because `v_{d-1}` is structurally shared across all nodes (it lands cleanly before any divergence), so Cnt with `previous = v_{d-1}.said` validates uniformly across nodes — solving the cross-node propagation problem that breaks tip-extension and combined-digest approaches.

**2. Privileged-divergence-is-terminal**: divergence at a version where the divergent set contains at least one privileged event makes the chain immediately and terminally contested. Privileged events differ per primitive:

- **KEL privileged**: `Rec`, `Ror`, `Cnt`, `Dec` (all recovery-revealing events).
- **IEL privileged**: every event kind — `Icp`, `Evl`, `Sea`, `Cnt`, `Dec`. All IEL events are governance-authorized including `Icp`. (The chain cannot be contested before its inception; the rule is structurally vacuous at `Icp` itself but applies uniformly to any divergence post-inception.)
- **SEL privileged**: `Sea`, `Rpr`, `Cnt`, `Dec` (all governance-authorized events).

Cnt is one such privileged event; its presence in the divergent set triggers contested via this same rule. There is no "Cnt-specific path" in verifier logic — Cnt is just another privileged event whose presence in the divergent set triggers contested.

**Important distinction**: Rec (KEL) and Rpr (SEL) resolve divergence by archiving events via the discriminator. They take two parent shapes, named by what `previous` points at:

- **Branch-tip-extending shape** (`Rec.previous` / `Rpr.previous` is a branch tip at `v_d`): Rec/Rpr extends that branch at `v_{d+1}`; the other branch is archived. Used when one branch is the operator's legitimate content and the operator preserves it.
- **Divergence-ancestor-extending shape** (`Rec.previous` / `Rpr.previous` is `v_{d-1}`, the divergence ancestor): Rec/Rpr lands at `v_d`; ALL events at `version >= d` (both branches) are archived. Rec/Rpr is the only event at `v_d` after the discriminator runs. Used when both branches at `v_d` are adversary-planted; the operator replaces `v_d` entirely.

Cnt shares the divergence-ancestor-extending shape's parent (`previous = v_{d-1}.said`, lands at `v_d`) but has a different effect: Cnt joins the divergent set as a 3rd event at `v_d` WITHOUT archival, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. The kind discriminator (Rec/Rpr vs Cnt) determines whether the chain recovers (archival) or terminates (no archival).

**3. Upgrade rule for cross-node consistency** (applies to **non-archiving privileged events** with `previous = v_{d-1}.said` — `Ror`, `Cnt`, `Dec` on KEL; `Sea`, `Cnt`, `Dec` on SEL; n/a on IEL, where every event is privileged so no non-privileged divergent set can form): when a node has a non-privileged divergent set at `v_d` and gossip delivers such a privileged event for that same `v_d`, the node accepts the privileged event as a third event in the divergent set. Local state transitions from non-privileged-divergent (recoverable) to contested (terminal). Without this rule, different nodes that received different subsets of concurrent submissions would converge on different chain states; the upgrade rule eliminates that divergence for the non-archiving privileged kinds.

The divergence invariant relaxes to allow up to 3 events at `v_d` when **exactly one** is privileged — the upgrade event. **3 events with 2+ privileged is structurally unreachable**: any privileged event in the original 2-event divergent set triggers privileged-divergence-is-terminal immediately, and the contested-state gate rejects any subsequent submission. Only when the original 2 events are both non-privileged does the upgrade-rule path open to add a 3rd privileged event.

**Kind-discriminator routing precedence.** Privileged events route by kind in the merge engine, so the upgrade rule's scope is well-defined and the rules above don't conflict with one another:

- **Archiving privileged kinds** — `Rec` (KEL), `Rpr` (SEL): go through the discriminator's archival path. The branch-tip-extending shape has `previous = v_d.said` (a tip), lands at `v_{d+1}`, archives the other branch. The divergence-ancestor-extending shape has `previous = v_{d-1}.said`, lands at `v_d`, archives both v_d branches. Either shape bypasses the upgrade rule — the discriminator removes the divergent set before any divergent-set check fires.
- **Non-archiving privileged kinds** — `Ror`, `Cnt`, `Dec` on KEL; `Sea`, `Cnt`, `Dec` on SEL: do not archive. When their parent is `v_{d-1}.said` and a non-privileged divergent set already exists at `v_d`, they join the divergent set as a third event via the upgrade rule, triggering contested via privileged-divergence-is-terminal. Their parent shapes vary: `Cnt.previous = v_{tip-1}.said` (Cnt's special parent rule), which resolves to `v_{d-1}.said` when tip is at `v_d`; `Ror`/`Dec`/`Sea` extend the tip directly with `previous = tip.said`, which resolves to `v_{d-1}.said` when the submitter's local tip is at `v_{d-1}`. In every case the event lands at `v_d` (see the **Cnt is always at v_d** invariant below; the same lands-at-v_d behavior holds for Ror/Sea/Dec when their parent is v_{d-1}.said).

The verifier rule simplifies to:
- Divergent at `v_d`?
  - No → linear (active or terminal-via-Dec).
  - Yes → privileged event in the divergent set?
    - Yes → contested (terminal).
    - No → divergent (recoverable via Rec on KEL or Rpr on SEL; no recovery primitive on IEL — divergent IEL is auto-contested because every IEL event is privileged).

**Cnt is always at `v_d`.** Across every valid scenario the parent rule resolves to land Cnt at the divergence version. The three scenarios:

```
Scenario 1 — Cnt on a linear chain (creates fresh divergence at v_d):

  Pre-state:        ... → v_{d-1} → v_d  (existing tip at v_d)
                                      ↑
                                     tip

  Cnt construction: cnt.previous = v_{tip-1}.said = v_{d-1}.said
                    cnt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ existing tip @ v_d  ┐
                                   └─ cnt          @ v_d  ┴── contested (cnt privileged)


Scenario 2 — Cnt on an already-divergent chain (joins divergent set at v_d):

  Pre-state (existing non-priv divergence at v_d, e.g., ixn-ixn race on KEL).
  The pre-existing branch may have extended past v_d before divergence was
  observed (up to ~62 events on KEL per proactive-ROR; ~63 on SEL per
  proactive-evaluation; always single-event on IEL since every IEL event
  advances the seal and 2-event divergence is contested-terminal at first
  observation). The new (divergence-causing) branch is always single-event
  at v_d — freeze-on-divergence blocks any further extension once divergence
  is observed:
                    ... → v_{d-1} ─┬─ ixn_a @ v_d → ixn_a' @ v_{d+1} → …    (pre-existing; may extend)
                                   └─ ixn_b @ v_d                           (new; frozen at single event)

  Cnt's parent rule selects the new branch's v_{tip-1}, which is v_{d-1}
  (NOT the pre-existing branch's v_{tip-1}, which would sit at v_d or later):
                    cnt.previous = v_{d-1}.said
                    cnt.serial   = d

  Post-state:       ... → v_{d-1} ─┬─ ixn_a @ v_d → ixn_a' @ v_{d+1} → …    ┐
                                   ├─ ixn_b @ v_d                           ├── contested (cnt privileged)
                                   └─ cnt   @ v_d                           ┘


Scenario 3 — Sequential post-ixn Cnt (Cnt extends an existing v_d event after gossip):

  Step 1 — ixn_a lands at v_d on Node A (linear at v_d):
                    ... → v_{d-1} → ixn_a @ v_d
                                       ↑
                                      tip

  Step 2 — gossip propagates ixn_a to Node C; Node C's tip is now v_d.

  Step 3 — Node C constructs cnt_c. tip = v_d, v_{tip-1} = v_{d-1}:
                    cnt_c.previous = v_{d-1}.said
                    cnt_c.serial   = d

  Final state on Node C:
                    ... → v_{d-1} ─┬─ ixn_a @ v_d  ┐
                                   └─ cnt_c @ v_d  ┴── contested (cnt_c privileged)
```

Across all three scenarios: Cnt's parent is `v_{d-1}` (the divergence ancestor / parent of the pre-Cnt v_d event), Cnt's serial equals `d`, Cnt lands at `v_d`. The invariant — **Cnt is at `v_d` in every valid scenario** — falls out of the `v_{tip-1}` parent rule applied across linear and divergent shapes.

The same lands-at-`v_d` behavior holds for non-archiving privileged events whose parent happens to be `v_{d-1}.said` for other reasons (Ror/Dec on KEL, Sea/Dec on SEL, when the submitter's local tip is at `v_{d-1}`). They join the divergent set at `v_d` via the upgrade rule and trigger contested.

**Cnt's authorization** resolves through the same policy/key state required to accept `v_{tip}` — i.e., the commitments made at `v_{tip-1}` for the verifier to accept events that extend it. On a divergent chain, that's the same authorization material the verifier used to accept the existing events at `v_d` that already extend `v_{d-1}`. For KEL specifically, Cnt's dual signature is produced under the private signing and recovery keys whose public-key preimages are committed by `v_{tip-1}`'s `rotation_hash` and `recovery_hash` — the same private-key material any non-Cnt event extending `v_{tip-1}` would need. (Revealing the public-key preimage via a prior event landing at `v_{tip}` does not yield the corresponding private key; signing capability remains operator-held.) For IEL, it's the `governance_policy` declared at `v_{tip-1}`. For SEL, it's the IEL-resolved governance policy at the SEL's `identity_event` binding for `v_{tip-1}`.

Cnt's authorization is **HARD**, like every other event's. **General invariant: any event with failed auth is rejected.** A Cnt whose dual-signature, governance-anchor, or IEL-resolved-policy check fails is rejected by the verifier. The chain stays at its prior state. The DB-cannot-be-trusted invariant requires this — an unauthorized terminal must not advance the chain locally. The same rule applies to Dec.

**Operator recourse against signing-key-only Rot takeover (KEL specifically)**: Cnt's `v_{tip-1}` parent rule preserves operator recourse against an adversary holding only the signing key — the recovery-key preimage committed at `v_{N-1}` is not revealed by the adversary's Rot at `v_N`, so only the operator's dual-sig satisfies. See [primitives/kel/event-log.md §Operator recourse against signing-key-only Rot takeover](primitives/kel/event-log.md#operator-recourse-against-signing-key-only-rot-takeover) for the key-state walkthrough.

`Cnt` and `Dec` are not mutually exclusive — see [§Cnt Overrides Dec](#cnt-overrides-dec). Coerced/forced `Dec` is operationally indistinguishable from legitimate `Dec` and the protocol does not attempt to relitigate it. The adversary-Dec-after-takeover scenario is the same unavoidable case as adversary-rotates-governance: operational defense only, no protocol recourse.

From the moment a contested transition occurs (Cnt lands or a privileged event upgrades a divergent set), no further events on this chain are accepted.

#### One Divergent Generation at a Time

The protocol bounds divergence to **one unresolved generation at a time** on any given chain. Within a generation, the divergent set at `v_d` carries 2 events when all non-privileged (recoverable via `Rec` on KEL / `Rpr` on SEL) or 3 events when the upgrade rule has added a non-archiving privileged event (transition to contested-terminal; the 3rd event is the upgrade event). Beyond `v_d`, the divergence invariant caps each branch at 1 event per version (the post-divergence linear-extension cap, applied per branch).

Two unresolved generations cannot coexist on the same chain. A second divergent generation at some `v_{d'} > d` would necessarily place 2 events at `v_{d'}` (one per branch on the second divergence), violating the first generation's post-divergence cap. The structural rules forbid stacking.

**Implication for the verifier walker.** An archiving privileged event (`Rec` on KEL, `Rpr` on SEL) resolves a divergent generation; its archival must be applied to the walker's running state before any subsequent walk step that could introduce a new divergence. Without inline normalization, the chain would carry a stale divergent set into post-resolution state, structurally forbidding any further divergence even after semantic resolution. Per-primitive implementation invariants in [primitives/kel/merge.md §Key Invariants](primitives/kel/merge.md#key-invariants) and [primitives/sel/merge.md §Key Invariants](primitives/sel/merge.md#key-invariants).

#### Cnt Overrides Dec

`Cnt` and `Dec` are both terminal kinds: at most one `Cnt` per log, at most one `Dec` per log. They are **not** mutually exclusive — when both land on the same chain via concurrent submission, `Cnt` overrides `Dec` and the chain converges to contested.

The override is load-bearing for protocol convergence, not a security hardening. Without it, a `Cnt`-`Dec` race produces an unreconcilable cross-node split:

- Some nodes accept `Cnt` first → contested-state gate locks; gossip-delivered `Dec` is rejected.
- Other nodes accept `Dec` first → decommissioned-state gate locks; gossip-delivered `Cnt` is rejected.
- Effective-SAID diverges across the federation (`hash("contested:{prefix}")` on contested nodes vs a Dec-based SAID on decommissioned nodes); anti-entropy spins forever finding mismatched SAIDs but cannot fix either side.
- The chain has two different "authentic" terminal states across the federation under the same prefix — a protocol-completeness failure. There is no single answer to "what is the state of this chain?"

**Override rule.** The decommissioned-state gate accepts a gossip-delivered `Cnt` whenever the `Cnt` is structurally valid against the chain — i.e., its `previous` matches some `v_x.said` where another event in the chain also extends `v_x`, so the `Cnt` lands as one member of a divergent set at `v_x`. The chain transitions from decommissioned to contested via privileged-divergence-is-terminal: `Cnt` is privileged, and its presence in any divergent set fires the rule. The `Dec`, the `Cnt`, and any pre-Dec events all stay in storage as forensic record. The asymmetry is intentional: the contested-state gate does **not** accept incoming `Dec` — `Cnt` always wins on a `Cnt`-`Dec` collision.

The Cnt's landing version depends on the submitter's tip at construction time:

- **Post-Dec construction** (Cnt submitter observed `Dec` via gossip first; tip = `Dec` at `v_d`): `cnt.previous = v_{tip-1}.said = v_{d-1}.said = Dec.previous`; Cnt lands at `v_d` alongside Dec; divergent set `{Dec, Cnt}` at `v_d`.
- **Pre-Dec construction** (Cnt submitter's tip is the chain's pre-Dec tip at `v_{d-1}`; true-concurrent with `Dec`): `cnt.previous = v_{tip-1}.said = v_{d-2}.said`; Cnt lands at `v_{d-1}` as sibling of the pre-Dec tip event; divergent set `{pre-Dec-tip-event, Cnt}` at `v_{d-1}`. Dec sits at `v_d` on the pre-Dec-tip-extending branch (forensic record on Dec'd nodes; rejected by the contested-state gate on Cnt-first nodes).

Both shapes terminate at contested and converge on `hash("contested:{prefix}")`.

**Federation-wide convergence is restored.** Every `Cnt`-`Dec` race ends with all nodes converging on contested via anti-entropy. The cost the protocol pays: a chain that had cleanly decommissioned can be upgraded to contested by a later `Cnt` arrival. The safety side-effect: an adversary's racing `Dec` cannot launder a contested compromise into a clean-retirement appearance — the operator's `Cnt` (or any contesting party's `Cnt`) propagates and forces contested federation-wide.

`Cnt`-`Cnt` and `Dec`-`Dec` collisions are still impossible — the contested-state gate (after `Cnt` lands) and decommissioned-state gate (after `Dec` lands, except for incoming `Cnt`) reject same-kind incoming terminals. The override mechanic is `Cnt`-into-Dec'd-chain specifically.

The rule applies uniformly across KEL, IEL, and SEL — the convergence failure mode is identical on all three primitives, so the override mechanic is identical.

#### Anchor Tier Elevation

Privileged IEL and SEL events anchor in higher-tier KEL events, not in routine `Ixn`. The tier required scales with the event's privilege: tier-1 (routine extension) anchors in `Ixn`; tier-2 (governance act — declaration, evolution, or seal advance — or binding establishment) anchors in `Rot`; tier-3 (recovery or terminal) anchors in `Ror`. The elevation closes the signing-key-only adversarial pathway to forging governance acts, binding establishments, and terminal events on the chains that root other chains' authority.

KEL closes this surface intrinsically: KEL `Cnt`/`Dec` are dual-signed (signing + recovery), already requiring tier-3 key material to forge. IEL and SEL have no analogous intrinsic mechanism — they piggyback on KEL's tier hierarchy by requiring privileged IEL/SEL events to anchor in KEL events of the matching tier.

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
| `Sea` | `Rot` | 2 |
| `Cnt` | `Ror` | 3 |
| `Dec` | `Ror` | 3 |

| SEL Event | Anchor kind | Tier |
|-----------|-------------|------|
| `Icp` | (none) | n/a — permissionless, no authorization, no anchor |
| `Est` | `Rot` | 2 (binding establishment; camping defense) |
| `Upd` | `Ixn` | 1 |
| `Sea` | `Rot` | 2 |
| `Rpr` | `Ror` | 3 |
| `Cnt` | `Ror` | 3 |
| `Dec` | `Ror` | 3 |

**Policy satisfaction under elevation.** The policy DSL has leaf nodes (`Endorse(prefix)`, `Delegate(delegator)`) that test anchor presence and internal nodes (`Weighted`, nested `Policy`) that compose leaf results. Under anchor elevation, the leaf-level anchor check requires the hosting KEL event to be of the kind specified by the event's tier (`Ixn` for tier 1, `Rot` for tier 2, `Ror` for tier 3); a leaf that finds an anchor of the wrong kind evaluates as unsatisfied. DSL composition is unchanged — `Weighted` still sums satisfied-child weights against the minimum; `Policy` still recursively resolves and evaluates; `Delegate` still requires a delegate's anchor on the SAID, where the delegate is in turn delegated by the delegator named in the policy (the specific delegate is discovered at evaluation time, which is what allows operator-side fleet scaling). The verifier accepts the event when the top-level policy evaluates as satisfied, where satisfaction is computed against the tier-appropriate anchor check at every leaf.

**Strict event-kind anchor.** The tables name a single anchor kind per tier (`Rot` for tier 2, `Ror` for tier 3), not a tier-membership set. `Rot` reveals only the rotation tier; `Ror` reveals both rotation and recovery in one event. Each is the minimum-burn anchor for its tier. Operators whose KEL is divergent must first submit `Rec` to return the chain to a linear state; anchor emission lives on forward-extension events (`Ixn`/`Rot`/`Ror`), not on the recovery primitive (the protocol keeps event semantics explicit and non-conflated — see [primitives/kel/events.md §Anchor on Rot and Ror](primitives/kel/events.md#anchor-on-rot-and-ror)). The extra `Rec` carries no security cost — pre-rotation makes each revealing event commit a fresh `recovery_hash`, so the v_{N-1} preimage revealed by `Rec` is dead authority once `Rec` lands.

**SEL `Est` and camping defense.** SEL prefix derives from `(identity, topic)` — predictable and well-known. An adversary can race-incept SEL chains for any tuple an operator might use. SEL `Icp` is permissionless and dedup-equivalent: any party's `Icp` for the same tuple produces the same SAID and lands once regardless of who submits it. The actual binding and authorization happen at the next event — `Est` — which carries `identity_event` (binding to an IEL policy state) and is authorized under the IEL-resolved `auth_policy`. Elevating `Est` to tier 2 raises the per-camp cost: each camping attempt requires the camper's policy members to each produce a KEL `Rot` anchor. Mass camping becomes economically expensive; single-target camping remains possible but at a real cost. The operator's legitimate `Est` and a camper's `Est` create a divergent set at v1 (different `identity_event` or content → different SAIDs), resolved via `Rpr`.

IEL has no `Est` counterpart because IEL `Icp` is itself the binding event — policies are declared inline at inception, authorized by the founding governance threshold. IEL prefix derives from `(auth_policy, governance_policy, nonce)` where `nonce` is opaque random bytes chosen by the inceptor; the resulting prefix is structurally unpredictable from outside, so the well-known-tuple camping surface doesn't exist. IEL `Icp` is tier-2 anchored: the founding governance act is the same kind of act as `Evl`/`Sea`, and tier-2 (rotation-key preimage per contributing member) prevents signing-only compromise from creating fake-but-validly-governed IELs under stolen policy membership.

**Cross-chain anchor symmetry.** KEL achieves tier-3 intrinsically via dual-signature against `rotation_hash` and `recovery_hash` preimages. IEL/SEL achieve it via anchor on KEL `Ror`. Both require the same cryptographic key material; the mechanism differs because IEL/SEL have no intrinsic key state to elevate against. KEL `Cnt`/`Dec` are unchanged by anchor elevation — they do not anchor in another chain.

**What anchor elevation defends.**

- **Signing-key-only adversarial governance takeover.** Without elevation, an adversary with signing-only compromise of policy members could forge tier-1-anchored events. Under elevation, IEL `Icp`/`Evl`/`Sea` and SEL `Est` require `Rot` per contributing member; `Rot` requires the pre-committed rotation-key preimage, which signing-only compromise does not yield. Governance acts (declaration, evolution, seal advance), SEL binding camping, and fake-IEL creation via signing-only compromise are all closed.
- **Adversarial terminal events without recovery-key compromise.** `Cnt`/`Dec` require `Ror` per contributing member; `Ror` requires the rotation-key preimage AND the recovery-key preimage (both committed by prior establishment events, neither yet revealed). An adversary lacking the recovery-key preimage for any contributing member cannot forge tier-3-anchored terminal events. Rotation-key compromise alone is insufficient.
- **Operator-side rotated-out kill-switch.** A rotated-out party who could in principle `Cnt` under `v_{tip-1}`'s policy now needs `Ror` per contributing member — possession of both rotation-key and recovery-key preimages across the contributing policy members, not signing-key access. The structural authority of `v_{tip-1}`'s policy persists; the bar to exploit it is raised from tier 1 to tier 3.

**What anchor elevation does not defend.**

- **Recovery-key compromise.** A party holding both rotation- and recovery-key preimages (the tier-3 preimage pair) for enough policy members to satisfy the threshold can forge any IEL/SEL event class up to and including terminal events. They are structurally indistinguishable from the legitimate operator. Operational defenses (custody separation, threshold redundancy, monitoring) remain the only mitigation.
- **Fractured governance.** A rotated-out party convincing other policy members to voluntarily participate in a contesting event satisfies anchor checks legitimately. The protocol cannot distinguish "legitimate threshold coalition" from "rotated-out party plus current-state members." This is social, not adversarial.
- **Custody-degraded members.** Elevation's marginal value scales with per-member key-tier custody separation. A reference implementation that holds all three tiers on a single device gets no marginal protection — full-device compromise yields all three. The protocol is custody-agnostic; trait implementations can provide stronger custody options (HSM separation, geographic split, ceremony-gated reveal). Custody hygiene is a trait/integration concern, not a protocol one.

Anchor tier elevation is a **verifier-side rule**. The verifier walks each IEL/SEL event and checks anchor presence of the required kind in candidate policy members' KELs as part of computing threshold satisfaction. Submit handlers invoke the verifier; consumers reading gossip-received, replicated, or bootstrapped data enforce the same check. No submit-handler-only carve-out exists.

#### Trust Model on Contested Chains

A chain on which Cnt has landed is **whole-suspect**. Pre-Cnt events do not retain authorization grounding for new trust decisions. Dependent chains bound to a contested IEL/KEL lose their authorization basis and require operator reincept under a new prefix.

The reasoning is structural, not statistical. When Cnt lands, both the legitimate operator and an adversary (if they hold current authority) can submit it — Cnt requires current-state authorization, and "who actually has current authority" is exactly what's in question when compromise is suspected. The signature on an adversarial Cnt satisfies the same policy a legitimate Cnt would; consumers have no protocol-observable way to determine which party submitted it.

After Cnt lands, the only way to identify which events on the chain were authored legitimately would be an out-of-band claim from the owner — "events 1 through N were mine; events N+1 onward were the adversary's." The protocol has no trusted way to bring such a claim into the chain. The chain is terminal: no further events can carry signed attestations from the owner. Verification tokens cannot be augmented with claims that originated outside the chain. Consumers relying on protocol-trusted information have nothing to distinguish "this event was authored legitimately" from "this event may have been adversarial."

The conservative — and only protocol-grounded — response is to treat the entire chain as suspect. Pre-Cnt events stay readable as forensic record but they cannot ground new trust decisions. Consumers may apply out-of-band judgment about specific events if they have it (their own observation history; an external attestation from the owner via a different channel) but the protocol cannot make those judgments for them.

Contrast with **Decommission** (Dec): Dec is the operator's clean-retirement signal — no compromise, the operator intentionally ending the chain. Pre-Dec events retain trust under their original authorization. Future submissions are rejected, with one exception: a gossip-delivered `Cnt` overrides Dec and transitions the chain to contested per [§Cnt Overrides Dec](#cnt-overrides-dec); once overridden, the whole-chain-suspect rule applies and pre-Dec trust grounding evaporates. Absent that override, past content keeps its meaning. The asymmetry exists because if Dec also wiped trust, it would just be Cnt by another name; the whole reason for two terminal kinds is that Dec means "clean stop" and Cnt means "compromised."

For a chain that is divergent but not yet contested — divergence has been observed but Cnt hasn't landed — events at versions before the divergence point keep their trust grounding (the pre-divergence portion is structurally still linear and authorized). Events at versions after the divergence point are flagged as untrusted in the verifier's output but stay in storage. This intermediate state resolves either by Cnt (chain becomes whole-suspect) or, where applicable, by recovery / repair (KEL Rec, SEL Rpr — chain returns to active trusted state with the discriminator-archived branch removed from live storage).

##### Cases that all look identical to a consumer

A worked enumeration to make the indistinguishability concrete. In each case the resulting chain shape is the same; the consumer can't tell which case actually happened from the chain alone.

1. **Operator detects a second governance party's Evl, submits Cnt to terminate before further damage.** Cnt = legitimate operator action; some prior events may have been adversary-authored.
2. **Adversary holds current governance, submits Cnt as denial-of-service.** Cnt = adversary action; prior chain may or may not have been tainted.
3. **Adversary rotates governance away from operator via a legitimate-looking Evl, then submits Cnt under the new authority.** Cnt = adversary action under freshly-rotated authority; operator has no protocol recourse.
4. **Two legitimate parties race-extend (no compromise), one submits Cnt to terminate the messy state.** Cnt = legitimate; no actual compromise; pre-Cnt events all legitimate.
5. **Adversary acquires keys briefly, doesn't act, operator detects key exposure and Cnts as a precaution.** Cnt = legitimate; past events may or may not have been compromised during the exposure window.

Same chain shape in every case. The protocol cannot distinguish them. Treating the chain as suspect is the only response that fails secure across all five.

#### Limit of the Doctrine

The doctrine closes attacks rooted in **past** state. It does NOT defend against compromise of **current** state.

If an adversary acquires sufficient currently-controlling authority — current KEL signing+recovery keys; current IEL `governance_policy` threshold; current SEL identity binding's authorizing IEL event — they ARE the chain's current state by every protocol-observable measure. They can:

- Submit governance-authorized events (KEL `Rot`/`Ror`, IEL `Evl`, SEL `Sea`) that legitimately rotate authority away from the prior operator.
- Subsequently submit `Cnt` (or any other governance act) under the new authority.
- Lock the legitimate prior operator out of all protocol-level recourse.

There is no protocol mechanism to distinguish "legitimately current" from "compromise-acquired-current." There is a narrow detect-and-respond window before the rotation lands: if the legitimate operator detects compromise and submits `Cnt` under the still-current pre-rotation authority before the adversary's rotation event lands, the legitimate `Cnt` wins. After the rotation, no protocol-level recourse remains.

**Defense for current-state compromise is operational**, not structural:
- High thresholds for governance / recovery — make "controls current authority" hard to achieve.
- Separation of custody — no single point of compromise grants current-state authority.
- Monitoring for unexpected governance / rotation events — fire alerts before adversary completes rotation.
- Fast operator response — cut the detect-to-Cnt latency to within the gossip window.
- **Threshold redundancy** — re-anchor via a different threshold-satisfying subset when one identity becomes contested (see [features/policy.md §Threshold Redundancy](features/policy.md#threshold-redundancy)).
- **Abandon-and-reincept** under a new prefix when current-state compromise is suspected — start fresh with new keys/policies; existing dependent chains rebind forward to the new identity.

The trade the protocol makes is intentional: a narrow current-state-compromise vulnerability (high-friction, time-bounded, operationally mitigable) in exchange for closing the much broader past-state kill-switch surface (low-friction, time-unbounded, structurally unmitigable without this doctrine).

##### Adversary Patience and Policy Redundancy

The detect-and-respond window above assumes the adversary acts as soon as they hold sufficient authority. A strategic adversary doesn't. They accumulate — compromise key 1, wait, compromise key 2, wait, compromise key 3, then act once they hold a satisfying combination of the current policy. The window the operator has to respond is bounded by the adversary's timeline (when they choose to act), not by the operator's observation (when they detect the first compromise). Compromise detection at the per-key level may produce no protocol-observable signal until the adversary's accumulation completes; by then the rotation event is already authorized to land.

This makes policy design a budget against strategic patience, not a checkbox:

- **High thresholds + custody separation** raise the cost of accumulating sufficient authority. Each additional independently-held key in the policy is an additional independent compromise the adversary must accomplish. Geographic, organizational, and supply-chain separation between key custodians multiplies the cost of accumulation.
- **Threshold redundancy** (`threshold(N, M)` with `M > N`) tolerates loss of `M − N` identities. The operator who detects partial compromise of a subset ratchets-out the compromised members via `Evl` (declaring a new policy that excludes them); the chain remains under operator authority. See [features/policy.md §Threshold Redundancy](features/policy.md#threshold-redundancy).
- **Hierarchical scope partitioning** (a root identity governs a fleet of subordinate identities; each subordinate anchors a narrower scope) bounds the blast radius. A compromise at a leaf doesn't compromise the root or its siblings; the operator's response is scoped to the affected leaf.

The operational stakes for getting policy design wrong are concrete. A chain whose policy permits no ratchet-out path — e.g., `threshold(N, N)` (a unanimous policy with no redundancy beyond the threshold) — loses to the first compromise that hits the threshold. The operator's only response is reincept under a new prefix, which propagates to every consumer of the identity: every service config, every anchor allowlist, every KEL-backed binding, every peer registry needs to be updated to the new prefix. At federation scale this is a coordinated, expensive rollout — colloquially the "truck-roll." Every consumer is touched; coordination across operators (especially across organizational boundaries) introduces wall-clock delays measured in days or weeks.

Policies designed for ratchet-out — high thresholds, redundancy beyond the threshold, hierarchical scope partitioning — keep the prefix stable across compromise events. **Survivable compromise instead of catastrophic reincept.** Design policies to survive compromise without truck-roll; treat reincept as the option of last resort, not the routine response.

The principle applies uniformly across KEL, IEL, and SEL. KEL's recovery key custody benefits from physical separation from the signing key (the privileged-vs-routine asymmetry the dual-signature requirement was designed for). IEL's `governance_policy` benefits from `M > N` thresholds across distinct organizational custodians and from hierarchical structure (root IEL → subordinate IELs scoped narrowly). SEL inherits both via its IEL binding — a well-designed IEL governance policy is the SEL's main defense against adversary patience.

**Cascade-reincept honesty**: reincept is needed when the IEL or SEL *itself* is contested, not when a KEL it merely references is contested. A contested **IEL** invalidates every SEL bound to it — those SELs lose their authorization basis and require operator reincept under a new prefix. A contested **SEL** is just itself dead. A contested **KEL** is more nuanced: whether dependent IELs lose authorization grounding depends on (a) whether the contested KEL ever anchored events on those IELs, and (b) whether the relevant policy has redundancy that lets it evaluate as satisfied without the contested KEL's contribution. Policies with `M > N` threshold redundancy across distinct custodians absorb a single member's contest — past anchored events stay satisfied via the surviving members' contributions, and the operator's forward response is governance evolution (`Evl`) to rotate the contested KEL out of the policy. No IEL reincept needed.

The expensive case is contesting an **IEL at the root of a dependency tree**: the contest cascades transitively to every SEL (and credential issuance, anchor allowlist, peer registry, etc.) bound to it. **Don't put your entire dependent tree under a single root IEL that, if contested, costs you everything.** Identity hierarchies should be designed with the cascade in mind — partition the dependency graph so any single IEL's contest has a bounded blast radius.

##### Exclusion Evolutions and the Seal Advance

The kill-switch authority granted by `v_{tip-1}`'s policy is symmetric. It serves the operator against single-event adversarial takeover (the operator's `Cnt` against an adversary's `Rot`/`Evl`/`Sea`); it also serves rotated-out parties against the operator's evolution event. Same mechanism, different actors. After a legitimate `Evl` at `v_N` rotates governance from `P_old` to `P_new`, `v_{N-1}`'s policy remains the parent-at-(seal − 1) authorization basis until the seal advances past `v_N`. Any party who satisfies `P_old` can `Cnt` the chain at `v_N` within that window — subject to the [§Anchor Tier Elevation](#anchor-tier-elevation) bar (rotation- and recovery-tier per contributing member, not signing-only).

The window is operationally meaningful only on **exclusion evolutions** — where `P_new` strictly removes parties who satisfied `P_old` (a removed member, a raised threshold past someone's contribution, a participant replacement). Pure additions or threshold-decreases that keep the prior membership don't create new "had authority, lost it" positions; anyone who could `Cnt` under `P_old` can also `Cnt` under `P_new`. No new attack surface opens. Only exclusion evolutions put a specific party in the structurally unique position of being able to satisfy `P_old` but not `P_new`.

**`Sea` advances the seal.** Both IEL and SEL provide a `Sea` event kind whose role is to advance the seal without changing governance. On IEL, `Sea` declares no policy evolution (companion to `Evl`, which requires evolution). On SEL, `Sea` re-evaluates the IEL binding and advances the seal, optionally updating `identity_event` to a newer IEL state — pure seal advance when `identity_event` is unchanged. A `Sea` at `v_{N+1}` advances the seal past `v_N`; once landed, `v_{N-1}`'s policy is no longer the parent-at-(seal − 1) basis. The excluded party loses the structural recourse the window provided.

`Sea` is tier-2 anchored (KEL `Rot` per contributing member) — the same elevation as `Evl`. The cost to forge a `Sea` is exactly the cost to forge an `Evl`; an adversary who could prematurely advance the seal could already perform the original takeover. `Sea`'s value is shape correctness and audit clarity, not lowering the bar.

**Operator-discipline recommendation: batch `[Evl, Sea]` on exclusion evolutions.** Submit the exclusion `Evl` and the seal-advancing `Sea` as a single batch. The `Sea` lands at `v_{N+1}` immediately after the `Evl` at `v_N`, advancing the seal past the exclusion point in the same submission. This closes the operator-side window where forgetting to follow up would leave `v_{N-1}`'s policy as the parent-at-(seal − 1) basis indefinitely. The `Sea` is authorized under the new (post-`Evl`) policy, which the operator now controls.

Shape constraints on `Sea`:

- Parent cannot be `Icp` — `Sea` is meaningful only after a policy-evolution event has opened a window.
- Parent cannot be another `Sea` *with identical content* — back-to-back seal advances with no semantic difference are an invalid shape. (On IEL, `Sea` carries no content fields, so any back-to-back Sea is forbidden. On SEL, `Sea`-`Sea` is allowed when the second `Sea` advances `identity_event` to a newer IEL state — re-ratcheting the binding after the bound IEL evolves again.)
- Parent cannot be `Cnt`/`Dec` — terminal events do not extend.

SEL inherits the concern via its IEL binding: an exclusion evolution on the bound IEL leaves a window during which `v_{N-1}`'s IEL-policy parties can `Cnt` any SEL whose `identity_event` resolves to the pre-exclusion state. An IEL `Sea` resolves the IEL-level exposure; an SEL `Sea` resolves the SEL-level exposure by re-anchoring the binding past the exclusion.

---

## Part 2: Cross-Cutting Doctrines

Properties that hold across all primitives and bind them into a coherent protocol. These are not security invariants in the narrow sense — they constrain how the protocol composes (across nodes, across event kinds, across time) rather than asserting an authorization rule. Doctrine rules in Part 1 lean on these for their cryptographic-soundness argument.

### Ordering Without Timestamps

KELS chain events (KEL, IEL, SEL) carry no wall-clock timestamp field. Ordering is by version number + cryptographic chain linkage (`previous` SAID).

#### Why no event-level timestamps

Wall-clock timestamps on chain events would not be cryptographically meaningful for ordering or tiebreaking:

- An event author can write any timestamp they choose. The protocol can only verify that an event was *observed* at-or-before "now"; it cannot verify the event was crafted when its timestamp claims.
- Clock drift across federation nodes precludes timestamps as a reliable cross-node ordering signal. Different nodes' clocks may disagree; relying on them for "who was first" would let drift, not data, decide chain outcomes.
- Cryptographically verifiable ordering already exists via version numbers and `previous` SAID linkage. Adding wall-clock timestamps to chain events would be redundant for ordering and unsound for tiebreaking — it would introduce an untrusted input as a protocol decision input.

Where timestamps DO appear in KELS, they serve narrow roles within a **single party's reference frame**, not chain ordering or cross-node consensus:

- **Peer-to-peer signed requests** carry a Unix timestamp + nonce; the receiving party verifies the timestamp against its own clock within a 60-second window and deduplicates via the nonce cache.
- **Exchange envelopes** carry `created_at` and a per-envelope `nonce`; recipients evaluate freshness against their own clock at decryption time.
- **Mail nonce expiry** evicts cache entries older than a configured window.

In each case the timestamp is consumed by a single party using its own clock — drift across the federation doesn't affect correctness. None of these timestamps appear in chain events, and none influence chain ordering.

#### Application-layer time-of-creation evidence

Applications building on KELS may need time-of-creation evidence (audit trails, regulatory reporting, claim validity windows). The recommended pattern is to carry timestamps as application-layer fields on the *content* a chain event anchors, not on the chain event itself. KELS-provided application primitives already follow this pattern:

- **Credentials** carry `issued_at` (required) and `expires_at` (optional). The verifier checks `expires_at` against its own clock at verification time. See [creds.md](features/creds.md).
- **Exchange envelopes** carry `created_at`. See [exchange.md](features/exchange.md).

For applications that need third-party-attested timestamps (e.g., legal contexts where a notary's stamp is required), the right pattern is an external attestation: a notary signs `(content_said, timestamp)` as a separate object, which the application carries alongside the content. The KELS chain still anchors the content SAID; the notary's stamp lives in application metadata.

### Federation Convergence

KELS depends on **eventual cross-node convergence**: gossip propagation, paired with deterministic effective-SAID computation, ensures every chain resolves to the same semantic state on every node in a healthy federation.

The assumption has three components:

- **Gossip propagates events.** Anti-entropy and submission-time fan-out push new events to all nodes within a bounded propagation window. (The bound itself is operational and lives in [infrastructure/gossip.md](infrastructure/gossip.md); the doctrine asserts only the eventual property.)
- **Semantic state is a function of the events.** Each node's view of a chain (active / divergent / contested / decommissioned, with which events at which versions) is computed deterministically from the events that node holds; identical event sets yield identical state.
- **Effective-SAID determinism on terminal/divergent chains.** Where chain contents may differ across nodes (different surviving fork events, different forensic snapshots), `hash_effective_said` computes a deterministic SAID that depends only on chain semantic state, not byte-identical content. Anti-entropy compares effective SAIDs and reconciles mismatches.

Doctrine rules that lean on convergence as their cryptographic-soundness argument:
- [§Cnt Overrides Dec](#cnt-overrides-dec) — restores convergence on `Cnt`/`Dec` races.
- [§Privileged Divergence is Terminal](#privileged-divergence-is-terminal-cnt-triggers-it-uniformly)'s upgrade rule — restores convergence on non-archiving privileged events arriving via gossip into a non-priv divergent set.
- **End-verifiability over data-from-any-source** — the verifier produces the same answer because the data is semantically the same (or effective-SAID-identical) across nodes.
- **Single-node-compromise mitigation** — depends on cross-node replication surfacing tampering as divergence.

Convergence is the load-bearing assumption that makes the protocol's cryptographic invariants behave equivalently from any node a consumer queries. **Single-node deployments forfeit this property** — they trade convergence-via-replication for operational simplicity, and accept the structural weakening of DB-tampering surfacing. See [../analysis/protocol-attack-surface.md §DB Compromise + Key Compromise](../analysis/protocol-attack-surface.md#db-compromise--key-compromise) for the carve-out.

Convergence is among gossip-participating nodes. **Permanent node loss before propagation completes** (a node going offline while it still holds events not yet seen by other peers) is a deployment-shape concern — replication factor, node uptime, backup procedures, and clean retirement workflows. It is not a doctrine concern: the protocol asserts what convergence *means* and how it's computed; operators bear responsibility for keeping enough nodes online long enough for it to occur in practice. Operational guidance lives in the operations docs.

Per-primitive proof matrices in [primitives/kel/reconciliation.md](primitives/kel/reconciliation.md), [primitives/iel/reconciliation.md](primitives/iel/reconciliation.md), and [primitives/sel/reconciliation.md](primitives/sel/reconciliation.md) demonstrate convergence holds for each primitive under all state × submission × gossip combinations.

### Extension Discipline

The protocol cannot — and does not — prevent any currently-authorized party from chaining a new event onto any existing chain event. `previous` validates against the structural parent (the event whose SAID is named), not against "who authored the parent." A current-authority holder can technically point `previous` at any prior event the verifier would accept as a parent.

The operator's design discipline closes the implicit-endorsement gap. The discipline splits by event semantics:

#### Endorsement events — extend only attested events

All chain events except `Cnt` and `Dec` are **endorsement-class**: signing an event with `previous = parent.said` is a structural attestation that the predecessor is acceptable as the parent state for further chain evolution. Extending an adversary's event with an endorsement-class event would be semantically equivalent to endorsing it — the operator's signed event chains from, and carries forward, the adversary's content. (`Cnt` and `Dec` are termination-class — see below.)

The operator extends only:

- **Their own previously-signed events.** Any event the operator authored is theirs to extend.
- **Attested-shared state.** Two structural shapes:
  - **The divergence ancestor `v_{d-1}`.** On a fork-contest, `v_{d-1}` is the unique shared parent of all events at `v_d`. Every node accepts `v_{d-1}` as authentic; extending it (e.g., a divergence-ancestor-extending `Rec`/`Rpr`) carries no implicit endorsement of either `v_d` branch.
  - **SEL `Icp` via dedup-equivalence.** SEL `Icp` is permissionless and deterministic — the prefix derives from `(identity, topic)` and `Icp.said` derives from the full event with `said`+`prefix` blanked. Any submitter's `Icp` for the same `(identity, topic)` produces the same SAID. The operator's own `Icp` is therefore structurally indistinguishable from any other submitter's `Icp`; extending it is extending the operator's own attested state, not the adversary's.

The operator never points an endorsement-class event's `previous` at an adversary event. This is an operator-side construction rule applied at the builder layer — the verifier accepts any structurally-valid parent reference; the discipline closes the gap that the verifier structurally cannot.

#### Termination events — repudiation, not endorsement

`Cnt` and `Dec` are **termination-class**. `previous = parent.said` on a termination event structurally means "I observe this chain state and terminate it," not "I accept the parent as a basis for further chain evolution." There is no further chain evolution to endorse; the chain ends with the terminal.

The implication is that **termination events follow the `previous = v_{tip-1}.said` parent rule unconditionally**, including the rare case where `v_{tip-1}` is an adversary event:

- **Cnt on an adversary-extended linear chain.** If an adversary captures the operator's signing key (KEL) or `auth_policy` material (SEL) and submits one or more endorsement-class events `v_N`, `v_{N+1}`, …, `v_M` onto the operator's chain (linear extension; no divergence yet), the operator's local tip after gossip is `v_M`. Operator's `Cnt.previous = v_{tip-1}.said = v_{M-1}.said` — which on a multi-event-extended chain is an adversary event. This is intentional. Cnt's repudiation semantic is what makes it coherent to point at an adversary event in this shape: the operator is observing the chain's tampered state and terminating it, not extending the adversary's chain.

  ```
  Pre-state (adversary-extended linear chain; operator's last attested
  event is v_{N-1}; v_N..v_M are adversary events):

    ... → v_{N-1} → v_N_adv → v_{N+1}_adv → ... → v_M_adv   (tip)
            ↑                                          ↑
            operator's last                            adversary-extended
            attestation                                tip

  Operator submits Cnt:
    cnt.previous = v_{tip-1}.said = v_{M-1}_adv.said
    cnt.version  = M

  Post-state (fresh divergence at v_M; privileged-divergence fires):

    ... → v_{N-1} → ... → v_{M-1}_adv ─┬─ v_M_adv ┐
                                       └─ Cnt     ┴── contested-terminal

  Cnt's previous points at an adversary event (v_{M-1}_adv). This is
  the termination exception: Cnt is repudiation, not endorsement; the
  operator is not attesting to v_{M-1}_adv's acceptability as a parent
  for further evolution — there is no further evolution after Cnt.
  ```

- **Dec in practice extends only attested state.** `Dec` means clean retirement, which is not the operator's response to an adversary-extended chain. The operator's response to adversary extension is `Cnt`, not `Dec`. So while Dec is termination-class by semantics, in practice an operator's Dec only extends their own attested tip.

#### Implications

- **SEL pre-Icp camping response (endorsement-class).** When an adversary submits `[Icp, Est_stale]` first, the operator's response is `[Icp, Est_legit]` with `Est_legit.previous = Icp.said` (extending `Icp` via dedup-equivalence), **not** `previous = Est_stale.said`. `Est_legit` is endorsement-class; pointing it at `Est_stale` would attest to `Est_stale`'s acceptability as a parent. The construction creates a non-privileged divergent set at `v_1`; the operator resolves via `Rpr` extending their `Est_legit` branch.

- **KEL/SEL divergence resolution (endorsement-class).** The operator's `Rec` (KEL) or `Rpr` (SEL) extends either the divergence ancestor `v_{d-1}` (attested-shared; divergence-ancestor-extending shape, lands at `v_d`) or their own existing branch tip at `v_d` (own attestation; branch-tip-extending shape, lands at `v_{d+1}`). The operator never points an endorsement-class `Rec`/`Rpr` at the other branch's tip. The "whoever holds the recovery/governance key dictates which branch survives" language reduces to "the operator extends their own branch or `v_{d-1}`."

- **Cnt placement (termination-class; exception to the no-extend-adversary rule).** `Cnt.previous = v_{tip-1}.said` resolves uniformly across linear and divergent shapes. On a linear chain with no adversary extension, `v_{tip-1}` is the parent of the operator's own tip. On a divergent chain, `v_{tip-1}` is `v_{d-1}` (the divergence ancestor; attested-shared by the divergence invariant). On an adversary-extended linear chain, `v_{tip-1}` may be an adversary event — Cnt's repudiation semantic makes this coherent, per the diagram above.

- **Endorsement-class events never extend adversary content.** This rule is structurally absolute. Termination-class events follow the protocol's structural parent rule unconditionally, with the only practical case where `previous` lands on an adversary event being `Cnt` on a multi-event adversary-extended linear chain. When prose anywhere in the design or analysis docs claims an operator's endorsement-class event linearly extends an adversary event, the prose is wrong by construction.

#### Cross-primitive symmetry

The discipline is structurally identical across the three primitives. The shapes of "own previous tip" and "attested-shared state" instantiate differently per primitive (KEL: `v_{d-1}` and own-branch tips; IEL: `v_{d-1}` only — every event is governance-authorized so there are no auth-only operator-extension paths; SEL: `v_{d-1}`, `Icp` via dedup, and own-branch tips), but the underlying principle — operators attest only to their own content or to genuinely shared state, with termination events following the structural parent rule unconditionally — applies without primitive-specific exception.

---

## Part 3: Verification Mechanics

The implementation invariants that make Part 1's security invariants enforceable. Verification tokens, advisory locks, and inline reference checking are the patterns by which "the database cannot be trusted" gets converted into safe operations — verification and use happen in the same pass, under the same lock, against the same trusted context.

### Verification tokens as proof of verification

Functions that consume chain data accept a verification token (`&KelVerification`, `&IelVerification`, `&SelVerification`) as a parameter. Holding the token proves the corresponding chain was verified. Token fields are private with no public constructor — the only way to obtain one is through the corresponding verifier (`KelVerifier`, `IelVerifier`, `SelVerifier`).

### Merge Verification

When merging new events into an existing chain (submit handler), first verify the entire existing chain in the DB using the corresponding verifier with paginated reads under an advisory lock. Obtain a trusted verification token from the verifier and use that token's data as the context for verifying the new incoming events — never re-query the DB between verification and use. The pattern applies uniformly across KEL, IEL, and SEL submit paths.

### Inline reference checking

Each verifier supports registering SAIDs of interest before the walk so the walk records what it observed without separate DB queries. KEL registers anchor SAIDs (KEL ixns observed at IEL/SEL Icp time and similar binding points); IEL and SEL register caller-cared-about SAIDs for satisfaction tracking. Registration happens before the walk; results are available on the verification token. The pattern eliminates a second DB pass for SAID-presence questions.

### Advisory Locking

All verify-then-write paths hold PostgreSQL advisory locks for the duration of both verification and write. Per-primitive locked-transaction types implement the corresponding `PageLoader` trait by reading under the advisory lock; the same transaction is then used for the write. This eliminates time-of-check-to-time-of-use vulnerabilities. Applies uniformly across KEL, IEL, and SEL submit paths.
