# IEL Verification Protocol

Source-of-truth for the algorithm that validates Identity Event Log (IEL) chains. The IEL counterpart to [../sel/verification.md](../sel/verification.md) and [../kel/verification.md](../kel/verification.md).

## Overview

IEL verification ensures:
- Events match their explicit per-kind schemas (`IdentityEvent::validate_structure`)
- Versions start at 0 and increment by 1 with no gaps
- The inception event has a valid prefix (derives from `(authPolicy, governancePolicy, nonce)`)
- All event prefixes match
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from current state to inception via `previous` links
- `Icp` is anchored under its declared `governancePolicy` (self-governance-endorsement — every IEL event is a governance act)
- `Evl` / `Dec` are anchored under the branch's tracked `governancePolicy`
- Any policy referenced as `authPolicy` or `governancePolicy` (introduced at Icp or evolved via Evl) has `immune: true` — the verifier rejects the chain otherwise as a structural error (policy immunity rule; see [event-log.md §Evaluation Seal and Policy Immunity](event-log.md#evaluation-seal-and-policy-immunity))

Events are linked by their `previous` SAID. Serial is the position in the chain (inception is serial 0).

Like SEL, IEL has no per-event signature — authorization is via the *anchoring model*: `authPolicy` and `governancePolicy` resolve to KEL prefixes whose `ixn` events anchor the IEL event's SAID. The verifier resolves these policies through a `PolicyChecker` that fetches and verifies the anchoring KEL events on demand.

The verifier answers a single question: **is this chain shape structurally authentic?** Consumer trust ("should I trust authorization claims from this chain?") is a separate concern handled at the auth/policy layer through `policy_satisfied`, soft-fail propagation, and `satisfied_saids` (see [event-log.md §Divergence, Contestation, and the Trust Layer](event-log.md#divergence-contestation-and-the-trust-layer)). The verifier accepts divergent chains as structurally valid regardless of whether the divergence arose from federation race or threshold compromise; the trust layer applies the consumer-side semantics on top of the authenticated data.

## Verification Algorithm

`IelVerifier` (`lib/kels/src/types/iel/verification.rs`) processes events in a single forward pass, verifying structure and policy satisfaction simultaneously. Events must arrive in `serial ASC, kind sort_priority ASC, said ASC` order.

### Per-Event Checks

For each event in a page:

```
verify_event(event):
    // 1. SAID and prefix integrity
    event.verify()  // Inception: verify both prefix and SAID; subsequent: verify SAID

    // 2. Prefix consistency
    if event.prefix != verifier.prefix:
        return Error("Prefix mismatch")

    // 3. Structure validation
    IdentityEvent::validate_structure(event)  // per-kind field rules

    // 4. Serial continuity
    if event.serial != expected_serial:
        return Error("Serial gap or regression")

    // 5. Chain continuity (previous pointer matches a known branch tip)
    match event to a branch via event.previous
    if no matching branch:
        return Error("Previous SAID not found")

```

### Generation Processing

Events at the same serial form a **generation**. The verifier processes all events in a generation together:

```
verify_generation(events_at_serial):
    if events_at_serial.len() > branches.len():
        // More events than branches = divergence detected
        fork BranchState for new branches
        record divergenceAncestor (the SAID of v_{d-1}) if first divergence

    for each event:
        match to branch via event.previous
        verify policy satisfaction for that branch
```

Maximum 2 events per generation. v0 divergence is rejected outright.

### Policy Resolution

When an event requires policy satisfaction, the verifier resolves the relevant policy via the `PolicyChecker`:

```
verify_policy(event, branch):
    match event.kind:
        Icp           → self_satisfies(event)  // anchored under event.governancePolicy; tier-2 (Rot anchor)
        Evl           → satisfies(event, branch.trackedGovernancePolicy)  // tier-2 (Rot anchor)
        Dec           → satisfies(event, branch.trackedGovernancePolicy)  // tier-3 (Ror anchor)

    PolicyChecker resolves the policy by SAID, then evaluates anchoring:
    each Endorse(KEL_PREFIX) and Delegate(KEL_PREFIX) leaf node in the
    policy must have an anchor of the required kind (Ixn / Rot / Ror per
    the event's tier — see [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation))
    in the named KEL anchoring this event's SAID. Wrong-kind anchor for a
    leaf evaluates as unsatisfied.
```

Policy state is **branch-tracked**. Two fields:

- `trackedAuthPolicy`
  - *Seeded by* `Icp.authPolicy` after the immunity check (below).
  - *Updated by* any authorized `Evl` carrying a new `authPolicy`, subject to the immunity check.
  - *Consumed by* SEL `Upd` / `Est` via `ielEvent` binding; never authorizes IEL events themselves.

- `trackedGovernancePolicy`
  - *Seeded by* `Icp.governancePolicy` after the immunity check AND after the verifier confirms `Icp.said` is anchored under the declared policy (the self-endorsement check).
  - *Updated by* any authorized `Evl` carrying a new `governancePolicy`, subject to the immunity check.
  - *Consumed by* every IEL event's authorization gate plus SEL `Sea`/`Rpr`/`Dec` via `ielEvent` binding.

**Immunity check.** Whenever `trackedAuthPolicy` or `trackedGovernancePolicy` is seeded or updated, the verifier fetches the referenced policy and confirms `immune: true`. A non-immune policy referenced as either is a structural error; the chain is rejected. Mirrors the merge-time check (see [merge.md](merge.md#1-structural-and-authorization-validation)); both layers enforce because the verifier processes data from any source (gossip, peer pulls, restored backups, bootstrap) and cannot trust that the originating node enforced it.

> **Evolution authorization uses the *previous* tracked policy.** An `Evl` evolving `authPolicy` is itself authorized by the prior `trackedGovernancePolicy`, not by the new one it's introducing. This prevents an actor with auth-only authority from elevating themselves to governance authority.

### Terminal-state determination and authorization

All events on IEL require HARD anchor: a `Dec` whose governance check fails is rejected at the verifier; the chain stays at its prior state. Structural integrity rules — SAID validity, serial monotonicity, immunity check on policy evolution — stay HARD as well.

The verifier's terminal-state-determination rule on IEL is structural:
- Divergent at `v_d`? **Yes → contested (terminal).** Every IEL event is privileged, so any divergent set on IEL contains a privileged event by construction; privileged-divergence-is-terminal fires at first 2-event observation. The "divergent-but-not-yet-contested" intermediate state doesn't arise on IEL; it exists for KEL (non-privileged Rot/Ixn divergence, recoverable via `Rec`) and SEL (non-privileged Upd divergence, recoverable via `Rpr`).
- Linear with a `Dec` event present? Decommissioned (terminal-via-Dec).
- Linear without `Dec`? Active.

### Contested-state derivation

On IEL, the contested chain state is derived structurally from divergence: `is_contested ⇔ is_divergent`. Every IEL event is privileged, so the verifier sets `is_contested = true` whenever it observes a divergent set. Both accessors are exposed for cross-primitive API symmetry with KEL and SEL — `is_contested()` wraps `is_divergent()` on IEL. On KEL and SEL the two diverge: a non-privileged divergent set is `is_divergent` without being `is_contested` until a non-archiving privileged event joins via the upgrade rule.

The handler-level rejection on contested/decommissioned chains is a separate seam that prevents new submits; this verifier-level mechanism handles events that reach the verifier some other way (gossip-pulled chains where the local node hadn't yet observed the terminal, resume from a stored chain that contains a terminal).

### Caller-bounded SAID querying

The chain-wide `policy_satisfied: bool` answers "is the chain currently authoritative" in aggregate, but consumers — notably the SEL verifier when resolving `ielEvent` bindings — need to ask about specific events: "is THIS IEL event valid for SEL to bind under, and what `authPolicy` / `governancePolicy` was tracked there?" The verifier exposes a caller-bounded query pattern mirroring `KelVerification`:

- Caller provides `queried_saids: BTreeSet<Digest256>` up-front — the IEL event SAIDs the caller cares about.
- During the chain walk, for each event whose SAID appears in `queried_saids`:
  - If the event is on the pre-divergence shared portion of the chain (or the chain is non-divergent) AND auth-passed, the verifier adds the SAID to `satisfied_saids`.
  - The verifier snapshots the event's tracked `(authPolicy, governancePolicy)` into a SAID-keyed map, available post-verification via `auth_policy_at(said)` / `governance_policy_at(said)`.
- For events NOT in `queried_saids`, the verifier still performs anchor checks during the walk (chain-validity requires it) but does not retain per-event policy state — branch state's running `trackedAuthPolicy` / `trackedGovernancePolicy` is sufficient for in-flight checks. No snapshot is kept post-verification; `auth_policy_at(said)` / `governance_policy_at(said)` return `None` for any SAID outside `queried_saids`.

The pattern is bounded by what the caller asks about, not by chain size — verification doesn't accumulate the universe of chain SAIDs or the universe of per-event policy state. The SEL verifier collects `ielEvent` references from its own chain walk in a pre-pass, passes them as `queried_saids` to the IEL verification, and uses `is_said_satisfied` + `auth_policy_at` / `governance_policy_at` to resolve each binding. Same shape as KEL's `is_said_anchored`. Token memory is `O(|queried_saids|)`, not `O(chain length)`. Callers that need post-hoc resolution for SAIDs they didn't declare go through `IelResolver` directly.

## Verification Return Value

`IelVerifier::finish()` produces an `IelVerification` token — the proof-of-verification type:

```
IelVerification:
    prefix: Digest256
    branches: Vec<BranchTip>                 // 1 = linear, 2 = divergent
    divergenceAncestor: Option<Digest256>   // SAID of v_{d-1} on a divergent chain (None on linear)
    is_contested: bool                       // derived: branches.len() > 1 (equivalent to is_divergent on IEL)
    is_decommissioned: bool
    lastSealAdvancingEvent: Option<Digest256> // SAID of most recent Evl
    queried_saids: BTreeSet<Digest256>       // caller-declared SAIDs of interest
    satisfied_saids: BTreeSet<Digest256>     // verifier-populated subset (auth-passed, pre-divergence)
    // policy_history: BTreeMap<Digest256, (Digest256, Digest256)> — caller-bounded by queried_saids
```

Accessors:

- `current_event()` → `None` if divergent
- `prefix()`
- `auth_policy_at(event_said)` — SAID of the `authPolicy` tracked at the named IEL event, IF `event_said` was pre-declared in `queried_saids`. Returns `None` for SAIDs outside `queried_saids` (caller-bounded; see §Caller-Bounded SAID Querying). Used by SEL verification to resolve `ielEvent` bindings.
- `governance_policy_at(event_said)` — same, for governancePolicy.
- `policy_satisfied()` — overall policy satisfaction across the chain.
- `lastSealAdvancingEvent()` — SAID of the most recent `Evl` (the evaluation seal).
- `divergenceAncestor()` — SAID of `v_{d-1}` on a divergent chain (`None` on linear).
- `is_divergent()` — `branches.len() > 1`.
- `is_contested()` — equivalent to `is_divergent()` on IEL; wraps it for cross-primitive API symmetry (see §Contested-state derivation above).
- `is_decommissioned()` — `true` when the linear branch tip is a `Dec` event (a contested chain is not also decommissioned — divergence is contested-terminal on IEL by privileged-divergence-is-terminal, so no subsequent `Dec` can land on a contested chain).
- `effective_tail_said()` — deterministic per-prefix SAID used for cross-node convergence. Single branch (active or terminal-via-Dec): tip event SAID. Contested (= divergent): `hash_effective_said("contested:{prefix}")`. None for the empty chain. Mirrors KEL's contested shape per `lib/kels/src/types/kel/verification.rs:142-158`; the KEL "divergent, not-yet-contested" branch has no IEL analog because divergent IEL is always contested.

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix derivation | Inception prefix recomputed from `(authPolicy, governancePolicy, nonce)` and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | `previous` field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Serial monotonicity | Each event's serial equals predecessor's serial + 1 |
| Inception serial | Inception (no `previous`) must have serial 0 |
| `governancePolicy` satisfaction at Icp | `evaluate_anchored_policy(event.governancePolicy, event.said)` (self-governance-endorsement) |
| `governancePolicy` satisfaction | `evaluate_anchored_policy(branch.trackedGovernancePolicy, event.said)` for Evl/Dec |
| Policy immunity | Every introduced/evolved authPolicy or governancePolicy must have `immune: true` |

Note: There is no content-preservation rule (IEL has no `content` field). There is no proactive-evaluation bound (every IEL event is governance-authorized — implicit bound).

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `IelVerification` token (`is_divergent()`, `divergenceAncestor()`, `is_contested()` — all equivalent on IEL).
- Both branches of a divergent chain are verified independently (the verifier forks `BranchState` per branch).
- Divergence is contested-terminal on IEL by the privileged-divergence-is-terminal rule (every IEL event is privileged); there is no `Rpr` to resolve it. The chain stays divergent forever as forensic record; the operator's recourse is reincept under a new prefix. See [merge.md §Terminal-State Gate](merge.md#2-terminal-state-gate).

## Streaming

IEL verification follows the cross-primitive streaming pattern (see [../../../../protocol-doctrine.md §Streaming](../../../../protocol-doctrine.md#streaming)). Verifier type: `IelVerifier`. Proof-of-verification token: `IelVerification`. Per-IEL specifics: every IEL event is governance-authorized so divergent sets are immediately contested-terminal at first 2-event observation — branches max out at 2 in the divergent case but the chain never returns to a single-tip recovered state on IEL (no `Rpr`); the verifier resolves policy satisfaction via a `PolicyChecker` against the bound KEL anchors; caller-bounded SAID querying against `queried_saids` mirrors KEL's inline anchor checking.

`IelVerifier` walks forward through events page by page, verifying integrity and policy satisfaction without loading the full chain into memory. It supports both linear and divergent chains by tracking per-branch state.

```
struct IelVerifier {
    prefix: Digest256,
    checker: Arc<dyn PolicyChecker>,
    branches: HashMap<Digest256, BranchState>,   // keyed by tip SAID
    last_verified_serial: Option<u64>,
    divergenceAncestor: Option<Digest256>,
    is_contested: bool,                          // derived: branches.len() > 1 (equivalent to is_divergent on IEL)
    is_decommissioned: bool,
    ...
}
```

### Constructors

- `IelVerifier::new(Some(prefix), checker)` — Start from inception. Full verification of untrusted chains.
- `IelVerifier::resume(prefix, &IelVerification, checker)` — Resume from a verified `IelVerification` token. Symmetric to `KelVerifier::resume` and `SelVerifier::resume`.

### Usage

```rust
let mut verifier = IelVerifier::new(Some(&prefix), checker);
loop {
    let (events, has_more) = source.fetch_page(prefix, since, limit).await?;
    verifier.verify_page(&events).await?;
    if !has_more { break; }
    since = events.last().map(|e| &e.said);
}
let verification = verifier.finish().await?;
```

### Per-Event Checks

1. SAID integrity (`event.verify()`)
2. Prefix matches verifier's prefix
3. Serial continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure`)
6. Topic consistency
7. Policy satisfaction via `PolicyChecker` (`governancePolicy` for every kind — Icp anchored under its declared `governancePolicy`; Evl/Dec anchored under the branch's tracked `governancePolicy`)
8. Immunity check on policy seed/update

## Cross-Chain Use: SEL Authorization Resolution

SEL verification depends on IEL verification for resolving `ielEvent` bindings. The flow:

1. SEL event has `ielEvent = IEL_X.said`.
2. SEL verifier (or merge handler) needs to know "what authPolicy or governancePolicy was declared/evolved at IEL_X?"
3. The IEL is fetched (or already cached). `IelVerification` is loaded or computed.
4. `auth_policy_at(IEL_X.said)` (or `governance_policy_at(...)`) returns the relevant policy SAID.
5. SEL event's anchor is verified against that policy.

The IEL verifier produces these accessors as part of its normal verification output. SEL verification is a consumer of IEL verification, not an inverter or re-implementor.

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, immunity rule.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [events.md](events.md) — Per-kind structural rules.
- [../sel/verification.md](../sel/verification.md) — SEL verification (consumer of IEL verification for binding resolution).
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL and anchoring model.
- [../../../../protocol-doctrine.md §Part 3 Verification Mechanics](../../../../protocol-doctrine.md#part-3-verification-mechanics) — Cross-primitive verification doctrine (streaming, tokens, effective-SAID synthetic comparison).
- [../kel/verification.md](../kel/verification.md) — KEL counterpart.
