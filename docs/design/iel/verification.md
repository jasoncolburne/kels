# IEL Verification Protocol

Source-of-truth for the algorithm that validates Identity Event Log (IEL) chains. The IEL counterpart to [../sel/verification.md](../sel/verification.md) and [../kel/verification.md](../kel/verification.md).

## Overview

IEL verification ensures:
- Events match their explicit per-kind schemas (`IdentityEvent::validate_structure`)
- Versions start at 0 and increment by 1 with no gaps
- The inception event has a valid prefix (derives from `(auth_policy, governance_policy, topic)`)
- All event prefixes match
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from current state to inception via `previous` links
- `Icp` is anchored under its declared `auth_policy` (self-authorization)
- `Evl` / `Cnt` / `Dec` are anchored under the branch's tracked `governance_policy`
- Any policy referenced as `auth_policy` or `governance_policy` (introduced at Icp or evolved via Evl) has `immune: true` — the verifier rejects the chain otherwise as a structural error (policy immunity rule; see [event-log.md §Evaluation Seal and Anchor Non-Poisonability](event-log.md#evaluation-seal-and-anchor-non-poisonability))

Events are linked by their `previous` SAID. Version is the position in the chain (inception is version 0).

Like SEL, IEL has no per-event signature — authorization is via the *anchoring model*: `auth_policy` and `governance_policy` resolve to KEL prefixes whose `ixn` events anchor the IEL event's SAID. The verifier resolves these policies through a `PolicyChecker` that fetches and verifies the anchoring KEL events on demand.

## Verification Algorithm

`IelVerifier` (`lib/kels/src/types/iel/verification.rs`) processes events in a single forward pass, verifying structure and policy satisfaction simultaneously. Events must arrive in `version ASC, kind sort_priority ASC, said ASC` order.

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

    // 4. Version continuity
    if event.version != expected_version:
        return Error("Version gap or regression")

    // 5. Chain continuity (previous pointer matches a known branch tip)
    match event to a branch via event.previous
    if no matching branch:
        return Error("Previous SAID not found")

    // 6. Topic consistency
    if event.topic != branch.topic:
        return Error("Topic mismatch")
```

### Generation Processing

Events at the same version form a **generation**. The verifier processes all events in a generation together:

```
verify_generation(events_at_version):
    if events_at_version.len() > branches.len():
        // More events than branches = divergence detected
        fork BranchState for new branches
        record diverged_at_version if first divergence

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
        Icp           → self_satisfies(event)  // anchored under event.auth_policy
        Evl           → satisfies(event, branch.tracked_governance_policy)
        Cnt, Dec      → satisfies(event, branch.tracked_governance_policy)

    PolicyChecker resolves the policy by SAID, then evaluates anchoring:
    each Endorse(KEL_PREFIX) node in the policy must have an ixn anchor
    in the named KEL anchoring this event's SAID.
```

Policy state is **branch-tracked**:

- `tracked_auth_policy` — seeded from v0's `auth_policy` declaration *after* the verifier confirms (a) the policy is immune (see Immunity check below) and (b) Icp.said is anchored under it. Updated whenever an authorized `Evl` carries a new `auth_policy` (subject to the same immunity check on the new policy).
- `tracked_governance_policy` — seeded from v0's `governance_policy` declaration. Updated whenever an authorized `Evl` carries a new `governance_policy`. Subject to the immunity check on every introduction or evolution.

**Immunity check.** Whenever `tracked_auth_policy` or `tracked_governance_policy` is seeded or updated, the verifier fetches the referenced policy and confirms `immune: true`. A non-immune policy referenced as either is a structural error and the chain is rejected. This mirrors the merge-time check (see [merge.md](merge.md#1-structural-and-authorization-validation)) — both submit and verify enforce the rule because the verifier processes data from any source (gossip, peer pulls, restored backups, bootstrap) and cannot trust that the originating node enforced it.

Authorization checks use the *previous tracked* policy values for `Evl` (an Evl evolving auth_policy is itself authorized by the prior `tracked_governance_policy`, not by the new one it's introducing). This prevents an actor with auth-only authority from elevating themselves.

## Verification Return Value

`IelVerifier::finish()` produces an `IelVerification` token — the proof-of-verification type:

```
IelVerification:
    prefix: Digest256
    branches: Vec<BranchTip>            // 1 = linear, 2 = divergent
    diverged_at_version: Option<u64>
    is_contested: bool
    is_decommissioned: bool
    last_governance_version: Option<u64>  // version of most recent Evl
```

Accessors:

- `current_event()` → `None` if divergent
- `prefix()`, `topic()`
- `auth_policy_at(event_said)` — the auth_policy declared/evolved at the named IEL event (used by SE verification to resolve `identity_event` bindings)
- `governance_policy_at(event_said)` — same, for governance_policy
- `policy_satisfied()` — overall policy satisfaction across the chain
- `last_governance_version()`
- `is_contested()`, `is_decommissioned()`, `diverged_at_version()`

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix derivation | Inception prefix recomputed from `(auth_policy, governance_policy, topic)` and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | `previous` field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Version monotonicity | Each event's version equals predecessor's version + 1 |
| Inception version | Inception (no `previous`) must have version 0 |
| Topic consistency | All events on a branch share the same topic |
| `auth_policy` satisfaction at Icp | `evaluate_anchored_policy(event.auth_policy, event.said)` |
| `governance_policy` satisfaction | `evaluate_anchored_policy(branch.tracked_governance_policy, event.said)` for Evl/Cnt/Dec |
| Policy immunity | Every introduced/evolved auth_policy or governance_policy must have `immune: true` |

Note: There is no content-preservation rule (IEL has no `content` field). There is no proactive-evaluation bound (every IEL event after Icp is governance-authorized — implicit bound).

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `IelVerification` token (`is_divergent()`, `diverged_at_version()`)
- Both branches of a divergent chain are verified independently (the verifier forks `BranchState` per branch)
- The submit handler resolves divergence via `Cnt` (see [merge.md](merge.md)). There is no `Rpr` on IEL; divergent chains stay divergent until contested.

## Streaming Verification (IelVerifier)

`IelVerifier` walks forward through events page by page, verifying integrity and policy satisfaction without loading the full chain into memory. It supports both linear and divergent chains by tracking per-branch state.

```
struct IelVerifier {
    prefix: Digest256,
    checker: Arc<dyn PolicyChecker>,
    branches: HashMap<Digest256, BranchState>,   // keyed by tip SAID
    last_verified_version: Option<u64>,
    diverged_at_version: Option<u64>,
    is_contested: bool,
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
3. Version continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure`)
6. Topic consistency
7. Policy satisfaction via `PolicyChecker` (auth_policy at Icp; governance_policy for Evl/Cnt/Dec)
8. Immunity check on policy seed/update

## Cross-Chain Use: SE Authorization Resolution

SE verification depends on IEL verification for resolving `identity_event` bindings. The flow:

1. SE event has `identity_event = IEL_X.said`.
2. SE verifier (or merge handler) needs to know "what auth_policy or governance_policy was declared/evolved at IEL_X?"
3. The IEL is fetched (or already cached). `IelVerification` is loaded or computed.
4. `auth_policy_at(IEL_X.said)` (or `governance_policy_at(...)`) returns the relevant policy SAID.
5. SE event's anchor is verified against that policy.

The IEL verifier produces these accessors as part of its normal verification output. SE verification is a consumer of IEL verification, not an inverter or re-implementor.

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, immunity rule.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [events.md](events.md) — Per-kind structural rules.
- [../sel/verification.md](../sel/verification.md) — SE verification (consumer of IEL verification for binding resolution).
- [../policy.md](../policy.md) — Policy DSL and anchoring model.
- [../streaming-verification-architecture.md](../streaming-verification-architecture.md) — Cross-side streaming-verification architecture.
- [../kel/verification.md](../kel/verification.md) — KEL counterpart.
