# SEL Verification Protocol

This document describes the verification protocol used to validate the integrity and policy-satisfaction of a SAD Event Log (SEL). It is the SEL counterpart to [../kel/verification.md](../kel/verification.md).

## Overview

SEL verification ensures:
- Events match their explicit per-kind schemas (`SadEvent::validate_structure`)
- Versions start at 0 and increment by 1 with no gaps
- The inception event has a valid prefix (derives from `write_policy` + `topic`)
- All event prefixes match
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from current state to inception via `previous` links
- `write_policy` is satisfied by anchoring (per `Endorse(KEL_PREFIX)` resolution)
- `governance_policy` is satisfied at every `Sea` / `Rpr` / `Cnt` / `Dec`
- The content-preservation rule holds (Sea/Rpr/Cnt/Dec must carry forward `previous.content`)
- The proactive-evaluation rule holds (`MAX_NON_EVALUATION_EVENTS = 63`)

Events are linked by their `previous` SAID. Version is the position in the chain (inception is version 0).

Unlike KEL, SEL has no per-event signature verification — authorization is via the *anchoring model*: `write_policy` and `governance_policy` resolve to KEL prefixes whose `ixn` events anchor the SAD event's SAID. The verifier resolves these policies through a `PolicyChecker` that fetches and verifies the anchoring KEL events on demand.

## Verification Algorithm

`SelVerifier` (`lib/kels/src/types/sad/verification.rs`) processes events in a single forward pass, verifying structure and policy satisfaction simultaneously. Events must arrive in `version ASC, kind sort_priority ASC, said ASC` order with complete generations.

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
    SadEvent::validate_structure(event)  // per-kind field rules

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

### Policy Resolution

When an event requires policy satisfaction, the verifier resolves the relevant policy via the `PolicyChecker`:

```
verify_policy(event, branch):
    policy = match event.kind:
        Icp           → event.write_policy (the policy declared at v0; no prior tracked state)
        Est, Upd      → branch.tracked_write_policy
        Sea, Rpr, Cnt, Dec → branch.tracked_governance_policy

    // Anchoring model: policy resolves to Endorse(KEL_PREFIX) nodes;
    // each must have an ixn anchor in the named KEL anchoring this event's SAID.
    PolicyChecker::evaluate_anchored_policy(policy, event.said) → bool
```

Policy state is **branch-tracked**:

- `tracked_write_policy` — seeded from v0's `write_policy` declaration *after* the verifier confirms Icp.said is anchored under it. Updated whenever an authorized `Sea` carries a new `write_policy`.
- `tracked_governance_policy` — seeded from v0's `governance_policy` (if present), or from v1's `Est` (if v0 omitted it). Updated whenever an authorized `Sea` carries a new `governance_policy`.

Authorization checks for v1+ are against the *tracked* (effective) values, not the event's own field. This prevents an adversary who satisfies the current `write_policy` from replacing the policy via an Upd-style event: policy replacement requires satisfying the stricter `governance_policy`. For v0 (Icp), the policy resolution is against the event's own declared `write_policy`, since no prior tracked state exists — the inceptor proves membership in the policy they're declaring.

### Content Preservation

Every `Sea` / `Rpr` / `Cnt` / `Dec` must satisfy `event.content == previous.content`. The verifier rejects any such event whose content differs from its predecessor's. `Upd` is the sole content-mutating kind; `Icp` and `Est` forbid content entirely.

## Verification Return Value

`SelVerifier::finish()` produces a `SelVerification` token — the proof-of-verification type:

```
SelVerification:
    prefix: Digest256
    branches: Vec<BranchTip>            // one per branch (1 = linear, N = divergent)
    diverged_at_version: Option<u64>
    is_contested: bool
    is_decommissioned: bool
    last_governance_version: Option<u64>  // version of most recent Sea/Rpr (the seal)
```

Accessors (per [../sadstore.md §Verification](../sadstore.md)):

- `current_event()` → `None` if divergent
- `current_content()` → `None` if divergent
- `prefix()`, `topic()`
- `write_policy()` → branch's tracked (effective) write policy
- `policy_satisfied()` — overall policy satisfaction across the chain
- `last_governance_version()`, `establishment_version()`
- `is_contested()`, `is_decommissioned()`, `diverged_at_version()`

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix derivation | Inception prefix recomputed from `write_policy + topic` and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | `previous` field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Version monotonicity | Each event's version equals predecessor's version + 1 |
| Inception version | Inception (no `previous`) must have version 0 |
| Topic consistency | All events on a branch share the same topic |
| `write_policy` satisfaction | `evaluate_anchored_policy(branch.tracked_write_policy, event.said)` |
| `governance_policy` satisfaction | `evaluate_anchored_policy(branch.tracked_governance_policy, event.said)` for Sea/Rpr/Cnt/Dec |
| Content preservation | `event.content == previous.content` for Sea/Rpr/Cnt/Dec |
| Proactive evaluation | At most `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events between Sea/Rpr/Cnt/Dec |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `SelVerification` token (`is_divergent()`, `diverged_at_version()`)
- All branches of a divergent chain are verified independently (the verifier forks `BranchState` per branch)
- The submit handler resolves divergence via `Rpr` (see [merge.md](merge.md))

## Streaming Verification (SelVerifier)

`SelVerifier` walks forward through events page by page, verifying integrity and policy satisfaction without loading the full chain into memory. It supports both linear and divergent chains by tracking per-branch state.

```
struct SelVerifier {
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

- `SelVerifier::new(Some(prefix), checker)` — Start from inception. Full verification of untrusted chains.
- `SelVerifier::resume(prefix, &SelVerification, checker)` — Resume from a verified `SelVerification` token. Used by the submit handler's discriminator path to verify a single page without re-verifying the whole chain. Symmetric to `KelVerifier::resume`.

### Usage

```rust
let mut verifier = SelVerifier::new(Some(&prefix), checker);
loop {
    let (events, has_more) = source.fetch_page(prefix, since, limit).await?;
    verifier.verify_page(&events).await?;
    if !has_more { break; }
    since = events.last().map(|e| &e.said);
}
let verification = verifier.finish().await?;
```

### Paginated Verification Helpers

Two top-level helpers in `lib/kels/src/types/sad/sync.rs`:

- **`verify_sad_events(client, prefix, checker)`** — Pages through a remote SADStore via `HttpSadSource`, verifying each page. Returns a trusted `SelVerification` token. Used by the builder's `repair`/`contest`/`decommission` pre-flight gate (see [event-log.md §Builder pre-flight](event-log.md) for the discriminator's use of this).
- **`sel_completed_verification(loader, prefix, page_size, max_pages)`** — Pages through a `SelPageLoader` (typically `SadStorePageLoader` over a local `SadStore`), calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations spanning pages. Returns a trusted `SelVerification` token.

The `max_pages` parameter prevents resource exhaustion (default bounded by environment).

### Per-Event Checks

1. SAID integrity (`event.verify()`)
2. Prefix matches verifier's prefix
3. Version continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure`)
6. Topic consistency
7. Content preservation (Sea/Rpr/Cnt/Dec must equal `previous.content`)
8. Policy satisfaction via `PolicyChecker` (write_policy or governance_policy per kind)

## References

- [event-log.md](event-log.md) — Chain lifecycle, evaluation seal, anchor non-poisonability.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [events.md](events.md) — Per-kind structural rules.
- [../policy.md](../policy.md) — Policy DSL and anchoring model.
- [../streaming-verification-architecture.md](../streaming-verification-architecture.md) — Cross-side streaming-verification architecture.
- [../kel/verification.md](../kel/verification.md) — KEL counterpart.
