# SEL Verification Protocol

This document describes the verification protocol used to validate the integrity and authorization of a SAD Event Log (SEL). It is the SEL counterpart to [../iel/verification.md](../iel/verification.md) and [../kel/verification.md](../kel/verification.md).

## Overview

SEL verification ensures:
- Events match their explicit per-kind schemas (`SadEvent::validate_structure`)
- Versions start at 0 and increment by 1 with no gaps
- The inception event has a valid prefix (derives from `(identity, topic)`)
- All event prefixes match
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from current state to inception via `previous` links
- Topic is consistent across the chain
- The content-preservation rule holds (Sea/Rpr/Cnt/Dec must carry forward `previous.content`)
- The proactive-evaluation rule holds (`MAX_NON_EVALUATION_EVENTS = 63`)
- Every v1+ event's `identity_event` references a real IEL event in the chain bound at inception (`prefix == identity`)
- Authorization for v1+ events resolves through the bound IEL event's declared/evolved policy:
  - `Upd` → IEL's tracked `auth_policy` at the bound event
  - `Sea` / `Rpr` / `Cnt` / `Dec` → IEL's tracked `governance_policy` at the bound event
- Anchoring of the SE event's SAID under the resolved IEL policy
- Monotonic-on-SE-chain: each event's `identity_event` is at-or-after the chain's prior `last_identity_event` in IEL chain order

Events are linked by their `previous` SAID. Version is the position in the chain (inception is version 0).

Like IEL and today's SEL, authorization is via the *anchoring model*: policies resolve to KEL prefixes whose `ixn` events anchor the SE event's SAID. The verifier resolves the IEL-side policies through a `PolicyChecker` extended for cross-chain resolution.

## Verification Algorithm

`SelVerifier` (`lib/kels/src/types/sad/verification.rs`) processes events in a single forward pass. Events must arrive in `version ASC, kind sort_priority ASC, said ASC` order with complete generations.

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

    // 5. Chain continuity
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
        verify cross-chain authorization for that branch (v1+ events)
```

### Authorization Resolution (v1+ events)

When an event requires authorization, the verifier resolves through the bound IEL event:

```
verify_authorization(event, branch):
    // Inception is permissionless — no authorization gate at v0
    if event.kind == Icp:
        return Ok

    // Confirm identity_event references a real IEL event with matching prefix
    iel_event = checker.fetch_iel_event(branch.identity, event.identity_event)
    if iel_event is None or iel_event.prefix != branch.identity:
        return Error("identity_event does not resolve to bound IEL")

    // Pick the relevant policy from the IEL event
    policy = match event.kind:
        Upd                  → iel_event.auth_policy_or_carried_forward
        Sea, Rpr, Cnt, Dec   → iel_event.governance_policy_or_carried_forward

    // The IEL event must declare/evolve the relevant policy.
    // (Cross-chain helper resolves "the auth_policy that was tracked at IEL_X" —
    //  if iel_event itself doesn't carry the field, walk back through IEL until
    //  finding the most recent event that did.)

    // Verify the SE event's anchoring under that policy
    if !checker.evaluate_anchored_policy(policy, event.said):
        return Error("Authorization failed")

    // Monotonic ratchet
    if event.identity_event ranks before branch.last_identity_event in IEL order:
        return Error("identity_event regression — non-monotonic")
    branch.last_identity_event = event.identity_event
```

The "ranks before" comparison requires walking the IEL chain (or comparing cached per-event-version metadata). The IEL is structurally a linear chain (or divergent — in which case the bound event must be on a single resolvable branch).

### Inception Batch Rule (verifier-level note)

The inception batch rule `[Icp, Upd]` minimum is enforced at the **submit handler**, not in the verifier per se. The verifier walks events as they exist; if the chain has only an `Icp` with no v1, that's "incomplete" rather than "invalid." The submit handler is what prevents an Icp-alone batch from landing in storage in the first place. See [merge.md](merge.md).

### Branch State

```
struct SadBranchTip {
    tip: SadEvent,                        // current tip event
    identity: Digest256,                  // bound IEL prefix (set at Icp)
    last_identity_event: Option<Digest256>, // ratchet — highest IEL event bound across the branch
    events_since_evaluation: u64,
    last_governance_version: Option<u64>,
}
```

There is **no** `tracked_write_policy` or `tracked_governance_policy` on SE branch state. Authorization policies live on IEL; SE branch state holds only the binding (`identity`) and the ratchet (`last_identity_event`).

## Verification Return Value

`SelVerifier::finish()` produces a `SelVerification` token:

```
SelVerification:
    prefix: Digest256
    branches: Vec<BranchTip>            // 1 = linear, 2 = divergent
    diverged_at_version: Option<u64>
    is_contested: bool
    is_decommissioned: bool
    last_governance_version: Option<u64>  // version of most recent Sea/Rpr
    last_identity_event: Option<Digest256> // chain's highest-bound IEL event
```

Accessors:

- `current_event()` → `None` if divergent
- `current_content()` → `None` if divergent
- `prefix()`, `topic()`, `identity()` → the bound IEL prefix
- `last_identity_event()` → the chain's highest-bound IEL event (across branches)
- `policy_satisfied()` — overall authorization satisfaction across the chain
- `last_governance_version()`
- `is_contested()`, `is_decommissioned()`, `diverged_at_version()`

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix derivation | Inception prefix recomputed from `(identity, topic)` and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | `previous` field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Version monotonicity | Each event's version equals predecessor's version + 1 |
| Inception version | Inception (no `previous`) must have version 0 |
| Topic consistency | All events on a branch share the same topic |
| `identity_event` binding | Resolves to an IEL event with matching prefix |
| Authorization | `evaluate_anchored_policy(IEL-resolved-policy, event.said)` |
| Monotonic identity ratchet | `event.identity_event >= branch.last_identity_event` in IEL chain order |
| Content preservation | `event.content == previous.content` for Sea/Rpr/Cnt/Dec |
| Proactive evaluation | At most `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events between Sea/Rpr/Cnt/Dec |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `SelVerification` token (`is_divergent()`, `diverged_at_version()`)
- Both branches of a divergent chain are verified independently (the verifier forks `BranchState` per branch)
- The submit handler resolves divergence via `Rpr` (see [merge.md](merge.md))

## Streaming Verification (SelVerifier)

`SelVerifier` walks forward through events page by page, verifying integrity and authorization without loading the full chain into memory.

```
struct SelVerifier {
    prefix: Digest256,
    checker: Arc<dyn PolicyChecker>,    // extended to resolve IEL events for binding
    branches: HashMap<Digest256, BranchState>,
    last_verified_version: Option<u64>,
    diverged_at_version: Option<u64>,
    is_contested: bool,
    is_decommissioned: bool,
    ...
}
```

### Constructors

- `SelVerifier::new(Some(prefix), checker)` — Start from inception. Full verification of untrusted chains.
- `SelVerifier::resume(prefix, &SelVerification, checker)` — Resume from a verified `SelVerification` token. Used by the submit handler's discriminator path to verify a single page without re-verifying the whole chain.

### PolicyChecker extension

The `PolicyChecker` trait (post-Gap-0 shape: `is_anchored(said, policy)` + `is_immune(policy)`, defined in `lib/kels/src/types/policy_checker.rs`) is extended with cross-chain helpers for SE binding resolution:

```rust
trait PolicyChecker: Send + Sync {
    // Base methods (Gap 0 — defined for KEL/IEL/SEL):
    async fn is_anchored(&self, said: &Digest256, policy: &Digest256)
        -> Result<bool, KelsError>;
    async fn is_immune(&self, policy: &Digest256)
        -> Result<bool, KelsError>;

    // Cross-chain: fetch a specific IEL event by SAID
    async fn fetch_iel_event(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<IdentityEvent, KelsError>;

    // Cross-chain: resolve the tracked policy at an IEL event (walks back from
    // the named event, finding the most recent prior IEL event that established
    // the relevant policy field — auth_policy or governance_policy)
    async fn resolve_auth_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;
    async fn resolve_governance_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;
}
```

The SE merge handler does NOT separately re-check `is_immune` on IEL-resolved policies. The IEL primitive's submit and verification gates are the canonical immunity enforcement; calling it again at SE-side would be defense-in-depth that drifts. SE trusts the IEL gate. (`is_immune` remains on the trait for IEL's own use — both at IEL submit time and IEL verification time.)

The implementations cache aggressively: one IEL event fetch per binding; tracked-policy resolution memoized per `(identity, iel_event_said, policy_kind)` triple.

### Paginated Verification Helpers

Two top-level helpers in `lib/kels/src/types/sad/sync.rs`:

- **`verify_sad_events(client, prefix, checker)`** — Pages through a remote SADStore, verifying each page. Returns a trusted `SelVerification` token.
- **`sel_completed_verification(loader, prefix, page_size, max_pages)`** — Pages through a `SelPageLoader`, calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations spanning pages.

## Path-Agnostic Validation

The validation rules above apply identically at submit, gossip ingestion, bootstrap, and re-verification. KELS data is path-agnostic — a SE event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. See [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules) for the cross-chain rationale.

## References

- [event-log.md](event-log.md) — Chain lifecycle, repair, contest, decommission.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [events.md](events.md) — Per-kind structural rules.
- [../iel/verification.md](../iel/verification.md) — IEL counterpart (provides binding resolution for SE).
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle (immunity rule, anchor stability).
- [../policy.md](../policy.md) — Policy DSL and anchoring model.
- [../streaming-verification-architecture.md](../streaming-verification-architecture.md) — Cross-side streaming-verification architecture.
- [../kel/verification.md](../kel/verification.md) — KEL counterpart.
