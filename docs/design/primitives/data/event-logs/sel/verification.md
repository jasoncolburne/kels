# SEL Verification Protocol

This document describes the verification protocol used to validate the integrity and authorization of a SAD Event Log (SEL). It is the SEL counterpart to [../iel/verification.md](../iel/verification.md) and [../kel/verification.md](../kel/verification.md).

## Overview

SEL verification ensures the following, grouped by concern:

**Structural rules:**

- Events match their explicit per-kind schemas (`SadEvent::validate_structure`).
- Serials start at 0 and increment by 1 with no gaps.
- The inception event has a valid prefix (derives from `(identity, topic)`).
- All event prefixes match.
- All events have valid self-addressing identifiers (SAIDs).
- Events chain correctly from current state to inception via `previous` links.
- Topic is consistent across the chain.

**Content rules:**

- The content-preservation rule holds (`Sea`/`Rpr`/`Cnt`/`Dec` must carry forward `previous.content`).
- The proactive-evaluation rule holds (`MAX_NON_EVALUATION_EVENTS = 63`).

**Cross-chain authorization rules:**

- Every v1+ event's `ielEvent` references a real IEL event in the chain bound at inception (`prefix == identity`).
- Authorization for v1+ events resolves through the bound IEL event's declared/evolved policy:
  - `Est` / `Upd` → IEL's tracked `authPolicy` at the bound event
  - `Sea` / `Rpr` / `Cnt` / `Dec` → IEL's tracked `governancePolicy` at the bound event
- The SEL event's SAID is anchored under the resolved IEL policy.
- Per-event parent-monotonic on `ielEvent` (SEL-specific; no analog on KEL/IEL): each event's `ielEvent` is at-or-after its parent event's `ielEvent` in IEL chain order, applied per branch independently. Within-chain policy variation across SEL branches is bounded by the seal-cap and by privileged-divergence-is-terminal.

Events are linked by their `previous` SAID. Serial is the position in the chain (inception is serial 0).

Like IEL, authorization is via the *anchoring model*: policies resolve to KEL prefixes whose `ixn` events anchor the SEL event's SAID. The verifier uses two traits — `PolicyChecker` for anchor-and-immunity checks (the same trait IEL/KEL use), and `IelResolver` for cross-chain navigation into the bound IEL.

## Verification Algorithm

`SelVerifier` (`lib/kels/src/types/sad/verification.rs`) processes events in a single forward pass. Events must arrive in `serial ASC, kind sort_priority ASC, said ASC` order with complete generations.

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

    // 4. Serial continuity
    if event.serial != expected_serial:
        return Error("Serial gap or regression")

    // 5. Chain continuity
    match event to a branch via event.previous
    if no matching branch:
        return Error("Previous SAID not found")

    // 6. Topic consistency
    if event.topic != branch.topic:
        return Error("Topic mismatch")

    // 7. Sea parent-kind constraint (chain-state, requires predecessor)
    if event.kind == Sea:
        parent = lookup event.previous
        if parent.kind in {Cnt, Dec}:
            return Error("Sea parent cannot be terminal")
        if parent.kind == Sea:
            // Sea-Sea allowed on SEL only when the new Sea strictly advances
            // ielEvent beyond the parent Sea's ielEvent in IEL
            // chain order (stricter than parent-monotonic, which admits equality;
            // equal ielEvent between consecutive Seas is semantically
            // redundant and rejected). See events.md.
            if not event.ielEvent > parent.ielEvent in IEL chain order:
                return Error("Sea-Sea must strictly advance ielEvent")
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
        verify cross-chain authorization for that branch (v1+ events)
```

### Authorization Resolution (v1+ events)

When an event requires authorization, the verifier resolves through the bound IEL event:

```
verify_authorization(event, branch):
    // Inception is permissionless — no authorization gate at v0
    if event.kind == Icp:
        return Ok

    // Confirm ielEvent references a real IEL event with matching prefix.
    // BadIdentityBinding fires when the SAID isn't found, prefix mismatches,
    // or the bound event sits on a post-divergence IEL branch.
    ielEvent = resolver.fetch_iel_event(branch.identity, event.ielEvent)

    // Resolve the relevant policy via SAID-keyed direct lookup against the
    // IEL's IelVerification::policy_history (carry-forward applied at IEL
    // verification time, not at resolve time — no walk-back here).
    policy = match event.kind:
        Est, Upd             → resolver.resolve_auth_policy_at(branch.identity, event.ielEvent)
        Sea, Rpr, Cnt, Dec   → resolver.resolve_governance_policy_at(branch.identity, event.ielEvent)

    // Verify the SEL event's anchoring under that policy, with the
    // anchor kind required by the event's tier per
    // [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation):
    //   Upd          → Ixn  (tier 1)
    //   Est, Sea     → Rot  (tier 2)
    //   Rpr, Cnt, Dec → Ror (tier 3)
    // Each Endorse / Delegate leaf in the policy must have an anchor
    // of the required kind in the named KEL. Wrong-kind anchor for a
    // leaf evaluates as unsatisfied; policy-level satisfaction is
    // computed against the tier-appropriate leaf checks.
    if !checker.is_anchored_at_tier(event.said, policy, event.kind.anchor_tier()):
        return Error("Authorization failed")

    // Per-event parent-monotonic on ielEvent
    parent_event = lookup_event(event.previous)  // already in branch state
    if parent_event has ielEvent AND
       event.ielEvent ranks before parent_event.ielEvent in IEL order:
        return Error("ielEvent regression — parent-monotonic violated")
    branch.tip_iel_event = event.ielEvent  // for the next event extending this branch
```

The "ranks before" comparison uses cached IEL chain-order positions: the verifier batches every v1+ event's `ielEvent` plus each branch's tip's `ielEvent` into a single `IelResolver::iel_chain_positions` call per generation, then compares positions in O(1). The IEL is structurally a linear chain (or divergent — in which case the bound event must be on a single resolvable branch).

The check is **per-branch**: each branch's walk independently compares each event's `ielEvent` against its parent's. Branches with different parent-chains do not constrain each other's `ielEvent` values. A new branch that forks from `v_{d-1}` (e.g., a Cnt fork-contest forming its own singleton branch at `v_d`) only needs to satisfy `event.ielEvent >= v_{d-1}.ielEvent` — it is not constrained by `ielEvent` values on the other branches at `v_d` or beyond.

The chain-wide `lastIelEvent` (the highest `ielEvent` across all events in the chain) is a derived aggregate, computed at finish time, used by consumers for queries about how far the chain has bound to. It is not used as a flowing watermark gate during the walk.

### Soft-fail vs hard-fail policy

Authorization failures in step 4 (cross-chain authorization) are mapped to either a **hard fail** (the chain doesn't advance, the verifier returns an error, the submit handler rejects) or a **soft fail** (the chain advances locally but is flagged in content-based terminal state).

**Default: all authorization gates are HARD.** The table below shows that every kind × failure-mode combination is HARD in the normal case. The only exception — soft-fail propagation in the divergent-but-not-yet-contested window — is described in §Post-divergence soft-fail propagation below.

| Kind | Authorization gate | Anchor failure | Wrong-kind anchor | Binding failure | Parent-monotonic regression |
|------|--------------------|----------------|-------------------|------------------|------------------------------|
| `Est` | `authPolicy` (tier 2, `Rot`) | **HARD** | **HARD** | **HARD** (`BadIdentityBinding`) | **HARD** (`BadIdentityBinding`) |
| `Upd` | `authPolicy` (tier 1, `Ixn`) | **HARD** | **HARD** | **HARD** (`BadIdentityBinding`) | **HARD** (`BadIdentityBinding`) |
| `Sea` | `governancePolicy` (tier 2, `Rot`) | **HARD** | **HARD** | **HARD** | **HARD** |
| `Rpr` | `governancePolicy` (tier 3, `Ror`) | **HARD** | **HARD** | **HARD** | **HARD** |
| `Cnt` | `governancePolicy` (tier 3, `Ror`) | **HARD** | **HARD** | **HARD** | **HARD** |
| `Dec` | `governancePolicy` (tier 3, `Ror`) | **HARD** | **HARD** | **HARD** | **HARD** |

Hard fails leave the chain at its prior tip. The verifier does not advance the branch's tip `ielEvent` on a hard-failing event — only events that hard-pass *all* of fetch / divergence / policy-pick / anchor / parent-monotonic update the per-branch state.

All events require HARD anchor: a Cnt or Dec whose cross-chain anchor check or `IelDivergent` check fails is rejected at the verifier; the chain stays at its prior state. The chain advances iff auth holds.

The rationale for HARD anchor on all events: the DB cannot be trusted (see [../../../../protocol-doctrine.md](../../../../protocol-doctrine.md)). An unauthorized event lands in storage as a corrupted state; the verifier should reject it so the chain stays at its actual current state, not a fake-terminal state induced by a forged Cnt/Dec. The "chain stuck at a tip the owner intends to abandon" concern is operator-side and resolved by reincept under a new prefix, not by allowing unauthorized terminals to advance the chain locally. See [../../../../protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../../../protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

#### Post-divergence soft-fail propagation

The verification cutoff for "valid for downstream binding" is `first_divergent_serial`. A `Cnt` structurally creates divergence (it extends an existing tip that isn't the chain's max serial), so contested chains always have a divergence point. `Dec` only lands on non-divergent chains (routing rejects Dec on divergent with `ContestRequired`), so decommissioned chains have no cutoff and the Dec event itself is a valid event in the chain. (A `Cnt` overriding `Dec` per [../../../../protocol-doctrine.md §Cnt Overrides Dec](../../../../protocol-doctrine.md#cnt-overrides-dec) lands as the second event in a `{Dec, Cnt}` divergent set at `v_d` — the chain transitions to contested through the standard privileged-divergence path; Dec itself still landed onto a non-divergent chain at submit time, so no new verifier logic is required.)

For events at `serial >= first_divergent_serial` on a chain that is divergent-but-not-yet-contested (non-privileged-divergent — `Upd`-`Upd` race scenarios at v ≥ 2, or `Est`-`Est` race scenarios at v = 1): auth-check failures convert to SOFT. The verifier doesn't return Err; it sets the chain-wide `policy_satisfied = false` and continues. Once the chain is contested (any privileged event in the divergent set), the whole-chain-suspect rule applies and the per-event soft-fail propagation rule's purpose is superseded by the whole-chain framing. Structural integrity rules (SAID, serial monotonicity, content preservation, BadIdentityBinding, etc.) stay HARD regardless of position.

Why preserve rather than reject during the divergent-but-not-yet-contested window: hard-rejecting post-divergence-point events would discard them from the forensic record and bounce the entire verification, leaving consumers unable to read pre-divergence state. Soft-fail preserves the events structurally while making clear that verification doesn't bless them. Once the chain transitions to contested (privileged-divergence rule fires), the whole-chain-suspect framing supersedes — consumers don't trust pre-Cnt content for new authorization either way.

This rule is path-agnostic: it fires identically on submit, gossip-receipt, and resume verification paths. The handler-level rejection on contested/decommissioned chains (`merge.md §Terminal-State Gate`) is a separate seam that prevents new submits; this verifier-level mechanism handles events that reach the verifier some other way (concurrent siblings within a batch that introduces the Cnt, gossip-pulled chains where the local node hadn't yet observed the terminal, resume from a stored chain that contains a terminal).

### Terminal-state determination

The verifier's terminal-state-determination rule simplifies to:
- Divergent at `v_d`?
  - No → linear (active or terminal-via-Dec).
  - Yes → divergent set contains a privileged event (`Sea`/`Rpr`/`Cnt`/`Dec`)?
    - Yes → contested (terminal).
    - No → divergent (recoverable via `Rpr`).

Cnt is a privileged event whose presence in the divergent set triggers contested via this rule.

### Cnt parent resolution

Cnt's parent rule (`previous = v_{tip-1}.said`) resolves uniformly across linear and divergent chain shapes — see [../../../../protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../../../protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the cross-shape derivation and worked diagrams. SEL-specific: on a divergent chain, the pre-existing branch may have extended past `v_d` up to the proactive-evaluation cap; Cnt's parent rule selects `v_{d-1}` for cross-node uniformity.

**Implementation note.** Cnt is processed inline with the chain walk. When the walk reaches the generation at `v_d`, branch state's `tip_iel_event` holds `v_{tip-1}.ielEvent` (because `v_tip` has not yet been processed). Cnt and the existing tip at `v_d` are processed as siblings of the same generation; both have parent `v_{tip-1}` and both check parent-monotonic against `v_{tip-1}.ielEvent` from branch state. After the generation is processed, branch state forks per branch with each branch's own tip ielEvent. No new cache slot in branch state. (Authorization itself resolves via the bound IEL event referenced by Cnt's own `ielEvent`, not via SEL's branch state; cross-chain via `IelResolver`.)

### Upgrade rule

When a node has a non-privileged divergent set at `v_d` (max 2 events: `Upd`-`Upd` race at v ≥ 2; `Est`-`Est` at v = 1 is non-privileged-divergent but unreachable by the upgrade-rule path since all privileged kinds have `serial >= 2` — Est-Est resolves only via `Rpr`) and gossip delivers a non-archiving privileged event for that same `v_d` (`Sea`, `Cnt`, or `Dec` with `previous = v_{d-1}.said`), the verifier accepts the privileged event as a third event in the divergent set. Local state transitions from non-privileged-divergent (recoverable) to contested (terminal).

`Rpr` is the archiving exception — its discriminator removes the divergent set before any divergent-set check fires, so it never participates in the upgrade rule (the other non-archiving privileged kinds — `Sea`, `Cnt`, `Dec` — do, when their parent is `v_{d-1}.said`). See [../../../../protocol-doctrine.md §Two privileged event classes: archiving vs non-archiving](../../../../protocol-doctrine.md#two-privileged-event-classes-archiving-vs-non-archiving) for the doctrinal frame.

### Caller-bounded SAID querying

The chain-wide `policy_satisfied: bool` answers "is the chain currently authoritative" in aggregate, but consumers (notably the SEL verifier when resolving `ielEvent` bindings into IEL) need to ask about specific events: "is THIS IEL event valid for binding?" The verifier exposes a caller-bounded query pattern mirroring `KelVerification` (`lib/kels/src/types/kel/verification.rs:50-51`):

- Caller provides `queried_saids: BTreeSet<Digest256>` up-front — the SAIDs the caller cares about.
- During the chain walk, for each event whose SAID appears in `queried_saids`: if the event is at `serial < first_divergent_serial` (or chain is non-divergent) AND auth-passed, the verifier adds the SAID to `satisfied_saids`.
- Token exposes `is_said_satisfied(said) -> bool` and `satisfied_saids() -> &BTreeSet<Digest256>`.

The pattern is bounded by what the caller asks about, not by chain size — verification doesn't accumulate the universe of chain SAIDs. The SEL verifier collects ielEvent SAIDs from its own chain walk, passes them as queried_saids to the IEL verification, and uses `is_said_satisfied` to decide whether each binding is valid. Same shape as KEL's `is_said_anchored`.

### Inception batch rule

The inception batch rule `[Icp, Est]` minimum is a chain-validity rule enforced inside the verifier (#171): `SelVerifier::finish_internal` rejects with `IncompleteInception` whenever any branch tip is still an `Icp` (Icp is structurally pinned to v=0, so an Icp tip identifies the lone-`[Icp]` chain). Every consumer's verifier walk applies the same rule — a tampered DB serving `[Icp]` alone is rejected at end-verification. See [merge.md](merge.md) for the per-batch routing context.

### Branch State

```
struct SadBranchTip {
    tip: SadEvent,                        // current tip event
    identity: Digest256,                  // bound IEL prefix (set at Icp)
    tip_iel_event: Option<Digest256>, // tip event's ielEvent — used for the per-event parent-monotonic check on the next event extending this branch
    events_since_evaluation: u64,
    lastSealAdvancingEvent: Option<Digest256>, // SAID of most recent Sea/Rpr on this branch
}
```

SEL branch state does **not** track authorization policies per branch. Those policies live on IEL; SEL branch state holds only the binding (`identity`) and the per-branch tip's `ielEvent`. Per-branch state is sufficient for the per-event parent-monotonic check — the verifier compares each new event's `ielEvent` against its branch tip's `ielEvent` (which equals the parent event's `ielEvent`, since the new event extends that tip).

## Verification Return Value

`SelVerifier::finish()` produces a `SelVerification` token:

```
SelVerification:
    prefix: Digest256
    branches: Vec<BranchTip>                  // 1 = linear, 2 = divergent (or 3 with Cnt fork-contest)
    divergenceAncestor: Option<Digest256>    // SAID of v_{d-1} on a divergent chain (None on linear)
    is_contested: bool
    is_decommissioned: bool
    lastSealAdvancingEvent: Option<Digest256>  // SAID of most recent Sea/Rpr
    lastIelEvent: Option<Digest256>    // derived aggregate: max ielEvent across all events in the chain
```

Accessors:

- `current_event()` → `None` if divergent
- `current_content()` → `None` if divergent
- `prefix()`, `topic()`, `identity()` → the bound IEL prefix
- `lastIelEvent()` → derived aggregate; max ielEvent across all events in the chain (informational, not used as a gate)
- `policy_satisfied()` — overall authorization satisfaction across the chain
- `lastSealAdvancingEvent()` — SAID of the most recent `Sea`/`Rpr`
- `divergenceAncestor()` — SAID of `v_{d-1}` on a divergent chain (`None` on linear)
- `is_divergent()` — `branches.len() > 1`.
- `is_contested()`, `is_decommissioned()`

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix derivation | Inception prefix recomputed from `(identity, topic)` and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | `previous` field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Serial monotonicity | Each event's serial equals predecessor's serial + 1 |
| Inception serial | Inception (no `previous`) must have serial 0 |
| Topic consistency | All events on a branch share the same topic |
| `ielEvent` binding | Resolves to an IEL event with matching prefix |
| Authorization | `evaluate_anchored_policy(IEL-resolved-policy, event.said)` |
| Per-event parent-monotonic on `ielEvent` | `event.ielEvent >= parent_event.ielEvent` in IEL chain order; parent via `previous` SAID; checked per branch independently |
| Content preservation | `event.content == previous.content` for Sea/Rpr/Cnt/Dec |
| Proactive evaluation | At most `MAX_NON_EVALUATION_EVENTS = 63` non-evaluation events between Sea/Rpr/Cnt/Dec |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `SelVerification` token (`is_divergent()`, `divergenceAncestor()`)
- Both branches of a divergent chain are verified independently (the verifier forks `BranchState` per branch)
- The submit handler resolves divergence via `Rpr` (see [merge.md](merge.md))

## Streaming

SEL verification follows the cross-primitive streaming pattern (see [../../../../protocol-doctrine.md §Streaming](../../../../protocol-doctrine.md#streaming)). Verifier type: `SelVerifier`. Proof-of-verification token: `SelVerification`. Per-SEL specifics: cross-chain `ielEvent` resolution via `IelResolver` (separate trait from `PolicyChecker` — see §Two-trait split below); per-event parent-monotonic check on `ielEvent` walked per-branch; post-divergence soft-fail propagation on non-privileged divergent sets; constructors `new` / `resume`.

`SelVerifier` walks forward through events page by page, verifying integrity and authorization without loading the full chain into memory.

```
struct SelVerifier {
    prefix: Digest256,
    checker: Arc<dyn PolicyChecker>,    // anchor-and-immunity (KEL/IEL/SEL share this trait)
    resolver: Arc<dyn IelResolver>,     // cross-chain navigation into the bound IEL
    branches: HashMap<Digest256, BranchState>,
    last_verified_serial: Option<u64>,
    divergenceAncestor: Option<Digest256>,
    is_contested: bool,
    is_decommissioned: bool,
    ...
}
```

### Constructors

- `SelVerifier::new(Some(prefix), checker, resolver)` — Start from inception. Full verification of untrusted chains.
- `SelVerifier::resume(prefix, &SelVerification, checker, resolver)` — Resume from a verified `SelVerification` token. Used by the submit handler's discriminator path to verify a single page without re-verifying the whole chain.

### Two-trait split: `PolicyChecker` and `IelResolver`

SEL verification depends on two orthogonal abstractions: **policy evaluation** (anchor checks, immunity) and **IEL chain navigation** (binding resolution, divergence checks, chain-order lookups). These are split into separate traits so neither surface muddles the other.

`PolicyChecker` is unchanged from KEL/IEL — anchor-and-immunity only:

```rust
trait PolicyChecker: Send + Sync {
    async fn is_anchored(&self, said: &Digest256, policy: &Digest256)
        -> Result<bool, KelsError>;
    async fn is_immune(&self, policy: &Digest256)
        -> Result<bool, KelsError>;
}
```

`IelResolver` is new — it abstracts cross-chain access into a specific IEL identity. Implementations scope every operation to a given IEL prefix and reject any SAID whose stored event prefix doesn't match (`KelsError::BadIdentityBinding`):

```rust
#[async_trait]
trait IelResolver: Send + Sync {
    /// Fetch a single IEL event by SAID, scoped to `identity`.
    /// BadIdentityBinding when SAID not present or prefix mismatches.
    async fn fetch_iel_event(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<IdentityEvent, KelsError>;

    /// SAID-keyed direct lookup against `IelVerification::policy_history`
    /// (carry-forward already applied at IEL verification time — no chain
    /// walk here). Returns IelDivergent when the bound event lives at-or-
    /// after the IEL's `first_divergent_serial`; pre-divergence shared
    /// events resolve cleanly even on a divergent IEL.
    async fn resolve_auth_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;
    async fn resolve_governance_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;

    /// Batch-fetch IEL chain-order positions for the SEL verifier's per-event
    /// parent-monotonic check on ielEvent. Returns BadIdentityBinding for
    /// any SAID that doesn't resolve in the named IEL — chain-integrity breach,
    /// the entire call fails.
    async fn iel_chain_positions(&self, identity: &Digest256, saids: &[Digest256])
        -> Result<HashMap<Digest256, IelChainPosition>, KelsError>;
}
```

The SEL merge handler does NOT separately re-check `is_immune` on IEL-resolved policies. The IEL primitive's submit and verification gates are the canonical immunity enforcement; calling it again at SEL-side would be defense-in-depth that drifts. SEL trusts the IEL gate. `is_immune` remains on `PolicyChecker` for IEL's own use (both IEL submit and IEL verification).

#### Implementation notes

The production resolver (`AnchoredIelResolver`, `lib/kels/src/iel_resolver.rs`) re-verifies the named IEL on each call to obtain a fresh `IelVerification` token. Layered caching lives above the trait so the impl stays simple and the divergence gate is exercised cleanly per call.

### Paginated Verification Helpers

Two top-level helpers in `lib/kels/src/types/sad/sync.rs`:

- **`verify_sel_events(client, prefix, checker)`** — Pages through a remote SADStore, verifying each page. Returns a trusted `SelVerification` token.
- **`sel_completed_verification(loader, prefix, page_size, max_pages)`** — Pages through a `SelPageLoader`, calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations spanning pages.

## Path-Agnostic Validation

The validation rules above apply identically at submit, gossip ingestion, bootstrap, and re-verification. KELS data is path-agnostic — a SEL event accepted at one node should be acceptable at every other node, and pulling data from one instance into another should not change its validity. See [../iel/event-log.md §Path-agnostic validation rules](../iel/event-log.md#path-agnostic-validation-rules) for the cross-chain rationale.

## References

- [event-log.md](event-log.md) — Chain lifecycle, repair, contest, decommission.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [events.md](events.md) — Per-kind structural rules.
- [../iel/verification.md](../iel/verification.md) — IEL counterpart (provides binding resolution for SEL).
- [../iel/event-log.md](../iel/event-log.md) — IEL lifecycle (immunity rule, anchor stability).
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL and anchoring model.
- [../../../../protocol-doctrine.md §Part 3 Verification Mechanics](../../../../protocol-doctrine.md#part-3-verification-mechanics) — Cross-primitive verification doctrine (streaming, tokens, effective-SAID synthetic comparison).
- [../kel/verification.md](../kel/verification.md) — KEL counterpart.
