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

Like IEL and today's SEL, authorization is via the *anchoring model*: policies resolve to KEL prefixes whose `ixn` events anchor the SE event's SAID. The verifier uses two traits — `PolicyChecker` for anchor-and-immunity checks (the same trait IEL/KEL use), and `IelResolver` for cross-chain navigation into the bound IEL.

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

    // Confirm identity_event references a real IEL event with matching prefix.
    // BadIdentityBinding fires when the SAID isn't found, prefix mismatches,
    // or the bound event sits on a post-divergence IEL branch.
    iel_event = resolver.fetch_iel_event(branch.identity, event.identity_event)

    // Resolve the relevant policy via SAID-keyed direct lookup against the
    // IEL's IelVerification::policy_history (carry-forward applied at IEL
    // verification time, not at resolve time — no walk-back here).
    policy = match event.kind:
        Upd                  → resolver.resolve_auth_policy_at(branch.identity, event.identity_event)
        Sea, Rpr, Cnt, Dec   → resolver.resolve_governance_policy_at(branch.identity, event.identity_event)

    // Verify the SE event's anchoring under that policy
    if !checker.is_anchored(event.said, policy):
        return Error("Authorization failed")

    // Monotonic ratchet
    if event.identity_event ranks before branch.last_identity_event in IEL order:
        return Error("identity_event regression — non-monotonic")
    branch.last_identity_event = event.identity_event
```

The "ranks before" comparison uses cached IEL chain-order positions: the verifier batches every v1+ event's `identity_event` plus each branch's current `last_identity_event` into a single `IelResolver::iel_chain_positions` call per generation, then compares positions in O(1). The IEL is structurally a linear chain (or divergent — in which case the bound event must be on a single resolvable branch).

### Soft-fail vs hard-fail policy

Authorization failures in step 4 (cross-chain authorization) are mapped to either a **hard fail** (the chain doesn't advance, the verifier returns an error, the submit handler rejects) or a **soft fail** (the chain advances locally but is flagged in content-based terminal state). The mapping is per kind:

| Kind | Authorization gate | Anchor failure | Binding failure | Ratchet regression |
|------|--------------------|----------------|------------------|---------------------|
| `Upd` | `auth_policy` | **HARD** | **HARD** (`BadIdentityBinding`) | **HARD** (`BadIdentityBinding`) |
| `Sea` | `governance_policy` | **HARD** | **HARD** | **HARD** |
| `Rpr` | `governance_policy` | **HARD** | **HARD** | **HARD** |
| `Cnt` | `governance_policy` | **SOFT** (chain becomes Contested with `policy_satisfied=false`) | **HARD** | **HARD** |
| `Dec` | `governance_policy` | **SOFT** (chain becomes Decommissioned with `policy_satisfied=false`) | **HARD** | **HARD** |

Hard fails leave the chain at its prior tip. The verifier does not advance `last_identity_event` on a hard-failing event — only events that hard-pass *all* of fetch / divergence / policy-pick / anchor advance the ratchet.

Soft fails apply only to terminal kinds (`Cnt` / `Dec`) and only on the cross-chain anchor check or on `IelDivergent`. The chain advances to the terminal state but the verifier's content-based terminal flag carries `policy_satisfied=false`, signalling that the terminal action stands but its authorization didn't resolve cleanly. Content-preservation and structural rules remain HARD for terminal kinds — those failures bounce the batch.

The rationale: terminal events (Cnt/Dec) describe an end-state declaration; rejecting them outright when the cross-chain check fails would leave the chain stuck at a tip the owner intends to abandon. Owners need a soft-fail path so a govfailed Cnt/Dec still terminates the chain locally, with the failure surfaced for downstream consumers via the content-based flag rather than an open chain on a defunct identity.

#### Post-divergence soft-fail propagation

The verification cutoff for "valid for downstream binding" is `first_divergent_version`. A `Cnt` structurally creates divergence (it extends an existing tip that isn't the chain's max version), so contested chains always have a divergence point. `Dec` only lands on non-divergent chains (routing rejects Dec on divergent with `ContestRequired`), so decommissioned chains have no cutoff and the Dec event itself is a valid event in the chain.

For events at `version >= first_divergent_version` (post-divergence on a Cnt'd chain): auth-check failures convert to SOFT. The verifier doesn't return Err; it sets the chain-wide `policy_satisfied = false` and continues. Pre-divergence events follow the existing soft/hard mapping above. Structural integrity rules (SAID, version monotonicity, content preservation, BadIdentityBinding, etc.) stay HARD regardless of position — Cnt doesn't change whether an event is well-formed.

Why preserve rather than reject: `Cnt` semantically means "the governance keys may be compromised; I cannot recover this chain." Hard-rejecting post-divergence events would discard the adversary's actions from the forensic record and bounce the entire verification, leaving consumers unable to read pre-divergence state. Soft-fail preserves the events structurally while making clear that verification doesn't bless them.

This rule is path-agnostic: it fires identically on submit, gossip-receipt, and resume verification paths. The handler-level rejection on contested/decommissioned chains (`merge.md §Terminal-State Gate`) is a separate seam that prevents new submits; this verifier-level mechanism handles events that reach the verifier some other way (concurrent siblings within a batch that introduces the Cnt, gossip-pulled chains where the local node hadn't yet observed the terminal, resume from a stored chain that contains a terminal).

#### Caller-bounded SAID querying (`queried_saids` / `satisfied_saids`)

The chain-wide `policy_satisfied: bool` answers "is the chain currently authoritative" in aggregate, but consumers (notably the SE verifier when resolving `identity_event` bindings into IEL) need to ask about specific events: "is THIS IEL event valid for binding?" The verifier exposes a caller-bounded query pattern mirroring `KelVerification` (`lib/kels/src/types/kel/verification.rs:50-51`):

- Caller provides `queried_saids: BTreeSet<Digest256>` up-front — the SAIDs the caller cares about.
- During the chain walk, for each event whose SAID appears in `queried_saids`: if the event is at `version < first_divergent_version` (or chain is non-divergent) AND auth-passed, the verifier adds the SAID to `satisfied_saids`.
- Token exposes `is_said_satisfied(said) -> bool` and `satisfied_saids() -> &BTreeSet<Digest256>`.

The pattern is bounded by what the caller asks about, not by chain size — verification doesn't accumulate the universe of chain SAIDs. The SE verifier collects identity_event SAIDs from its own chain walk, passes them as queried_saids to the IEL verification, and uses `is_said_satisfied` to decide whether each binding is valid. Same shape as KEL's `is_said_anchored`.

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

SE branch state does **not** track authorization policies per branch. Those policies live on IEL; SE branch state holds only the binding (`identity`) and the ratchet (`last_identity_event`).

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
    checker: Arc<dyn PolicyChecker>,    // anchor-and-immunity (KEL/IEL/SEL share this trait)
    resolver: Arc<dyn IelResolver>,     // cross-chain navigation into the bound IEL
    branches: HashMap<Digest256, BranchState>,
    last_verified_version: Option<u64>,
    diverged_at_version: Option<u64>,
    is_contested: bool,
    is_decommissioned: bool,
    ...
}
```

### Constructors

- `SelVerifier::new(Some(prefix), checker, resolver)` — Start from inception. Full verification of untrusted chains.
- `SelVerifier::resume(prefix, &SelVerification, checker, resolver)` — Resume from a verified `SelVerification` token. Used by the submit handler's discriminator path to verify a single page without re-verifying the whole chain.

### Two-trait split: `PolicyChecker` and `IelResolver`

Round 12 splits SE-verifier dependencies into two orthogonal traits so that policy evaluation and IEL chain navigation don't muddle inside one surface.

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
    /// after the IEL's `first_divergent_version`; pre-divergence shared
    /// events resolve cleanly even on a divergent IEL.
    async fn resolve_auth_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;
    async fn resolve_governance_policy_at(&self, identity: &Digest256, iel_event_said: &Digest256)
        -> Result<Digest256, KelsError>;

    /// Batch-fetch IEL chain-order positions for the SE verifier's monotonic-
    /// ratchet check. Returns BadIdentityBinding for any SAID that doesn't
    /// resolve in the named IEL — chain-integrity breach, the entire call fails.
    async fn iel_chain_positions(&self, identity: &Digest256, saids: &[Digest256])
        -> Result<HashMap<Digest256, IelChainPosition>, KelsError>;
}
```

The SE merge handler does NOT separately re-check `is_immune` on IEL-resolved policies. The IEL primitive's submit and verification gates are the canonical immunity enforcement; calling it again at SE-side would be defense-in-depth that drifts. SE trusts the IEL gate. `is_immune` remains on `PolicyChecker` for IEL's own use (both IEL submit and IEL verification).

The production resolver (`AnchoredIelResolver`, `lib/kels/src/iel_resolver.rs`) re-verifies the named IEL on each call to obtain a fresh `IelVerification` token; layered caching lives above the trait so the impl stays simple and the divergence gate is exercised cleanly per call.

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
