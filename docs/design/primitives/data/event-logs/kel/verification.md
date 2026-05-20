# KEL Verification Protocol

This document describes the verification protocol used to validate the integrity and authenticity of a Key Event Log (KEL).

## Overview

KEL verification ensures:
- Events match their explicit schemas
- Serials start at 0 and increment by 1 with no gaps
- The inception event has a valid prefix
- All event prefixes match
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from current state to inception via `previous` links
- Pre-rotation commitments are honored (rotation hash → public key)
- Recovery key commitments are honored (recovery hash → recovery key)
- All signatures are valid

Events are linked by their `previous` SAID field. Generation is computed dynamically by following the chain from inception (generation 0).

## Verification Algorithm

`KelVerifier` processes events in a single forward pass, verifying structure and cryptography simultaneously. Events must arrive in `serial ASC, kind sort_priority ASC, said ASC` order with complete generations.

### Per-Event Checks

For each event in the page:

```
verify_event(event):
    // 1. SAID and prefix integrity
    event.verify()  // Inception: verify both prefix and SAID; subsequent: verify SAID

    // 2. Prefix consistency
    if event.prefix != verifier.prefix:
        return Error("Prefix mismatch")

    // 3. Structure validation
    validate_structure(event)  // Required fields present for event kind

    // 4. Serial continuity
    if event.serial != expected_serial:
        return Error("Serial gap or regression")

    // 5. Chain continuity (previous pointer matches a known branch tip)
    match event to a branch via event.previous
    if no matching branch:
        return Error("Previous SAID not found")

    // 6. Anchor format validation
    if event.anchor exists:
        verify anchor is a valid CESR digest
```

Anchor *kind* validation (`Ixn`/`Rot`/`Ror` per tier 1/2/3) is cross-chain — IEL/SEL verifiers enforce it when evaluating cross-chain policy satisfaction. KEL verification itself only validates anchor *format*.

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
        verify crypto for that branch
```

### Establishment event processing

When an establishment event is encountered (icp, dip, rot, rec, ror, dec), the verifier checks the forward-key commitments made by the previous establishment event. `branch.pending_rotation_hash` and `branch.pending_recovery_hash` are the digests committed by the prior establishment; the current event must reveal a public key whose digest matches.

```
process_establishment(event, branch):
    new_public_key = parse(event.publicKey)

    // Verify rotation hash commitment (forward commitment from previous establishment)
    if branch.pending_rotation_hash exists:
        expected = compute_rotation_hash(new_public_key)
        if branch.pending_rotation_hash != expected:
            return Error("Public key does not match rotation hash")

    // Verify recovery hash commitment
    if branch.pending_recovery_hash exists AND event.reveals_recovery_key():
        expected = compute_rotation_hash(event.recoveryKey)
        if branch.pending_recovery_hash != expected:
            return Error("Recovery key does not match recovery hash")

    // Update branch state
    branch.current_public_key = new_public_key
    branch.pending_rotation_hash = event.rotationHash
    branch.pending_recovery_hash = event.recoveryHash
    branch.establishment_tip = event
```

### Signature verification

```
verify_signatures(signed_event, publicKey):
    // SAID is Blake3 hash of canonical JSON — signing the SAID bytes
    // is equivalent to signing the content but more efficient
    data = signed_event.event.said.as_bytes()

    // Primary signature
    signature = parse_signature(signed_event.signature)
    publicKey.verify(data, signature)

    // Recovery signature (dual authorization for rec, ror, dec)
    if signed_event.recovery_signature exists:
        recoveryKey = parse_key(signed_event.event.recoveryKey)
        recovery_sig = parse_signature(signed_event.recovery_signature)
        recoveryKey.verify(data, recovery_sig)
```

## Verification Return Value

`KelVerifier::into_verification()` produces a `KelVerification` token — the proof-of-verification type:

```
KelVerification:
    prefix: String
    branch_tips: Vec<BranchTip>                     // one per branch (1 = linear, N = divergent)
    is_contested: bool
    divergenceAncestor: Option<Digest256>          // SAID of v_{d-1} on a divergent chain (None on linear)
    lastSealAdvancingEvent: Option<Digest256>     // SAID of most recent Rec/Ror/Rot that landed cleanly on the linear chain (seal-cap watermark); a priv event creating or joining a divergent set does NOT advance the seal
    lastRecoveryRevealingEvent: Option<Digest256> // SAID of most recent Rec/Ror/Dec (spent-key / immunity rule; rotation cadence is operator guidance)
    anchored_saids: BTreeSet<Digest256>
    queried_saids: BTreeSet<Digest256>

BranchTip:
    tip: SignedKeyEvent            // chain head (latest event on this branch)
    establishment_tip: SignedKeyEvent  // last establishment event (provides signing key)
```

Derived accessors:
- `current_public_key()` → `None` if divergent (ambiguous)
- `last_establishment_event()` → `None` if divergent
- `is_decommissioned()` → `true` when the linear branch tip is a `Dec` event (a contested chain is not also decommissioned — when `Dec` lands in a divergent set the chain transitions directly to Contested via privileged-divergence-is-terminal)
- `is_divergent()` → `branch_tips.len() > 1`
- `effective_tail_said()` → single tip SAID, `hash("contested:{prefix}")` for contested, `hash("divergent:{prefix}")` for divergent
- `is_said_anchored()`, `anchors_all_saids()` → inline anchor checking results

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix integrity | Inception prefix recomputed and compared |
| Prefix consistency | All events have same prefix |
| Event chaining | Previous field points to valid prior event SAID |
| Chain completeness | All `previous` references resolve to existing events |
| Serial monotonicity | Each event's serial must equal previous event's serial + 1 |
| Inception serial | Inception events (no `previous`) must have serial 0 |
| Pre-rotation commitment | rotationHash matches next publicKey |
| Recovery commitment | recoveryHash matches revealed recoveryKey |
| Signature validity | Cryptographic signature verification against SAID bytes |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `KelVerification` token (`is_divergent()`, `divergenceAncestor()`)
- All branches of a divergent KEL are verified independently (the verifier forks `BranchState` per branch)
- The submit handler is responsible for resolving divergence

### Terminal-state determination

The verifier's terminal-state-determination rule simplifies to:
- Divergent at `v_d`?
  - No → linear (active or terminal-via-Dec).
  - Yes → divergent set contains a privileged event (`Rot`, `Ror`, or `Dec`)?
    - Yes → contested (terminal).
    - No → divergent (recoverable via `Rec`).

(`Rec` is archiving — its discriminator removes the divergent set before any divergent-set check fires, so `Rec` never appears in the divergent set at terminal-state-determination time.)

### Contested-state transition: privileged event placement

A privileged event (`Rot`, `Ror`, or `Dec`) with `previous = v_{d-1}.said` and `serial = d` lands at `v_d` and joins or creates the divergent set, firing privileged-divergence-is-terminal. The locked-portion bound prevents `previous` from being in the chain's locked portion; on KEL the seal-cap enforces this. See [../../../../protocol-doctrine.md §Worked scenarios — contested-state creation](../../../../protocol-doctrine.md#worked-scenarios--contested-state-creation) for the cross-shape derivation and diagrams. `v_{d-1}` is the unique parent at `serial − 1` shared across all nodes by chain validity (it lands cleanly before any divergence), making the parent shape cross-node-validatable regardless of which divergent contents each node observed.

**Implementation note.** The contesting event is processed inline with the chain walk. When the walk reaches `v_d`, branch state holds `v_{d-1}`'s commitments (`rotationHash` and `recoveryHash`, set when `v_{d-1}` was processed and not yet consumed by `v_d`'s establishment update). The contesting event and the existing event(s) at `v_d` are processed as siblings of the same generation, both consuming `v_{d-1}`'s commitments — `Rot` via single-signature against `rotationHash`; `Ror`/`Dec` via dual-signature against both `rotationHash` and `recoveryHash`. No new cache slot in branch state.

### Upgrade rule

When a node has a non-privileged divergent set at `v_d` (max 2 events: `Ixn`-`Ixn` race) and gossip delivers a privileged event for that same `v_d` (`Rot`, `Ror`, or `Dec` with `previous = v_{d-1}.said`), the verifier accepts the privileged event as a third event in the divergent set. Local state transitions from non-privileged-divergent (recoverable) to contested (terminal).

`Rec` is the archiving exception — its discriminator removes the divergent set before any divergent-set check fires, so it never participates in the upgrade rule. See [../../../../protocol-doctrine.md §Routing semantics of privileged and archiving kinds](../../../../protocol-doctrine.md#routing-semantics-of-privileged-and-archiving-kinds) for the doctrinal frame.

### Contested-event authorization (HARD)

> **Verifier vs merge-engine semantics.** The verifier itself does not reject events — it records signature-check results on the verification token and surfaces authorization failures via `policy_satisfied = false` (plus per-kind indicators where applicable). "HARD" below refers to **merge-engine enforcement against the verifier's output**: when the submit handler runs the verifier and observes an auth failure, the merge engine rejects the candidate batch and the new events never land. The verifier-side soft-fail composition is documented in [../../../../protocol-doctrine.md §Verifier and merge are distinct treatments](../../../../protocol-doctrine.md#verifier-and-merge-are-distinct-treatments).

The contesting privileged event's authorization is verified against `v_{d-1}`'s commitments — `Rot` via single-signature against `rotationHash`; `Ror`/`Dec` via dual-signature against `rotationHash` AND `recoveryHash`. Authorization failure is HARD at the merge layer — a contesting event whose signatures don't verify is rejected by the merge engine on the verifier's output; the chain stays at its prior state. Per-kind signature shape is documented in [events.md §Authorization model](events.md#authorization-model); the HARD-at-the-merge-layer rule applies uniformly to all privileged kinds.

## Event Types and Their Signatures

Event kind values are version-qualified in serialized form (e.g. `kels/kel/v1/events/icp`).

| Event Type | Primary Signature | Recovery Signature |
|------------|-------------------|-------------------|
| `icp` (incept) | Signing key | - |
| `dip` (delegated incept) | Signing key | - |
| `ixn` (interact) | Signing key | - |
| `rot` (rotate) | Next signing key (pre-committed) | - |
| `ror` (rotate recovery) | Next signing key | Recovery key |
| `rec` (recover) | Next signing key | Recovery key |
| `dec` (decommission) | Next signing key | Recovery key |

Events with recovery signatures require dual authorization, making them the highest authority operations in the KEL.

## Streaming

KEL verification follows the cross-primitive streaming pattern (see [../../../../protocol-doctrine.md §Streaming](../../../../protocol-doctrine.md#streaming)). Verifier type: `KelVerifier`. Proof-of-verification token: `KelVerification`. Per-KEL specifics: branch-tip behavior on divergence (verifier forks `BranchState` per branch and tracks `divergenceAncestor`); inline anchor checking against caller-registered SAIDs; constructors `new` / `resume` / `from_branch_tip`.

`KelVerifier` is the sole verification mechanism for KELs. It walks forward through events page by page, verifying cryptographic integrity without loading the full KEL into memory. Events are processed in **generations** (all events at a given serial). When multiple events appear at the same serial (divergence), the verifier forks `BranchState` — each new event is matched to its branch via the `previous` pointer.

```
struct KelVerifier {
    prefix: String,
    branches: HashMap<String, BranchState>,  // keyed by tip SAID
    last_verified_serial: Option<u64>,
    divergenceAncestor: Option<Digest256>,
    is_contested: bool,
    queried_saids: BTreeSet<String>,   // anchor checking
    anchored_saids: BTreeSet<String>,  // anchor checking
}
```

### Constructors

- `KelVerifier::new(prefix)` — Start from inception. Full verification of untrusted KELs.
- `KelVerifier::resume(prefix, &KelVerification)` — Resume from a verified `KelVerification` token. Used by the submit handler's fast path to verify appended events without re-verifying the entire KEL.
- `KelVerifier::from_branch_tip(prefix, &BranchTip)` — Resume verification from a specific branch tip. Used for verifying events against a specific branch in divergence/recovery scenarios.

### Usage

```
let mut verifier = KelVerifier::new(prefix);
loop {
    let (events, has_more) = source.fetch_page(prefix, since, limit).await?;
    verifier.verify_page(&events)?;
    sink.store_page(prefix, &events).await?;
    if !has_more { break; }
    since = events.last().map(|e| &e.event.said);
}
let verification = verifier.into_verification();
```

### Inline anchor checking

Register SAIDs to check before verification with `verifier.check_anchors(saids)`. As the verifier processes events, it checks each event's anchor field against the queried SAIDs. Results are available on the `KelVerification` token via `is_said_anchored()` and `anchors_all_saids()`.

Anchor fields appear on `Ixn`, `Rot`, and `Ror` events — `Ixn.anchor` is required (tier 1), `Rot.anchor` / `Ror.anchor` are optional (tier 2 / tier 3) and used by cross-chain verifiers per [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation). The `check_anchors()` match scans all three kinds. Cross-chain consumers (IEL/SEL verifiers) need to know not just that a SAID is anchored but in which kind of KEL event — `KelVerification` exposes the anchoring event's kind so callers can enforce tier-appropriate anchor checks.

### PageLoader implementations

KEL implements the streaming pattern's `PageLoader` trait with three flavors:

- `KelStorePageLoader` — wraps a `KelStore` reference; non-locking reads.
- `KelTransaction` — reads under a PostgreSQL advisory lock, then reuses the same transaction for the subsequent write. Used by submit-handler paths.
- `LockedKelTransaction` — identity service's advisory-locked transaction wrapper.

### Paginated verification helper

`completed_verification(loader, prefix, page_size, max_pages, anchors)` pages through a `PageLoader`, calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations that span pages. Returns a trusted `KelVerification` token. The `max_pages` parameter prevents resource exhaustion (default 64 pages = ~2K events; configurable via `KELS_MAX_VERIFICATION_PAGES`).

### Checks per event

1. SAID integrity (`event.verify()`)
2. Prefix matches verifier's prefix
3. Serial continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure()`)
6. Anchor format validation (anchors must be valid CESR digests)
7. For establishment events: rotation hash forward commitment, recovery hash commitment
8. Signature verification (primary + dual for recovery events)
