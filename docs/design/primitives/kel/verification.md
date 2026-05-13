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

### Generation Processing

Events at the same serial form a **generation**. The verifier processes all events in a generation together:

```
verify_generation(events_at_serial):
    if events_at_serial.len() > branches.len():
        // More events than branches = divergence detected
        fork BranchState for new branches
        record divergence_ancestor (the SAID of v_{d-1}) if first divergence

    for each event:
        match to branch via event.previous
        verify crypto for that branch
```

### Establishment Event Processing

When an establishment event is encountered (icp, dip, rot, rec, ror, cnt, dec):

```
process_establishment(event, branch):
    new_public_key = parse(event.public_key)

    // Verify rotation hash commitment (forward commitment from previous establishment)
    if branch.pending_rotation_hash exists:
        expected = compute_rotation_hash(new_public_key)
        if branch.pending_rotation_hash != expected:
            return Error("Public key does not match rotation hash")

    // Verify recovery hash commitment
    if branch.pending_recovery_hash exists AND event.reveals_recovery_key():
        expected = compute_rotation_hash(event.recovery_key)
        if branch.pending_recovery_hash != expected:
            return Error("Recovery key does not match recovery hash")

    // Update branch state
    branch.current_public_key = new_public_key
    branch.pending_rotation_hash = event.rotation_hash
    branch.pending_recovery_hash = event.recovery_hash
    branch.establishment_tip = event
```

### Signature Verification

```
verify_signatures(signed_event, public_key):
    // SAID is Blake3 hash of canonical JSON — signing the SAID bytes
    // is equivalent to signing the content but more efficient
    data = signed_event.event.said.as_bytes()

    // Primary signature
    signature = parse_signature(signed_event.signature)
    public_key.verify(data, signature)

    // Recovery signature (dual authorization for rec, ror, cnt, dec)
    if signed_event.recovery_signature exists:
        recovery_key = parse_key(signed_event.event.recovery_key)
        recovery_sig = parse_signature(signed_event.recovery_signature)
        recovery_key.verify(data, recovery_sig)
```

## Verification Return Value

`KelVerifier::into_verification()` produces a `KelVerification` token — the proof-of-verification type:

```
KelVerification:
    prefix: String
    branch_tips: Vec<BranchTip>                     // one per branch (1 = linear, N = divergent)
    is_contested: bool
    divergence_ancestor: Option<Digest256>          // SAID of v_{d-1} on a divergent chain (None on linear)
    last_recovery_revealing_event: Option<Digest256> // SAID of most recent Rec/Ror/Cnt/Dec
    anchored_saids: BTreeSet<Digest256>
    queried_saids: BTreeSet<Digest256>

BranchTip:
    tip: SignedKeyEvent            // chain head (latest event on this branch)
    establishment_tip: SignedKeyEvent  // last establishment event (provides signing key)
```

Derived accessors:
- `current_public_key()` → `None` if divergent (ambiguous)
- `last_establishment_event()` → `None` if divergent
- `is_decommissioned()` → contested, or single branch with decommission tip
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
| Pre-rotation commitment | rotation_hash matches next public_key |
| Recovery commitment | recovery_hash matches revealed recovery_key |
| Signature validity | Cryptographic signature verification against SAID bytes |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and tracked in the `KelVerification` token (`is_divergent()`, `divergence_ancestor()`)
- All branches of a divergent KEL are verified independently (the verifier forks `BranchState` per branch)
- The submit handler is responsible for resolving divergence

### Terminal-state determination

The verifier's terminal-state-determination rule simplifies to:
- Divergent at `v_d`?
  - No → linear (active or terminal-via-Dec).
  - Yes → divergent set contains a privileged event (`Rec`/`Ror`/`Cnt`/`Dec` — recovery-revealing)?
    - Yes → contested (terminal).
    - No → divergent (recoverable via `Rec`).

Cnt is a privileged event whose presence in the divergent set triggers contested via this rule. See [../protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly).

### Cnt parent resolution

Cnt's `previous` always points to `v_{tip-1}` — the parent of the chain's current tip on a linear chain (creates fresh divergence at the tip's serial), or `v_{d-1}` on a divergent chain (the divergence ancestor; the new (divergence-causing) branch is single-event at `v_d` by freeze-on-divergence, so its `v_{tip-1}` is `v_{d-1}` — same `v_{tip-1}` rule applied to different chain shapes; the pre-existing branch may have extended past `v_d` up to the proactive-ROR cap, but Cnt's parent rule selects `v_{d-1}` for cross-node uniformity).

**Implementation note.** Cnt is processed inline with the chain walk. When the walk reaches the generation at `v_d`, branch state holds `v_{tip-1}`'s commitments (`rotation_hash` and `recovery_hash`, set when `v_{tip-1}` was processed and not yet consumed by `v_tip`'s establishment update). Cnt and the existing tip at `v_d` are processed as siblings of the same generation, both consuming `v_{tip-1}`'s commitments — Cnt via its dual-signature check, the tip via its own establishment check. No new cache slot in branch state.

### Upgrade rule

When a node has a non-privileged divergent set at `v_d` (max 2 events, e.g., `Rot`-`Rot`, `Ixn`-`Ixn`, or `Rot`-`Ixn` race) and gossip delivers a non-archiving privileged event for that same `v_d` (`Ror`, `Cnt`, or `Dec` with `previous = v_{d-1}.said`), the verifier accepts the privileged event as a third event in the divergent set. Local state transitions from non-privileged-divergent (recoverable) to contested (terminal). The divergence invariant relaxes to allow up to 3 events at `v_d` when **exactly one** is privileged — the upgrade event. (3 events with 2+ privileged is structurally unreachable: any privileged event in the original 2-event divergent set transitions the chain to contested-terminal immediately (privileged-divergence-is-terminal), and the contested-state gate rejects any subsequent submission. Only when the original 2 events are both non-privileged does the upgrade-rule path open up to add a 3rd privileged event.)

**`Rec` is the archiving exception.** `Rec` is privileged but goes through the discriminator's archival path: `Rec.previous = v_d.said` (branch-tip-extending shape) lands at `v_{d+1}` and archives the other branch; `Rec.previous = v_{d-1}.said` (divergence-ancestor-extending shape) lands at `v_d` and archives both v_d branches. Either shape removes the divergent set before any divergent-set check fires, so `Rec` never participates in the upgrade rule. The other non-archiving privileged kinds (`Ror`, `Cnt`, `Dec`) do participate when their parent is `v_{d-1}.said`. See [../protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](../../protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) for the doctrinal frame.

### Cnt authorization (HARD)

Cnt's dual-signature is verified against `v_{tip-1}`'s commitments: signing key (preimage of `v_{tip-1}`'s `rotation_hash`) + recovery key (preimage of `v_{tip-1}`'s `recovery_hash`). Authorization failure is HARD — a Cnt whose signatures don't verify is rejected by the verifier; the chain stays at its prior state. The general invariant "any event with failed auth is rejected" applies to all event kinds.

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
| `cnt` (contest) | Next signing key | Recovery key |
| `dec` (decommission) | Next signing key | Recovery key |

Events with recovery signatures require dual authorization, making them the highest authority operations in the KEL.

## Streaming Verification (KelVerifier)

`KelVerifier` is the sole verification mechanism for KELs. It walks forward through events page by page, verifying cryptographic integrity without loading the full KEL into memory. It supports both linear and divergent KELs by tracking per-branch state.

Events are processed in **generations** (all events at a given serial). When multiple events appear at the same serial (divergence), the verifier forks `BranchState` — each new event is matched to its branch via the `previous` pointer.

```
struct KelVerifier {
    prefix: String,
    branches: HashMap<String, BranchState>,  // keyed by tip SAID
    last_verified_serial: Option<u64>,
    divergence_ancestor: Option<Digest256>,
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

### Inline Anchor Checking

Register SAIDs to check before verification with `verifier.check_anchors(saids)`. As the verifier processes events, it checks each event's anchor field against the queried SAIDs. Results are available on the `KelVerification` token via `is_said_anchored()` and `anchors_all_saids()`.

Anchor fields appear on `Ixn`, `Rot`, and `Ror` events — `Ixn.anchor` is required (tier 1), `Rot.anchor` / `Ror.anchor` are optional (tier 2 / tier 3) and used by cross-chain verifiers per [§Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation). The `check_anchors()` match scans all three kinds. Cross-chain consumers (IEL/SEL verifiers) need to know not just that a SAID is anchored but in which kind of KEL event — `KelVerification` exposes the anchoring event's kind so callers can enforce tier-appropriate anchor checks.

### Paginated Verification Helper

`completed_verification(loader, prefix, page_size, max_pages, anchors)` pages through a `PageLoader` (implemented by `KelStorePageLoader` for `KelStore`, or by transaction wrappers for advisory-locked reads), calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations that span pages. Returns a trusted `KelVerification` token. The `max_pages` parameter prevents resource exhaustion (default 64 pages = ~2K events).

### Checks Per Event

1. SAID integrity (`event.verify()`)
2. Prefix matches verifier's prefix
3. Serial continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure()`)
6. Anchor format validation (anchors must be valid CESR digests)
7. For establishment events: rotation hash forward commitment, recovery hash commitment
8. Signature verification (primary + dual for recovery events)
