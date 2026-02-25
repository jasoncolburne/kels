# KEL Verification Protocol

This document describes the verification protocol used to validate the integrity and authenticity of a Key Event Log (KEL).

## Overview

KEL verification ensures:
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from inception to current state via `previous` links
- Pre-rotation commitments are honored (rotation hash → public key)
- Recovery key commitments are honored (recovery hash → recovery key)
- All signatures are valid

Events are linked by their `previous` SAID field. Generation is computed dynamically by following the chain from inception (generation 0).

## Verification Algorithm

`KelVerifier` processes events in a single forward pass, verifying structure and cryptography simultaneously. Events must arrive in `serial ASC, said ASC` order with complete generations.

### Per-Event Checks

For each event in the page:

```
verify_event(event):
    // 1. SAID integrity
    event.verify()  // Recompute SAID, compare to stored

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
        record diverged_at_serial if first divergence

    for each event:
        match to branch via event.previous
        verify crypto for that branch
```

### Establishment Event Processing

When an establishment event is encountered (icp, rot, rec, ror, cnt, dec):

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

`KelVerifier::into_verification()` produces a `Verification` token — the proof-of-verification type:

```
Verification:
    prefix: String
    branch_tips: Vec<BranchTip>   // one per branch (1 = linear, N = divergent)
    is_contested: bool
    diverged_at_serial: Option<u64>
    anchored_saids: HashSet<String>
    queried_saids: HashSet<String>

BranchTip:
    tip: SignedKeyEvent            // chain head (latest event on this branch)
    establishment_tip: SignedKeyEvent  // last establishment event (provides signing key)
```

Derived accessors:
- `current_public_key()` → `None` if divergent (ambiguous)
- `last_establishment_event()` → `None` if divergent
- `is_decommissioned()` → contested, or single branch with decommission tip
- `is_divergent()` → `branch_tips.len() > 1`
- `effective_tail_said()` → single tip SAID or `hash_tip_saids()` for divergent
- `is_said_anchored()`, `anchors_all_saids()` → inline anchor checking results

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
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
- Divergence is detected and tracked in the `Verification` token (`is_divergent()`, `diverged_at_serial()`)
- All branches of a divergent KEL are verified independently (the verifier forks `BranchState` per branch)
- The submit handler is responsible for resolving divergence

## Event Types and Their Signatures

Event kind values are version-qualified in serialized form (e.g. `kels/v1/icp`).

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
    diverged_at_serial: Option<u64>,
    is_contested: bool,
    queried_saids: HashSet<String>,   // anchor checking
    anchored_saids: HashSet<String>,  // anchor checking
}
```

### Constructors

- `KelVerifier::new(prefix)` — Start from inception. Full verification of untrusted KELs.
- `KelVerifier::resume(prefix, &Verification)` — Resume from a verified `Verification` token. Used by the submit handler's fast path to verify appended events without re-verifying the entire KEL.
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

Register SAIDs to check before verification with `verifier.check_anchors(saids)`. As the verifier processes events, it checks each event's anchor field against the queried SAIDs. Results are available on the `Verification` token via `is_said_anchored()` and `anchors_all_saids()`.

### Paginated Verification Helper

`completed_verification(loader, prefix, page_size, max_pages, anchors)` pages through a `PageLoader` (implemented by `StorePageLoader` for `KelStore`, or by transaction wrappers for advisory-locked reads), calling `truncate_incomplete_generation()` at page boundaries to handle divergent generations that span pages. Returns a trusted `Verification` token. The `max_pages` parameter prevents resource exhaustion (default 512 pages = ~262K events).

### Checks Per Event

1. SAID integrity (`event.verify()`)
2. Prefix matches verifier's prefix
3. Serial continuity (events arrive in generation order)
4. Previous-pointer continuity (event chains from a known branch tip)
5. Structure validation (`validate_structure()`)
6. Anchor format validation (anchors must be valid CESR digests)
7. For establishment events: rotation hash forward commitment, recovery hash commitment
8. Signature verification (primary + dual for recovery events)
