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

## Verification Phases

### Phase 1: Forward Pass (Structure Verification)

The forward pass iterates through events by following `previous` links, validating structural properties.

#### 1.1 Chain Building

Events are sorted by following the `previous` chain from inception:

```
start with inception events (previous = None)
for each generation:
    find events whose previous matches current generation's SAIDs
    add to sorted list
```

#### 1.2 Divergence Detection

```
if multiple events share the same previous AND no divergence detected yet:
    record divergence_info = {
        diverged_at_generation: generation,
        divergent_saids: [event SAIDs at this generation]
    }
```

Multiple events with the same `previous` indicates divergence (conflicting event chains).

#### 1.3 Event Basics

For each event:

```
verify_event_basics(event, prefix):
    // Verify SAID is self-consistent
    event.verify()  // Computes SAID and compares to stored SAID

    // Verify prefix matches KEL prefix
    if event.prefix != kel_prefix:
        return Error("Prefix mismatch")
```

#### 1.4 Valid Tails Tracking

Note: There is no separate chaining verification step in the forward pass. Chain integrity is validated implicitly by `walk_generations()` (which follows `previous` links to build the generation map) and explicitly by the backward pass (which walks `previous` pointers and checks serial monotonicity).

```
for each event:
    if event.previous exists:
        valid_tails.remove(event.previous)
    valid_tails.insert(event.said)
```

This tracks the "tips" of all event chains. At the end:
- Single tail = linear KEL
- Multiple tails = divergent KEL

### Phase 2: Backward Pass (Cryptographic Verification)

For each valid tail, walk backward verifying cryptographic properties.

```
for each tail_said in valid_tails:
    verify_branch_from_tail(tail_said)
```

#### 2.1 Backward Walk

```
verify_branch_from_tail(tail_said):
    current_said = tail_said
    next_establishment = None  // Later establishment event
    revealed_recovery_key = None
    pending_events = []  // Non-establishment events awaiting verification

    while current_said exists:
        event = get_event(current_said)

        if event.is_establishment():
            process_establishment_event(event)
        else:
            pending_events.push(event)

        if event.previous exists:
            // Verify serial monotonicity: previous event must have serial == event.serial - 1
            prev_event = get_event(event.previous)
            if event.serial != prev_event.serial + 1:
                return Error("Serial not monotonically increasing")
            current_said = event.previous
        else:
            // Inception event must have serial 0
            if event.serial != 0:
                return Error("Inception event has non-zero serial")
            break
```

#### 2.2 Establishment Event Processing

```
process_establishment_event(event):
    public_key = parse(event.public_key)

    // Verify rotation hash commitment
    if next_establishment exists:
        verify_establishment_security(event, next_establishment)

    // Verify recovery key revelation
    if event.has_recovery_hash AND revealed_recovery_key:
        verify_recovery_key_revelation(event, revealed_recovery_key)

    // Track recovery key state
    if event.reveals_recovery_key():
        revealed_recovery_key = event.recovery_key
    else if event.has_recovery_hash:
        revealed_recovery_key = None  // New commitment resets revelation

    // Verify pending non-establishment events
    for pending in pending_events:
        verify_signatures(pending, public_key)
    pending_events.clear()

    // Verify this event's signature
    verify_signatures(event, public_key)

    next_establishment = event
```

#### 2.3 Pre-rotation Verification

```
verify_establishment_security(event, future_event):
    if event.rotation_hash exists:
        expected_hash = compute_rotation_hash(future_event.public_key)
        if event.rotation_hash != expected_hash:
            return Error("Public key does not match rotation hash")
```

This ensures the pre-rotation commitment is honored: the rotation hash in event N must match the public key revealed in event N+1.

#### 2.4 Recovery Key Verification

```
verify_recovery_key_revelation(event, recovery_key):
    expected_hash = compute_rotation_hash(recovery_key)
    if event.recovery_hash != expected_hash:
        return Error("Recovery key does not match recovery hash")
```

Similar to rotation verification, but for recovery keys.

#### 2.5 Signature Verification

```
verify_signatures(signed_event, public_key):
    // The SAID is a Blake3 hash of the canonical JSON content,
    // so signing/verifying the SAID bytes is equivalent to signing
    // the canonical content but more efficient.
    data = signed_event.event.said.as_bytes()

    // Verify primary signature
    signature = parse_signature(signed_event.signature)
    public_key.verify(data, signature)

    // Verify recovery signature if present (dual authorization)
    if signed_event.recovery_signature exists:
        recovery_key = parse_key(signed_event.event.recovery_key)
        recovery_sig = parse_signature(signed_event.recovery_signature)
        recovery_key.verify(data, recovery_sig)
```

### Phase 3: Final Validation

```
if pending_events not empty:
    return Error("Non-establishment events before inception")

if revealed_recovery_key is still set:
    return Error("Recovery key revealed before commitment")
```

## Verification Return Value

```
verify() -> Result<Option<DivergenceInfo>, KelsError>

Success cases:
- Ok(None) = KEL is valid and linear (no divergence)
- Ok(Some(DivergenceInfo)) = KEL is valid but divergent

DivergenceInfo:
    diverged_at_generation: u64
    divergent_saids: HashSet<String>
```

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
- Divergence is detected and reported via `DivergenceInfo`
- All branches of a divergent KEL are verified independently
- The merge protocol is responsible for resolving divergence

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
