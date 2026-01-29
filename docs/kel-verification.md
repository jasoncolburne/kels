# KEL Verification Protocol

This document describes the verification protocol used to validate the integrity and authenticity of a Key Event Log (KEL).

## Overview

KEL verification ensures:
- All events have valid self-addressing identifiers (SAIDs)
- Events chain correctly from inception to current state
- Pre-rotation commitments are honored (rotation hash → public key)
- Recovery key commitments are honored (recovery hash → recovery key)
- All signatures are valid
- Version numbers are contiguous

## Verification Phases

### Phase 1: Forward Pass (Structure Verification)

The forward pass iterates through events in version order, validating structural properties.

#### 1.1 Version Continuity

```
for each (expected_version, (actual_version, events)):
    if actual_version != expected_version:
        return Error("Missing version")
```

Versions must be contiguous starting from 0. Gaps indicate missing events.

#### 1.2 Divergence Detection

```
if events_at_version.len() > 1 AND no divergence detected yet:
    record divergence_info = {
        diverged_at_version: version,
        divergent_saids: [event SAIDs at this version]
    }
```

Multiple events at the same version indicates divergence (conflicting event chains).

#### 1.3 Event Basics

For each event at each version:

```
verify_event_basics(event, prefix, version):
    // Verify SAID is self-consistent
    event.verify()  // Computes SAID and compares to stored SAID

    // Verify prefix matches KEL prefix
    if event.prefix != kel_prefix:
        return Error("Prefix mismatch")
```

#### 1.4 Chaining Verification

```
verify_chaining(event, version, events_by_version):
    if version == 0:
        // Must be inception (icp or dip)
        if not event.is_inception():
            return Error("KEL does not start with inception")
        if event.previous is not None:
            return Error("Inception has previous field")
        return OK

    // Non-inception must chain from valid previous
    if event.previous is None:
        return Error("Event has no previous field")

    previous_events = events_by_version[version - 1]
    if event.previous not in [e.said for e in previous_events]:
        return Error("Chains from unknown previous")
```

#### 1.5 Valid Tails Tracking

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

        current_said = event.previous
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
    // Reconstruct signed data
    data = canonical_json(signed_event.event)

    // Verify primary signature
    signature = parse_signature(signed_event.signature)
    public_key.verify(data, signature)

    // Verify recovery signature if present
    if signed_event.recovery_signature exists:
        recovery_sig = parse_signature(signed_event.recovery_signature)
        // Recovery signature verified against recovery key
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
    diverged_at_version: u64
    divergent_saids: Vec<String>
```

## Key Properties Verified

| Property | Verification Method |
|----------|---------------------|
| SAID integrity | Recompute and compare |
| Prefix consistency | All events have same prefix |
| Version continuity | No gaps in version sequence |
| Event chaining | Previous field points to valid prior event |
| Pre-rotation commitment | rotation_hash matches next public_key |
| Recovery commitment | recovery_hash matches revealed recovery_key |
| Signature validity | Cryptographic signature verification |

## Divergence Handling

Verification does NOT fail on divergence. Instead:
- Divergence is detected and reported via `DivergenceInfo`
- All branches of a divergent KEL are verified independently
- The merge protocol is responsible for resolving divergence

## Event Types and Their Signatures

| Event Type | Primary Signature | Recovery Signature |
|------------|-------------------|-------------------|
| `icp` (inception) | Signing key | - |
| `ixn` (interaction) | Signing key | - |
| `rot` (rotation) | Next signing key (pre-committed) | - |
| `ror` (recovery rotation) | Next signing key | Recovery key |
| `rec` (recovery) | Next signing key | Recovery key |
| `cnt` (contest) | Next signing key | Recovery key |
| `dec` (decommission) | Next signing key | Recovery key |

Events with recovery signatures require dual authorization, making them the highest authority operations in the KEL.
