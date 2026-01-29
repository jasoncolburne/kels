# KEL Merge Protocol

This document describes the merge protocol used when new events are submitted to a Key Event Log (KEL).

## Overview

The merge operation integrates new events into an existing KEL while handling:
- Normal event appends
- Idempotent resubmissions
- Divergence detection (conflicting events at the same version)
- Recovery from divergence
- Contest when both parties have the recovery key

## Return Values

The merge function returns a tuple of three elements:
1. **Archived events** - Events removed from the KEL (adversary events during recovery)
2. **Added events** - Events successfully added to the KEL
3. **Merge result** - One of the `KelMergeResult` variants

### KelMergeResult Variants

| Result | Meaning | KEL State After |
|--------|---------|-----------------|
| `Verified` | Events accepted normally | OK |
| `Recovered` | Recovery succeeded, adversary events archived | OK |
| `Recoverable` | Divergence detected, owner can submit `rec` | Frozen (divergent) |
| `Contestable` | Adversary revealed recovery key, owner must submit `cnt` | Frozen (divergent) |
| `Contested` | Both parties revealed recovery keys, KEL permanently frozen | Contested |
| `Frozen` | KEL already divergent, only recovery events accepted | Frozen (divergent) |
| `RecoveryProtected` | Recovery event protects this version from re-divergence | Unchanged |

## Merge Flow

### 1. Pre-merge Validation

```
if events is empty:
    return Error("No events to add")

if KEL is contested:
    return Error("KEL is already contested")

for each event:
    validate event structure (SAID, required fields)
```

### 2. Handle Already-Divergent KEL

If the KEL is already divergent (frozen):

```
if KEL has divergence AND first event does NOT reveal recovery key:
    return Frozen  // Only rec/ror/dec/cnt can unfreeze
```

### 3. Recovery from Divergent KEL

If the KEL is divergent and receiving a recovery-revealing event:

**Contest path** (`cnt` event):
```
if first event is contest:
    append contest event
    verify KEL
    return Contested
```

**Recovery path** (`rec`/`ror`/`dec` event):
```
trace owner's chain from recovery event's previous field
remove adversary events (those not in owner's chain)
append recovery events
verify KEL
return Recovered
```

### 4. Normal Merge (Non-divergent KEL)

Calculate where new events should be inserted based on version:

**Case A: Append (no overlap)**
```
if existing_length == first_event.version:
    if KEL is decommissioned:
        return Error("KEL decommissioned")
    append all events
    return Verified
```

**Case B: Overlap (potential divergence)**
```
for each overlapping position:
    if old_event.said != new_event.said:
        // Divergence detected!
        goto divergence_handling

if all overlapping events match:
    append any remaining new events
    return Verified  // Idempotent submission
```

**Case C: Gap**
```
if first_event.version > existing_length:
    return Error("Events not contiguous")
```

### 5. Divergence Handling

When divergence is detected during overlap checking:

```
divergent_old_events = existing events from divergence point
divergent_new_events = submitted events from divergence point

// Check if recovery already protects this version
if KEL reveals recovery at or after this version:
    if new event is NOT contest:
        return RecoveryProtected
    // Contest events are allowed through

// Check what kind of events are involved
old_has_recovery = any old event reveals recovery key
new_has_recovery = any new event reveals recovery key

if new_has_recovery:
    if old_has_recovery AND new event is contest:
        append contest event
        return Contested
    else if old_has_recovery:
        return Contestable  // Owner must contest, not recover
    else:
        truncate at divergence point
        append recovery events
        return Recovered
else:
    // No recovery event - freeze KEL
    push single divergent event
    if old_has_recovery:
        return Contestable
    else:
        return Recoverable
```

### 6. Post-merge Verification

After any successful merge that modified the KEL:
```
verify KEL integrity
return result
```

## State Diagram

```
                    ┌─────────┐
                    │   OK    │
                    └────┬────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         divergence            decommission
         detected                   │
              │                     ▼
              ▼               ┌───────────┐
       ┌───────────┐          │Decommiss- │
       │  Frozen   │          │   ioned   │
       │(divergent)│          └───────────┘
       └─────┬─────┘
             │
    ┌────────┴────────┐
    │                 │
  rec/ror/dec        cnt
    │                 │
    ▼                 ▼
┌───────┐       ┌───────────┐
│  OK   │       │ Contested │
│(recov)│       │ (frozen)  │
└───────┘       └───────────┘
```

## Key Invariants

1. **Events are sorted by version** - The internal event list is always sorted
2. **Only one divergent event added** - When divergence is detected, only the first conflicting event is stored
3. **Recovery protects against re-divergence** - Once a recovery-revealing event exists at version N, divergence at version <= N is rejected
4. **Contest is the only response to adversary recovery** - If adversary revealed recovery key, owner must contest (not recover)
5. **Contested KELs are permanently frozen** - No events can be added after contest
