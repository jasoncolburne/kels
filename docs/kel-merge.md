# KEL Merge Protocol

This document describes the merge protocol used when new events are submitted to a Key Event Log (KEL).

## Overview

The merge operation integrates new events into an existing KEL while handling:
- Normal event appends
- Idempotent resubmissions
- Divergence detection (conflicting events at the same generation)
- Recovery from divergence
- Contest when both parties have the recovery key

Events are linked by their `previous` SAID field. Generation is the position in the chain, computed dynamically by following `previous` links from tail(s) to inception (generation 0).

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
| `Contested` | Both parties revealed recovery keys, KEL permanently frozen | Contested |
| `Frozen` | KEL already divergent, only recovery events accepted | Frozen (divergent) |
| `RecoveryProtected` | Recovery event protects this generation from re-divergence | Unchanged |

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

Determine where new events fit by following `previous` links:

**Case A: Append (chains from current tail)**
```
if first_event.previous == current_tail.said:
    if KEL is decommissioned:
        return Error("KEL decommissioned")
    append all events
    return Verified
```

**Case B: Overlap (potential divergence)**
```
for each event where previous already has a successor:
    if existing_successor.said != new_event.said:
        // Divergence detected!
        goto divergence_handling

if all events already exist (same SAIDs):
    return Verified  // Idempotent submission
```

**Case C: Gap**
```
if first_event.previous not found in KEL:
    return Error("Events not contiguous - missing previous event")
```

### 5. Divergence Handling

When divergence is detected (multiple events share same `previous`):

```
divergent_old_events = existing events from divergence point
divergent_new_events = submitted events from divergence point

// Check if recovery already protects this generation
if KEL reveals recovery at or after this generation:
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
        return RecoveryProtected  // Owner must contest, not recover
    else:
        remove adversary events (trace owner's chain via previous)
        append recovery events
        return Recovered
else:
    // No recovery event - freeze KEL
    push single divergent event
    if old_has_recovery:
        return RecoveryProtected
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

1. **Events are sorted by chain order** - The internal event list is sorted by following `previous` links from inception
2. **Only one divergent event added** - When divergence is detected, only the first conflicting event is stored
3. **Recovery protects against re-divergence** - Once a recovery-revealing event exists at generation N, divergence at generation <= N is rejected
4. **Contest is the only response to adversary recovery** - If adversary revealed recovery key, owner must contest (not recover)
5. **Contested KELs are permanently frozen** - No events can be added after contest
