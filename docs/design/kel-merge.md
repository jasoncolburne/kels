# KEL Merge Protocol

This document describes the merge protocol used when new events are submitted to a Key Event Log (KEL).

## Overview

The merge operation integrates new events into an existing KEL while handling:
- Normal event appends
- Idempotent resubmissions
- Divergence detection (conflicting events at the same generation)
- Recovery from divergence
- Contest when both parties have the recovery key

Events are linked by their `previous` SAID field. Generation is the position in the chain (inception is generation 0), computed by counting `previous` links back to inception.

## Return Values

The merge function returns a tuple of three elements:
1. **Archived events** - Events removed from the KEL (adversary events during recovery)
2. **Added events** - Events successfully added to the KEL
3. **Merge result** - One of the `KelMergeResult` variants

### KelMergeResult Variants

| Result | Meaning | KEL State After |
|--------|---------|-----------------|
| `Accepted` | Events accepted normally | OK |
| `Recovered` | Recovery succeeded, adversary events archived | OK |
| `Diverged` | Divergence first detected, KEL now frozen, owner can submit `rec` | Frozen (divergent) |
| `Contested` | Both parties revealed recovery keys, KEL permanently frozen | Contested |
| `RecoverRequired` | KEL already frozen (divergent), only `rec`/`cnt` events accepted | Frozen (divergent) |
| `ContestRequired` | Recovery key revealed, owner must submit `cnt` to freeze | Unchanged |

## Merge Flow

### 0. Inception Dedup (Re-submission from Genesis)

If the submitted events start from inception (`previous` is `None`) and the KEL already has events, merge skips known duplicates and recurses with the remaining new events. This allows callers to submit a full KEL (including inception) without triggering "Events not contiguous" errors. If the inception event SAID doesn't match the existing KEL's inception, the merge returns an error. If all events are duplicates, the merge returns `Accepted` with no changes.

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
    // Look ahead for a rec event in the batch — handles the case where
    // the owner's pre-recovery events precede the recovery event
    // (e.g., [owner_ixn, rec] submitted to a KEL frozen with only adversary events)
    if batch contains a rec event:
        add pre-rec events to establish owner's chain in the fork
        process rec event via recovery path below
        return Recovered
    return RecoverRequired  // No recovery event in batch
```

### 3. Recovery from Divergent KEL

If the KEL is divergent and receiving a recovery-revealing event:

**Contest path** (`cnt` event):
```
if first event is contest:
    if KEL does NOT reveal recovery in divergent events:
        return Error(Frozen)  // Can only contest if adversary also revealed recovery
    if more than one event submitted:
        return Error("Cannot append events after contest")
    append contest event
    verify KEL
    return Contested
```

**Recovery path** (`rec` event):
```
if batch contains a rec event (at any position):
    add pre-rec events to establish owner's chain in the fork
    if KEL reveals recovery in divergent events:
        return Error(ContestRequired)  // Adversary has recovery key, must contest
    trace owner's chain from recovery event's previous field
    remove adversary events (those not in owner's chain)
    append recovery events
    verify KEL
    return Recovered
```

**No recovery event in batch**:
```
return RecoverRequired  // Only rec/cnt can resolve a divergent KEL
```

### 4. Normal Merge (Non-divergent KEL)

Determine where new events fit by following `previous` links:

**Case A: Append (chains from current tail)**
```
if first_event.previous == current_tail.said:
    if KEL is decommissioned:
        return Error("KEL decommissioned")
    append all events
    return Accepted
```

**Case B: Overlap (potential divergence)**
```
for each event where previous already has a successor:
    if existing_successor.said != new_event.said:
        // Divergence detected!
        goto divergence_handling

if all events already exist (same SAIDs):
    return Accepted  // Idempotent submission
```

**Case C: Gap**
```
if first_event.previous not found in KEL:
    return Error("Events not contiguous - missing previous event")
```

### 5. Divergence Handling

When divergence is detected (multiple events share same `previous`):

```
divergent_old_events = existing events from divergence point (walk back from current tail)
divergent_new_events = submitted events not already in KEL

// Check if existing divergent events reveal recovery key
if old events reveal recovery:
    if divergent new event is contest:
        if more than one event submitted:
            return Error("Cannot append events after contest")
        append contest event
        return Contested
    else:
        return ContestRequired  // Owner must contest, not recover
else if batch contains a rec event (at any position):
    add pre-rec events to establish owner's chain in the fork
    trace owner's chain from recovery event's previous field
    remove adversary events (those not in owner's chain)
    append recovery events
    return Recovered
else:
    // No recovery event in batch - freeze KEL, mark as divergent
    push single divergent event
    return Diverged
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
   rec               cnt
    │                 │
    ▼                 ▼
┌───────┐       ┌───────────┐
│  OK   │       │ Contested │
│(recov)│       │ (frozen)  │
└───────┘       └───────────┘
```

## Merge Transaction API

The merge logic lives in `lib/kels/src/merge.rs` and is exposed via two public types:

- **`MergeTransaction<T>`** — wraps a `TransactionExecutor` (PostgreSQL transaction with advisory lock) and provides `merge_events(&mut self, events: &[SignedKeyEvent]) -> Result<MergeOutcome, KelsError>`. This is the single entry point for all write paths — gossip, federation sync, direct submissions, and the `save_with_merge()` method generated by the `SignedEvents` derive macro all funnel through it.
- **`MergeOutcome`** — the merge result: `{ result: KelMergeResult, diverged_at: Option<u64>, tip_said: Option<String> }`. The `diverged_at` field records the serial at which divergence was first detected. The `tip_said` is the effective SAID after the merge (single tip SAID for linear KELs, composite hash for divergent).

The `SignedEvents` derive macro generates a `save_with_merge(prefix, events)` method on repositories that acquires an advisory lock, constructs a `MergeTransaction`, and calls `merge_events()`. The optional `audit_table` attribute enables adversary event archival during recovery.

## Submit Handler Architecture

The KELS service's `submit_events` handler routes submissions through two paths based on the `Verification` token obtained from `completed_verification()` under an advisory lock:

### Fast Path (~99% of submissions)

Conditions: single tip (non-divergent), submitted events chain from the tip, KEL not contested.

Uses `KelVerifier::resume(prefix, &ctx)` for incremental verification against the verified `Verification` token. **No full KEL load** — the `Verification` carries the branch tip and establishment state needed to continue. Events are inserted directly.

### Full Path (divergence/recovery/overlap)

Uses bounded DB operations with the verified `Verification` token. No full KEL in memory. Each case is handled independently:

- **Already divergent + contest**: Query events from `diverged_at_serial` onward to check recovery key revelation. Verify contest event, insert.
- **Already divergent + recovery**: Walk owner chain backward via paginated DB queries, collect adversary events, archive them, insert recovery events.
- **New divergence/overlap**: Fetch referenced event by SAID, check for duplicates, fork if needed.
- **Inception overlap**: Batch check submitted SAIDs, skip duplicates, process remaining.

## Pagination

All KEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The CASE expression uses `EventKind::sort_priority()` to ensure state-determining events (recovery, contest) sort after normal events at the same serial. The `MAX_EVENTS_PER_KEL_QUERY` constant (512) controls the page size for both reads and the submit handler's full path. Responses include `has_more` to indicate truncation.

## Key Invariants

1. **Events are sorted deterministically** - Events are sorted by `(serial, kind_priority, said)` where kind priority is: icp=0, dip=1, ixn=2, rot=3, ror=4, dec=5, rec=6, cnt=7 (event kind values are version-qualified in serialized form, e.g. `kels/v1/icp`). The SAID tiebreaker is purely for determinism — it has no semantic meaning, but ensures identical ordering across all nodes when two events share the same serial and kind (e.g., two competing `ixn` events in a divergent fork). This sort order is critical for gossip propagation: when fork siblings (e.g., `dec` + `cnt`) are submitted as a single batch, `partition_for_submission()` sorts them so non-contest events come before contest events, ensuring the merge processes the divergence-establishing event before the contest
2. **Only one divergent event added** - When divergence is detected, only the first conflicting event is stored
3. **Recovery key revelation requires contest** - Once a recovery-revealing event exists in a divergent branch, non-contest submissions return `ContestRequired` (owner must contest instead)
4. **Contest is the only response to adversary recovery** - If adversary revealed recovery key, owner must contest (not recover)
5. **Contested KELs are permanently frozen** - No events can be added after contest
