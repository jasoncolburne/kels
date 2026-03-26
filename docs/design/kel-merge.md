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

The merge function returns a `MergeOutcome`:
- **`result`** - A `KelMergeResult` variant (see below)
- **`diverged_at`** - Serial at which divergence was detected, if any
- **`tip_said`** - SAID of the new tip event for linear appends, or `None` for divergent/complex paths

During recovery, adversary events are identified, archived to mirror tables, and removed from the live chain — all synchronously within the merge transaction. A `RecoveryRecord` audit entry is created atomically.

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

If the KEL is already divergent (frozen), the merge engine searches the batch for `cnt` or `rec` to determine routing. Pre-recovery/pre-contest events in the batch establish the owner's chain in the fork.

**Contest path** (`cnt` anywhere in batch, must be last):
```
if batch contains a cnt event:
    if cnt is not the last event: return Error("Contest must be last")
    if KEL does NOT reveal recovery in divergent events:
        return RecoverRequired  // No recovery revealed — recover, don't contest
    verify batch against branch tip
    append all events (owner's chain + cnt)
    return Contested
```

**Recovery path** (`rec` anywhere in batch):
```
if batch contains a rec event:
    if existing events reveal recovery key:
        return ContestRequired  // Adversary has recovery key, must contest
    verify batch against branch tip
    check if adversary revealed recovery key (detailed check via find_adversary_event)
    archive adversary events
    append all events (owner's chain + rec + optional rot)
    create RecoveryRecord
    return Recovered
```

**No `cnt` or `rec` in batch**:
```
return RecoverRequired  // Only rec/cnt can resolve a divergent KEL
```

### 3. Normal Merge (Non-divergent KEL)

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

### 4. Divergence Handling (Overlap)

When submitted events chain from an earlier point in a non-divergent KEL, creating a fork:

```
diverged_at = branch_point.serial + 1
verify batch against branch tip

// Check if existing events from divergence onward reveal recovery key
if existing events reveal recovery:
    if batch contains cnt (must be last):
        append all events (owner's chain + cnt)
        return Contested
    else:
        return ContestRequired  // Owner must contest, not recover

// Check for recovery in submitted events
if batch contains rec:
    archive existing adversary events
    append all events (owner's chain + rec + optional rot)
    create RecoveryRecord
    return Recovered

// No recovery event — insert single forking event to establish divergence
push single divergent event
return Diverged
```

### 5. Post-merge Verification

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
- **`MergeOutcome`** — the merge result: `{ result: KelMergeResult, diverged_at: Option<u64>, tip_said: Option<String> }`. The `diverged_at` field records the serial at which divergence was first detected. The `tip_said` is the SAID of the new tip event for linear appends, or `None` for divergent KELs and other complex merge paths (callers that need the effective SAID for divergent KELs compute it separately via `compute_prefix_effective_said`).

The `SignedEvents` derive macro generates a `save_with_merge(prefix, events)` method on repositories that acquires an advisory lock, constructs a `MergeTransaction`, and calls `merge_events()`. The `recovery_table` attribute specifies the table for `RecoveryRecord` creation. Adversary archival happens synchronously within the merge transaction.

## Submit Handler Architecture

The KELS service's `submit_events` handler routes submissions through two paths based on the `KelVerification` token obtained from `completed_verification()` under an advisory lock:

### Fast Path (~99% of submissions)

Conditions: single tip (non-divergent), submitted events chain from the tip, KEL not contested.

Uses `KelVerifier::resume(prefix, &kel_verification)` for incremental verification against the verified `KelVerification` token. **No full KEL load** — the `KelVerification` carries the branch tip and establishment state needed to continue. Events are inserted directly.

### Full Path (divergence/recovery/overlap)

Uses bounded DB operations with the verified `KelVerification` token. No full KEL in memory. Each case is handled independently:

- **Already divergent + contest**: Query events from `diverged_at_serial` onward to check recovery key revelation. Verify contest event, insert.
- **Already divergent + recovery**: Walk owner chain backward via paginated DB queries, collect adversary events, archive them, insert recovery events.
- **New divergence/overlap**: Fetch referenced event by SAID, check for duplicates, fork if needed.
- **Inception overlap**: Batch check submitted SAIDs, skip duplicates, process remaining.

## Pagination

All KEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The CASE expression uses `EventKind::sort_priority()` to ensure state-determining events (recovery, contest) sort after normal events at the same serial. The `MAX_EVENTS_PER_KEL_QUERY` constant (32) controls the page size for both reads and the submit handler's full path. Responses include `has_more` to indicate truncation.

## Key Invariants

1. **Events are sorted deterministically** - Events are sorted by `(serial, kind_priority, said)` where kind priority is: icp=0, dip=1, ixn=2, rot=3, ror=4, dec=5, rec=6, cnt=7 (event kind values are version-qualified in serialized form, e.g. `kels/v1/icp`). The SAID tiebreaker is purely for determinism — it has no semantic meaning, but ensures identical ordering across all nodes when two events share the same serial and kind (e.g., two competing `ixn` events in a divergent fork). This sort order is critical for gossip propagation: when fork siblings (e.g., `dec` + `cnt`) are submitted as a single batch, `partition_for_submission()` sorts them so non-contest events come before contest events, ensuring the merge processes the divergence-establishing event before the contest
2. **Only one divergent event added** - When divergence is detected, only the first conflicting event is stored
3. **Recovery key revelation requires contest** - Once a recovery-revealing event exists in a divergent branch, non-contest submissions return `ContestRequired` (owner must contest instead)
4. **Contest is the only response to adversary recovery** - If adversary revealed recovery key, owner must contest (not recover)
5. **Contested KELs are permanently frozen** - No events can be added after contest
