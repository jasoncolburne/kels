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

During recovery, adversary events are identified, archived to mirror tables, and removed from the live chain — all synchronously within the merge transaction. A `RecoveryRecord` audit entry is created atomically, and `kels_recovery_events` join records link the recovery to each archived adversary event.

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

`merge_events` is the single entry point. It validates, verifies the existing KEL, then routes to one of three handlers.

### 1. Validation and Verification

```
validate all events belong to this prefix
validate all signatures (format, dual-sig for recovery events)
verify entire existing KEL via completed_verification → KelVerification token
validate event structure (SAID, required fields)
reject batches containing both rec and cnt (contradictory intent)
```

The `KelVerification` token is the trusted context for all routing decisions. The DB cannot be trusted directly (verification invariant).

### 2. Routing

Three handlers based on the `KelVerification` and the submitted events:

```
if events chain from current tip (normal append):
    → handle_normal_append
else if KEL is empty and events start from inception:
    → handle_new_kel
else:
    → handle_full_path
```

### 3. Normal Append (~99% of submissions)

Events chain directly from the current tip of a non-divergent KEL.

```
if KEL is decommissioned:
    return Error("KEL decommissioned")
if batch contains contest:
    return Error("Contest requires divergence")
continue KEL verification with submitted events (via KelVerifier::resume from tip)
check proactive ROR compliance
insert events
return Accepted
```

### 4. New KEL

Events start from inception (`previous` is `None`) and no KEL exists yet.

```
verify events via KelVerifier::new (full verification from inception)
check proactive ROR compliance
insert events
return Accepted
```

### 5. Full Path (divergence/recovery/overlap)

Reached when events don't chain from the current tip and the KEL is not empty. Handles deduplication, divergent KELs, and overlap submissions.

#### 5a. Contested check

```
if KEL is contested:
    return Error("KEL is already contested")
```

#### 5b. Deduplication

```
check submitted SAIDs against existing SAIDs in DB
filter out events that already exist
if all events are duplicates:
    return Accepted (no changes)
if first remaining event has no previous:
    return Error("Inception event SAID mismatch")
```

This handles partial re-submissions (e.g., gossip sending a full KEL including events the node already has). After dedup, if the remaining events chain from the current tip, they are processed as a normal append.

#### 5c. Divergent KEL

If the `KelVerification` shows the KEL is already divergent, the merge engine searches the batch for `cnt` or `rec` to determine routing. Pre-recovery/pre-contest events in the batch establish the owner's chain in the fork.

**Contest path** (`cnt` anywhere in batch, must be last):
```
if batch contains a cnt event:
    if cnt is not the last event: return Error("Contest must be last")
    if KEL does NOT reveal recovery in divergent events:
        return RecoverRequired  // No recovery revealed — recover, don't contest
    continue KEL verification with submitted events (from branch tip)
    check proactive ROR compliance
    append all events (owner's chain + cnt)
    return Contested
```

**Recovery path** (`rec` anywhere in batch):
```
if batch contains a rec event:
    if existing events reveal recovery key:
        return ContestRequired  // Adversary has recovery key, must contest
    continue KEL verification with submitted events (from branch tip)
    check proactive ROR compliance
    check if adversary revealed recovery key (detailed check via find_adversary_event)
    archive adversary events
    append all events (owner's chain + rec + optional rot)
    create RecoveryRecord + kels_recovery_events links
    return Recovered
```

**No `cnt` or `rec` in batch**:
```
return RecoverRequired/ContestRequired  // Only rec/cnt can resolve a divergent KEL
```

#### 5d. Overlap (non-divergent KEL)

Events chain from an earlier point in a non-divergent KEL, creating a potential fork. The branch point is the existing event whose SAID matches the first submitted event's `previous`.

```
diverged_at = branch_point.serial + 1
continue KEL verification with submitted events (from branch point)
check proactive ROR compliance

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

The merge engine (`merge_events`) handles all routing internally. The KELS service's `submit_events` handler calls `save_with_merge` which acquires an advisory lock, constructs a `MergeTransaction`, and calls `merge_events`. The merge engine:

1. Validates and verifies the existing KEL under the advisory lock
2. Routes to the appropriate handler (normal append, new KEL, or full path)
3. Each handler verifies the submitted events and inserts them

**Normal append** (~99% of submissions): Uses `KelVerifier::resume` for incremental verification. No full KEL load — the `KelVerification` carries the branch tip and establishment state.

**Full path** (divergence/recovery/overlap): Uses bounded DB operations with the `KelVerification` token. No full KEL in memory. Deduplicates first, then routes to divergent or overlap handlers.

## Pagination

All KEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The CASE expression uses `EventKind::sort_priority()` to ensure state-determining events (recovery, contest) sort after normal events at the same serial. `MINIMUM_PAGE_SIZE` (64) / `page_size()` controls the page size for both reads and the submit handler's full path. Responses include `has_more` to indicate truncation.

## Key Invariants

1. **Events are sorted deterministically** - Events are sorted by `(serial, kind_priority, said)` where kind priority is: icp=0, dip=1, ixn=2, rot=3, ror=4, dec=5, rec=6, cnt=7 (event kind values are version-qualified in serialized form, e.g. `kels/events/v1/icp`). The SAID tiebreaker is purely for determinism — it has no semantic meaning, but ensures identical ordering across all nodes when two events share the same serial and kind (e.g., two competing `ixn` events in a divergent fork). This sort order is critical for gossip propagation: when fork siblings (e.g., `dec` + `cnt`) are submitted as a single batch, `partition_for_submission()` sorts them so non-contest events come before contest events, ensuring the merge processes the divergence-establishing event before the contest
2. **Only one divergent event added** - When divergence is detected, only the first conflicting event is stored
3. **Recovery key revelation requires contest** - Once a recovery-revealing event exists in a divergent branch, non-contest submissions return `ContestRequired` (owner must contest instead)
4. **Contest is the only response to adversary recovery** - If adversary revealed recovery key, owner must contest (not recover)
5. **Contested KELs are permanently frozen** - No events can be added after contest
