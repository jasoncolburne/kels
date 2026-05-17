# KEL Merge Protocol

This document describes the merge protocol used when new events are submitted to a Key Event Log (KEL).

## Overview

The merge operation integrates new events into an existing KEL while handling:
- Normal event appends
- Idempotent resubmissions
- Divergence detection (conflicting events at the same generation)
- Recovery from divergence (via `Rec`)
- Contest (`Cnt`) — extends `v_{tip-1}` with the dual signature against the keys committed at `v_{tip-1}` (rotation-key preimage AND recovery-key preimage). See [event-log.md §Operator recourse against signing-key-only Rot takeover](event-log.md#operator-recourse-against-signing-key-only-rot-takeover).

Events are linked by their `previous` SAID field. Generation is the position in the chain (inception is generation 0), computed by counting `previous` links back to inception.

## Merge Outcome

The merge function returns a `MergeOutcome`:
- **`result`** - A `KelMergeResult` variant (see below)
- **`divergedAt`** - Serial at which divergence was detected, if any
- **`tipSaid`** - SAID of the new tip event for linear appends, or `None` for divergent/complex paths

During recovery, the discriminator identifies the events on the branch not extended by `Rec.previous`, archives them to mirror tables, and removes them from the live chain — all synchronously within the merge transaction. A `RecoveryRecord` audit entry is created atomically, and `kels_recovery_events` join records link the recovery to each archived event.

### KelMergeResult Variants

| Result | Meaning | KEL State After |
|--------|---------|-----------------|
| `Accepted` | Events accepted normally | OK |
| `Recovered` | Recovery succeeded, non-surviving branch events archived | OK |
| `Diverged` | Non-privileged divergence first detected, recoverable via `Rec` | Divergent (non-privileged, recoverable) |
| `Contested` | Privileged-divergence rule fired or explicit `Cnt` landed; chain permanently terminal | Contested |
| `RecoverRequired` | KEL is non-privileged-divergent; only `Rec`/`Cnt` events accepted | Divergent (non-privileged) |
| `ContestRequired` | Recovery key revealed in divergent set; the chain must be terminated via `Cnt` | Unchanged |

## Merge Flow

`merge_events` is the single entry point. It validates, verifies the existing KEL, then routes to one of three handlers.

### 1. Validation and Verification

```
validate all events belong to this prefix
validate all signatures (format, dual-sig for recovery events)
verify entire existing KEL via completed_verification → KelVerification token
validate event structure (SAID, required fields)
reject batches containing both rec and cnt
```

The `KelVerification` token is the trusted context for all routing decisions. The DB cannot be trusted directly (verification invariant).

**On the rec-and-cnt rejection.** A batch containing both `Rec` and `Cnt` is structurally contradictory: `Rec` means "preserve the chain via recovery," `Cnt` means "terminate the chain." No operator-intent shape lands both in one batch, so the merge engine rejects up front rather than working out which semantic to apply.

### 2. Terminal-State Gate

Before routing, check whether the chain is already terminal:

```
if chain has any Cnt event → reject ContestedKel
if chain has any Dec event:
    if batch is a single Cnt whose `previous` matches some `v_x.said` where
       another event in the chain also extends `v_x` (i.e., Cnt creates or joins
       a divergent set at `v_{x+1}` — the "other event" is `Dec` itself in Case A,
       the pre-Dec tip in Case B):
        // Cnt-overrides-Dec — see ../../protocol-doctrine.md §Cnt Overrides Dec.
        // Two shapes converge to Contested:
        //   Case A (post-Dec sequential):    Cnt.previous = Dec.previous = v_{d-1}.said;
        //                                    Cnt lands at v_d alongside Dec.
        //   Case B (pre-Dec true-concurrent): Cnt.previous = v_{d-1}.said matches the
        //                                    pre-Dec tip's parent; Cnt lands at v_d
        //                                    as sibling of the pre-Dec tip; Dec sits
        //                                    at v_{d+1} on the surviving branch.
        // verify Cnt's dual signatures against v_{d-1}'s rotationHash / recoveryHash.
        // privileged-divergence-is-terminal fires; chain becomes Contested.
        accept and route to contest path
    else:
        reject KelDecommissioned
```

Fires before all other routing. Terminal state means no further events of any kind, with the single exception of an overriding `Cnt` on a Dec'd chain. Structurally parallel to IEL/SEL Terminal-State Gates.

### 3. Routing

Three handlers based on the `KelVerification` and the submitted events:

```
if events chain from current tip (normal append):
    → handle_normal_append
else if KEL is empty and events start from inception:
    → handle_new_kel
else:
    → handle_full_path
```

### 4. Normal Append (~99% of submissions)

Events chain directly from the current tip of a non-divergent KEL. Decommissioned and Contested chains are handled by §2 Terminal-State Gate and cannot reach this branch (a Dec'd chain's tip is `Dec`, which is terminal — nothing extends it; a Contested chain rejects all submissions).

```
continue KEL verification with submitted events (via KelVerifier::resume from tip)
check proactive ROR compliance
insert events
return Accepted
```

`Cnt` cannot reach this branch: `Cnt.previous = v_{tip-1}.said` (not `tip.said`), so it does not chain from the current tip and routing sends it to §6 Full Path (Overlap subbranch).

### 5. New KEL

Events start from inception (`previous` is `None`) and no KEL exists yet.

```
verify events via KelVerifier::new (full verification from inception)
check proactive ROR compliance
insert events
return Accepted
```

### 6. Full Path (divergence/recovery/overlap)

Reached when events don't chain from the current tip and the KEL is not empty. Handles deduplication, divergent KELs, and overlap submissions.

This handler subdivides into: §6a Dedup → §6b Divergent KEL (Cnt path | Rec path | else) → §6c Overlap (Cnt-on-recovered branch | Rec batch | else).

#### 6a. Deduplication

```
check submitted SAIDs against existing SAIDs in DB
filter out events that already exist
if all events are duplicates:
    return Accepted (no changes)
if first remaining event has no previous:
    return Error("Inception event SAID mismatch")
```

This handles partial re-submissions (e.g., gossip sending a full KEL including events the node already has). After dedup, if the remaining events chain from the current tip, they are processed as a normal append.

#### 6b. Divergent KEL

If the `KelVerification` shows the KEL is already divergent, the merge engine searches the batch for `cnt` or `rec` to determine routing. Pre-recovery/pre-contest events in the batch establish the surviving branch (the chain identified by `Rec.previous` walkback or the operator's intended Cnt extension).

**Contest path** (`cnt` anywhere in batch, must be last):
```
if batch contains a cnt event:
    if cnt is not the last event: return Error("Contest must be last")
    verify cnt's parent shape: cnt.previous = v_{d-1}.said
        (cnt joins the existing divergent set at v_d as a 3rd event via the upgrade rule;
         the new branch is single-event by freeze-on-divergence — its v_{tip-1} is v_{d-1})
    continue KEL verification with submitted events
    check proactive ROR compliance
    insert cnt as the 3rd event at v_d
    return Contested
        (privileged-divergence-is-terminal fires; cnt is privileged → chain contested-terminal.
         Cnt always joins the divergent set via the upgrade rule, regardless of whether
         recovery has been revealed on either branch.)
```

**Recovery path** (`rec` anywhere in batch):
```
if batch contains a rec event:
    if existing events reveal recovery key:
        return ContestRequired  // Adversary has recovery key, must contest
    continue KEL verification with submitted events (from branch tip)
    check proactive ROR compliance
    check whether the contesting branch reveals recovery key (detailed check via find_adversary_event)
    archive non-surviving branch events
    append all events (surviving branch + rec + optional rot)
    create RecoveryRecord + kels_recovery_events links
    return Recovered
```

**No `cnt` or `rec` in batch**:
```
return RecoverRequired/ContestRequired  // Only rec/cnt can resolve a divergent KEL
```

#### 6c. Overlap (non-divergent KEL)

Events chain from an earlier point in a non-divergent KEL, creating a potential fork. The branch point is the existing event whose SAID matches the first submitted event's `previous`.

```
divergedAt = branch_point.serial + 1
continue KEL verification with submitted events (from branch point)
check proactive ROR compliance

// Check if existing events from divergence onward reveal recovery key
if existing events reveal recovery:
    if batch contains cnt (must be last):
        append all events (surviving branch + cnt)
        return Contested
    else:
        return ContestRequired  // Owner must contest, not recover

// Check for recovery in submitted events
if batch contains rec:
    archive existing non-surviving branch events
    append all events (surviving branch + rec + optional rot)
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
- **`MergeOutcome`** — the merge result: `{ result: KelMergeResult, divergedAt: Option<u64>, tipSaid: Option<String> }`. The `divergedAt` field records the serial at which divergence was first detected. The `tipSaid` is the SAID of the new tip event for linear appends, or `None` for divergent KELs and other complex merge paths (callers that need the effective SAID for divergent KELs compute it separately via `compute_prefix_effective_said`).

The `SignedEvents` derive macro generates a `save_with_merge(prefix, events)` method on repositories that acquires an advisory lock, constructs a `MergeTransaction`, and calls `merge_events()`. The `recovery_table` attribute specifies the table for `RecoveryRecord` creation. Adversary archival happens synchronously within the merge transaction.

## Submit Handler Architecture

The merge engine (`merge_events`) handles all routing internally. The KELS service's `submit_events` handler calls `save_with_merge` which acquires an advisory lock, constructs a `MergeTransaction`, and calls `merge_events`. The merge engine:

1. Validates and verifies the existing KEL under the advisory lock
2. Routes to the appropriate handler (normal append, new KEL, or full path)
3. Each handler verifies the submitted events and inserts them

**Normal append** (~99% of submissions): Uses `KelVerifier::resume` for incremental verification. No full KEL load — the `KelVerification` carries the branch tip and establishment state.

**Full path** (divergence/recovery/overlap): Uses bounded DB operations with the `KelVerification` token. No full KEL in memory. Deduplicates first, then routes to divergent or overlap handlers.

## Pagination

All KEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events that share the same serial. The CASE expression uses `KeyEventKind::sort_priority()` to ensure state-determining events (recovery, contest) sort after normal events at the same serial. `MINIMUM_PAGE_SIZE` (64) / `page_size()` controls the page size for both reads and the submit handler's full path. Responses include `has_more` to indicate truncation.

## Gossip Send-Side Partitioning (divergent KELs)

Propagating a divergent KEL chain to a remote node requires more than ordering events by canonical chain order. The receiver's submit handler routes batches by content predicates (`is_contest`, divergent-rejection); a single batch that contains both pre-divergence events and a post-divergence non-`Cnt` extension would route through "normal append (overlap creates fork)" and the second branch's events get rejected. To make propagation succeed, the SENDER partitions the chain into sub-batches the receiver will accept under its routing rules and sends them in sequence.

`send_divergent_events` (`lib/kels/src/types/kel/sync.rs:517`) handles the partitioning: longer chain first as paged non-divergent appends, then the contesting / fork event as an atomic batch. See [reconciliation.md §Transfer ordering](reconciliation.md#transfer-ordering) for the per-state matrix and case-handling.

**Why send-side, not receive-side:** receive-side ordering can sort what arrived but cannot fix structural composition problems where the receiver's submit handler will reject a particular batch composition. The sender has full chain visibility and can produce sequences that compose correctly given the receiver's routing rules. Relying on the receiver's submit handler to "figure out" complex batches is invariant-protection reasoning; the cryptographic-soundness argument is that the sender produces sequences that the routing rules accept by construction.

## Key Invariants

1. **Events are sorted deterministically** by `(serial, kind_priority, said)`. Kind priority: `icp=0, dip=1, ixn=2, rot=3, ror=4, rec=5, dec=6, cnt=7`. The SAID tiebreaker is for determinism only; it has no semantic meaning. See §Why sort priority matters below.
2. **Only one divergent event added** — when divergence is detected, only the first conflicting event is stored.
3. **Recovery key revelation requires contest** — once a recovery-revealing event exists in a divergent branch, non-contest submissions return `ContestRequired`.
4. **Contest is the only response when the recovery key is revealed in divergence** — the chain must be terminated via `Cnt`; no further `Rec` is possible because the recovery key is no longer secret.
5. **Contested KELs are permanently frozen** — no events can be added after contest.
6. **Branch-scoped verifier input on `Rec`** — Rec verification is branch-scoped, not chain-scoped. The walker's running state never carries the divergent set across the archival boundary. See §Branch-scoped Rec verification below.

### Why sort priority matters

The sort order is critical for gossip propagation. When fork siblings (e.g., `dec` + `cnt`) are submitted as a single batch, `partition_for_submission()` sorts them so non-contest events come before contest events, ensuring the merge processes the divergence-establishing event before the contest. Two competing `ixn` events in a divergent fork get the same priority and break the tie by SAID — identical ordering across all nodes.

(Event kind values are version-qualified in serialized form — e.g., `kels/kel/v1/events/icp` — but the version qualifier is separate from the chain-event serial used elsewhere in this doc.)

### Branch-scoped Rec verification

When verifying a `Rec` batch, `KelVerifier::from_branch_tip(prefix, anchor_tip, ...)` (`lib/kels/src/merge.rs:902`) seeds the verifier from `Rec.previous` (the operator's chosen anchor — branch tip in branch-tip-extending shape, or `v_{d-1}` in divergence-ancestor-extending shape). `verify_page(new_events)` (`merge.rs:911`) walks only that branch plus the pending batch; the to-be-archived branch is in storage but never in the walker's input stream. `archive_adversary_chain(...)` (`merge.rs:942`) runs only after verification succeeds.

This honors the one-divergent-generation-at-a-time invariant (see [../../protocol-doctrine.md §One Divergent Generation at a Time](../../protocol-doctrine.md#one-divergent-generation-at-a-time)).

## References

- [event-log.md](event-log.md) — Chain lifecycle, recovery, contest, decommission.
- [reconciliation.md](reconciliation.md) — Multi-node correctness proof matrix.
- [verification.md](verification.md) — `KelVerifier` algorithm.
- [events.md](events.md) — Per-kind reference.
- [../iel/merge.md](../iel/merge.md) — IEL counterpart.
- [../sel/merge.md](../sel/merge.md) — SEL counterpart (which has `Rpr` and the discriminator).
