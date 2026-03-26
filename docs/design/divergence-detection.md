# KELS Divergence Detection and Recovery

> **Note**: Event kind values are version-qualified in serialized form (e.g. `kels/v1/icp`). This document uses short names for brevity.

## Problem Statement

In a distributed KELS deployment, an adversary who has compromised a signing key can submit conflicting events to different nodes simultaneously. Before nodes synchronize via gossip, both nodes may accept different events at the same generation (position in the chain), creating a fork in the KEL.

The legitimate owner must be able to:
1. Detect that divergence has occurred
2. Recover by proving ownership of the recovery key
3. Continue using their KEL normally after recovery

## Design Goals

1. **Store enough valid events to describe security state** - Don't reject the first conflicting event at the database level; let clients detect and resolve divergence
2. **Derive state from data** - No separate divergence flag; compute from event structure
3. **Freeze on divergence** - Prevent further damage until owner recovers
4. **Archive synchronously on recovery** - The `rec` (or `rec+rot`) is accepted atomically in the merge transaction. Adversary events are identified, archived to mirror tables, and removed from the live chain — all within the same transaction. The proactive ROR invariant (`MAX_NON_REVEALING_EVENTS = 62`) guarantees the adversary chain never exceeds one page, making synchronous archival feasible. A `RecoveryRecord` provides an immutable audit trail.
5. **Contest mechanism** - Clarifies state is totally compromised through data representation, preventing further additions
6. **Simple client API** - `KeyEventBuilder` handles complexity internally

## Architecture

### Divergence Detection

Divergence is detected when multiple events share the same `previous` SAID (i.e., multiple events at the same generation):

```
Normal KEL:     g0 → g1 → g2 → g3
Divergent KEL:  g0 → g1 → g2 → g3(owner)
                           ↘ g3(adversary)
```

Events are linked by their `previous` field (the SAID of the prior event). Generation is the position in the chain, computed dynamically by following `previous` links from inception.

After verification, `KelVerification::diverged_at_serial()` returns the first serial with multiple events.

### Owner Tail Tracking

The `KeyEventBuilder` tracks the owner's local KEL in memory. The `get_owner_tail()` method returns the last event in the builder's in-memory KEL. The builder loads its state from the local `KelStore` at construction time (via `with_dependencies`) or can be refreshed via `reload()`.

The owner's tail is the **source of truth** for chaining all events:
1. Normal operations (rotate, interact, etc.) chain from the owner's tail
2. Recovery operations chain from the owner's tail
3. The tail identifies which events belong to the owner in a divergent KEL
4. Determines if the owner has rotated since divergence began

* It's impossible to truly know whether events in the owner tail were submitted by the owner and not an adversary, but the distinction helps with reasoning. The 'owner' is assumed to be the recovering/contesting party.

### Event Flow

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ validate signature
  │                                      │ check for divergence
  │                                      │ store event
  │<──── BatchSubmitResponse ────────────│
  │      { applied: true,                │
  │        diverged_at: None }           │
  │                                      │
```

On divergence (event causes divergence but is accepted):

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ detect SAID mismatch at generation N
  │                                      │ store as divergent event
  │<──── BatchSubmitResponse ────────────│
  │      { applied: true,                │
  │        diverged_at: Some(N) }        │
  │                                      │
  │ create rec event from owner's tail   │
  │                                      │
  │──── submit_events([rec]) ───────────>│
  │                                      │ store rec (+ rot if needed)
  │                                      │ create RecoveryRecord
  │<──── BatchSubmitResponse ────────────│
  │      { applied: true }               │
  │                                      │
  │ (adversary events archived           │
  │  synchronously in merge transaction) │
```

When KEL is already frozen (submitting to a divergent KEL):

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ KEL already divergent
  │                                      │ reject event (not stored)
  │<──── BatchSubmitResponse ────────────│
  │      { applied: false,               │
  │        diverged_at: Some(N) }        │
  │                                      │
  │  create rec event from owner's tail  │
  │                                      │
  │──── submit_events([rec]) ───────────>│
  │                                      │
  │   original data, chained from rec    |
  │                                      │
  │──── submit_events([event*]) ────────>│
  │                                      │ ...
```

It is also possible to prepend the event in a batch when recovering:

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ KEL already divergent
  │                                      │ reject event (not stored)
  │<──── BatchSubmitResponse ────────────│
  │      { applied: false,               │
  │        diverged_at: Some(N) }        │
  │                                      │
  │           create rec event           │
  │                                      │
  │──── submit_events([event,rec]) ─────>│
  │                                      │ ...
```

## Key Components

### KeyEventBuilder

Manages event creation with automatic state tracking:

```rust
// Load existing KEL
let builder = KeyEventBuilder::with_dependencies(
    key_provider,
    Some(kels_client),
    Some(kel_store),
    Some(prefix),
).await?;

// Operations automatically handle divergence
let result = builder.interact("anchor-said").await;
match result {
    Ok((event, sig)) => { /* success */ }
    Err(KelsError::DivergenceDetected { submission_accepted, .. }) => {
        // submission_accepted indicates if the event was stored despite divergence
        builder.recover().await?;
    }
}
```

### Two-Phase Key Rotation

Key rotations use stage/commit/rollback to ensure recovery is possible:

1. `stage_rotation()` - Stage new key, keep old key active
2. Submit event to KELS
3. On success: `commit()` - Activate new key
4. On divergence with `submission_accepted: true`: `commit()` - Event was stored
5. On divergence with `submission_accepted: false`: `rollback()` - Event was rejected

The CLI must save key state whenever keys are committed (both success and accepted divergence).

All key-rotating builder methods (`rotate()`, `rotate_recovery()`, `contest()`) handle `DivergenceDetected { submission_accepted: true }` by returning the signed event successfully, allowing the CLI to persist the new key state.

### Recovery Events

Recovery (`rec`) is an **establishment event** that proves ownership and rotates keys. It requires dual signatures:
- Current rotation key (the `next_key` that was pre-committed in the owner's latest establishment event)
- Recovery key (proves recovery authority)

The `rec` event establishes new forward keys:
- The rotation key becomes the new current signing key
- A fresh next key is committed via `rotation_hash`
- A fresh recovery key is committed via `recovery_hash`

**Recovery Chaining**: The `rec` event chains from the owner's tail event, not the remote event. This ensures the `rotation_hash` in the chain-from event matches the owner's current rotation key.

**Conditional Rotation After Recovery**: After submitting `rec`, the owner may need an additional `rot` event to escape a potentially compromised key:

| Scenario | Owner rotated at/after divergence? | Adversary rotated? | Extra rot needed? |
|----------|-----------------------------------|-------------------|-------------------|
| Adversary ixn only | No | No | No |
| Adversary rotated, owner didn't | No | Yes | **Yes** |
| Both rotated | Yes | Yes | No |
| Owner rotated, adversary ixn | Yes | No | No |

The logic is: `needs_extra_rot = adversary_rotated && !owner_rotated`

If the owner has already rotated at or after the divergence point, they've escaped to a key the adversary doesn't know.

### Contest Events

If the adversary has revealed their recovery key (submitted `rec`, `ror`, `dec`, or `cnt`), the owner submits a contest (`cnt`) event instead of `rec`. This permanently freezes the KEL.

**Contest does not archive**: Unlike `rec`, a `cnt` event simply appends to the divergent KEL without removing any events. The KEL remains divergent but is frozen - no further events can be added. This preserves all events for forensic analysis.

A KEL is considered contested if it contains **any** `cnt` event (not just if the last event is `cnt`).

## Database Schema

### Prefix Index

```sql
-- Index for querying events by prefix
CREATE INDEX kels_key_events_prefix_idx
  ON kels_key_events(prefix);
```

Events are linked by their `previous` SAID field rather than a serial number. Multiple events can share the same `previous` value, indicating divergence. That said, in a KEL, divergent events may also share serial numbers.

### Recovery Records and Synchronous Archival

When a `rec` (or `rec+rot`) event resolves divergence, the merge engine identifies the adversary events, archives them to mirror tables, inserts the recovery events, and creates a `RecoveryRecord` — all within the same advisory-locked transaction. Recovery completes atomically: either the adversary is fully archived and the clean chain restored, or nothing changes.

**How?** The proactive ROR invariant (`MAX_NON_REVEALING_EVENTS = 62`) guarantees that an adversary can only fork after the last recovery-revealing event. Combined with the proactive ROR enforcement, the adversary chain never exceeds one page (`MINIMUM_PAGE_SIZE = 64`), making synchronous archival in a single transaction feasible.

**Why archive instead of truncate?** A database-level truncation would lose the adversary events permanently. Archival moves events to `kels_archived_events` and `kels_archived_event_signatures` (mirror tables with the same schema), preserving them for forensic analysis. The `RecoveryRecord` provides an immutable audit trail linking archived events to the recovery that created them.

```sql
CREATE TABLE kels_recovery (
    said TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL
);

CREATE TABLE kels_archived_events (LIKE kels_key_events INCLUDING ALL);
CREATE TABLE kels_archived_event_signatures (LIKE kels_key_event_signatures INCLUDING ALL);
```

## API Reference

### Submit Events

```
POST /api/v1/kels/events
Content-Type: application/json

[{ signed_event }, ...]

Response:
{
  "applied": true,
  "divergedAt": <serial> | null
}
```

Where `divergedAt` is the serial number (0-indexed position in chain) where divergence was detected, or null if no divergence.

### Fetch KEL (paginated)

```
GET /api/v1/kels/kel/:prefix?limit=32&since=<SAID>

Response: { "events": [SignedKeyEvent, ...], "hasMore": bool }
```

Returns a `SignedKeyEventPage`. Use `?since=SAID` for delta fetch (events after a given SAID). Use `?limit=N` to control page size (1-64, default 64). Loop with `hasMore` for full retrieval.

### Fetch Recovery History

```
GET /api/v1/kels/kel/:prefix/audit

Response: [RecoveryRecord, ...]
```

Recovery records are separate from the paginated KEL endpoint. Each record is an immutable audit entry documenting a recovery — when it happened, what serial the divergence was at, and what was archived.

## CLI Commands

### Standard Operations

```bash
kels-cli incept                              # Create new KEL
kels-cli rotate --prefix <prefix>            # Rotate signing key
kels-cli rotate-recovery --prefix <prefix>   # Rotate recovery key
kels-cli anchor --prefix <prefix> --said <s> # Anchor SAID
kels-cli recover --prefix <prefix>           # Recover from divergence
kels-cli decommission --prefix <prefix>      # Decommission KEL
kels-cli get <prefix>                        # Fetch KEL from server
kels-cli status --prefix <prefix>            # Show local KEL status
kels-cli list                                # List local KELs
```

### Testing (dev-tools feature)

The test scripts simulate adversaries by backing up and swapping the local state directory:

```bash
# In test scripts (test-adversarial.sh):
swap_to_adversary    # Switch to backed-up adversary state
kels-cli adversary inject --prefix <prefix> --events ixn,rot
swap_to_owner        # Switch back to owner state
```

The `adversary inject` command submits events to the server without updating local state. While useful for extending a KEL without divergence, when combined with state directory swapping allows for divergence injection. This simulates an adversary who captured the owner's keys at a point in time.

## Security Considerations

### Frozen State

Once divergence is detected, the KEL is frozen:
- No new events accepted except `rec` or `cnt` (and `cnt` only when recovery key has been revealed)
- Prevents adversary from extending their fork
- Server returns `{ applied: false, diverged_at: N }` for rejected submissions, allowing client to recover or sync

### Contest Escalation

Contest escalation is based on whether existing divergent events reveal the recovery key, not on generation comparison:
- If any divergent event in the KEL reveals the recovery key (`rec`, `ror`, `cnt`, `dec`), non-contest submissions return `ContestRequired` — the owner must contest, not recover
- If no recovery key has been revealed, `cnt` returns `RecoverRequired` — the owner should recover, not contest
- Enables proactive protection: rotating recovery key (`ror`) causes future adversary submissions before that point to require contest

### Contest Finality

If both parties have used the recovery key, contest (`cnt`) permanently freezes the KEL. Neither party can add more events. This is the correct outcome when key compromise is total.

A KEL with any `cnt` event is permanently frozen and will reject all new submissions.

## Testing

### E2E Test Scenarios

**test-kels.sh - Basic Operations:**
1. Create inception event
2. Rotate signing key
3. Anchor SAID (interaction)
4. Rotate recovery key
5. Fetch KEL from server
6. Check local status
7. List local KELs
8. Create second KEL
9. Decommission first KEL
10. Verify decommissioned KEL rejects events

**test-adversarial.sh - Divergence and Recovery:**
1. **Adversary Injects Interaction** - ixn attack, owner recovers
2. **Adversary Injects Rotation** - rot attack, owner recovers with extra rot (adversary knew rotation key)
3. **Multiple Adversary Events** - ixn,ixn,rot attack, owner recovers with extra rot
4. **Data Integrity After Recovery** - Pre-attack anchors preserved
5. **Owner Submits Divergent Rotation** - Owner's rot conflicts, owner recovers (no extra rot - owner already rotated)
6. **Adversary Injects Recovery Rotation (ror)** - Owner contests, KEL frozen
7. **Adversary Decommissions KEL** - dec attack, owner contests
8. **Adversary Rotates Then Anchors** - rot,ixn,ixn chain, owner recovers with extra rot
9. **Adversary Double Rotation** - rot,rot attack, owner recovers with extra rot
10. **Owner Rotates, Then Adversary Attacks** - Post-rotation ixn attack, owner recovers (no extra rot)
11. **Adversary Decommissions After Owner Anchors** - dec attack on data, owner contests
12. **Adversary Injects Recovery (rec)** - rec attack, owner contests
13. **Adversary Attacks Old Generation After Multiple Rotations** - Owner already rotated twice, adversary injects at old generation, owner recovers (no extra rot - owner already escaped)
14. **Submission When Frozen** - All operations rejected on contested KEL
15. **Proactive Recovery Protection via ROR** - Owner rotates recovery key, preventing historical injection
16. **Post-Recovery Protection** - After recovery, adversary cannot re-diverge at earlier generations

**test-reconciliation.sh - Multi-Node Reconciliation:**
1. **Recovered KEL → Adversary Node** - Owner recovers on node-d, recovery propagates to node-e (which has adversary chain), all nodes converge with 1 archived event
2. **Post-Recovery Events → Adversary Node** - After recovery, owner anchors new data; post-recovery events propagate to nodes that had adversary chain
3. **Adversary rot,ixn,ixn + Recovery Propagation** - Adversary rotation chain on node-e, owner recovers on node-d with extra rot, all nodes converge with 3 archived events
4. **Contested KEL Propagation (cnt on shorter chain)** - Adversary ror+ixn (longer chain) on node-e, owner contests on node-d; cnt reaches all nodes despite being on shorter chain
5. **Contested KEL Propagation (cnt on longer chain)** - Adversary ror (shorter) on node-e, owner has ixn+cnt (longer chain); cnt propagates naturally
6. **Contest During Active Archival** - Adversary submits rec on node-d, owner contests; archival detects cnt and transitions to contested terminal state
7. **Double Recovery Rejected** - Owner recovers, then adversary tries second rec; rejected with ContestRequired
8. **Contested Effective SAID Convergence** - After contest, all nodes report same effective SAID even if event counts differ
9. **Submissions Rejected on Contested KEL** - All event types (ixn, rot, dec) rejected on contested KEL
10. **Submissions Rejected on Decommissioned KEL** - Events rejected after decommission
