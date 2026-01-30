# KELS Divergence Detection and Recovery

## Problem Statement

In a distributed KELS deployment, an adversary who has compromised a signing key can submit conflicting events to different nodes simultaneously. Before nodes synchronize via gossip, both nodes may accept different events at the same generation (position in the chain), creating a fork in the KEL.

The legitimate owner must be able to:
1. Detect that divergence has occurred
2. Recover by proving ownership of the recovery key
3. Continue using their KEL normally after recovery

## Design Goals

1. **Store all valid events** - Don't reject conflicting events at the database level; let clients detect and resolve divergence
2. **Derive state from data** - No separate divergence flag; compute from event structure
3. **Freeze on divergence** - Prevent further damage until owner recovers
4. **Archive on recovery** - Preserve adversary events for audit purposes
5. **Simple client API** - `KeyEventBuilder` handles complexity internally

## Architecture

### Divergence Detection

Divergence is detected when multiple events share the same `previous` SAID (i.e., multiple events at the same generation):

```
Normal KEL:     g0 → g1 → g2 → g3
Divergent KEL:  g0 → g1 → g2 → g3(owner)
                           ↘ g3(adversary)
```

Events are linked by their `previous` field (the SAID of the prior event). Generation is the position in the chain, computed dynamically by following `previous` links from inception.

The `Kel::find_divergence()` method returns the first generation with multiple SAIDs.

### Owner Tail Tracking

The `KelStore` tracks the owner's tail SAID via `save_owner_tail()` / `load_owner_tail()`. This is updated whenever an event is successfully accepted by KELS (including when divergence is detected but the event was still stored).

The owner's tail is the **source of truth** for chaining all events:
1. Normal operations (rotate, interact, etc.) chain from the owner's tail
2. Recovery operations chain from the owner's tail
3. The tail identifies which events belong to the owner in a divergent KEL
4. Determines if the owner has rotated since divergence began

### Event Flow

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ validate signature
  │                                      │ check for divergence
  │                                      │ store event
  │<──── BatchSubmitResponse ────────────│
  │      { accepted: true,               │
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
  │      { accepted: true,               │
  │        diverged_at: Some(N) }        │
  │                                      │
  │──── fetch_full_kel() ───────────────>│
  │<──── [all events including forks] ───│
  │                                      │
  │ detect divergence locally            │
  │ create rec event from owner's tail   │
  │                                      │
  │──── submit_events([rec]) ───────────>│
  │                                      │ archive adversary events
  │                                      │ store rec
  │<──── BatchSubmitResponse ────────────│
  │      { accepted: true }              │
```

When KEL is already frozen (submitting to a divergent KEL):

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ KEL already divergent
  │                                      │ reject event (not stored)
  │<──── BatchSubmitResponse ────────────│
  │      { accepted: false,              │
  │        diverged_at: Some(N) }        │
  │                                      │
  │──── fetch_full_kel() ───────────────>│
  │<──── [all events including forks] ───│
  │                                      │
  │ sync local state with server         │
  │ create rec event from owner's tail   │
  │                                      │
  │──── submit_events([rec]) ───────────>│
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

### Recovery Events

Recovery (`rec`) is an **establishment event** that proves ownership and rotates keys. It requires dual signatures:
- Current rotation key (the `next_key` that was pre-committed in the owner's latest establishment event)
- Recovery key (proves recovery authority)

The `rec` event establishes new forward keys:
- The rotation key becomes the new current signing key
- A fresh next key is committed via `rotation_hash`
- A fresh recovery key is committed via `recovery_hash`

**Recovery Chaining**: The `rec` event chains from the owner's tail event (tracked via `owner_tail`), not the last agreed event. This ensures the `rotation_hash` in the chain-from event matches the owner's current rotation key.

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

Events are linked by their `previous` SAID field rather than a version number. Multiple events can share the same `previous` value, indicating divergence.

### Audit Records

Archived events preserved for forensics:

```sql
CREATE TABLE kels_audit_records (
    said CHAR(44) PRIMARY KEY,
    kel_prefix CHAR(44) NOT NULL,
    kind VARCHAR(32) NOT NULL,  -- 'rec' or 'cnt'
    data_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
```

## API Reference

### Submit Events

```
POST /api/kels/events
Content-Type: application/json

[{ signed_event }, ...]

Response:
{
  "accepted": true,
  "divergedAt": <generation> | null
}
```

Where `divergedAt` is the generation number (0-indexed position in chain) where divergence was detected, or null if no divergence.

### Fetch KEL

```
GET /api/kels/kel/:prefix

Response: [SignedKeyEvent, ...]
```

### Fetch KEL with Audit Records

```
GET /api/kels/kel/:prefix?audit=true

Response: {
  "events": [SignedKeyEvent, ...],
  "audit_records": [KelsAuditRecord, ...]
}
```

### Fetch Since SAID

```
GET /api/kels/kel/:prefix/since/:said

Response: [SignedKeyEvent, ...]
```

SAID-based queries return all events added after a given event, including divergent events.

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

The `adversary inject` command submits events to the server without updating local state. Combined with state directory swapping, this simulates an adversary who captured the owner's keys at a point in time.

## Security Considerations

### Frozen State

Once divergence is detected, the KEL is frozen:
- No new events accepted except `rec` or `cnt`
- Prevents adversary from extending their fork
- Server returns `{ accepted: false, diverged_at: N }` for rejected submissions, allowing client to sync

### Recovery Protection

Any recovery-revealing event (`rec`, `ror`, `cnt`, `dec`) at generation N protects generation N and all earlier generations:
- All events except `cnt` at generation <= N are rejected with `RecoveryProtected`
- Prevents re-divergence at the recovery generation
- Enables proactive protection: rotating recovery key (`ror`) prevents adversary from injecting events at earlier generations
- Only contest (`cnt`) events are allowed through - once anyone reveals recovery, the only valid response is to contest

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
