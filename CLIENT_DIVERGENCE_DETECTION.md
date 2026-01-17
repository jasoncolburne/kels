# KELS Divergence Detection and Recovery

## Problem Statement

In a distributed KELS deployment, an adversary who has compromised a signing key can submit conflicting events to different nodes simultaneously. Before nodes synchronize via gossip, both nodes may accept different events at the same version, creating a fork in the KEL.

The legitimate owner must be able to:
1. Detect that divergence has occurred
2. Recover by proving ownership of the recovery key
3. Continue using their KEL normally after recovery

## Design Goals

1. **Store all valid events** - Don't reject conflicting events at the database level; let clients detect and resolve divergence
2. **Derive state from data** - No separate divergence flag; compute from event structure
3. **Freeze on divergence** - Prevent further damage until owner recovers
4. **Archive on recovery** - Preserve divergent events for audit purposes
5. **Simple client API** - `KeyEventBuilder` handles complexity internally

## Architecture

### Divergence Detection

Divergence is detected when multiple events exist at the same version:

```
Normal KEL:     v0 → v1 → v2 → v3
Divergent KEL:  v0 → v1 → v2 → v3(owner)
                           ↘ v3(adversary)
```

The `Kel::find_divergence()` method returns the first version with multiple SAIDs.

### Trusted State

`KelBuilderState` tracks the last trusted position in a KEL:

| Field | Purpose |
|-------|---------|
| `last_trusted_event` | Event to chain new events from |
| `last_trusted_establishment_event` | Last establishment event for key validation |
| `trusted_cursor` | Index where trust ends (divergence point or event count) |

For a divergent KEL, these point to the last event **before** the divergence point, ensuring new events chain from the valid portion.

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

On divergence:

```
Client                              KELS Server
  │                                      │
  │──── submit_events([event]) ─────────>│
  │                                      │ detect SAID mismatch at version N
  │                                      │ store as divergent event
  │<──── BatchSubmitResponse ────────────│
  │      { accepted: true,               │
  │        diverged_at: Some("E...") }   │
  │                                      │
  │──── fetch_full_kel() ───────────────>│
  │<──── [all events including forks] ───│
  │                                      │
  │ detect divergence locally            │
  │ create rec event from last trusted   │
  │                                      │
  │──── submit_events([rec]) ───────────>│
  │                                      │ archive divergent events
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
  │        diverged_at: Some("E...") }   │
  │                                      │
  │──── fetch_full_kel() ───────────────>│
  │<──── [all events including forks] ───│
  │                                      │
  │ sync local state with server         │
  │ create rec event from last trusted   │
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
    Err(KelsError::DivergenceDetected(_)) => {
        builder.recover().await?;
    }
}
```

### Two-Phase Key Rotation

Key rotations use prepare/commit/rollback to ensure recovery is possible:

1. `prepare_rotation()` - Stage new key, keep old key active
2. Submit event to KELS
3. On success: `commit_rotation()` - Activate new key
4. On divergence: `rollback_rotation()` - Keep old key for recovery

### Recovery Events

Recovery (`rec`) is an **establishment event** that both proves ownership and rotates keys. It requires dual signatures:
- Pre-committed rotation key at the divergence point (proves ownership of the key that was committed in `rotation_hash`)
- Recovery key (proves recovery authority)

The `rec` event establishes new forward keys:
- The pre-committed rotation key becomes the new current signing key
- A fresh next key is committed via `rotation_hash`
- A fresh recovery key is committed via `recovery_hash`

This means if the adversary rotated at the divergence point (consuming the same pre-committed key), the owner's `rec` at that version has dual signatures while the adversary's `rot` only has one. The `rec` trumps the `rot` and also handles key rotation in a single event.

**Historical Key Recovery**: If the owner has rotated keys after the divergence point (e.g., adversary attacked at v3 but owner already rotated at v3 and v4), recovery uses the **historical** pre-committed key from when the divergence occurred. The `KeyEventBuilder` automatically:
1. Fetches the KELS KEL to find the exact divergence point
2. Calculates which key generation was pre-committed at that version
3. Signs with that historical key
4. Resets the key provider state to continue from the recovery point

If the adversary has already used the recovery key, the owner submits a contest (`cnt`) event instead, permanently freezing the KEL.

## Database Schema

### Non-Unique Version Index

```sql
-- Allows multiple events at same version
CREATE INDEX kels_key_events_prefix_version_idx
  ON kels_key_events(prefix, version);
```

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
  "divergedAt": "ESaid..." | null
}
```

### Fetch KEL

```
GET /api/kels/kel/:prefix

Response: [SignedKeyEvent, ...]
```

### Fetch Since Timestamp

```
GET /api/kels/kel/:prefix/since/:timestamp

Response: [SignedKeyEvent, ...]
```

Timestamp-based queries ensure clients see all new events, including divergent events at earlier versions.

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

```bash
kels-cli adversary inject --prefix <prefix> --events ixn,rot
```

Injects events to server without updating local state, simulating an adversary.

## Security Considerations

### Frozen State

Once divergence is detected, the KEL is frozen:
- No new events accepted except `rec` or `cnt`
- Prevents adversary from extending their fork
- Server returns `{ accepted: false, diverged_at: "E..." }` for rejected submissions, allowing client to sync

### Recovery Protection

Any recovery-revealing event (`rec`, `ror`, `cnt`, `dec`) at version N protects version N and all earlier versions:
- Non-recovery events at version <= N are rejected with `RecoveryProtected`
- Prevents re-divergence at the recovery version
- Enables proactive protection: rotating recovery key (`ror`) prevents adversary from injecting events at earlier versions
- Recovery-revealing events (like `cnt` to contest) are still allowed through

### Contest Finality

If both parties have used the recovery key, contest (`cnt`) permanently freezes the KEL. Neither party can add more events. This is the correct outcome when key compromise is total.

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
2. **Adversary Injects Rotation** - rot attack, owner recovers
3. **Multiple Adversary Events** - ixn,ixn,rot attack, owner recovers
4. **Data Integrity After Recovery** - Pre-attack anchors preserved
5. **Owner Submits Divergent Rotation** - Owner's rot conflicts, owner recovers
6. **Adversary Injects Recovery Rotation (ror)** - Owner contests, KEL frozen
7. **Adversary Decommissions KEL** - dec attack, owner contests
8. **Adversary Rotates Then Anchors** - rot,ixn,ixn chain, owner recovers
9. **Adversary Double Rotation** - rot,rot attack, owner recovers
10. **Owner Rotates, Then Adversary Attacks** - Post-rotation ixn attack, owner recovers
11. **Adversary Decommissions After Owner Anchors** - dec attack on data, owner contests
12. **Adversary Injects Recovery (rec)** - rec attack, owner contests
13. **Adversary Attacks Old Version After Multiple Rotations** - Historical key injection, owner recovers with historical key
14. **Submission When Frozen** - All operations rejected on contested KEL
15. **Proactive Recovery Protection via ROR** - Owner rotates recovery key, preventing historical injection
16. **Post-Recovery Protection** - After recovery, adversary cannot re-diverge at earlier versions
