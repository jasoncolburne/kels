# Recovery Workflow

## Historical Context

The original architecture stored member KEL events through Raft consensus: each node submitted its identity KEL events to Raft, which verified them in `apply_submit_key_events` and maintained a `member_contexts` HashMap of `KelVerification` tokens in the replicated state machine. This created several issues that motivated the current decoupled design:

### Issue 1: Composite SAID Cursor

`sync_own_kel` and `ensure_own_kel_synced` use `effective_tail_said()` as a `since` cursor when fetching delta events from the identity service. For divergent KELs, this returns a composite hash (Blake3 of sorted tip SAIDs) that doesn't correspond to any real event SAID. The identity service returns "not found," silently breaking sync.

### Issue 2: Raft Cannot Handle Recovery

The Raft state machine's `apply_submit_key_events` stores full key events, verifies them, and maintains `KelVerification` in `member_contexts`. But it has no recovery merge logic:

1. **Verifier can't rewind:** `KelVerifier::resume()` continues from a `KelVerification` context. If the underlying KEL needs to be re-verified from scratch (e.g., after recovery resolves divergence), the verifier can't "go back."

2. **Snapshot compaction loses events:** After Raft snapshot compaction, the original clean events are gone from the log; only the (possibly corrupted) `KelVerification` survives in the snapshot.

3. **No recovery path:** If a member KEL becomes divergent or is maliciously extended (via DB attack with key compromise), the registry can't accept a recovered KEL from identity because the verifier can't process recovery events that resolve divergence it didn't observe.

### Attack Scenarios

- **DB tamper with key compromise:** Attacker gains DB access and has compromised the signing key. They inject a divergent event into `MemberKelRepository`. The Raft integrity check (DB SAID vs Raft SAID) catches this, but recovery requires re-verifying from scratch, which the Raft-embedded verifier can't do.

- **Identity DB tamper:** Attacker modifies the identity service's KEL. The sync loop picks up corrupted events and submits them to Raft. After Raft applies them, the `member_contexts` contains a corrupted `KelVerification`. Recovery requires identity to issue a recovery event, but Raft can't process it against the corrupted context.

- **Malicious KEL extension:** An insider extends a member KEL with unauthorized events. These pass verification (valid signatures) but shouldn't be trusted. Recovery requires the identity operator to issue a contest or recovery event, which again needs the full chain context.

## Current Architecture

### Principle: Direct Push, No Raft Involvement

Raft has no role in member KEL synchronization. The submit handler eagerly fans out all KEL appends to other registries. If fan-out fails, each node's background sync loop fills in gaps by comparing effective SAIDs and pushing deltas to stale members. Recovery events from identity propagate through this same mechanism.

### Data Flow

1. **Submit handler** (`POST /api/v1/member-kels/events`):
   - Stores events locally via `save_with_merge`
   - Fans out to other members only when the submitted prefix matches the receiver's own prefix
   - This means identity pushes to local registry → local registry fans out; other members just store

2. **Sync loop** (every node, periodically):
   - Fetch own KEL from identity using `HttpKelSource`
   - Store locally using `forward_key_events` with `RepositoryKelStore` as the sink
   - Compare own effective SAID with each member's view
   - Push delta events to members with stale state

3. **Anchoring verification** at consumption time:
   - `verify_member_anchoring_from_repo` reads from `MemberKelRepository` and performs full verification

### Recovery Propagation

When a member KEL needs recovery:

1. **Identity operator** issues a recovery/contest event via identity-admin CLI
2. **Sync loop** picks up the new events from identity
3. **`forward_key_events`** stores the recovery events locally (merge handles divergence + recovery naturally)
4. **Sync loop** detects stale members and pushes delta events directly via HTTP
5. **Other nodes** receive and store the recovered KEL events

No special recovery logic needed in Raft. The existing verification infrastructure handles all cases.

### Verification Invariant (Unchanged)

The DB cannot be trusted. All operations fall into three categories:

1. **Serving** - returning data to a client/peer. No verification needed.
2. **Consuming** - using data for security decisions. Requires a `KelVerification` token.
3. **Resolving** - comparing state to decide sync. Wrong answers trigger unnecessary syncs, not security holes.

## Operator Recovery Workflow

When a member KEL is compromised, the operator uses the identity-admin CLI:

1. **`identity-admin recover`** - Issues a recovery event, reveals the recovery key
2. **`identity-admin rotate-recovery`** - Rotates both signing and recovery keys
3. **`identity-admin contest`** - Permanently freezes a divergent KEL (adversary revealed recovery key)
4. **`identity-admin decommission`** - Ends the KEL permanently

Each of these creates events in the identity service's KEL. The registry sync loop automatically picks them up and propagates them to all federation members.
