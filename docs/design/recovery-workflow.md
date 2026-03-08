# Recovery Workflow: Decoupling Member KELs from Raft

## Problem Statement

The original architecture stores member KEL events through Raft consensus: each node submits its identity KEL events to Raft, which verifies them in `apply_submit_key_events` and maintains a `member_contexts` HashMap of `Verification` tokens in the replicated state machine. This creates several issues:

### Issue 1: Composite SAID Cursor

`sync_own_kel` and `ensure_own_kel_synced` use `effective_tail_said()` as a `since` cursor when fetching delta events from the identity service. For divergent KELs, this returns a composite hash (Blake3 of sorted tip SAIDs) that doesn't correspond to any real event SAID. The identity service returns "not found," silently breaking sync.

### Issue 2: Raft Cannot Handle Recovery

The Raft state machine's `apply_submit_key_events` stores full key events, verifies them, and maintains `Verification` in `member_contexts`. But it has no recovery merge logic:

1. **Verifier can't rewind:** `KelVerifier::resume()` continues from a `Verification` context. If the underlying KEL needs to be re-verified from scratch (e.g., after recovery resolves divergence), the verifier can't "go back."

2. **Snapshot compaction loses events:** After Raft snapshot compaction, the original clean events are gone from the log; only the (possibly corrupted) `Verification` survives in the snapshot.

3. **No recovery path:** If a member KEL becomes divergent or is maliciously extended (via DB attack with key compromise), the registry can't accept a recovered KEL from identity because the verifier can't process recovery events that resolve divergence it didn't observe.

### Attack Scenarios

- **DB tamper with key compromise:** Attacker gains DB access and has compromised the signing key. They inject a divergent event into `MemberKelRepository`. The Raft integrity check (DB SAID vs Raft SAID) catches this, but recovery requires re-verifying from scratch, which the Raft-embedded verifier can't do.

- **Identity DB tamper:** Attacker modifies the identity service's KEL. The sync loop picks up corrupted events and submits them to Raft. After Raft applies them, the `member_contexts` contains a corrupted `Verification`. Recovery requires identity to issue a recovery event, but Raft can't process it against the corrupted context.

- **Malicious KEL extension:** An insider extends a member KEL with unauthorized events. These pass verification (valid signatures) but shouldn't be trusted. Recovery requires the identity operator to issue a contest or recovery event, which again needs the full chain context.

## New Architecture

### Principle: Raft Stores Triggers, Not Events

Raft consensus is used for what it's good at: agreeing on "this prefix needs syncing." Each member independently fetches and verifies KELs using the existing `transfer_key_events` infrastructure. Recovery from identity propagates naturally through the sync loop.

### Data Flow

1. **Sync loop** (every node, periodically):
   - Fetch own KEL from identity using `HttpKelSource`
   - Verify and store locally using `transfer_key_events` with `RepositoryKelStore` as the sink
   - If new events were stored, submit `SyncMemberKel { prefix }` to Raft

2. **Raft apply** for `SyncMemberKel`:
   - Trivial: just acknowledges consensus that this prefix has new data
   - No verification, no DB writes, no `member_contexts` update

3. **Other nodes** observe the Raft trigger:
   - Fetch from the advertising member's registry using `HttpKelSource` pointed at `GET /api/member-kels/{prefix}`
   - Verify and store locally using the same `transfer_key_events` flow

4. **Anchoring verification** moves to consumption time:
   - `verify_member_anchoring_from_repo` already reads from `MemberKelRepository` and performs full verification
   - The only change is how that DB gets populated (sync fetch instead of Raft-replicated events)

### Recovery Propagation

When a member KEL needs recovery:

1. **Identity operator** issues a recovery/contest event via identity-admin CLI
2. **Sync loop** picks up the new events from identity
3. **`transfer_key_events`** handles the recovery naturally (it verifies from scratch, sees the divergence + recovery)
4. **`SyncMemberKel`** notifies other nodes via Raft
5. **Other nodes** fetch the recovered KEL and verify independently

No special recovery logic needed in Raft. The existing verification infrastructure handles all cases.

### Verification Invariant (Unchanged)

The DB cannot be trusted. All operations fall into three categories:

1. **Serving** - returning data to a client/peer. No verification needed.
2. **Consuming** - using data for security decisions. Requires a `Verification` token.
3. **Resolving** - comparing state to decide sync. Wrong answers trigger unnecessary syncs, not security holes.

## Operator Recovery Workflow

When a member KEL is compromised, the operator uses the identity-admin CLI:

1. **`identity-admin recover`** - Issues a recovery event, reveals the recovery key
2. **`identity-admin rotate-recovery`** - Rotates both signing and recovery keys
3. **`identity-admin contest`** - Permanently freezes a divergent KEL (adversary revealed recovery key)
4. **`identity-admin decommission`** - Ends the KEL permanently

Each of these creates events in the identity service's KEL. The registry sync loop automatically picks them up and propagates them to all federation members.
