# Recovery Workflow

## Architecture

### Direct Push

The submit handler eagerly fans out all KEL appends to other registries. If fan-out fails, each node's background sync loop fills in gaps by comparing effective SAIDs and pushing deltas to stale members. Recovery events from identity propagate through this same mechanism.

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

### Verification Invariant

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
