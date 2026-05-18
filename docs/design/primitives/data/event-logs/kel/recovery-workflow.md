# Recovery Workflow

This doc describes the operator-side CLI workflow for KEL `Rec` / `Ror` / `Dec` ceremonies and their propagation through the registry.

For the chain-state semantics each ceremony reaches, see the design docs:

- What `Rec` archives → [event-log.md §Recovery (Rec)](event-log.md#recovery-rec).
- How a chain transitions to Contested (structural reference: a non-archiving privileged event landing in a divergent set fires privileged-divergence-is-terminal) → [event-log.md §Contested-state transitions](event-log.md#contested-state-transitions).
- The parent-at-(seal − 1) carve-out and the spent-key rule → [event-log.md §Seal and Key Non-Poisonability](event-log.md#seal-and-key-non-poisonability).

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

1. **Identity operator** issues a recovery (`Rec`), recovery-rotation (`Ror`), or decommission (`Dec`) event via identity-admin CLI
2. **Sync loop** picks up the new events from identity
3. **`forward_key_events`** stores the recovery events locally (merge handles divergence + recovery naturally)
4. **Sync loop** detects stale members and pushes delta events directly via HTTP
5. **Other nodes** receive and store the recovered KEL events

### Verification Invariant

See [../../../../protocol-doctrine.md §Operation Categories](../../../../protocol-doctrine.md#operation-categories) for the structural framing.

## Operator Recovery Workflow

When a member KEL is compromised, the operator's recourse depends on what has been compromised:

1. **`identity-admin recover`** — Issues a recovery event (`Rec`), reveals the recovery key, archives the compromised branch via the discriminator. Applicable when the recovery key is still uncompromised.
2. **`identity-admin rotate-recovery`** — Issues a recovery-rotation event (`Ror`), rotating both signing and recovery keys. Used for the proactive-ROR cadence and as a forward-secrecy ratchet.
3. **`identity-admin decommission`** — Issues a `Dec` event, ending the KEL cleanly on a linear chain.

If the recovery key has been compromised (no in-band recovery path remains), the recourse is at the IEL layer: rotate the compromised KEL out of the dependent IEL's `governancePolicy` via IEL `Evl`. The protocol has no in-band primitive that re-grants authority to a party who no longer holds the chain's commitments; the KEL prefix is retired from the federation by IEL-policy evolution.

Each CLI command creates events in the identity service's KEL. The registry sync loop automatically picks them up and propagates them to all federation members.
