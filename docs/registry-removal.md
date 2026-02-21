# Registry Removal (Decommission)

## Why Trusted Prefixes Are Permanent

Once a registry's prefix is in `TRUSTED_REGISTRY_MEMBERS`, it must remain there permanently. Removing a trusted prefix would break verification of all historical data that registry anchored in the Raft log:

- **Votes**: Each vote's SAID is anchored in the voter's KEL. Removing the voter's prefix makes those votes unverifiable.
- **Proposals**: Proposal SAIDs are anchored in the proposer's KEL. Removing the proposer's prefix breaks the audit trail.
- **Peer records**: Peers are anchored in the authorizing registry's KEL. Removing that registry's prefix makes the peer's provenance unverifiable.

The Raft-replicated KEL preserves the ability to verify this data even after the registry is gone.

## Decommission Procedure

Before removing a registry from the federation:

### Step 1: Decommission the Identity KEL

The registry operator triggers decommission of the identity KEL by submitting a `dec` (decommission) event. This event requires dual signatures (both current key and recovery key), making it as secure as a recovery event.

```
EventKind::Dec
```

The `dec` event signals a clean, intentional termination of the KEL.

### Step 2: Submit to Raft

The `dec` event is submitted to Raft via the KEL sync loop (or eagerly after the decommission). Once in Raft:

- `Kel::is_decommissioned()` returns `true` for this prefix
- `Kel::merge()` rejects any further events with `KelsError::KelDecommissioned`
- The KEL is frozen at its final state

### Step 3: Remove from Federation

After decommission is confirmed in Raft, the registry can be removed from the active federation:

1. Submit a removal proposal via the admin CLI
2. Other members vote to approve the removal
3. The registry's Raft node is removed from the cluster

### Step 4: Keep the Prefix

The prefix stays in `TRUSTED_REGISTRY_MEMBERS` in all builds. The KEL lives on in Raft snapshots, ensuring all historical data remains verifiable.

## What Happens Without Decommission

If a registry is removed without decommissioning:

- The KEL is frozen at its last known state in Raft
- Historical data anchored by that registry remains verifiable
- There is no clean termination signal, so it's unclear whether the registry was intentionally retired or lost
- The frozen KEL still prevents key reuse since the last rotation hash is uncommitted

Decommission is strongly preferred for a clean audit trail.

## Summary

| Action | Result |
|--------|--------|
| Decommission + remove | Clean termination, KEL frozen with `dec` event, prefix stays in trusted set |
| Remove without decommission | KEL frozen at last state, no termination signal, prefix stays in trusted set |
| Remove prefix from trusted set | **Never do this** - breaks verification of all historical data |
