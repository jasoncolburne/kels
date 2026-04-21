# Registry Removal (Decommission)

## Why Trusted Prefixes Are Permanent

Once a registry's prefix is in `TRUSTED_REGISTRY_MEMBERS`, it must remain there permanently. Removing a trusted prefix would break verification of all historical data that registry anchored:

- **Votes**: Each vote's SAID is anchored in the voter's KEL. Removing the voter's prefix makes those votes unverifiable.
- **Proposals**: Proposal SAIDs are anchored in the proposer's KEL. Removing the proposer's prefix breaks the audit trail.
- **Peer records**: Peers are anchored in the authorizing registry's KEL. Removing that registry's prefix makes the peer's provenance unverifiable.

The locally-stored member KEL preserves the ability to verify this data even after the registry is gone.

## Decommission Procedure

Before removing a registry from the federation:

### Step 1: Decommission the Identity KEL

The registry operator triggers decommission of the identity KEL by submitting a `dec` (decommission) event. This event requires dual signatures (both current key and recovery key), making it as secure as a recovery event.

```
KeyEventKind::Dec
```

The `dec` event signals a clean, intentional termination of the KEL.

### Step 2: Propagate to Members

The `dec` event propagates to other federation members via the member KEL sync loop (within 30s). Once stored on all members:

- `KelVerification::is_decommissioned()` returns `true` for this prefix
- The submit handler rejects any further events with `KelsError::KelDecommissioned`
- The KEL is frozen at its final state

### Step 3: Remove from Federation

After decommission is confirmed across all members, the registry can be removed from the active federation.

If any nodes are associated with the registry and should be removed, they should likely be removed before removing the registry.

### Step 4: Keep the Prefix

The prefix stays in `TRUSTED_REGISTRY_MEMBERS` in all builds. The KEL lives on in each member's local `MemberKelRepository`, ensuring all historical data remains verifiable.

## What Happens Without Decommission

If a registry is removed from the federation without decommissioning its identity KEL first:

- The KEL remains in each member's local store but is **not frozen** — it still accepts new events from anyone who holds the signing key
- Without the `dec` event's dual-signature termination, the registry's keys cannot be safely retired — an attacker who compromises the signing key can extend the KEL and anchor unauthorized data
- The auto-rotation loop is no longer running, so the signing key is never refreshed, increasing the window of exposure over time

Decommission freezes the KEL with a dual-signed `dec` event, eliminating this risk, while historical data anchored by that registry remains verifiable.

Decommission is strongly preferred for a clean audit trail.

## Summary

| Action | Result |
|--------|--------|
| Decommission + remove | Clean termination, KEL frozen with `dec` event, prefix stays in trusted set |
| Remove without decommission | KEL still live (not frozen), stale keys become a growing liability, prefix stays in trusted set |
| Remove prefix from trusted set | **Never do this** - breaks verification of all historical data |
