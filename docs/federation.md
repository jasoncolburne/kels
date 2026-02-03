# Multi-Registry Federation

This document describes the multi-registry federation architecture that enables multiple independent registries across different clouds/regions with automatic failover and peer management.

## Overview

Federation enables:
- **Core peer set**: Global allowlist shared by all registries via Raft consensus
- **Regional allowlists**: Each registry manages its own local peers
- **Automatic failover**: Leader election for core set management
- **Multi-party operation**: Different organizations can run their own registries while sharing a global trust backbone

## Architecture

```
                    REGISTRY FEDERATION (Raft Consensus)
    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
    │   │ Registry A  │◄──►│ Registry B  │◄──►│ Registry C  │     │
    │   │ (Leader)    │    │ (Follower)  │    │ (Follower)  │     │
    │   │ Party: Acme │    │ Party: Beta │    │ Party: Gamma│     │
    │   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘     │
    │          │                  │                  │            │
    │          │     CORE PEER SET (replicated via Raft)          │
    │          │     + Regional peers (local only)                │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
              │                    │                    │
              ▼                    ▼                    ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │ KELS nodes      │  │ KELS nodes      │  │ KELS nodes      │
    │ (Acme region)   │  │ (Beta region)   │  │ (Gamma region)  │
    │                 │  │                 │  │                 │
    │ Trust: Core +   │  │ Trust: Core +   │  │ Trust: Core +   │
    │        Acme     │  │        Beta     │  │        Gamma    │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Peer Scopes

### Core Peers
- Replicated across all federation members via Raft consensus
- Only the elected leader can add or remove core peers
- All gossip nodes in the federation trust core peers

### Regional Peers
- Local to a single registry
- Can be added/removed by any registry operator
- Only trusted by nodes connected to that registry

Gossip nodes compute their allowlist as: `core_peers ∪ regional_peers`

## Raft Consensus

Federation uses [OpenRaft](https://github.com/datafuselabs/openraft) for distributed consensus.

### Leader Election
- Leader is automatically elected from federation members
- Leader handles all core peer modifications
- Follower registries reject core peer writes with an error message indicating the current leader

### State Machine
The Raft state machine maintains:
- List of core peers (peer_id, node_id, active status, scope)
- Each entry is cryptographically anchored in the leader's KEL

### Fault Tolerance
- Requires majority quorum (e.g., 2 of 3 registries) for core peer changes
- Regional operations continue independently during network partitions
- Leader election occurs automatically if current leader fails

## Configuration

### Registry Environment Variables

```bash
# Identity (this registry's own prefix)
REGISTRY_PREFIX=ERegistryAcme_______________________________

# Federation membership
FEDERATION_SELF_PREFIX=ERegistryAcme_______________________________
FEDERATION_MEMBERS=ERegistryAcme...,ERegistryBeta...,ERegistryGamma...
FEDERATION_URLS=ERegistryAcme...=https://registry.acme.com,ERegistryBeta...=https://registry.beta.io,ERegistryGamma...=https://registry.gamma.net
```

### Gossip Node Environment Variables

```bash
# Multiple registry URLs for failover (comma-separated)
REGISTRY_URLS=https://registry.acme.com,https://registry.beta.io,https://registry.gamma.net

# Trust anchor - the registry this node is associated with
REGISTRY_PREFIX=ERegistryAcme_______________________________
```

## Administration

### Viewing Federation Status

```bash
# On any registry
kels-registry-admin federation status

# Output:
Federation Status
==================================================
Node ID:       1
Self Prefix:   ERegistryAcme...
Is Leader:     Yes
Leader ID:     1
Leader Prefix: ERegistryAcme...
Term:          3
Last Log Idx:  42
Last Applied:  42

Federation Members:
  ERegistryAcme... (leader)
  ERegistryBeta...
  ERegistryGamma...
```

### Adding Core Peers

Core peers must be added on the leader registry:

```bash
# On leader registry only
kels-registry-admin peer add --peer-id Qm... --node-id node-1 --scope core

# On follower registries, this will fail:
# Error: Cannot modify core peer set - this registry is not the leader.
# Current leader: ERegistryBeta... (ID: 2)
```

### Adding Regional Peers

Regional peers can be added on any registry:

```bash
# On any registry
kels-registry-admin peer add --peer-id Qm... --node-id node-regional --scope regional
```

## Security Considerations

### Federation Membership

- Membership is controlled by the `FEDERATION_MEMBERS` environment variable
- Only known registry prefixes can participate in consensus
- This cannot be modified via the API - requires registry restart

### Message Authentication

- All Raft messages are signed with the sender's identity key (HSM-backed)
- Recipients verify signatures against the sender's KEL
- Messages from prefixes not in `FEDERATION_MEMBERS` are rejected

### Member KEL Caching

- Federation members cache each other's KELs on startup
- Cache is refreshed on signature verification failure (handles key rotation)
- No periodic refresh - only on-demand when needed

## Disaster Recovery

### Rogue Registry Scenario

If a federation member is compromised:

1. **Detection**: Audit logs show unexpected core peer changes with the rogue registry's prefix

2. **Isolation**: Update `FEDERATION_MEMBERS` on honest registries to exclude the rogue:
   ```bash
   FEDERATION_MEMBERS=ERegistryAcme...,ERegistryGamma...  # Beta removed
   ```

3. **Redeploy**: Restart honest registries with updated config
   - Rogue is excluded from consensus
   - New leader elected from remaining members

4. **Recovery**: If core peer set was compromised:
   ```bash
   # Manually re-add legitimate core peers
   kels-registry-admin peer add --scope core --peer-id Qm... --node-id node-1
   ```

5. **Gossip nodes auto-heal**: Next allowlist refresh removes unauthorized peers

### Quorum Requirements

- 3 registries: Need 2 for quorum (rogue needs 2 to cause damage)
- 5 registries: Need 3 for quorum (more resilient)

### Split-Brain Protection

- Raft requires majority quorum for writes
- Minority partition cannot modify core peer set
- Regional operations continue in all partitions

## API Endpoints

### Federation Status
```
GET /api/federation/status
```

Returns current federation state including leader, term, and membership.

### List Peers (Federated Mode)
```
GET /api/peers
```

Returns combined list of core peers (from Raft state machine) and regional peers (from local database).

### Federation RPC (Internal)
```
POST /api/federation/rpc
```

Internal endpoint for Raft protocol messages between registries. Not intended for external use.

## Testing

### Multi-Registry Federation Testing

The Garden configuration supports three federated registry environments:

```bash
# Deploy three federated registries
garden deploy --env=registry-a
garden run fetch-registry-prefix --env=registry-a

garden deploy --env=registry-b
garden run fetch-registry-prefix --env=registry-b

garden deploy --env=registry-c
garden run fetch-registry-prefix --env=registry-c

# Wait for leader election
sleep 10

# Deploy nodes (each to their respective registry)
garden deploy --env=node-a
garden run add-node-a --env=registry-a

garden deploy --env=node-b
garden run add-node-b --env=registry-b

garden deploy --env=node-c
garden run add-node-c --env=registry-c

# Deploy regional node (only to registry-a)
garden deploy --env=node-d
garden run add-node-d --env=registry-a

# View federation status
kubectl exec -n kels-registry-a deploy/kels-registry -- \
  /app/kels-registry-admin federation status
```

### Registry Prefix Management

Registry prefixes are stored in `.kels/federated-registries.json`:

```json
{
  "registry-a": "ERegistryAcme...",
  "registry-b": "ERegistryBeta...",
  "registry-c": "ERegistryGamma..."
}
```

Node environments are mapped to their registries:
- `node-a`, `node-d` -> `registry-a`
- `node-b` -> `registry-b`
- `node-c` -> `registry-c`
