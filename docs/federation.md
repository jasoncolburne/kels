# Multi-Registry Federation

This document describes the multi-registry federation architecture that enables independent registries across different clouds/regions with automatic failover and peer management.

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
- Requires consensus (1/3 of registries, min 2) for core peer changes
- Regional operations continue independently during network partitions
- Leader election occurs automatically if current leader fails

## Configuration

All services use **compile-time trusted prefixes** for zero-trust security. The prefixes must be baked into binaries at build time - they cannot be changed at runtime.

### Registry Configuration

**Compile-time (via Dockerfile build args):**
```bash
# Trusted registry prefixes for federation - MUST be set at compile time
TRUSTED_REGISTRY_PREFIXES=ERegistryAcme...,ERegistryBeta...,ERegistryGamma...
```

**Runtime (container environment):**
```bash
# This registry's identity (must be in TRUSTED_REGISTRY_PREFIXES)
FEDERATION_SELF_PREFIX=ERegistryAcme_______________________________

# URLs for reaching federation members (prefix=url pairs)
FEDERATION_URLS=ERegistryAcme...=https://registry.acme.com,ERegistryBeta...=https://registry.beta.io,ERegistryGamma...=https://registry.gamma.net
```

Registries verify incoming federation messages by:
1. Checking sender prefix is in compiled-in `TRUSTED_REGISTRY_PREFIXES`
2. Verifying message signature against sender's KEL

### Gossip Node Configuration

**Compile-time (via Dockerfile build args):**
```bash
# Trusted registry prefixes - MUST be set at compile time
TRUSTED_REGISTRY_PREFIXES=ERegistryAcme...,ERegistryBeta...,ERegistryGamma...
```

**Runtime (container environment):**
```bash
# Registry URL to connect to
REGISTRY_URL=https://registry.acme.com
```

The gossip service discovers the registry's prefix by fetching its KEL at startup and verifies it against the compiled-in trusted prefixes.

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

### Adding Core Peers (Multi-Party Approval)

Core peers require multi-party approval from federation members. This prevents any single compromised registry from unilaterally adding malicious peers.

**Approval Threshold**: `max(ceil(n/3), 2)` where n = number of federation members
- 3 members: need 2 approvals
- 4-6 members: need 2 approvals
- 7-9 members: need 3 approvals

**Step 1: Propose a new core peer**

Any federation member can propose a new core peer:

```bash
# From any registry in the federation
kels-registry-admin peer propose \
  --peer-id Qm... \
  --node-id node-1 \
  --kels-url http://kels.node-1.example.com \
  --gossip-multiaddr /dns4/gossip.node-1.example.com/tcp/4001

# Output:
# Proposal created: EProposal123...
# Waiting for 2 approvals (1/2 so far - proposer auto-votes)
```

**Step 2: Vote on the proposal**

Other federation members vote to approve:

```bash
# On another registry
kels-registry-admin peer vote --proposal-id EProposal123... --approve

# Output:
# Vote recorded. Status: 2/2 approvals - APPROVED
# Peer added to core set.
```

**Step 3: Monitor proposals**

```bash
# List pending proposals
kels-registry-admin peer proposals

# Check specific proposal status
kels-registry-admin peer proposal-status --proposal-id EProposal123...
```

**Proposal Expiration**: Proposals expire after 7 days if threshold is not met.

### Adding Regional Peers

Regional peers can be added on any registry, but require at least one active core peer to exist first:

```bash
# On any registry (requires at least one core peer to exist)
kels-registry-admin peer add --peer-id Qm... --node-id node-regional --scope regional

# If no core peers exist, you'll see:
# Error: Cannot add regional peer - no active core peers exist.
# Regional nodes need core nodes to connect to the gossip swarm.
# Add at least one core peer first with: peer add --scope core ...
```

**Why this restriction?** Regional nodes need core nodes to bootstrap their gossip connections. Without any core peers, the gossip swarm would be disjoint - regional nodes could not discover or connect to each other.

## Security Considerations

### Federation Membership

- Membership is controlled by the compile-time `TRUSTED_REGISTRY_PREFIXES` constant
- Only known registry prefixes can participate in consensus
- Cannot be changed at runtime - must be baked into the binary at build time

### Message Authentication

- All Raft messages are signed with the sender's identity key (HSM-backed)
- Recipients verify signatures against the sender's KEL
- Messages from prefixes not in `TRUSTED_REGISTRY_PREFIXES` are rejected

### Member KEL Caching

- Federation members cache each other's KELs on startup
- Cache is refreshed on signature verification failure (handles key rotation)
- No periodic refresh - only on-demand when needed

## Disaster Recovery

### Rogue Registry Scenario

If a federation member is compromised:

1. **Detection**: Audit logs show unexpected core peer changes with the rogue registry's prefix

2. **Isolation**: Update `TRUSTED_REGISTRY_PREFIXES` on honest registries to exclude the rogue:
   ```bash
   TRUSTED_REGISTRY_PREFIXES=ERegistryAcme...,ERegistryGamma...  # Beta removed
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

### Registry KELs
```
GET /api/registry-kels
```

Returns KELs for all federation members (for cross-registry verification).

### Admin API (localhost only)

Core peer proposal management:

```
GET    /api/admin/proposals                      # List pending proposals
POST   /api/admin/proposals                      # Propose a new core peer
GET    /api/admin/proposals/:proposal_id         # Get proposal details
POST   /api/admin/proposals/:proposal_id/vote    # Vote on a proposal
DELETE /api/admin/proposals/:proposal_id         # Withdraw a proposal
```

Regional peer management:

```
POST   /api/admin/peers              # Add a regional peer
DELETE /api/admin/peers/:peer_id     # Remove a peer
```

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

# Deploy core nodes
garden deploy --env=node-a
garden deploy --env=node-b
garden deploy --env=node-c

# Add core peers (requires multi-party approval)
# Step 1: Propose from registry-a
garden run propose-node-a --env=registry-a
# Output includes proposal ID

# Step 2: Vote from registry-b (use proposal ID from above)
garden run vote-peer --env=registry-b --var proposal=EProposal...

# Repeat for node-b and node-c

# Deploy regional node (no approval needed, but requires core peers)
garden deploy --env=node-d
garden run add-regional-node-d --env=registry-a

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
