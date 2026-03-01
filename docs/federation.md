# Multi-Registry Federation

This document describes the multi-registry federation architecture that enables independent registries across different clouds/regions with consensus-based peer management.

## Overview

Federation enables:
- **Peer set**: Global allowlist shared by all registries via Raft consensus
- **Leader election**: Raft consensus for peer set management
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
    │          │     PEER SET (replicated via Raft)  │            │
    └─────────────────────────────────────────────────────────────┘
               │                  │                  │
               ▼                  ▼                  ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │ KELS nodes      │  │ KELS nodes      │  │ KELS nodes      │
    │ (Acme region)   │  │ (Beta region)   │  │ (Gamma region)  │
    │                 │  │                 │  │                 │
    │ Trust: peer set │  │ Trust: peer set │  │ Trust: peer set │
    │                 │  │                 │  │                 │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Raft Consensus

Federation uses [OpenRaft](https://github.com/datafuselabs/openraft) for distributed consensus.

### Leader Election
- Leader is automatically elected from federation members
- Leader commits approved peer modifications to the Raft log
- Follower registries reject peer writes with an error message indicating the current leader

### State Machine
The Raft state machine maintains:
- List of peers (peer_prefix, node_id, active status)
- Each entry is anchored in a trusted registry's KEL (current leader)

### Fault Tolerance
- Minimum 3 votes required for peer approval regardless of federation size, scaling to ceil(n/3) for 10+ members
- Leader election occurs automatically if current leader fails

## Configuration

All services use **compile-time trusted prefixes** for zero-trust security. The prefixes must be baked into binaries at build time - they cannot be changed at runtime.

### Deployment Impact

Adding a new registry to the federation is a multi-step process: the new registry must be started first so it can incept its identity and produce a prefix. Once the prefix is known, all existing services are rebuilt and redeployed with the updated trust anchors (`TRUSTED_REGISTRY_MEMBERS` for kels-registry and `TRUSTED_REGISTRY_PREFIXES` for all services). The new registry is then redeployed alongside them with the same full set of trusted members and prefixes. Until this happens, existing members will reject messages from the unknown prefix. Unlike a PKI, however, this only needs to happen once per registry. Key rotations are handled transparently by the KEL and do not require redeployment.

### Registry Configuration

**Compile-time (via Dockerfile build args):**
```bash
# Trusted registry members for federation - MUST be set at compile time
# TRUSTED_REGISTRY_MEMBERS is a JSON array of {id, prefix, active} objects used by kels-registry
# for Raft node identity. This is distinct from TRUSTED_REGISTRY_PREFIXES (comma-separated
# prefixes used by gossip and identity services).
TRUSTED_REGISTRY_MEMBERS='[{"id":1,"prefix":"ERegistryAcme...","active":true},{"id":2,"prefix":"ERegistryBeta...","active":true},{"id":3,"prefix":"ERegistryGamma...","active":true}]'
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
1. Checking sender prefix is in compiled-in `TRUSTED_REGISTRY_MEMBERS`
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

### Adding Peers (Multi-Party Approval)

Peers require multi-party approval from federation members. This prevents any single compromised registry from unilaterally adding malicious peers — though a malicious peer could at most deny service, since all KEL events require valid signatures from the owner's keys and are verified during merge.

**Approval Threshold** (where n = number of federation members):

| n | threshold |
|---|-----------|
| 0-5 | 3 |
| 6-9 | 4 |
| 10+ | ceil(n/3) |

Minimum threshold is always 3 votes to prevent trivial collusion. Inspired by KERI's immunity constraint (M = F+1, F = (N-1)/3), with a hard floor of 3 and a smooth transition toward ceil(n/3) at scale.

**Step 1: Propose a new peer**

Any federation member can propose a new peer:

```bash
# From any registry in the federation
kels-registry-admin peer propose \
  --peer-prefix Qm... \
  --node-id node-1 \
  --kels-url http://kels.node-1.example.com \
  --gossip-addr gossip.node-1.example.com:4001

# Output:
# Proposal created: EProposal123...
# Waiting for 3 approvals (0/3 so far)
```

**Step 2: Vote on the proposal**

Other federation members vote to approve:

```bash
# On another registry
kels-registry-admin peer vote --proposal-id EProposal123... --approve

# Output:
# Vote recorded. Status: 2/2 approvals - APPROVED
# Peer added to peer set.
```

**Step 3: Monitor proposals**

```bash
# List pending proposals
kels-registry-admin peer proposals

# Check specific proposal status
kels-registry-admin peer proposal-status --proposal-id EProposal123...
```

**Proposal Expiration**: Proposals expire after 7 days if threshold is not met.

### Removing Peers (Multi-Party Approval)

Peer removal follows the same multi-party approval process as additions.

**Step 1: Propose removal of a peer**

```bash
# From any registry in the federation
kels-registry-admin peer propose-removal \
  --peer-prefix Qm...

# Output:
# Removal proposal created: EProposal456...
# Removal proposal created. Need 3 approvals.
```

**Step 2: Vote on the removal proposal**

```bash
# On another registry
kels-registry-admin peer vote --proposal-id EProposal456... --approve

# Output:
# Removal approved! Peer Qm... removed from peer set.
# Progress: 3/3 approvals
# Peer has been removed from the peer set.
```

After approval, the peer is deactivated and moved from active to inactive in the Raft state machine. The peer can be re-added later via a new addition proposal.

## Security Considerations

### Federation Membership

- Membership is controlled by the compile-time `TRUSTED_REGISTRY_MEMBERS` constant (JSON array of `{id, prefix, active}` objects for kels-registry) and `TRUSTED_REGISTRY_PREFIXES` (comma-separated prefixes for gossip and identity services)
- Only known registry prefixes can participate in consensus
- Cannot be changed at runtime - must be baked into the binary at build time

### Message Authentication

- All Raft messages are signed with the sender's identity key (HSM-backed)
- Recipients verify signatures against the sender's KEL
- Messages from prefixes not in `TRUSTED_REGISTRY_MEMBERS` are rejected

### Member KEL Replication

- Member KELs are replicated via Raft consensus (not ephemeral HTTP caches)
- Each member submits its own KEL to Raft via a periodic sync loop if required (every 30s)
- KELs survive registry restarts since they are part of the Raft-replicated state and snapshots
- Verification of anchored data uses the Raft-replicated KELs as the single source of truth
- See [Registry Removal](registry-removal.md) for decommission procedures

## Disaster Recovery

### Rogue Registry Scenario

If a federation member is compromised:

1. **Detection**: Audit logs show unexpected peer changes with the rogue registry's prefix

2. **Isolation**: Update `TRUSTED_REGISTRY_MEMBERS` and `TRUSTED_REGISTRY_PREFIXES` on honest services to exclude the rogue:
   ```bash
   TRUSTED_REGISTRY_MEMBERS='[{"id":1,"prefix":"ERegistryAcme...","active":true},{"id":3,"prefix":"ERegistryGamma...","active":true}]'  # Beta removed
   TRUSTED_REGISTRY_PREFIXES=ERegistryAcme...,ERegistryGamma...  # Beta removed
   ```

3. **Redeploy**: Restart honest registries with updated config
   - Rogue is excluded from consensus
   - New leader elected from remaining members

4. **Recovery**: If peer set was compromised, peers must be re-added via the standard proposal/vote process (`kels-registry-admin peer propose` followed by `kels-registry-admin peer vote` from the remaining honest registries). There is no direct `peer add` command.

5. **Gossip nodes auto-heal**: Next allowlist refresh removes unauthorized peers

### Approval Requirements

Peer changes require the approval threshold described above — minimum 3 votes, scaling to ceil(n/3) at scale. A single compromised registry cannot unilaterally modify the peer set.

#### Threshold Verification

The approval threshold is stored on each proposal at creation time. Verification is split across two layers:

- **Leader handler** (exact match): At proposal submission time, the leader rejects proposals where `threshold != approval_threshold()`. This prevents a proposer from submitting a low threshold in a large federation.
- **Raft `apply()`** (floor check): During log replay and replication, followers enforce only a minimum threshold floor (`compute_approval_threshold(0)`, currently 3). The exact-match check is deliberately not repeated here because the config may have changed since the entry was committed — a federation that grew from 3 to 10 members would incorrectly reject legitimate historical proposals from when the threshold was 3.

This split ensures that no peer change can be approved with fewer than 3 verified votes, while remaining safe across federation growth and Raft log replay. See [federation-state-machine.md](federation-state-machine.md#threshold-verification) for details.

### Split-Brain Protection

- Raft requires majority quorum for log replication
- Minority partition cannot replicate approved changes
- Minority partition is read-only until quorum is restored

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

Returns the peer set from the Raft state machine.

### Member Key Events
```
GET /api/member-kels
```

Returns KELs for all federation members (for cross-registry verification).

### Member Key Events (per-prefix)
```
GET /api/member-kels/:prefix?limit=N&since=SAID
```

Returns a specific member's KEL with pagination support.

### Admin API (localhost only)

Peer proposal management:

```
POST   /api/admin/addition-proposals              # Propose a new peer (addition)
POST   /api/admin/removal-proposals              # Propose removal of a peer
POST   /api/admin/proposals/:proposal_id         # Get proposal details (signed request)
POST   /api/admin/proposals/:proposal_id/vote    # Vote on a proposal (addition or removal)
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

# Deploy nodes
garden deploy --env=node-a
garden deploy --env=node-b
garden deploy --env=node-c

# Add peers (requires multi-party approval)
# Step 1: Propose from registry-a
garden run propose-add-node-a --env=registry-a
# Output includes proposal ID

# Step 2: Vote from registry-b (use proposal ID from above)
garden run vote-peer --env=registry-b --var proposal=EProposal...

# Repeat for node-b and node-c

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
- `node-b`, `node-e` -> `registry-b`
- `node-c`, `node-f` -> `registry-c`
