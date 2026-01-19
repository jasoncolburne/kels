# KELS Gossip Protocol

## Overview

The `kels-gossip` service synchronizes KELs between independent KELS deployments using libp2p. It enables high availability by replicating events across geographically distributed nodes.

## Architecture

```
                    KELS Namespace A
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   ┌──────────┐   publish    ┌───────┐   subscribe        │
│   │   KELS   │ ──────────▶  │ Redis │  ◀────────────┐    │
│   │  (HTTP)  │              │pub/sub│               │    │
│   └──────────┘              └───────┘               │    │
│        ▲                                    ┌───────┴───┐│
│        │ HTTP POST /api/kels/events         │kels-gossip││
│        └────────────────────────────────────│ (libp2p)  ││
│                                             └─────┬─────┘│
└───────────────────────────────────────────────────│──────┘
                                                    │
                                          libp2p gossipsub
                                        + request-response
                                                    │
┌───────────────────────────────────────────────────│──────┐
│                                             ┌─────┴─────┐│
│        ┌────────────────────────────────────│kels-gossip││
│        │ HTTP POST /api/kels/events         │ (libp2p)  ││
│        ▼                                    └───────┬───┘│
│   ┌──────────┐              ┌───────┐               │    │
│   │   KELS   │ ──────────▶  │ Redis │  ◀────────────┘    │
│   │  (HTTP)  │   publish    │pub/sub│   subscribe        │
│   └──────────┘              └───────┘                    │
│                                                          │
│                    KELS Namespace B                      │
└──────────────────────────────────────────────────────────┘
```

## Data Flow

### Outbound (local event → gossip network)

1. Client submits events to KELS via HTTP
2. KELS writes to DB, publishes `{prefix}:{said}` to Redis `kel_updates` channel
3. `kels-gossip` receives notification via Redis SUBSCRIBE
4. Broadcasts `KelAnnouncement { prefix, said }` to gossipsub topic

### Inbound (gossip network → local)

1. `kels-gossip` receives `KelAnnouncement` from gossipsub
2. Compares announced SAID with local latest SAID for that prefix
3. If SAIDs differ (or prefix unknown locally):
   - Sends `KelRequest { prefix }` to announcing peer via request-response
   - Receives `KelResponse { prefix, events }` with full KEL
   - Submits events to local KELS via `KelsClient::submit_events()`
4. KELS verifies signatures, merges into local KEL (handles divergence/recovery)

### Why SAID comparison?

- Simple equality check - if SAIDs match, nodes are in sync
- Divergent events at the same version have different SAIDs
- No timestamp or version tracking needed
- Works correctly with divergence detection

## Components

### Service Structure

```
services/kels-gossip/
├── Cargo.toml
├── Dockerfile
├── garden.yml
├── manifests.yml.tpl
└── src/
    ├── main.rs       # Entry point, config loading
    ├── lib.rs        # Service orchestration
    ├── gossip.rs     # libp2p swarm with gossipsub + request-response
    ├── sync.rs       # Redis subscriber, sync handler using KelsClient
    └── protocol.rs   # Message types (KelAnnouncement, KelRequest, KelResponse)
```

### Message Types

```rust
/// Broadcast via gossipsub to announce KEL updates
struct KelAnnouncement {
    prefix: String,
    said: String,
}

/// Request full KEL from a peer
struct KelRequest {
    prefix: String,
}

/// Response containing full KEL
struct KelResponse {
    prefix: String,
    events: Vec<SignedKeyEvent>,
}
```

### Protocols

| Protocol | Transport | Purpose |
|----------|-----------|---------|
| gossipsub | Flood/mesh | Broadcast announcements to all peers |
| request-response | Direct | Fetch KEL from specific peer |
| identify | Direct | Exchange peer metadata on connect |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `KELS_URL` | Local KELS HTTP endpoint | `http://kels:80` |
| `REDIS_URL` | Redis for pub/sub | `redis://redis:6379` |
| `GOSSIP_LISTEN_ADDR` | libp2p listen address | `/ip4/0.0.0.0/tcp/4001` |
| `GOSSIP_BOOTSTRAP_PEERS` | Comma-separated peer multiaddrs | (none) |
| `GOSSIP_TOPIC` | Gossipsub topic name | `kels/events/v1` |
| `GOSSIP_TEST_PROPAGATION_DELAY_MS` | Test-only delay before announcing | `0` |

## Design Decisions

### Separate deployment (not sidecar)

- Independent scaling - can run different replica counts
- Independent lifecycle - update gossip without restarting KELS
- Easier debugging and monitoring
- Communicates with KELS via HTTP (no direct DB access)

### Ephemeral libp2p identity

The gossip layer is **pure transport** with no cryptographic identity requirements:
- KELS verifies all event signatures when submitted via HTTP
- Invalid/forged events are rejected by KELS, not the gossip layer
- Gossip nodes use ephemeral libp2p keys generated on startup
- No identity persistence or HSM integration needed

### Full KEL fetch (not incremental)

- Simpler implementation - no version tracking needed
- KELS handles duplicate events idempotently
- Works correctly with divergence scenarios
- Bandwidth overhead acceptable for typical KEL sizes

### Bootstrap peers (not Kademlia DHT)

- Simpler deployment - no DHT state to manage
- Explicit peer configuration via environment variable
- Cross-namespace DNS for Kubernetes deployments
- Sufficient for typical deployment topologies

## Kubernetes Deployment

### Cross-namespace communication

Gossip nodes in different namespaces connect via fully-qualified DNS:

```yaml
# node-a environment
GOSSIP_BOOTSTRAP_PEERS: "/dns4/kels-gossip.kels-node-b.svc.cluster.local/tcp/4001"

# node-b environment
GOSSIP_BOOTSTRAP_PEERS: "/dns4/kels-gossip.kels-node-a.svc.cluster.local/tcp/4001"
```

### Services

Each namespace has:
- `kels-gossip` - ClusterIP service for libp2p connections
- `kels-gossip-headless` - Headless service for direct pod addressing

## Divergence Handling

When a KEL becomes divergent:

1. Both divergent branches propagate via gossip
2. Receiving node's KELS detects divergence during `merge()`
3. KEL enters frozen state until recovery or contest
4. Recovery events also propagate and resolve divergence

The gossip layer doesn't need special divergence logic - KELS handles all verification and merge semantics.

## Testing

### Test propagation delay

For adversarial testing scenarios, set `GOSSIP_TEST_PROPAGATION_DELAY_MS` to simulate slow gossip propagation. This allows testing race conditions and divergence scenarios.

### Integration test script

`clients/test/scripts/test-gossip.sh` verifies:
- Basic propagation (A → B)
- Rotation propagation
- Anchor propagation
- Multiple rapid events
- Divergence detection via gossip
- Recovery propagation
- Decommission propagation
