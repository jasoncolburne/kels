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
2. KELS writes to DB, then explicitly publishes `{prefix}:{said}` to Redis `kel_updates` channel, where `said` is the last **submitted** event's SAID (not the sorted KEL's last event — this distinction matters for same-kind forks where the sorted tail may be an event other nodes already have)
3. `kels-gossip` receives notification via Redis SUBSCRIBE
4. Broadcasts `KelAnnouncement { prefix, said }` to gossipsub topic

### Inbound (gossip network → local)

1. `kels-gossip` receives `KelAnnouncement` from gossipsub
2. Compares announced SAID with local latest SAID for that prefix
3. Checks if announced SAID already exists locally (we may be ahead of the announcer)
4. If SAID is new:
   - **Delta fetch** (`fetch_kel_since`): requests only events after local state
   - **Audit fetch** (on `KeyNotFound`): local SAID was purged by recovery — fetches with audit to get archived adversary events + clean chain, submits in recovery-aware stages
   - **Full fetch** (fallback): fetches entire KEL when delta fails for other reasons, or when prefix is unknown locally
   - **Event partitioning**: when events contain multiple divergent branches, adversary events are submitted first, then recovery events, so merge() can properly detect and resolve divergence
5. KELS verifies signatures, merges into local KEL (handles divergence/recovery)

### Why SAID comparison?

- Simple equality check - if SAIDs match, nodes are in sync
- Divergent events at the same generation have different SAIDs
- No timestamp or generation tracking needed
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
    ├── protocol.rs   # Message types (KelAnnouncement, KelRequest, KelResponse)
    ├── allowlist.rs  # Connection filtering based on peer allowlist
    ├── bootstrap.rs  # Bootstrap sync from existing peers
    ├── hsm_signer.rs # HSM-backed request signing
    └── peer_store.rs # Peer cache in PostgreSQL
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
| `NODE_ID` | Unique node identifier | `node-unknown` |
| `KELS_URL` | Local KELS HTTP endpoint | `http://kels:80` |
| `REDIS_URL` | Redis for pub/sub | `redis://redis:6379` |
| `REGISTRY_URL` | Registry service URL for bootstrap sync | (optional) |
| `GOSSIP_LISTEN_ADDR` | libp2p listen address | `/ip4/0.0.0.0/tcp/4001` |
| `GOSSIP_TOPIC` | Gossipsub topic name | `kels/events/v1` |
| `GOSSIP_TEST_PROPAGATION_DELAY_MS` | Test-only delay before announcing | `0` |

## Design Decisions

### Separate deployment (not sidecar)

- Independent scaling - can run different replica counts
- Independent lifecycle - update gossip without restarting KELS
- Easier debugging and monitoring
- Communicates with KELS via HTTP (no direct DB access)

### HSM-backed libp2p identity

Gossip nodes use persistent HSM-backed identities:
- Each node's libp2p identity is derived from a secp256r1 key stored in the HSM service
- The PeerId is deterministic - same HSM key = same PeerId across restarts
- Nodes must be added to the peer allowlist before they can connect to the gossip mesh
- Unauthorized peers are disconnected immediately after the Noise handshake
- See [Secure Registration](secure-registration.md) for details on the peer allowlist

### Delta-based sync with full-fetch fallback

- **Delta fetch** (`?since=<said>`) is the primary sync mechanism — only fetches events newer than local state
- Uses the `serial` field on `KeyEvent` for efficient DB-ordered queries (`ORDER BY serial ASC`)
- Falls back to **full KEL fetch** when delta is unavailable (e.g., new prefix, network error)
- **Recovery-aware audit fetch**: when a delta fetch fails with `KeyNotFound` (local SAID was purged by recovery on the remote), fetches with `?audit=true` to retrieve both the clean chain and archived adversary events
- Archived adversary events are submitted first (establishes the adversary branch), then the clean chain is split at the first recovery-revealing event and submitted in stages so merge() processes recovery correctly
- KELS handles duplicate events idempotently

### Registry-based discovery (not hardcoded bootstrap peers)

- Nodes register with the `kels-registry` service on startup
- New nodes query the registry for existing peers and bootstrap sync
- Peers discover each other dynamically via gossipsub mesh
- No hardcoded peer addresses needed in configuration
- See [registry.md](registry.md) for details on the registration protocol

## Kubernetes Deployment

### Cross-namespace communication

Gossip nodes in different namespaces connect via the registry service. The registry runs in its own namespace and nodes register with it on startup.

### Services

Each namespace has:
- `kels-gossip` - ClusterIP service for libp2p connections
- `kels-gossip-headless` - Headless service for direct pod addressing

### CoreDNS Configuration for `.kels` Domains

Nodes advertise URLs using `.kels` domains (e.g., `http://kels.kels-node-a.kels`) so that the same URLs work for both:
- **External clients** (iOS, CLI) - resolved via `/etc/hosts` or local DNS
- **Internal services** - resolved via CoreDNS inside the cluster

To enable internal resolution, CoreDNS must be configured with rewrite rules:

```bash
garden run coredns-config
```

This applies rewrite rules that translate `.kels` domains to `.svc.cluster.kels`:

```
rewrite name regex (.*)\.kels-registry-(.)\.kels {1}.kels-registry-{2}.svc.cluster.kels
rewrite name regex (.*)\.kels-node-(.)\.kels {1}.kels-node-{2}.svc.cluster.kels
```

**Platform-specific notes:**

| Platform | Notes |
|----------|-------|
| Docker Desktop | Works as-is with the provided script |
| minikube | May need to edit the `coredns` ConfigMap in `kube-system` namespace manually |
| kind | CoreDNS config is in `coredns` ConfigMap; may need cluster recreation to apply |
| EKS/GKE/AKS | Use cluster-specific DNS customization (e.g., CoreDNS ConfigMap or NodeLocal DNSCache) |
| k3s | Uses CoreDNS by default; same ConfigMap approach works |

If your Kubernetes distribution uses a different DNS provider or configuration method, adapt the rewrite rules accordingly. The key requirement is that `*.kels-node-X.kels` resolves to `*.kels-node-X.svc.cluster.kels` inside the cluster.

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

`clients/test/scripts/test-adversarial-advanced.sh` verifies multi-node adversarial scenarios:
- Dual adversary injection on separate nodes + owner recovery propagation
- Triple simultaneous events (adversary + adversary + owner) with delayed gossip

`clients/test/scripts/test-consistency.sh` verifies cross-node consistency:
- All nodes have the same set of prefixes
- All prefixes have the same event counts
- SHA-256 digest of each KEL matches across all nodes (signatures normalized by publicKey before hashing)
- Behavioral state consistency for any mismatched KELs
