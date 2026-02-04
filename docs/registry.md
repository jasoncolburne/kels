# KELS Node Registry & Bootstrap Sync

## Overview

The `kels-registry` service provides node registration and discovery for KELS gossip deployments. When new nodes come online, they query the registry to find peers, bootstrap sync missing KELs, then register as ready for queries. Clients discover nodes via the registry and test latency to select optimal nodes.

For multi-cloud/multi-region deployments, multiple registries can be federated using Raft consensus. See [Multi-Registry Federation](./federation.md) for details.

## Architecture

### Single Registry

```
                    ┌─────────────────────┐
                    │   kels-registry     │  (shared across all deployments)
                    │   (Standalone)      │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │  node-a     │     │  node-b     │     │  node-c...  │
    │ kels-gossip │◄───►│ kels-gossip │◄───►│ kels-gossip │
    └─────────────┘     └─────────────┘     └─────────────┘
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │    kels     │     │    kels     │     │    kels     │
    └─────────────┘     └─────────────┘     └─────────────┘
```

### Federated Registries

For high availability and multi-party operation, multiple registries can form a federation:

```
        REGISTRY FEDERATION (Raft Consensus)
    ┌─────────────────────────────────────────┐
    │  Registry A ◄──► Registry B ◄──► Registry C  │
    │  (Leader)       (Follower)      (Follower)   │
    └─────────────────────────────────────────┘
         │                │                │
         ▼                ▼                ▼
    [nodes a,d]      [node b]         [node c]
```

See [Multi-Registry Federation](./federation.md) for detailed documentation.

## Data Flow

### Node Startup (Bootstrap Sync)

1. Node starts, queries registry for bootstrap peers: `GET /api/nodes/bootstrap`
2. If no peers exist:
   - Register immediately as Ready
   - Start normal gossip operation
3. If peers exist:
   - Register as Bootstrapping
   - Start listening for gossip updates
   - For each bootstrap peer (in parallel):
     - Fetch prefix list: `GET /api/kels/prefixes?since=&limit=100`
     - For each prefix not in local DB:
       - Fetch KEL via gossip request-response
       - Submit to local KELS
   - Update registration to Ready
4. Continue normal gossip operation with heartbeats

### Client Node Discovery

1. Client queries registry for peers: `GET /api/peers`
2. Client extracts active peers with their `kels_url` endpoints
3. Client tests readiness of each node via `/ready` endpoint
4. Client tests latency to each Ready node via `/health` endpoint
5. Client selects node with lowest latency
6. Client caches node list with short TTL for retry resilience

## Components

### Service Structure

```
services/kels-registry/
├── Cargo.toml
├── Dockerfile
├── garden.yml
├── manifests.yml.tpl
└── src/
    ├── main.rs           # Entry point, tracing setup
    ├── lib.rs            # Module definitions
    ├── server.rs         # HTTP router and startup
    ├── handlers.rs       # All handlers (nodes, peers, registry KEL, federation)
    ├── store.rs          # Redis-backed node storage
    ├── signature.rs      # Signature verification
    ├── identity_client.rs # Client for identity service
    ├── peer_store.rs     # PostgreSQL peer repository
    ├── repository.rs     # Combined repository
    ├── federation/       # Multi-registry federation (Raft consensus)
    │   ├── mod.rs        # FederationNode entry point
    │   ├── config.rs     # Federation configuration
    │   ├── network.rs    # HTTP transport for Raft RPCs
    │   ├── state_machine.rs # Raft state machine (core peer set)
    │   ├── storage.rs    # Raft log/vote storage (PostgreSQL)
    │   └── types.rs      # Federation message types
    └── bin/
        └── kels-registry-admin.rs # Admin CLI for peer management
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/nodes/register` | Register or update a node (requires signed request) |
| `POST` | `/api/nodes/deregister` | Deregister a node (requires signed request) |
| `GET` | `/api/nodes` | List all registered nodes |
| `GET` | `/api/nodes/:node_id` | Get a specific node |
| `GET` | `/api/nodes/bootstrap` | Get bootstrap peers (excludes caller via `?exclude=node_id`) |
| `POST` | `/api/nodes/:node_id/heartbeat` | Keep-alive heartbeat |
| `POST` | `/api/nodes/status` | Update node status (requires signed request) |
| `GET` | `/api/peers` | Get peer allowlist (core + regional peers) |
| `GET` | `/api/registry-kel` | Get registry's KEL (for verifying peer SAIDs) |
| `GET` | `/api/federation/status` | Get federation status (leader, term, members) |
| `POST` | `/api/federation/rpc` | Internal Raft RPC (federation mode only) |
| `GET` | `/health` | Health check |

> **Note:** Registration and deregistration require cryptographically signed requests from nodes in the peer allowlist. See [Secure Registration](./secure-registration.md) for details. Federation endpoints are only available when federation is configured.

### Data Model

```rust
struct NodeRegistration {
    node_id: String,           // Unique identifier (e.g., "node-a")
    node_type: NodeType,       // Kels or Registry
    kels_url: String,          // HTTP endpoint for KELS API
    gossip_multiaddr: String,  // libp2p multiaddr for gossip
    registered_at: DateTime<Utc>,
    last_heartbeat: DateTime<Utc>,
    status: NodeStatus,
}

enum NodeType {
    Kels,      // Regular KELS node (has KEL storage)
    Registry,  // Registry node (no KEL storage, excluded from bootstrap)
}

enum NodeStatus {
    Bootstrapping,  // Node is syncing, not ready for queries
    Ready,          // Node is fully synced and accepting requests
    Unhealthy,      // Missed heartbeats
}
```

### KELS Prefix Listing (New Endpoint)

Added to the KELS service for bootstrap sync:

`GET /api/kels/prefixes?since=<cursor>&limit=<n>`

| Parameter | Description | Default |
|-----------|-------------|---------|
| `since` | Cursor (prefix) to start after | (beginning) |
| `limit` | Max prefixes to return | 100 (max: 1000) |

Response includes prefix:SAID pairs for efficient sync comparison:
```json
{
  "prefixes": [
    {"prefix": "Eabc123...", "said": "Exyz789..."},
    {"prefix": "Edef456...", "said": "Eqrs012..."}
  ],
  "nextCursor": "Edef456..."
}
```

During bootstrap sync, nodes compare remote SAIDs with local SAIDs to determine which KELs need syncing.

## Configuration

### Registry Service

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP listen port | `8092` |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379` |
| `HEARTBEAT_TIMEOUT_SECS` | Seconds before node marked unhealthy | `30` |
| `RUST_LOG` | Log level | `kels_registry=info` |

### Gossip Service

| Variable | Description | Default |
|----------|-------------|---------|
| `REGISTRY_URL` | Registry HTTP endpoint | (optional) |
| `NODE_ID` | Unique node identifier | (required) |
| `DATABASE_URL` | PostgreSQL URL for peer cache | (required) |
| `KELS_URL` | Local KELS HTTP endpoint | `http://kels:80` |
| `KELS_ADVERTISE_URL` | Advertised KELS URL for clients | (required) |
| `GOSSIP_LISTEN_ADDR` | libp2p listen address | `/ip4/0.0.0.0/tcp/4001` |
| `GOSSIP_ADVERTISE_ADDR` | libp2p advertised address | (required) |

## Design Decisions

### Redis-backed storage (not in-memory)

- Enables multiple registry replicas for HA
- Stateless service - any replica handles any request
- Heartbeat TTL via Redis EXPIRE for automatic cleanup
- Simple key-value storage with SCAN for listing

### Separate namespace deployment

- Registry is shared infrastructure across all node deployments
- Deployed once in `kels-registry` namespace
- Nodes in `kels-node-a`, `kels-node-b` etc. connect to shared registry
- Avoids circular dependencies during node bootstrap

### Bootstrap sync via KELS API (not direct DB)

- Uses existing `KelsClient` for consistency
- KELS validates all submitted events
- Paginated prefix listing handles large deployments
- Parallel fetching from multiple peers for speed

### Heartbeat-based health (not active probing)

- Nodes push heartbeats to registry
- Simpler than registry polling all nodes
- Redis TTL handles cleanup of dead nodes
- Nodes continue operating if registry temporarily unavailable

### Status states

- **Bootstrapping**: Node is syncing, clients should not query
- **Ready**: Node is fully synced, safe for client queries
- **Unhealthy**: Missed heartbeats, clients should avoid

## Kubernetes Deployment

### Namespace layout

```
kels-registry/     # Shared registry service + Redis
  └── kels-registry (Deployment)
  └── redis (Deployment)

kels-node-a/       # Node A deployment
  └── postgres (databases: kels, kels_gossip)
  └── redis
  └── kels
  └── kels-gossip

kels-node-b/       # Node B deployment
  └── postgres (databases: kels, kels_gossip)
  └── redis
  └── kels
  └── kels-gossip
```

### Garden environments

```yaml
environments:
  - name: registry
    defaultNamespace: kels-registry
  - name: node-a
    defaultNamespace: kels-node-a
  - name: node-b
    defaultNamespace: kels-node-b
```

### Deployment order

```bash
garden deploy --env=registry    # Deploy registry first
garden deploy --env=node-a      # First node registers as Ready
garden deploy --env=node-b      # Bootstrap syncs from node-a
```

## High Availability

### Registry HA

- Deploy 2+ registry replicas behind Kubernetes Service
- All state in Redis (no in-memory state)
- Load balancer distributes requests across replicas
- Redis can be clustered for HA if needed

### Node resilience

- If registry unavailable at startup, fallback to cached peers from previous connections
- Peer cache stored in PostgreSQL (`kels_gossip` database) for persistence across restarts
- Once bootstrapped, node operates via gossip mesh independently
- If heartbeat fails, node periodically re-registers
- Node continues normal gossip during re-registration attempts
- Gossip mesh handles discovery of stale/unavailable cached peers

#### Registry fallback algorithm

1. Try to connect to registry
2. If registry available:
   - Fetch bootstrap peers
   - Sync peer cache to database
3. If registry unavailable:
   - Load cached peers from database
   - Use cached peers for bootstrap sync
4. Continue attempting registry connection for heartbeats and discovery

### Client resilience

- Clients cache node list locally with short TTL
- On connection failure, try next node in list
- Periodically refresh node list from registry

## Client Discovery

### Rust Client (libkels)

```rust
use kels::{KelsClient, NodeInfo};

// Discover all nodes from registry, sorted by latency
let nodes: Vec<NodeInfo> = KelsClient::discover_nodes(registry_url).await?;

// Test latency to current node
let latency: Duration = client.test_latency().await?;

// Create client connected to fastest available node
let client = KelsClient::with_discovery(registry_url).await?;
```

### CLI

```bash
# List registered nodes with latency
kels-cli --registry http://registry:8092 list-nodes

# Auto-select fastest node for commands
kels-cli --registry http://registry:8092 --auto-select incept
kels-cli --registry http://registry:8092 --auto-select list
```

### iOS Client

```swift
import KelsCore

// Discover nodes from registry
let nodes = try await NodeDiscovery.discoverNodes(registryUrl: registryUrl)

// Get fastest ready node
if let fastest = try await NodeDiscovery.fastestNode(registryUrl: registryUrl) {
    viewModel.selectNode(fastest)
}
```

## Testing

### Manual verification

```bash
# Deploy registry
garden deploy --env=registry

# Deploy first node (registers immediately as Ready)
garden deploy --env=node-a

# Create KELs on node-a
kels-cli -u http://kels.kels-node-a.kels incept
kels-cli -u http://kels.kels-node-a.kels incept

# Deploy second node (bootstrap syncs from node-a)
garden deploy --env=node-b

# Verify node-b has the KELs
kels-cli -u http://kels.kels-node-b.kels list

# Test client discovery
kels-cli --registry http://kels-registry.kels-registry.kels list-nodes
```

### Integration tests

Test script: `clients/test/scripts/test-bootstrap.sh`

- Registry health check
- Node registration verification
- CLI node discovery (`list-nodes`)
- Prefix listing API with pagination
- Bootstrap sync verification (KEL propagation between nodes)
- Auto-select functionality

Run tests:
```bash
# From within test-client pod
./scripts/test-bootstrap.sh

# Or run all tests
./scripts/run-all-tests.sh
```
