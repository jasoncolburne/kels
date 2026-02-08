# Secure Node Registration

This document describes the cryptographically secured node registration system for KELS gossip nodes. All registration requests are signed using HSM-backed identities and verified against a peer allowlist.

## Overview

The secure registration system ensures that only authorized nodes can:
- Register with the kels-registry service
- Participate in the gossip network

Each node has a persistent secp256r1 identity stored in an HSM (the example implementation uses the software based SoftHSM2 - don't use this in production), and the registry verifies signatures against an allowlist of authorized PeerIds stored in PostgreSQL.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            kels-registry namespace                           │
│                                                                              │
│  ┌────────────┐    ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  identity  │───>│  Peer Allowlist │───>│  Registration Verification   │   │
│  │  service   │    │  (PostgreSQL)   │    │  - Verify signature          │   │
│  │ (1 replica)│    │  [PeerId list]  │    │  - Check PeerId in allowlist │   │
│  └─────┬──────┘    └─────────────────┘    └──────────────────────────────┘   │
│        │                                                                     │
│        ▼                                                                     │
│  ┌───────────┐                                                               │
│  │    HSM    │  (manages registry's KELS identity)                           │
│  │(SoftHSM2) │                                                               │
│  └───────────┘                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │ Signed HTTP requests
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│   node-a      │           │   node-b      │           │   node-c      │
│ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
│ │kels-gossip│◄├───────────┤►│kels-gossip│◄├───────────┤►│kels-gossip│ │
│ └─────┬─────┘ │           │ └─────┬─────┘ │           │ └─────┬─────┘ │
│       │       │           │       │       │           │       │       │
│       ▼       │           │       ▼       │           │       ▼       │
│ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
│ │    HSM    │ │           │ │    HSM    │ │           │ │    HSM    │ │
│ │(SoftHSM2) │ │           │ │(SoftHSM2) │ │           │ │(SoftHSM2) │ │
│ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │
└───────────────┘           └───────────────┘           └───────────────┘
```

### Identity Service

The registry namespace includes a dedicated identity service (single replica) that manages the registry's own KELS identity. This separation prevents race conditions when multiple registry replicas attempt identity operations simultaneously.

**Identity Service API:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/identity` | Get registry prefix |
| `GET` | `/api/identity/kel` | Get registry's full KEL |
| `POST` | `/api/identity/anchor` | Anchor a SAID in the registry's KEL |
| `POST` | `/api/identity/sign` | Sign data with registry's current key |

## Components

### HSM Service

Each node runs an HSM service (SoftHSM2) that provides:
- Persistent secp256r1 key storage
- Key generation (idempotent - returns existing key if present)
- Signing operations

**Key label convention:** `kels-gossip-{node_id}` (e.g., `kels-gossip-node-a`)

**HSM API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/hsm/keys` | Generate or get existing key (idempotent) |
| `GET` | `/api/hsm/keys/{label}/public` | Get public key (CESR qb64) |
| `POST` | `/api/hsm/keys/{label}/sign` | Sign data, returns CESR signature + public key |

### PeerId Derivation

The PeerId is cryptographically derived from the HSM public key:

1. HSM stores secp256r1 key (33-byte compressed SEC1 format)
2. Key is decompressed to 65-byte uncompressed format
3. libp2p derives PeerId from uncompressed public key
4. PeerId is stable across restarts (same HSM key = same PeerId)

### Peer Allowlist

Authorized peers are stored in PostgreSQL using verifiable-storage patterns:

```rust
struct Peer {
    said: String,             // Content hash (CESR Blake3)
    prefix: String,           // Stable lineage ID (peer-{peer_id})
    previous: Option<String>, // SAID of previous version
    version: u64,             // Version number
    created_at: DateTime,
    peer_id: String,          // libp2p PeerId (Base58)
    node_id: String,          // Human-readable name (e.g., "node-a")
    authorizing_kel: String,  // Prefix of the KEL that authorized this peer
    active: bool,             // Current authorization status
    scope: PeerScope,         // Core (federated) or Regional (local-only)
    kels_url: String,         // HTTP URL for KELS service
    gossip_multiaddr: String, // libp2p multiaddr for gossip connections
}
```

Each peer is a versioned entity - deactivation creates a new version with `active: false` rather than deleting the record.

**Authorizing KEL:**
The `authorizing_kel` field identifies which registry's KEL contains the cryptographic anchor for this peer record. When verifying a peer, the gossip node fetches the KEL for the `authorizing_kel` prefix and checks that the peer's SAID is anchored in it. This allows federated registries to authorize peers independently while maintaining cryptographic proof of authorization.

**Peer Scopes:**
- `Core`: Replicated across all registries in a federation via Raft consensus
- `Regional`: Local to this registry only, not shared across federation

For more details on peer scopes and federation, see [Multi-Registry Federation](./federation.md).

## Signed Request Format

Mutating registry operations require signed requests:

```rust
struct SignedRequest<T> {
    payload: T,           // The actual request data
    peer_id: String,      // Base58 PeerId of signer
    public_key: String,   // CESR qb64 encoded public key
    signature: String,    // CESR qb64 encoded signature
}
```

**Signature computation:**
1. Serialize payload to JSON (with `preserve_order` for determinism)
2. Sign the JSON bytes with secp256r1 key
3. Encode signature as CESR qb64

## API Changes

### Authenticated Endpoints

| Method | Path | Request Body | Description |
|--------|------|--------------|-------------|
| `POST` | `/api/nodes/register` | `SignedRequest<RegisterNodeRequest>` | Register a node |
| `POST` | `/api/nodes/deregister` | `SignedRequest<DeregisterRequest>` | Deregister a node |
| `POST` | `/api/nodes/status` | `SignedRequest<StatusUpdateRequest>` | Update node status |

### Unauthenticated Endpoints (unchanged)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/peers` | Get peer allowlist |
| `GET` | `/api/registry-kel` | Get registry's KEL |
| `GET` | `/health` | Health check |

## Verification Flow

When the registry receives a signed request:

1. **Parse signature components** from SignedRequest
2. **Verify signature** over payload JSON using CESR library
3. **Derive PeerId** from public key and verify it matches claimed peer_id
4. **Check allowlist** - query PostgreSQL for latest version of peer, verify `active: true`
5. **Process request** if all checks pass

```
┌──────────────────┐
│ Signed Request   │
│ - payload        │
│ - peer_id        │
│ - public_key     │
│ - signature      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Parse CESR keys  │
│ & signature      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Verify signature │────>│ 401 Unauthorized│
│ over payload     │ NO  │ (invalid sig)   │
└────────┬─────────┘     └─────────────────┘
         │ YES
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Derive PeerId    │────>│ 401 Unauthorized│
│ matches claimed? │ NO  │ (peer mismatch) │
└────────┬─────────┘     └─────────────────┘
         │ YES
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Query allowlist  │────>│ 403 Forbidden   │
│ peer active?     │ NO  │ (not authorized)│
└────────┬─────────┘     └─────────────────┘
         │ YES
         ▼
┌──────────────────┐
│ Process request  │
└──────────────────┘
```

## Request Signing Flow (Client Side)

kels-gossip signs requests using `HsmRegistrySigner`:

1. **Create signer** on startup with HSM URL and node_id
2. **Sign requests** by calling HSM sign endpoint (returns signature + public key)
3. **Derive peer_id** from returned public key
4. **Wrap payload** in SignedRequest with signature, public key, and peer_id

```rust
// In kels-gossip startup
let registry_signer = HsmRegistrySigner::new(hsm_url, &node_id);
let registry_client = KelsRegistryClient::with_signer(registry_url, Arc::new(registry_signer));

// Registration is now automatically signed
registry_client.register(node_id, kels_url, ...).await?;
```

The HSM sign endpoint returns both signature and public key in a single call, avoiding the need to cache or make separate requests.

## Allowlist Management

### Admin CLI

The `kels-registry-admin` CLI manages the peer allowlist:

```bash
# Add a peer to allowlist (regional scope by default)
kels-registry-admin peer add --peer-id 12D3KooWAbc... --node-id node-a \
  --kels-url http://kels.kels-node-a.kels \
  --gossip-multiaddr /dns4/kels-gossip.kels-node-a.kels/tcp/4001

# Add a core peer (in federated mode, must run on leader registry)
kels-registry-admin peer add --peer-id 12D3KooWAbc... --node-id node-a \
  --scope core \
  --kels-url http://kels.kels-node-a.kels \
  --gossip-multiaddr /dns4/kels-gossip.kels-node-a.kels/tcp/4001

# Remove a peer (creates deactivated version)
kels-registry-admin peer remove --peer-id 12D3KooWAbc...

# List all authorized peers
kels-registry-admin peer list
```

See [Multi-Registry Federation](./federation.md) for details on core vs regional peer scopes.

### Getting a Node's PeerId

Before a node can be added to the allowlist, you need its PeerId. Options:

1. **From logs:** Deploy the node, check kels-gossip logs for "Local PeerId: ..."
2. **From HSM:** Query HSM public key and derive PeerId programmatically

```bash
# Check kels-gossip logs
kubectl logs -n kels-node-a deploy/kels-gossip | grep PeerId
# Output: Local PeerId: 12D3KooWXyz...
```

## Node Onboarding Workflow

### Phase 1: Deploy Node (Unauthorized)

1. Deploy new node namespace with HSM service
2. Deploy kels-gossip - it generates/loads HSM key and logs PeerId
3. Node attempts to register with registry - **fails** (not in allowlist)
4. Node can still fetch KELS data via HTTP (read-only, no auth required)

### Phase 2: Authorize Node

1. Get PeerId from node logs
2. Add peer via admin CLI:
   ```bash
   kubectl exec -n kels-registry deploy/kels-registry -- \
     kels-registry-admin peer add --peer-id 12D3KooWXyz... --node-id node-x
   ```

### Phase 3: Node Becomes Operational

1. Node retries registration - **succeeds** (now in allowlist)
2. Node connects to gossip peers
3. Node is fully operational

## libp2p Connection Filtering

In addition to registry authentication, the gossip layer filters connections:

1. Noise handshake completes - peer identity verified
2. `AllowlistBehaviour` checks peer against cached allowlist
3. Unauthorized peers are immediately disconnected

```rust
// AllowlistBehaviour in kels-gossip
impl NetworkBehaviour for AllowlistBehaviour {
    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionEstablished(conn) = event {
            if !self.allowlist.blocking_read().contains(&conn.peer_id) {
                // Queue disconnection
                self.pending_disconnects.push(conn.peer_id);
            }
        }
    }
}
```

Nodes periodically refresh their allowlist from the registry's `/api/peers` endpoint.

## Security Considerations

### Key Protection

- HSM keys never leave the HSM service
- Private key operations happen inside SoftHSM2
- Each node has isolated HSM with separate persistent volume

### Identity Binding

- PeerId is cryptographically derived from HSM public key
- Cannot claim a different PeerId than what the key produces
- Same key always produces same PeerId (deterministic)

### Defense in Depth

1. **Registry layer:** Signature verification + allowlist check
2. **Gossip layer:** Connection filtering after Noise handshake
3. **Admin access:** CLI requires kubectl exec (same trust as cluster admin)

### Signature Algorithm

- **Key type:** secp256r1 (P-256, NIST curve)
- **Signature:** ECDSA with SHA-256
- **Encoding:** CESR qb64 for public keys and signatures
- **Payload:** Canonical JSON serialization (`preserve_order` feature)

### Read vs Write Security

| Operation | Authentication |
|-----------|---------------|
| Read KELS data | None (public) |
| Read peer list | None (public) |
| Register node | Signed + allowlist |
| Deregister node | Signed + allowlist |
| Status update | Signed + allowlist |
| Gossip connection | Allowlist check after handshake |

## Deployment

### Registry Namespace

```
kels-registry/
├── hsm (SoftHSM2 service)
├── identity (manages registry's KELS identity, 1 replica)
├── postgres (peer allowlist + identity KEL)
├── redis (node registrations)
└── kels-registry
```

### Node Namespace

```
kels-node-x/
├── hsm (SoftHSM2 service)
├── postgres (kels + kels_gossip DBs)
├── redis (KEL cache + pubsub)
├── kels
└── kels-gossip
```

## Troubleshooting

### Node Cannot Register

1. Check if peer is in allowlist:
   ```bash
   kubectl exec -n kels-registry deploy/kels-registry -- kels-registry-admin peer list
   ```

2. Verify PeerId matches:
   ```bash
   # Get PeerId from node logs
   kubectl logs -n kels-node-x deploy/kels-gossip | grep PeerId
   ```

3. Check registry logs for verification errors:
   ```bash
   kubectl logs -n kels-registry deploy/kels-registry
   ```

### Signature Verification Failed

- Ensure HSM is healthy and responding
- Check that the key label matches: `kels-gossip-{node_id}`
- Verify JSON serialization is deterministic (using `preserve_order`)

### Peer Not Connecting via Gossip

- Check allowlist refresh interval (default: 60 seconds)
- Verify peer is active in allowlist (not deactivated)
- Check AllowlistBehaviour logs for disconnection events
