# Secure Peer Authorization

This document describes the cryptographically secured peer authorization system for KELS gossip nodes. Signed requests are verified using HSM-backed identities against a peer allowlist.

## Overview

The secure authorization system ensures that only authorized nodes can:
- Participate in the gossip network
- Access authenticated endpoints (e.g., prefix listing)

Each node has a persistent ML-DSA-65 identity stored in an HSM (the example implementation uses `kels-mock-hsm`, a PKCS#11 cdylib — don't use this in production), and the registry verifies signatures against an allowlist of authorized PeerPrefixes stored in PostgreSQL.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            kels-registry namespace                           │
│                                                                              │
│  ┌────────────┐    ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  identity  │───>│  Peer Allowlist │───>│  Request Verification        │   │
│  │  service   │    │  (PostgreSQL)   │    │  - Verify signature          │   │
│  │ (1 replica)│    │  [PeerPrefix list]  │    │  - Check PeerPrefix in allowlist │   │
│  └─────┬──────┘    └─────────────────┘    └──────────────────────────────┘   │
│        │                                                                     │
│        ▼                                                                     │
│  ┌───────────┐                                                               │
│  │   HSM     │  (manages registry's KELS identity)                           │
│  │(mock HSM) │                                                               │
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
│ │   HSM     │ │           │ │   HSM     │ │           │ │   HSM     │ │
│ │(mock HSM) │ │           │ │(mock HSM) │ │           │ │(mock HSM) │ │
│ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │
└───────────────┘           └───────────────┘           └───────────────┘
```

### Identity Service

The registry namespace includes a dedicated identity service (single replica) that manages the registry's own KELS identity. This separation prevents race conditions when multiple registry replicas attempt identity operations simultaneously.

**Identity Service API:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/identity` | Get registry prefix |
| `GET` | `/api/identity/kel` | Get registry's KEL (paginated; `?limit=N&since=SAID`) |
| `POST` | `/api/identity/anchor` | Anchor a SAID in the registry's KEL |
| `POST` | `/api/identity/sign` | Sign data with registry's current key |
| `GET` | `/api/identity/status` | Get registry identity status |
| `POST` | `/api/identity/kel/manage` | Manage registry's KEL (rotate, recover, contest, decommission) |

## Components

### HSM (PKCS#11)

Each node's identity service loads a PKCS#11 .so directly via cryptoki:
- Persistent ML-DSA-65 key storage
- Key generation (idempotent - returns existing key if present)
- Signing operations

The development deployment uses `kels-mock-hsm` (`libkels_mock_hsm.so`), a PKCS#11 cdylib implementing ML-DSA-65 via fips204. In production, swap the `PKCS11_LIBRARY` env var to a real HSM's PKCS#11 .so (CloudHSM, Luna, etc.).

**Key label convention:** `kels-gossip-{node_id}` (e.g., `kels-gossip-node-a`)

### PeerPrefix Derivation

The PeerPrefix is cryptographically derived from the node's identity KEL:

1. The identity service manages the node's KEL (backed by HSM ML-DSA-65 keys)
2. The PeerPrefix is the prefix of the node's identity KEL (44-char CESR-encoded Blake3 hash)
3. PeerPrefix is stable across restarts — the identity does not change even if keys rotate

### Peer Allowlist

Authorized peers are stored in PostgreSQL using verifiable-storage patterns:

```rust
struct Peer {
    said: String,             // Content hash (CESR Blake3)
    prefix: String,           // Stable lineage ID
    previous: Option<String>, // SAID of previous version
    version: u64,             // Version number
    created_at: StorageDatetime,
    peer_prefix: String,          // NodePrefix (44-char CESR)
    node_id: String,          // Human-readable name (e.g., "node-a")
    authorizing_kel: String,  // Prefix of the KEL that authorized this peer
    active: bool,             // Current authorization status
    kels_url: String,         // HTTP URL for KELS service
    gossip_addr: String,     // Gossip address (host:port)
}
```

Each peer is a versioned entity - deactivation creates a new version with `active: false` rather than deleting the record.

**Authorizing KEL:**
The `authorizing_kel` field identifies which registry's KEL contains the cryptographic anchor for this peer record. When verifying a peer, the gossip node fetches the KEL for the `authorizing_kel` prefix and checks that the peer's SAID is anchored in it. This allows federated registries to authorize peers independently while maintaining cryptographic proof of authorization.

For more details on federation, see [Multi-Registry Federation](./federation.md).

## Signed Request Format

Mutating registry operations require signed requests:

```rust
struct SignedRequest<T> {
    payload: T,           // The actual request data
    peer_prefix: String,  // CESR qb64 PeerPrefix of signer (44-char CESR-encoded Blake3 hash)
    signature: String,    // CESR qb64 encoded signature
}
```

**Signature computation:**
1. Serialize payload to JSON (with `preserve_order` for determinism)
2. Sign the JSON bytes with the node's signing key (ML-DSA-65 for infrastructure)
3. Encode signature as CESR qb64

## Verification Flow

When a service receives a signed request:

1. **Parse signature components** from SignedRequest
2. **Look up peer** by `peer_prefix` in the database, fetch their KEL, and extract the current public key
3. **Verify signature** over payload JSON against the public key from the peer's KEL
4. **Check allowlist** - query PostgreSQL for latest version of peer, verify `active: true`
5. **Process request** if all checks pass

```
┌──────────────────┐
│ Signed Request   │
│ - payload        │
│ - peer_prefix    │
│ - signature      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Look up peer by  │────>│ 401 Unauthorized│
│ peer_prefix,     │ NO  │ (unknown peer)  │
│ fetch KEL,       │     └─────────────────┘
│ extract pubkey   │
└────────┬─────────┘
         │ YES
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Verify signature │────>│ 401 Unauthorized│
│ against KEL key  │ NO  │ (invalid sig)   │
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

kels-gossip signs requests using `IdentitySigner`:

1. **Create signer** on startup with identity service URL and peer_prefix
2. **Sign requests** by calling the identity service sign endpoint (returns signature)
3. **Wrap payload** in SignedRequest with signature and peer_prefix

```rust
// In kels-gossip startup
let registry_signer = IdentitySigner::new(identity_url, &peer_prefix);

// Sign a request payload and submit it
let signed = sign_request(&registry_signer, &payload).await?;
```

The public key is not included in the request. During verification, the service looks up the peer by `peer_prefix`, fetches their KEL, and extracts the public key to verify the signature.

## Allowlist Management

### Admin CLI

The `kels-registry-admin` CLI manages the peer allowlist:

```bash
# Add a peer to allowlist
kels-registry-admin peer add --peer-id 12D3KooWAbc... --node-id node-a \
  --kels-url http://kels.kels-node-a.kels \
  --gossip-addr kels-gossip.kels-node-a.kels:4001

# Remove a peer (creates deactivated version)
kels-registry-admin peer remove --peer-id 12D3KooWAbc...

# List all authorized peers
kels-registry-admin peer list
```

See [Multi-Registry Federation](./federation.md) for details on the multi-party approval process.

### Getting a Node's PeerPrefix

Before a node can be added to the allowlist, you need its PeerPrefix. Options:

1. **From logs:** Deploy the node, check kels-gossip logs for "Local PeerPrefix: ..."
2. **From HSM:** Query HSM public key and derive PeerPrefix programmatically

```bash
# Check kels-gossip logs
kubectl logs -n kels-node-a deploy/kels-gossip | grep PeerPrefix
# Output: Local PeerPrefix: 12D3KooWXyz...
```

## Node Onboarding Workflow

### Phase 1: Deploy Node (Unauthorized)

1. Deploy new node namespace with identity service (loads PKCS#11 HSM)
2. Deploy kels-gossip - it generates/loads HSM key and logs PeerPrefix
3. Node attempts to connect to gossip peers - **rejected** (not in allowlist)
4. Node can still fetch KELS data via HTTP (read-only, no auth required)

### Phase 2: Authorize Node

1. Get PeerPrefix from node logs
2. Add peer via admin CLI:
   ```bash
   kubectl exec -n kels-registry deploy/kels-registry -- \
     kels-registry-admin peer add --peer-id 12D3KooWXyz... --node-id node-x
   ```

### Phase 3: Node Becomes Operational

1. Other nodes refresh their allowlist and accept connections from the new peer
2. Node connects to gossip peers
3. Node is fully operational

## Gossip Connection Filtering

In addition to registry authentication, the gossip layer verifies connections during the handshake:

1. Exchange 44-byte prefixes
2. ML-KEM-768 key exchange — initiator generates keypair and sends encapsulation key (qb64), acceptor encapsulates and sends ciphertext back (qb64), both derive shared secret
3. Mutual ML-DSA-65 signature exchange — each side signs JSON payload `{our_ek, their_ek, their_prefix}`
4. `KelsPeerVerifier` checks the peer's NodePrefix against the verified allowlist
5. `KelsPeerVerifier` verifies the handshake signature against the peer's KEL public key
6. ML-DSA-65 only enforcement — P-256 peers are rejected
7. Session keys derived from shared secret via BLAKE3 KDF with context `"kels/gossip/v2/keys/..."`
8. Unknown peers trigger a one-shot allowlist refresh before rejection
9. Key mismatches (due to rotation) trigger a KEL re-fetch from the peer before rejection

Nodes periodically refresh their allowlist from the registry's `/api/peers` endpoint (default: every 60 seconds).

## Security Considerations

### Key Protection

- HSM keys never leave the PKCS#11 module
- Private key operations happen inside the HSM (mock HSM in development, real HSM in production)
- Each node has isolated HSM with separate persistent volume

### Identity Binding

- PeerPrefix is the prefix of the node's identity KEL (44-char CESR-encoded Blake3 hash)
- PeerPrefix is stable across restarts and key rotations
- The public key used for verification is extracted from the peer's KEL, not sent with requests

### Defense in Depth

1. **Registry layer:** Signature verification + allowlist check
2. **Gossip layer:** Connection filtering during ML-KEM-768 + ML-DSA-65 handshake
3. **Admin access:** CLI requires kubectl exec (same trust as cluster admin)

### Signature Algorithm

- **Key type (infrastructure):** ML-DSA-65 (FIPS 204, 192-bit post-quantum security)
- **Signature:** ML-DSA-65
- **Encoding:** CESR qb64 for public keys and signatures
- **Payload:** Canonical JSON serialization (`preserve_order` feature)

Note: The KELS core service accepts both P-256 (ECDSA) and ML-DSA-65 KELs, supporting mobile clients that may still use P-256.

### Read vs Write Security

| Operation | Authentication |
|-----------|---------------|
| Read KELS data | None (public) |
| Read peer list | None (public) |
| Prefix listing | Signed + allowlist |
| Gossip connection | Verified allowlist + KEL signature check during handshake |

## Deployment

### Registry Namespace

```
kels-registry/
├── identity (manages registry's KELS identity, 1 replica; loads PKCS#11 .so for HSM)
├── postgres (peer allowlist + identity KEL)
├── redis
└── kels-registry
```

### Node Namespace

```
kels-node-x/
├── identity (manages node's KELS identity; loads PKCS#11 .so for HSM)
├── postgres (kels + kels_gossip DBs)
├── redis (KEL cache + pubsub)
├── kels
└── kels-gossip
```

## Troubleshooting

### Node Cannot Connect

1. Check if peer is in allowlist:
   ```bash
   kubectl exec -n kels-registry deploy/kels-registry -- kels-registry-admin peer list
   ```

2. Verify PeerPrefix matches:
   ```bash
   # Get PeerPrefix from node logs
   kubectl logs -n kels-node-x deploy/kels-gossip | grep PeerPrefix
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
- Check allowlist refresh logs for disconnection events
