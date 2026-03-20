# KELS Gossip Protocol

## Overview

The `kels-gossip` service synchronizes KELs between independent KELS deployments using a custom gossip protocol (HyParView membership + PlumTree epidemic broadcast over TCP with ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication + AES-GCM-256 authenticated encryption). The KEM algorithm is auto-negotiated: if any peer in the federation uses ML-DSA-87, all connections use ML-KEM-1024; otherwise ML-KEM-768. Nodes announce KEL updates as `prefix:said` pairs via PlumTree broadcast — events themselves are not transmitted over the gossip layer. When a node receives an announcement with an unfamiliar SAID, it fetches the missing events via HTTP — first from the origin peer, then falling back to other peers in the allowlist.

## Architecture

```
                    KELS Namespace A
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   ┌──────────┐   publish    ┌───────┐   subscribe        │
│   │   KELS   │ ──────────▶  │ Redis │  ◀────────────┐    │
│   │  (HTTP)  │  prefix:said │pub/sub│               │    │
│   └──────────┘              └───────┘               │    │
│     ▲      ▲                                ┌───────┴───┐│
│     │      │ HTTP POST (submit events)      │kels-gossip││
│     │      └────────────────────────────────│ (gossip)  ││
│     │      * HTTP GET omitted for clarity   └─────┬─────┘│
│     │                                             │      │
└─────│─────────────────────────────────────────────│──────┘
      │                                             │
      │          PlumTree broadcast: prefix:said    │
      │                                             │
┌─────│─────────────────────────────────────────────│──────┐
│     │                                       ┌─────┴─────┐│
│     └───────────────────────────────────────│kels-gossip││
│  HTTP GET (fetch events from remote KELS)   │ (gossip)  ││
│        ┌────────────────────────────────────│           ││
│        │ HTTP POST (submit events)          └───────┬───┘│
│        ▼                                            │    │
│   ┌──────────┐              ┌───────┐               │    │
│   │   KELS   │ ──────────▶  │ Redis │  ◀────────────┘    │
│   │  (HTTP)  │  prefix:said │pub/sub│   subscribe        │
│   └──────────┘              └───────┘                    │
│                                                          │
└──────────────────────────────────────────────────────────┘
                     KELS Namespace B
```

## Data Flow

### Outbound (local event → gossip network)

1. Client submits events to KELS via HTTP
2. KELS writes to DB, then explicitly publishes `{prefix}:{said}` to Redis `kel_updates` channel, where `said` is the last **submitted** event's SAID (not the sorted KEL's last event — this distinction matters for same-kind forks where the sorted tail may be an event other nodes already have)
3. `kels-gossip` receives notification via Redis SUBSCRIBE
4. Broadcasts `KelAnnouncement { prefix, said }` via PlumTree to all peers

### Inbound (gossip network → local)

1. `kels-gossip` receives `KelAnnouncement` via PlumTree broadcast
2. Compares announced SAID with local latest SAID for that prefix
3. Checks if announced SAID already exists locally (we may be ahead of the announcer)
4. If SAID is new:
   - **Delta fetch** (`fetch_kel_since`): requests only events after local state
   - **Audit fetch** (on `EventNotFound`): local SAID was purged by recovery — fetches with audit to get archived adversary events + clean chain, submits in recovery-aware stages
   - **Full fetch** (fallback): fetches entire KEL when delta fails for other reasons, or when prefix is unknown locally
   - **Event partitioning**: when events contain multiple divergent branches, adversary events are submitted first, then recovery events, so merge() can properly detect and resolve divergence. Contest events (`cnt`) are always placed in the second (recovery) batch because they require divergence to already be established — the first batch must include the non-contest fork event to create the divergence that contest resolves. When fork siblings share the same `previous` and no recovery branch is identifiable, they are submitted as a single batch and `extend()` sorts them by `(serial, kind_priority, said)` to ensure correct ordering.
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
    ├── gossip_layer.rs # Custom gossip protocol wrapper (HyParView + PlumTree)
    ├── server.rs       # HTTP server for ready endpoint
    ├── sync.rs         # Redis subscriber, sync handler, anti-entropy loop
    ├── protocol.rs     # Message types (KelAnnouncement)
    ├── allowlist.rs    # Connection filtering based on verified peer allowlist
    ├── bootstrap.rs    # Bootstrap sync from existing peers
    └── hsm_signer.rs   # HSM-backed request signing and peer verification
```

### Message Types

```rust
/// Broadcast via PlumTree to announce KEL updates
struct KelAnnouncement {
    prefix: String,
    said: String,
    origin: String,  // NodePrefix of the originating peer
}
```

### Protocols

| Protocol | Transport | Purpose |
|----------|-----------|---------|
| PlumTree broadcast | TCP + ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 | Epidemic broadcast of announcements to all peers |
| HyParView membership | TCP + ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 | Mesh overlay maintenance (join, shuffle, forward-join) |
| HTTP fetch | HTTP | Fetch KEL events from peer's KELS service |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ID` | Unique node identifier | `node-unknown` |
| `KELS_URL` | Local KELS HTTP endpoint | `http://kels` |
| `KELS_ADVERTISE_URL` | Advertised KELS URL for clients | (required) |
| `REDIS_URL` | Redis for pub/sub | `redis://redis:6379` |
| `PKCS11_LIBRARY` | Path to PKCS#11 .so (mock HSM or real HSM) | (required) |
| `KELS_HSM_DATA_DIR` | HSM key persistence directory | (required) |
| `HSM_SLOT` | PKCS#11 slot number | (required) |
| `HSM_PIN` | PKCS#11 PIN | (required) |
| `IDENTITY_URL` | Identity service URL | `http://identity` |
| `FEDERATION_REGISTRY_URLS` | Comma-separated registry URLs for peer discovery and HA | (required) |
| `GOSSIP_LISTEN_ADDR` | TCP listen address (host:port) | `0.0.0.0:4001` |
| `GOSSIP_ADVERTISE_ADDR` | Advertised address for peer connections | same as listen |
| `GOSSIP_TOPIC` | Gossip topic name | `kels/events/v1` |
| `HTTP_LISTEN_HOST` | HTTP server listen host | `0.0.0.0` |
| `HTTP_LISTEN_PORT` | HTTP server listen port | `80` |
| `ANTI_ENTROPY_INTERVAL_SECS` | Anti-entropy repair loop interval | `10` |
| `ALLOWLIST_REFRESH_INTERVAL_SECS` | Allowlist refresh interval | `60` |

## Design Decisions

### Separate deployment (not sidecar)

- Independent scaling - can run different replica counts
- Independent lifecycle - update gossip without restarting KELS
- Easier debugging and monitoring
- Communicates with KELS via HTTP (no direct DB access)

### HSM-backed gossip identity

Gossip nodes use persistent HSM-backed identities:
- Each node's identity is cryptographically bound to ML-DSA-65 or ML-DSA-87 keys in the HSM — the identity does not change across restarts
- The NodePrefix (44-char CESR-encoded) identifies the node in the gossip mesh and verified allowlist
- Nodes must be added to the peer allowlist before they can connect to the gossip mesh
- Unauthorized peers are rejected during the gossip handshake
- Only ML-DSA-65/87 peers are accepted (P-256 peers are rejected)
- The handshake uses ML-KEM-768/1024 (auto-negotiated) key exchange + ML-DSA-65/87 signature authentication:
  1. Exchange 44-byte prefixes
  2. Initiator generates ML-KEM-768/1024 keypair, sends encapsulation key (qb64)
  3. Acceptor encapsulates, sends ciphertext back (qb64)
  4. Both derive 32-byte shared secret
  5. Each side signs JSON payload `{our_ek, their_ek, their_prefix}` with ML-DSA-65/87
  6. Exchange and verify signatures against peer's KEL public key
  7. Derive AES-GCM-256 session keys from shared secret via BLAKE3 KDF with context `"kels/gossip/v1/keys/..."`
- Security properties: forward secrecy (ephemeral ML-KEM), mutual authentication (ML-DSA signatures), post-quantum security
- See [Secure Registration](design/secure-registration.md) for details on the peer allowlist

### Delta-based sync with full-fetch fallback

- **Delta fetch** (`?since=<said>`) is the primary sync mechanism — only fetches events newer than local state
- Uses the `serial` field on `KeyEvent` for efficient DB-ordered queries (`ORDER BY serial ASC`)
- Falls back to **full KEL fetch** when delta is unavailable (e.g., new prefix, network error)
- **Recovery-aware audit fetch**: when a delta fetch fails with `EventNotFound` (local SAID was purged by recovery on the remote), fetches the KEL and audit records separately (`/api/kels/kel/:prefix` + `/api/kels/kel/:prefix/audit`) to retrieve both the clean chain and archived adversary events
- Archived adversary events are submitted first (establishes the adversary branch), then the clean chain is split before the event preceding the first recovery-revealing event and submitted in stages so merge() processes recovery correctly. The owner's event at the divergence serial is bundled with the recovery event — this ensures nodes that have only adversary events at that serial (no owner event) can insert the owner event as part of recovery processing (the submit handler's divergent recovery branch handles this via look-ahead for `rec` in the batch)
- KELS handles duplicate events idempotently

### Registry-based discovery (not hardcoded bootstrap peers)

- Nodes register with the `kels-registry` service on startup
- New nodes query the registry for existing peers and bootstrap sync
- Peers discover each other dynamically via the gossip mesh (HyParView membership protocol)
- No hardcoded peer addresses needed in configuration
- See [registry.md](registry.md) for details on the registration protocol

## Kubernetes Deployment

### Cross-namespace communication

Gossip nodes in different namespaces connect via the registry service. The registry runs in its own namespace and nodes register with it on startup.

### Services

Each namespace has:
- `kels-gossip` - ClusterIP service for gossip TCP connections

**Cross-cluster note:** The test harness colocates all nodes in one Kubernetes cluster with cross-namespace routing via CoreDNS rewrites. In a production deployment where nodes are in separate clusters or networks, each node's gossip TCP port must be externally reachable — e.g., via a LoadBalancer service, NodePort, or Gateway API TCPRoute. The gossip advertise address (`GOSSIP_ADVERTISE_ADDR`) should be set to the externally routable hostname and port.

### CoreDNS Configuration for `.kels` Domains

Nodes advertise URLs using `.kels` domains (e.g., `http://kels.kels-node-a.kels`) so that the same URLs work for both:
- **External clients** (iOS, CLI) - resolved via `/etc/hosts` or local DNS
- **Internal services** - resolved via CoreDNS inside the cluster

To enable internal resolution, CoreDNS must be configured with rewrite rules:

```bash
scripts/coredns.sh apply
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

## Anti-Entropy Repair

Gossip propagation can miss events due to timing gaps (e.g., between bootstrap preload and gossip join, DNS issues, connection failures). The anti-entropy loop detects and repairs silent divergence — where a node is missing events it never learned about. It also handles failed gossip fetches: when a fetch fails, the prefix is recorded as stale and picked up by Phase 1 within the next cycle.

### Two-phase repair (every `ANTI_ENTROPY_INTERVAL_SECS`, default 10s)

**Phase 1 — Targeted repair of known-stale prefixes:**
- Drains a Redis hash (`kels:anti_entropy:stale`) of `kel_prefix → source_node_prefix` entries
- For each entry, fetches the KEL from the source peer and submits locally
- Failures are re-queued for the next cycle (batch fetch failures and individual submit failures both re-record the stale entry)

**Phase 2 — Random sampling (runs every cycle):**
- Picks a random cursor and fetches one page of prefixes from both local KELS and a random peer
- Compares effective SAIDs — for non-divergent KELs this is the tip event's SAID; for divergent KELs this is a deterministic Blake3 hash of sorted tip SAIDs
- If digests match, done for this cycle
- If different, reconciles: fetches missing/different KELs in both directions
- Previously-seen remote effective SAIDs are skipped via per-prefix Redis SETs (`kels:anti_entropy:seen_saids:<prefix>`) — when a sync attempt fails (e.g., three-way divergence where nodes hold different adversary branch pairs), the remote's effective SAID is recorded so the same mismatch isn't retried. A new effective SAID (e.g., after recovery) will be retried and, on success, clears the seen set. The number of tracked prefixes is bounded by a sorted set with FIFO eviction

Stale prefix entries are populated by bootstrap sync failures, gossip fetch failures, and anti-entropy mismatches.

## Divergence Handling

When a KEL becomes divergent:

1. Both divergent branches propagate via gossip
2. Receiving node's KELS detects divergence during `merge()`
3. KEL enters frozen state until recovery or contest
4. Recovery events also propagate and resolve divergence

The gossip layer doesn't need special divergence logic - KELS handles all verification and merge semantics.

## Testing

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
- Triple adversary injection (3 adversary events on 3 nodes) + owner recovery
- Triple simultaneous events (2 adversary + 1 owner on 3 nodes) causing mixed divergence pairs across nodes + owner recovery propagation
- Adversary attack timed with owner recovery-rotation (ror), then owner recovery

`clients/test/scripts/test-consistency.sh` verifies cross-node consistency:
- All nodes have the same set of prefixes
- All prefixes have the same event counts
- MD5 digest of each KEL matches across all nodes (signatures normalized by publicKey before hashing)
- Behavioral state consistency for any mismatched KELs

`clients/test/scripts/test-resync.sh` verifies anti-entropy stale prefix repair:
- Fake stale prefix entries are dropped when all peers return 404
- Real fetch failures (caused by broken DNS) populate the stale prefix hash
- After DNS repair, the anti-entropy loop resolves stale entries
- Stale prefix hash is empty after resolution

The test is orchestrated by `make test-resync` which breaks CoreDNS for node-b (so gossip HTTP fetches fail while gossip announcements still flow over existing TCP connections), runs the setup phase, repairs DNS, then runs the verify phase.
