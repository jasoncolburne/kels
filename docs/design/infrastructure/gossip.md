# KELS Gossip Protocol

## Overview

The gossip service (`services/gossip`) synchronizes KELs between independent KELS deployments using a custom gossip protocol (HyParView membership + PlumTree epidemic broadcast over TCP with ML-KEM-1024 key exchange + ML-DSA-65/87 mutual authentication + AES-GCM-256 authenticated encryption). All gossip connections use ML-KEM-1024 regardless of peer signing algorithm — peers using ML-DSA-65 get stronger transport security than their signing keys require, while ML-DSA-87 peers get matched security. Nodes announce KEL updates as `prefix:said` pairs via PlumTree broadcast — events themselves are not transmitted over the gossip layer. When a node receives an announcement with an unfamiliar SAID, it fetches the missing events via HTTP — first from the origin peer, then falling back to other federation-authorized peers.

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
│     │      │ HTTP POST (submit events)      │  gossip   ││
│     │      └────────────────────────────────│ (service) ││
│     │      * HTTP GET omitted for clarity   └─────┬─────┘│
│     │                                             │      │
└─────│─────────────────────────────────────────────│──────┘
      │                                             │
      │          PlumTree broadcast: prefix:said    │
      │                                             │
┌─────│─────────────────────────────────────────────│──────┐
│     │                                       ┌─────┴─────┐│
│     └───────────────────────────────────────│  gossip   ││
│  HTTP GET (fetch events from remote KELS)   │ (service) ││
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
2. KELS writes to DB, then publishes `{prefix}:{effective_said}` to Redis `kel_updates` channel, where `effective_said` is the prefix's effective SAID (tip event SAID for non-divergent KELs, synthetic hash for divergent/contested KELs). This ensures the gossip feedback loop cache key matches regardless of KEL state.
3. The gossip service receives notification via Redis SUBSCRIBE
4. Broadcasts `KelAnnouncement { prefix, said }` via PlumTree to all peers

### Inbound (gossip network → local)

1. The gossip service receives `KelAnnouncement` via PlumTree broadcast
2. Compares announced SAID with local latest SAID for that prefix
3. Checks if announced SAID already exists locally (we may be ahead of the announcer)
4. If SAID is new:
   - **Delta fetch** (`fetch_kel_since`): requests only events after local state
   - **Audit fetch** (on `NotFound`): local SAID was purged by recovery — fetches with audit to get archived adversary events + clean chain, submits in recovery-aware stages
   - **Full fetch** (fallback): fetches entire KEL when delta fails for other reasons, or when prefix is unknown locally
   - **Event partitioning**: when events contain multiple divergent branches, adversary events are submitted first, then recovery events, so merge() can properly detect and resolve divergence. Non-archiving privileged events (`Ror`, `Dec`) that trigger contested-transition are placed in the second batch because they require the divergent set to already be established — the first batch must include the non-privileged fork event so the second batch's privileged event joins via the upgrade rule (or, on a linear chain, lands as a sibling of the existing tip via the divergence-ancestor-extending shape). When fork siblings share the same `previous` and no recovery branch is identifiable, they are submitted as a single batch and `extend()` sorts them by `(serial, kind_priority, said)` to ensure correct ordering.
5. KELS verifies signatures, merges into local KEL (handles divergence/recovery)

### Why SAID comparison?

- Simple equality check - if SAIDs match, nodes are in sync
- Divergent events at the same generation have different SAIDs
- No timestamp or generation tracking needed
- Works correctly with divergence detection

## Components

### Service Structure

```
services/gossip/
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
    ├── protocol.rs     # Message types (KelAnnouncement, SadAnnouncement)
    ├── authorization.rs # Handshake authorization against the federation IEL `authPolicy`
    ├── bootstrap.rs    # Bootstrap sync from existing peers
    └── hsm_signer.rs   # HSM-backed request signing and peer verification
```

### Topics

Gossip pubsub topics, one per subsystem:

| Topic | Carries |
|-------|---------|
| `kels/gossip/v1/topics/kel` | KEL chain announcements |
| `kels/gossip/v1/topics/iel` | IEL chain event announcements |
| `kels/gossip/v1/topics/sel` | SEL chain event announcements |
| `kels/gossip/v1/topics/sad` | SAD object announcements |
| `kels/gossip/v1/topics/mail` | Mail envelope announcements |

### Message Types

```rust
/// Broadcast via PlumTree to announce KEL updates (on `kels/gossip/v1/topics/kel`)
struct KelAnnouncement {
    prefix: String,
    said: String,
    origin: String,  // NodePrefix of the originating peer
}
```

### SADStore Replication

SAD object and SEL chain announcement types, the Redis channels that drive them (`sad_updates`, `sel_updates`), and the gossip policy that decides what gets broadcast are defined in [sadstore.md §Gossip Replication](sadstore.md#gossip-replication). The gossip service consumes those Redis channels and broadcasts on the `kels/gossip/v1/topics/sad` and `kels/gossip/v1/topics/sel` topics listed above.

### Protocols

| Protocol | Transport | Purpose |
|----------|-----------|---------|
| PlumTree broadcast | TCP + ML-KEM-1024 + ML-DSA-65/87 + AES-GCM-256 | Epidemic broadcast of announcements to all peers |
| HyParView membership | TCP + ML-KEM-1024 + ML-DSA-65/87 + AES-GCM-256 | Mesh overlay maintenance (join, shuffle, forward-join) |
| HTTP fetch | HTTP | Fetch KEL events from peer's KELS service |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ID` | Unique node identifier | `node-unknown` |
| `BASE_DOMAIN` | Base domain for service URL derivation | (derives KELS + SADStore URLs) |
| `KELS_URL` | Local KELS HTTP endpoint (override) | `http://kels` |
| `KELS_ADVERTISE_URL` | Advertised KELS URL for clients | (required) |
| `REDIS_URL` | Redis for pub/sub | `redis://redis:6379` |
| `PKCS11_LIBRARY_PATH` | Path to PKCS#11 .so (mock HSM or real HSM) | (required) |
| `KELS_HSM_DATA_DIR` | HSM key persistence directory | (required) |
| `HSM_SLOT` | PKCS#11 slot number | (required) |
| `HSM_PIN` | PKCS#11 PIN | (required) |
| `IDENTITY_URL` | Identity service URL | `http://identity` |
| `FEDERATION_IEL_PREFIX` | Runtime override of the compile-time federation IEL prefix (see [federation.md §Configuration](federation.md#configuration)) | (optional) |
| `GOSSIP_LISTEN_ADDR` | TCP listen address (host:port) | `0.0.0.0:4001` |
| `GOSSIP_ADVERTISE_ADDR` | Advertised address for peer connections | same as listen |
| `HTTP_LISTEN_HOST` | HTTP server listen host | `0.0.0.0` |
| `HTTP_LISTEN_PORT` | HTTP server listen port | `80` |
| `ANTI_ENTROPY_INTERVAL_SECS` | Anti-entropy repair loop interval | `10` |
| `AUTH_POLICY_REFRESH_INTERVAL_SECS` | Background interval to re-check the federation IEL `authPolicy` (defense against missed gossip-driven invalidations) | `60` |

## Design Decisions

### Separate deployment (not sidecar)

- Independent scaling - can run different replica counts
- Independent lifecycle - update gossip without restarting KELS
- Easier debugging and monitoring
- Communicates with KELS via HTTP (no direct DB access)

### HSM-backed gossip identity

Gossip identity, accepted algorithms, key custody, and the handshake authorization check against the federation IEL are documented in [peer-identity.md](peer-identity.md). This subsection covers the **transport-layer handshake mechanics** that establish the encrypted session once authorization has succeeded.

Development deployments load `kels-mock-hsm` (a PKCS#11 cdylib backed by fips204) — do not use it in production; swap `PKCS11_LIBRARY_PATH` to a real HSM's PKCS#11 .so (CloudHSM, Luna, etc.).

The handshake uses ML-KEM-1024 key exchange + ML-DSA-65/87 signature authentication:

1. Exchange 44-byte prefixes
2. Initiator generates ML-KEM-1024 keypair, sends encapsulation key (qb64)
3. Acceptor encapsulates, sends ciphertext back (qb64)
4. Both derive 32-byte shared secret
5. Each side signs JSON payload `{our_ek, their_ek, their_prefix}` with ML-DSA-65/87
6. Exchange and verify signatures against peer's KEL public key
7. Derive AES-GCM-256 session keys from shared secret via BLAKE3 KDF with context `"kels/gossip/v1/keys/..."`

Security properties: forward secrecy (ephemeral ML-KEM), mutual authentication (ML-DSA signatures), post-quantum security.

### Delta-based sync with full-fetch fallback

- **Delta fetch** (`?since=<said>`) is the primary sync mechanism — only fetches events newer than local state
- Uses the `serial` field on `KeyEvent` for efficient DB-ordered queries (`ORDER BY serial ASC`)
- Falls back to **full KEL fetch** when delta is unavailable (e.g., new prefix, network error)
- **Recovery-aware audit fetch**: when a delta fetch fails with `NotFound` (local SAID was purged by recovery on the remote), fetches the KEL and audit records separately (`/api/v1/kels/kel/:prefix` + `/api/v1/kels/kel/:prefix/audit`) to retrieve both the clean chain and archived adversary events
- Archived adversary events are submitted first (establishes the adversary branch), then the clean chain is split before the event preceding the first recovery-revealing event and submitted in stages so merge() processes recovery correctly. The owner's event at the divergence serial is bundled with the recovery event — this ensures nodes that have only adversary events at that serial (no owner event) can insert the owner event as part of recovery processing (the submit handler's divergent recovery branch handles this via look-ahead for `rec` in the batch)
- KELS handles duplicate events idempotently

### Federation-IEL-based discovery (not hardcoded bootstrap peers)

- Nodes hold the federation IEL locally and enumerate authorized peers from its current `authPolicy`
- Each peer publishes its current network endpoints via a per-peer address SEL; nodes walk those SELs to resolve addresses
- Initial state on a fresh node arrives via `transfer_*_events` (operator-coordinated, point-to-point) during the federation bootstrap ceremony or peer-onboarding; after that, the node participates in the gossip mesh and propagation runs normally
- Peers discover each other dynamically via the gossip mesh (HyParView membership protocol)
- See [discovery.md](discovery.md) for the full node-side discovery flow and [federation.md](federation.md) for the federation-as-identity model

## Transport reachability

The gossip protocol is TCP-based. Each peer publishes its advertised gossip endpoint (`host:port`) in its per-peer address SEL (see [discovery.md](discovery.md)). Other peers connect to that endpoint to gossip.

Production deployments must ensure each peer's advertised endpoint is reachable from every other peer in the federation — by whatever mechanism the deployment provides (public IPs, mesh routing, NAT traversal, LoadBalancer / NodePort / Gateway API TCPRoute in Kubernetes, etc.). The endpoint published in the address SEL must be the externally-routable one, not a local-only address; the gossip service surfaces this via `GOSSIP_ADVERTISE_ADDR`.

The in-repo Kubernetes test harness (see [`../../validation/k8s-test-harness.md`](../../validation/k8s-test-harness.md)) configures cross-namespace TCP via ClusterIP services and CoreDNS rewrites inside a single cluster. That is a test setup, not a production deployment recipe.

## Anti-Entropy Repair

Gossip propagation can miss events due to timing gaps (e.g., between bootstrap preload and gossip join, DNS issues, connection failures). The anti-entropy loop detects and repairs silent divergence — where a node is missing events it never learned about. It also handles failed gossip fetches: when a fetch fails, the prefix is recorded as stale and picked up by Phase 1 within the next cycle.

### Two-phase repair (every `ANTI_ENTROPY_INTERVAL_SECS`, default 10s)

**Phase 1 — Targeted repair of known-stale prefixes:**
- Drains a Redis hash (`kels:anti_entropy:stale`) of `kel_prefix → sourceNodePrefix` entries
- For each entry, fetches the KEL from the source peer and submits locally
- Failures are re-queued for the next cycle (batch fetch failures and individual submit failures both re-record the stale entry)

**Phase 2 — Random sampling (runs every cycle):**
- Picks a random cursor and fetches one page of prefixes from both local KELS and a random peer
- Compares effective SAIDs — for non-divergent KELs this is the tip event's SAID; for divergent KELs it's `hash("divergent:{prefix}")`; for contested KELs it's `hash("contested:{prefix}")`
- If digests match, done for this cycle
- If different, reconciles: fetches missing/different KELs in both directions
- Divergent and contested KELs use deterministic effective SAIDs (`hash("divergent:{prefix}")` and `hash("contested:{prefix}")`), so nodes with different fork events or archival states report the same SAID. Anti-entropy sees matching SAIDs and skips the prefix, avoiding wasted sync attempts that would just return `RecoverRequired`

Stale prefix entries are populated by bootstrap sync failures, gossip fetch failures, and anti-entropy mismatches.

## Divergence Handling

When a KEL becomes divergent:

1. Both divergent branches propagate via gossip
2. Receiving node's KELS detects divergence during `merge()`
3. KEL is in non-privileged-divergent state pending recovery; if a non-archiving privileged event (`Ror`/`Dec`) joins the divergent set, the chain transitions to Contested via privileged-divergence-is-terminal
4. Recovery (`Rec`) propagates via gossip and resolves non-privileged divergence by archiving the other branch via the discriminator

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
