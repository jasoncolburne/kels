# KELS Deployment Guide

## Overview

KELS supports two deployment modes:

- **Standalone** — a single `kels` service + PostgreSQL. No federation, no gossip, no Redis required. Suitable for development, small-scale applications, and environments where a single trusted node is sufficient. All core KEL operations work: inception, rotation, interaction, recovery, contest, decommission, and divergence handling.

- **Federated** — a network of registries and gossip nodes that replicate Key Event Logs across the network. Provides high availability, geographic distribution, and multi-party governance. The minimum viable federation requires 3 registries (for consensus quorum) and at least 1 gossip node.

The Garden configuration in this repository (`project.garden.yml` and per-service `garden.yml` files) is an example used for local testing. It can be used as a guide for understanding the deployment flow, but is not a reference for production deployments.

- `make test-node` deploys and tests a standalone node (~2 minutes)
- `make test-federation` deploys and tests a full federation (~22 minutes)

## Standalone Deployment

A standalone KELS node requires only two components:

- `kels` — KEL storage and retrieval API
- `postgres` — event and signature storage

This provides the full KEL API: event submission, paginated retrieval, divergence detection, recovery, contest, and decommission. Redis is not required — the kels service runs without caching in standalone mode. When `REDIS_URL` is not set, the service starts without Redis and the `/ready` endpoint returns `{"ready": true, "status": "standalone"}`.

Standalone mode does not include:
- Gossip replication (no `kels-gossip`)
- Federation consensus (no `kels-registry`)
- Peer authentication for the `/api/kels/prefixes` endpoint (requires Redis for peer verification)
- KEL caching (served directly from PostgreSQL on every request)

Multiple kels replicas can be deployed against the same PostgreSQL instance for horizontal scaling. Optionally, add Redis (`REDIS_URL` environment variable) to enable KEL caching and pub/sub cache invalidation across replicas for improved read performance.

## Federated Architecture

Each **registry** runs:
- `kels-registry` — federation consensus and peer management
- `identity` — the registry's own cryptographic identity (KEL + signing), loads PKCS#11 .so directly for HSM operations
- `postgres` — database for federation state, peer records, and the registry's KEL
- `redis` — node registration storage

Each **gossip node** runs:
- `kels` — KEL storage and retrieval API
- `kels-gossip` — custom gossip protocol (HyParView + PlumTree) for KEL replication
- `identity` — the node's own cryptographic identity (KEL + signing), loads PKCS#11 .so directly for HSM operations
- `postgres` — KEL storage and gossip peer cache
- `redis` — KEL caching and pub/sub invalidation

The identity service ships with `libkels_mock_hsm.so` (a PKCS#11 cdylib implementing ML-DSA-65 and ML-DSA-87 via fips204). In production, swap the `PKCS11_LIBRARY_PATH` env var to a real HSM's PKCS#11 .so (CloudHSM, Luna, etc.). A PVC is needed for `KELS_HSM_DATA_DIR` in development for key persistence (real HSMs persist natively).

## Federated Deployment Flow

The federated deployment follows a specific order because of compile-time trust anchors. `TRUSTED_REGISTRY_PREFIXES` (comma-separated prefixes) is baked into gossip nodes and CLI clients at compile time via the `federation` feature on libkels. `TRUSTED_REGISTRY_MEMBERS` (JSON) is baked into kels-registry. The kels and identity services do not require either — they can be built without knowing the registry prefixes, avoiding unnecessary recompilation during federation changes.

### Phase 1: Deploy Registries in Standalone Mode

Deploy all 3 registries without federation. Each generates its cryptographic identity on first boot.

```
deploy registry-a (standalone — no TRUSTED_REGISTRY_PREFIXES)
deploy registry-b (standalone)
deploy registry-c (standalone)
```

At this point each registry has:
- Generated an ML-DSA-65 or ML-DSA-87 keypair via the PKCS#11 HSM
- Created an inception event (KEL) establishing its identity
- A prefix derived from that inception event

### Phase 2: Collect Prefixes

Fetch each registry's prefix from its identity service. These prefixes form the trust anchor for the entire network.

```
fetch prefix from registry-a → save
fetch prefix from registry-b → save
fetch prefix from registry-c → save
```

In the test setup, these are saved to `.kels/federated-registries.json` (a JSON array with `id`, `name`, `prefix`, and `url` per registry) and extracted at build time into `TRUSTED_REGISTRY_PREFIXES` (comma-separated prefixes for gossip nodes and CLI clients) and `TRUSTED_REGISTRY_MEMBERS` (JSON with explicit `id`, `prefix`, and `active` for kels-registry Raft node IDs). The kels and identity services do not need these values and are not recompiled during this phase.

### Phase 3: Recompile and Redeploy Registries

Rebuild all binaries with the collected prefixes baked in, then redeploy the registries. On this second deployment, the registries detect federation configuration and start the Raft consensus cluster.

```
recompile kels-registry with TRUSTED_REGISTRY_MEMBERS
recompile gossip nodes with TRUSTED_REGISTRY_PREFIXES=<prefix-a>,<prefix-b>,<prefix-c>
redeploy registry-a (federation mode)
redeploy registry-b (federation mode)
redeploy registry-c (federation mode)
```

The registries now form a Raft cluster. Node 0 (the registry whose `id` is 0 in the JSON) auto-initializes the cluster after a short delay.

### Phase 4: Deploy Gossip Nodes

Deploy gossip nodes. Each node needs to be authorized in the peer allowlist before it can join the gossip network.

1. Deploy the node's infrastructure (kels, kels-gossip, identity, postgres, redis)
2. Propose the node as a peer from any registry (`kels-registry-admin peer propose-add-peer`)
3. Vote from enough registries to approve (`kels-registry-admin peer vote`)
4. Restart kels-gossip so it picks up its authorization (this should happen after 5 minutes but why wait)
5. The node bootstraps: fetches KELs from existing peers, joins the gossip mesh

### Phase 5: Verify

Run integration tests or manually verify:
- Nodes appear in peer discovery (`GET /api/peers`)
- KELs replicate across nodes via gossip
- Client discovery works (latency-sorted node selection)

## Compile-Time Trust Anchor

`TRUSTED_REGISTRY_PREFIXES` is the security foundation of the network. It's compiled into binaries that enable the `federation` feature on libkels:

- `kels-gossip` — peer allowlist verification, registry KEL verification
- Client binaries (`kels-cli`, `kels-bench`) — registry KEL verification during node discovery

Services that do **not** need `TRUSTED_REGISTRY_PREFIXES`:
- `kels` (service) — accepts any valid KEL; does not verify registry identity
- `identity` — manages its own KEL; does not verify registry identity
- `kels-registry` — uses `TRUSTED_REGISTRY_MEMBERS` (its own compile-time mechanism) instead

When `TRUSTED_REGISTRY_PREFIXES` changes (registries added or removed), only gossip nodes and client binaries need recompilation. The kels and identity services are unaffected.

## Federation Configuration

Each registry needs two categories of configuration:

**Compile-time (security — who to trust):**
- `TRUSTED_REGISTRY_PREFIXES` — comma-separated prefixes, baked into gossip nodes and client binaries (requires `federation` feature on libkels)
- `TRUSTED_REGISTRY_MEMBERS` — JSON array of `{id, prefix, active}` objects, baked into kels-registry only (explicit Raft node IDs)

**Runtime (operational — how to connect):**
- `FEDERATION_SELF_PREFIX` — this registry's own prefix
- `FEDERATION_URLS` — comma-separated `prefix=url` pairs for all federation members

If `TRUSTED_REGISTRY_MEMBERS` is empty, `FEDERATION_SELF_PREFIX` is unset, or the registry's own prefix is not in the trusted members list, the registry runs in standalone mode (no federation, no peer management). This last case enables deploying a new registry before it has been added to the trust anchor.

## Redis Authentication

Redis uses per-service ACL users with least-privilege command sets and key pattern isolation. The `default` user is disabled — unauthenticated access is rejected.

### ACL Users

| User | Keys | Channels | Commands |
|------|------|----------|----------|
| `kels` | `kels:kel:*`, `kels:verified-peer:*`, `kels:gossip:ready` (read-only) | `kel_updates` | `GET`, `SET`, `SETEX`, `DEL`, `PUBLISH`, `PING` |
| `gossip` | `kels:gossip:*`, `kels:anti_entropy:*` | `kel_updates` | `GET`, `SET`, `DEL`, `SUBSCRIBE`, `HSET`, `HGETALL`, `SADD`, `SREM`, `SISMEMBER`, `ZADD`, `ZCARD`, `ZPOPMIN`, `ZREM`, `PING` |
| `registry` | `kels-registry:*` | — | `GET`, `SET`, `DEL`, `SADD`, `SREM`, `SMEMBERS`, `MULTI`, `EXEC`, `PING` |

### Connection URLs

Each service connects with its own credentials via the Redis URL format `redis://user:password@host:port`. Passwords are configured in `project.garden.yml` under `var.redis.*Password`. Password hashes (SHA-256) are configured under `var.redis.*PasswordHash` and used in the Redis ACL configuration.

### Eviction Policy

The eviction policy is `volatile-lru`, which only evicts keys that have a TTL set. Cache keys (`kels:kel:*`, `kels:verified-peer:*`) have 1-hour TTLs and are reconstructable from the database on miss. Operational keys (gossip state, anti-entropy tracking, node registrations) have no TTL and are never evicted.

### Persistence

RDB snapshots are enabled (`save 300 1`, `save 60 100`) and stored on a PersistentVolumeClaim. This protects operational state across Redis restarts. At most a few minutes of data loss on crash — acceptable since anti-entropy will rediscover stale prefixes and nodes re-register on startup.

## Node Configuration

### Identity Service (`identity`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection URL |
| `PKCS11_LIBRARY_PATH` | Path to PKCS#11 .so (mock HSM or real HSM) |
| `KELS_HSM_DATA_DIR` | HSM key persistence directory |
| `HSM_SLOT` | PKCS#11 slot number |
| `HSM_PIN` | PKCS#11 PIN |
| `KEY_HANDLE_PREFIX` | HSM key handle prefix (`kels-registry` or `kels-gossip`) |
| `KEL_FORWARD_URL` | URL of colocated service to forward KEL events to |
| `KEL_FORWARD_PATH_PREFIX` | Path prefix for forwarding (`/api/member-kels` for registry, `/api/kels` for nodes) |
| `NEXT_SIGNING_ALGORITHM` | Algorithm for next signing key on rotation (`ml-dsa-65` or `ml-dsa-87`, default: `ml-dsa-65`) |
| `NEXT_RECOVERY_ALGORITHM` | Algorithm for next recovery key on rotation (`ml-dsa-65` or `ml-dsa-87`, default: `ml-dsa-87`) |
| `IDENTITY_ROTATION_INTERVAL_DAYS` | Auto-rotation interval in days (default: `180`) |
| `IDENTITY_ROTATION_CHECK_PERIOD_MINUTES` | How often to check if rotation is due, in minutes (default: `360`) |
| `RUST_LOG` | Logging level |

### KELS Service (`kels`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection URL |
| `FEDERATION_REGISTRY_URLS` | Registry URLs (comma-separated) |
| `REDIS_URL` | Redis for KEL caching and pub/sub invalidation |
| `KELS_MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE` | Per-prefix submission rate limit (default: `128`) |
| `KELS_MAX_WRITES_PER_IP_PER_SECOND` | Per-IP write rate limit (default: `200`) |
| `KELS_IP_RATE_LIMIT_BURST` | Per-IP burst allowance (default: `1000`) |
| `KELS_NONCE_WINDOW_SECS` | Nonce deduplication window in seconds; `0` disables (default: `60`) |
| `KELS_PAGE_SIZE` | Page size for KEL queries and responses (default: `32`) |
| `KELS_MAX_VERIFICATION_PAGES` | Max pages walked during verification (default: `64`) |
| `KELS_TEST_ENDPOINTS` | **NEVER set in production.** Enables unauthenticated test endpoints at `/api/test/*` that bypass timestamp validation, nonce deduplication, peer allowlist, and signature verification. A startup warning is logged when enabled. (default: `false`) |
| `RUST_LOG` | Logging level |

### Gossip Service (`kels-gossip`)

| Variable | Description |
|----------|-------------|
| `NODE_ID` | Unique node identifier |
| `KELS_URL` | Local KELS service URL |
| `KELS_ADVERTISE_URL` | URL clients use to reach this node's KELS service |
| `FEDERATION_REGISTRY_URLS` | All registry URLs (comma-separated, for peer discovery) |
| `GOSSIP_LISTEN_ADDR` | TCP listen address (e.g., `0.0.0.0:4001`) |
| `GOSSIP_ADVERTISE_ADDR` | Advertised gossip address for peer connections |
| `GOSSIP_TOPIC` | Gossip topic name |
| `HTTP_PORT` | HTTP server port for ready endpoint |
| `REDIS_URL` | Redis for ready state and caching |
| `ANTI_ENTROPY_INTERVAL_SECS` | Anti-entropy repair loop interval (default: 10) |
| `ALLOWLIST_REFRESH_INTERVAL_SECS` | Allowlist refresh interval (default: 60) |
| `RUST_LOG` | Logging level |

## Peer Lifecycle

### Adding a Peer

Peers require multi-party approval (minimum 3 votes from federation members):

```bash
# From any registry:
kels-registry-admin peer propose-add-peer \
  --peer-id <peer_prefix> \
  --node-id <node_id> \
  --kels-url <kels_url> \
  --gossip-addr <host:port>

# Produces a proposal ID. Vote from each registry:
kels-registry-admin peer vote --proposal <proposal_id> --approve

# After threshold votes, the peer is added to the allowlist.
# Restart the node's kels-gossip to pick up authorization.
```

### Removing a Peer

Peer removal also requires multi-party approval:

```bash
# From any registry:
kels-registry-admin peer propose-removal --peer-id <peer_prefix>

# Vote from each registry:
kels-registry-admin peer vote --proposal <proposal_id> --approve

# After threshold votes, the peer is removed from the allowlist.
```

## Approval Threshold

The vote threshold scales with federation size:

| Members | Threshold |
|---------|-----------|
| 3-5 | 3 |
| 6-9 | 4 |
| 10+ | ceil(n/3) |

## Test Deployment Reference

The `Makefile` contains the full test deployment sequence. The key targets in order:

```bash
make clean-garden              # Tear down existing deployment
make configure-dns             # Set up k8s DNS for cross-namespace resolution
make reset-federation-json     # Clear saved prefixes
make deploy-registries         # Phase 1: standalone registries
make fetch-prefixes            # Phase 2: collect prefixes
make redeploy-registries       # Phase 3: recompile + redeploy with federation
make deploy-all-nodes          # Phase 4: deploy and authorize nodes
```

Or run everything including tests:

```bash
make test-federation
```

## Adding a Registry

To expand the federation with a new registry after initial deployment:

1. **Deploy the new registry standalone** (generates its cryptographic identity on first boot)
2. **Fetch its prefix** using `federation-fetch.sh` — the script auto-assigns the next sequential `id` in `federated-registries.json`
3. **Recompile affected binaries** — kels-registry (with updated `TRUSTED_REGISTRY_MEMBERS`), gossip nodes and client binaries (with updated `TRUSTED_REGISTRY_PREFIXES`). The kels and identity services do not need recompilation
4. **Deploy updated client software** (iOS, CLI, etc.) — clients verify registry KELs against the compiled-in trust anchor
5. **Wait for acceptable client deployment coverage** before proceeding
6. **Update `FEDERATION_URLS`** environment variables to include the new registry's `prefix=url` mapping
7. **Redeploy gossip nodes** with the new trust anchor and registry URL
8. **Redeploy all registries** (existing + new) — node 0 auto-syncs Raft membership via `sync_membership()`

Notes:
- IDs are explicit in the JSON — entry ordering in `federated-registries.json` doesn't affect Raft node IDs
- The new registry joins the Raft cluster as a learner first, catches up on the log, then is promoted to voter
- `sync_membership()` is grow-only: a node compiled with an older binary (fewer members) will not shrink the voter set
- Freeze proposal creation/voting during the transition (steps 7-8) to avoid consensus disruption
