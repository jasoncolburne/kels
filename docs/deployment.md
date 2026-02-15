# KELS Deployment Guide

## Overview

A KELS deployment consists of a **federation of registries** and **gossip nodes** that replicate Key Event Logs across the network. The minimum viable deployment requires 3 registries (for consensus quorum) and at least 1 gossip node.

The Garden configuration in this repository (`project.garden.yml` and per-service `garden.yml` files) is an example used for local testing. It can be used as a guide for understanding the deployment flow, but is not a reference for production deployments.

The `test-comprehensive` Makefile target is the best way to understand the full deployment lifecycle end-to-end.

## Architecture

Each **registry** runs:
- `kels-registry` — federation consensus and peer management
- `identity` — the registry's own cryptographic identity (KEL + signing)
- `hsm` — hardware security module for key storage
- `postgres` — database for federation state, peer records, and the registry's KEL
- `redis` — node registration storage

Each **gossip node** runs:
- `kels` — KEL storage and retrieval API
- `kels-gossip` — libp2p gossip network for KEL replication
- `hsm` — key storage for gossip peer identity
- `postgres` — KEL storage and gossip peer cache
- `redis` — KEL caching and pub/sub invalidation

## Deployment Flow

The deployment follows a specific order because of a compile-time trust anchor: `TRUSTED_REGISTRY_PREFIXES`. This is a comma-separated list of registry identity prefixes that gets baked into every binary at compile time. The prefixes aren't known until each registry generates its identity, creating a bootstrap chicken-and-egg that's resolved with a two-phase deployment.

### Phase 1: Deploy Registries in Standalone Mode

Deploy all 3 registries without federation. Each generates its cryptographic identity on first boot.

```
deploy registry-a (standalone — no TRUSTED_REGISTRY_PREFIXES)
deploy registry-b (standalone)
deploy registry-c (standalone)
```

At this point each registry has:
- Generated a keypair via HSM
- Created an inception event (KEL) establishing its identity
- A prefix derived from that inception event

### Phase 2: Collect Prefixes

Fetch each registry's prefix from its identity service. These prefixes form the trust anchor for the entire network.

```
fetch prefix from registry-a → save
fetch prefix from registry-b → save
fetch prefix from registry-c → save
```

In the test setup, these are saved to `.kels/federated-registries.json` (a JSON array with `id`, `name`, `prefix`, and `url` per registry) and extracted at build time into `TRUSTED_REGISTRY_PREFIXES` (comma-separated prefixes for all services) and `TRUSTED_REGISTRY_MEMBERS` (JSON with explicit `id` + `prefix` for kels-registry Raft node IDs).

### Phase 3: Recompile and Redeploy Registries

Rebuild all binaries with the collected prefixes baked in, then redeploy the registries. On this second deployment, the registries detect federation configuration and start the Raft consensus cluster.

```
recompile with TRUSTED_REGISTRY_PREFIXES=<prefix-a>,<prefix-b>,<prefix-c>
redeploy registry-a (federation mode)
redeploy registry-b (federation mode)
redeploy registry-c (federation mode)
```

The registries now form a Raft cluster. Node 0 (the registry whose `id` is 0 in the JSON) auto-initializes the cluster after a short delay.

### Phase 4: Deploy Gossip Nodes

Deploy gossip nodes. Each node needs to be authorized in the peer allowlist before it can join the gossip network.

**Core nodes** (replicate across all registries):
1. Deploy the node's infrastructure (kels, kels-gossip, postgres, redis, hsm)
2. Propose the node as a core peer from any registry (`kels-registry-admin peer propose-add-peer`)
3. Vote from each registry to approve (`kels-registry-admin peer vote`)
4. Restart kels-gossip so it picks up its authorization
5. The node bootstraps: fetches KELs from existing peers, joins the gossip mesh

**Regional nodes** (replicate within one registry's network only):
1. Deploy the node's infrastructure
2. Add directly via the registry's admin API (`kels-registry-admin peer add-regional-peer`) — no proposal/vote needed
3. Restart kels-gossip

### Phase 5: Verify

Run integration tests or manually verify:
- Nodes appear in peer discovery (`GET /api/peers`)
- KELs replicate across nodes via gossip
- Client discovery works (latency-sorted node selection)

## Compile-Time Trust Anchor

`TRUSTED_REGISTRY_PREFIXES` is the security foundation of the network. It's compiled into every binary that needs to verify registry identity:

- `kels-registry` — federation membership, proposal/vote verification
- `kels-gossip` — peer allowlist verification, registry KEL verification
- `kels` (service) — signed request verification against peer allowlist
- Client libraries (`libkels`, `libkels-ffi`) — registry KEL verification during node discovery

When this value changes (registries added or removed), **all binaries must be recompiled and redeployed**.

## Federation Configuration

Each registry needs two categories of configuration:

**Compile-time (security — who to trust):**
- `TRUSTED_REGISTRY_PREFIXES` — comma-separated prefixes, baked into all binaries
- `TRUSTED_REGISTRY_MEMBERS` — JSON array of `{id, prefix}` objects, baked into kels-registry only (explicit Raft node IDs)

**Runtime (operational — how to connect):**
- `FEDERATION_SELF_PREFIX` — this registry's own prefix
- `FEDERATION_URLS` — comma-separated `prefix=url` pairs for all federation members

If `TRUSTED_REGISTRY_MEMBERS` is empty or `FEDERATION_SELF_PREFIX` is unset, the registry runs in standalone mode (no federation, no peer management).

## Gossip Node Configuration

Key environment variables for gossip nodes:

| Variable | Description |
|----------|-------------|
| `NODE_ID` | Unique node identifier |
| `KELS_URL` | Local KELS service URL |
| `KELS_ADVERTISE_URL` | URL clients use to reach this node's KELS service |
| `REGISTRY_URL` | Primary registry URL for this node |
| `FEDERATION_REGISTRY_URLS` | All registry URLs (comma-separated, for HA) |
| `GOSSIP_LISTEN_ADDR` | libp2p listen multiaddr (e.g., `/ip4/0.0.0.0/tcp/4001`) |
| `GOSSIP_ADVERTISE_ADDR` | libp2p advertised multiaddr |
| `HSM_URL` | HSM service URL for gossip peer identity |
| `REDIS_URL` | Redis for KEL caching |
| `RESYNC_INTERVAL_SECS` | Periodic resync interval (default: 300) |

## Core Peer Lifecycle

### Adding a Core Peer

Core peers require multi-party approval (minimum 3 votes from federation members):

```bash
# From any registry:
kels-registry-admin peer propose-add-peer \
  --peer-id <peer_id> \
  --node-id <node_id> \
  --kels-url <kels_url> \
  --gossip-multiaddr <multiaddr>

# Produces a proposal ID. Vote from each registry:
kels-registry-admin peer vote --proposal <proposal_id> --approve

# After threshold votes, the peer is added to the allowlist.
# Restart the node's kels-gossip to pick up authorization.
```

### Removing a Core Peer

Core peer removal also requires multi-party approval:

```bash
# From any registry:
kels-registry-admin peer propose-removal --peer-id <peer_id>

# Vote from each registry:
kels-registry-admin peer vote --proposal <proposal_id> --approve

# After threshold votes, the peer is removed from the allowlist.
```

### Regional Peers

Regional peers are added by a single registry without federation consensus:

```bash
kels-registry-admin peer add-regional-peer \
  --peer-id <peer_id> \
  --node-id <node_id> \
  --kels-url <kels_url> \
  --gossip-multiaddr <multiaddr>
```

Regional peers only replicate within that registry's network.

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
make test-comprehensive
```

## Adding a Registry

To expand the federation with a new registry after initial deployment:

1. **Deploy the new registry standalone** (generates its cryptographic identity on first boot)
2. **Fetch its prefix** using `federation-fetch.sh` — the script auto-assigns the next sequential `id` in `federated-registries.json`
3. **Recompile all binaries** with the updated trust anchors (`TRUSTED_REGISTRY_PREFIXES` and `TRUSTED_REGISTRY_MEMBERS`)
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
