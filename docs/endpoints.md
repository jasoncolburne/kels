# KELS Endpoints Reference

Complete inventory of HTTP endpoints, libp2p protocols, and internal RPC across all services.

## HSM Service

Internal PKCS#11 wrapper for SoftHSM2. No authentication — relies on network isolation (pod-internal only).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check probe |
| POST | `/api/hsm/keys` | None | Generate or retrieve secp256r1 keypair (get-or-create by label) |
| GET | `/api/hsm/keys` | None | List all key labels |
| GET | `/api/hsm/keys/:label/public` | None | Get compressed public key (CESR qb64) |
| POST | `/api/hsm/keys/:label/sign` | None | Sign data with ECDSA P-256; returns signature + public key (CESR qb64) |

**Notes:**
- Label validation: alphanumeric + `-_.`, max 128 chars
- All crypto values encoded as CESR qb64
- Sign endpoint accepts base64url-encoded data
- No rate limiting; depends entirely on network isolation

## Identity Service

HSM-backed key management for the registry's cryptographic identity (KEL). No authentication — internal to the registry pod.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check probe |
| GET | `/api/identity` | None | Get registry prefix |
| GET | `/api/identity/kel` | None | Get full registry KEL (fresh from DB) |
| POST | `/api/identity/anchor` | None | Anchor a SAID in registry's KEL (creates ixn event) |
| POST | `/api/identity/sign` | None | Sign arbitrary JSON data with current signing key |

**Notes:**
- Anchor serializes via RwLock — concurrent anchoring is safe but sequential
- KEL is read fresh from DB on each request (captures externally anchored events)
- Sign returns qb64-encoded signature + public key
- No external network exposure expected

## KELS Service

Key Event Log storage and retrieval. The primary data-plane service that gossip nodes and clients interact with.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| GET | `/ready` | None | Readiness check (checks `kels:gossip:ready` in Redis) |
| POST | `/api/kels/events` | None | Submit signed key events (validates signatures, merges KEL) |
| GET | `/api/kels/kel/:prefix` | None | Get KEL for prefix; `?audit=true` bypasses cache, `?since=SAID` for delta sync |
| GET | `/api/kels/events/:said/exists` | None | Check if event exists by SAID (200 or 404) |
| POST | `/api/kels/kels` | None | Batch fetch KELs for multiple prefixes (max 50); `prefixes` is a map of prefix → optional since SAID for delta sync |
| POST | `/api/kels/prefixes` | **Signed request** | List prefix states (paginated) for P2P sync |

**Notes:**
- `submit_events`: validates all signatures upfront; enforces dual-signature for recovery events; advisory DB lock per prefix for serialization; returns `{divergedAt, applied}`
- `list_prefixes` requires ECDSA signature verification + peer authorization check against peer allowlist (cached in Redis, refreshed from registry). Timestamp window: 60 seconds.
- `get_kel` uses Redis cache with pub/sub invalidation; falls back to DB on miss
- Error codes: `NotFound`, `BadRequest`, `Unauthorized`, `Frozen`, `Contested`, `RecoveryProtected`, `InternalError`

## KELS Registry Service

Peer allowlist management, node registration, federation consensus. Requires a federation of at least 3 registries for peer management (core peer approval requires a minimum of 3 votes). Standalone mode is used during bootstrap to generate the registry's identity before federation is configured.

### Standalone Mode

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| GET | `/api/registry-kel` | None | Get this registry's KEL (from identity service) |

### Federation Mode

All standalone endpoints plus:

#### Node Management (rate-limited)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/nodes/register` | **Signed + allowlisted** | Register a gossip node (peer_id must match allowlist entry) |
| POST | `/api/nodes/deregister` | **Signed + allowlisted** | Deregister a node |
| POST | `/api/nodes/status` | **Signed + allowlisted** | Update node status (Bootstrapping/Ready/Unhealthy) |

#### Peer Discovery

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/peers` | None | List peers (core from Raft + regional from local DB) |
| GET | `/api/registry-kels` | None | Get all federation member KELs (for HA — any registry serves all) |

#### Federation Protocol

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/federation/rpc` | **Federation member + KEL signature** | Raft RPC endpoint (AppendEntries, Vote, Snapshot) |
| GET | `/api/federation/status` | None | Federation status (leader, term, members) |
| GET | `/api/federation/proposals` | None | Completed proposals with votes (for independent verification) |

#### Admin API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/admin/addition-proposals` | **Federation member + KEL anchoring** | Submit an addition proposal (create v0 or withdraw v1); verifies SAID, chain, and KEL anchoring |
| POST | `/api/admin/removal-proposals` | **Federation member + KEL anchoring** | Submit a removal proposal (create v0 or withdraw v1); verifies SAID, chain, and KEL anchoring |
| GET | `/api/admin/proposals/:id` | **Localhost only** | Get specific addition proposal (returns `AdditionWithVotes`, searches pending + completed) |
| POST | `/api/admin/proposals/:id/vote` | **Federation member + KEL anchoring** | Vote on a proposal (addition or removal); verifies vote SAID and KEL anchoring |
| POST | `/api/admin/peers` | **Localhost only** | Add a regional peer (bypasses Raft) |

**Notes:**
- Node management endpoints: `verify_and_authorize()` validates ECDSA signature, checks peer_id in DB allowlist, verifies `active=true`, and enforces node_id matches the peer's authorized node_id
- Federation RPC: verifies sender_prefix is federation member, then validates signature against sender's KEL (current public key from last establishment event). Refreshes KEL on first failure.
- Admin API: `is_localhost()` checks `ConnectInfo<SocketAddr>.ip().is_loopback()` — returns 403 otherwise
- Proposal endpoint verifies: SAID integrity (`verify()`), full chain integrity for withdrawals (`AdditionHistory::verify()` / `RemovalHistory::verify()`), proposer is federation member, each record's SAID anchored in proposer's KEL
- Vote endpoint verifies: vote SAID integrity (`verify_said()`), proposal chain not withdrawn, voter is federation member, vote SAID anchored in voter's KEL
- Withdrawals: POST a v1 `PeerAdditionProposal` with `withdrawn_at` set; only allowed before any votes are cast

## KELS Gossip Service

libp2p-based gossip network for KEL replication across nodes.

### HTTP

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ready` | None | Readiness check (has bootstrap completed?) |

### libp2p Protocols

| Protocol | Auth | Description |
|----------|------|-------------|
| gossipsub (`kels/events/v1`) | **Message signing** (libp2p) | KEL update announcements (`KelAnnouncement` JSON: prefix, said, origin, destination, sender) |
| identify (`/kels/gossip/v1`) | **Noise handshake** | Peer discovery and capability exchange |
| AllowlistBehaviour | **Noise + allowlist** | Custom NetworkBehaviour that disconnects unauthorized peers post-handshake |

### Peer-to-Peer HTTP (between gossip nodes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/kels/prefixes` | **Signed request** | Fetch paginated prefix list for bootstrap (calls peer's KELS service) |
| POST | `/api/kels/kels` | None | Batch fetch KELs from peer for bootstrap (calls peer's KELS service) |

**Notes:**
- Transport: Noise protocol provides authenticated encryption; PeerId derived from ECDSA P-256 key
- AllowlistBehaviour: unknown inbound peers trigger allowlist refresh; pending peers held until verified or disconnected
- gossipsub config: heartbeat 1s, strict validation, mesh min 2 / target 3
- Scope-based routing: Regional announcements bridged to Core, Core rebroadcasts to All
- Allowlist refresh verifies: peer record SAID (`verify()`), peer SAID anchored in registry KEL, and for core peers — full DAG verification (`AdditionWithVotes::verify()`) + proposal records anchored in proposer's KEL + approval votes anchored in voter's KEL; threshold and member set derived from compiled-in trusted prefixes

## Authentication Methods Summary

| Method | Where Used | Mechanism |
|--------|-----------|-----------|
| **Signed request** | Node registration, prefix listing | ECDSA P-256 signature over JSON payload; peer_id derived from public key; checked against allowlist |
| **Federation KEL signature** | Raft RPC | Signed payload verified against sender's KEL (current key from last establishment event) |
| **Localhost only** | Admin API | `SocketAddr.ip().is_loopback()` check |
| **Federation membership** | Proposals, votes, RPC | `config.is_member(prefix)` — compile-time trusted prefixes |
| **Noise handshake** | libp2p connections | Authenticated encryption; PeerId = hash of public key |
| **Allowlist** | Gossip connections | PeerId checked against registry-sourced peer list with full KEL verification |
| **SAID integrity** | Peer records, votes | `SelfAddressed::verify()` — content hash matches declared SAID |
| **KEL anchoring** | Peer records, votes | SAID must appear in an ixn event in the authorizing registry's KEL |
| **Compile-time trust** | All clients | `TRUSTED_REGISTRY_PREFIXES` env var baked at compile time; KEL prefixes must match |
| **No auth** | Health checks, public reads | `/health`, `/ready`, KEL fetches, peer listing, federation status |
