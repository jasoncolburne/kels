# KELS Endpoints Reference

Complete inventory of HTTP endpoints, gossip protocols, and internal RPC across all services.

## HSM Service

Internal PKCS#11 wrapper for SoftHSM2. No authentication — relies on network isolation (pod-internal only).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check probe |
| POST | `/api/hsm/keys` | None | Generate or retrieve secp256r1 keypair (get-or-create by label) |
| GET | `/api/hsm/keys` | None | List all key labels |
| GET | `/api/hsm/keys/:label/public` | None | Get compressed public key (CESR qb64) |
| POST | `/api/hsm/keys/:label/sign` | None | Sign data with ECDSA P-256; returns signature + public key (CESR qb64) |
| POST | `/api/hsm/keys/:label/ecdh` | None | ECDH key agreement (CKM_ECDH1_DERIVE); accepts base64url peer public key, returns base64url shared secret |

**Notes:**
- Label validation: alphanumeric + `-_.`, max 128 chars
- All crypto values encoded as CESR qb64
- Sign endpoint accepts base64url-encoded data
- No rate limiting; depends entirely on network isolation

## Identity Service

HSM-backed key management for cryptographic identity (KEL). Used by both registries and gossip nodes. Most endpoints have no authentication — internal to the pod. The rotate endpoint requires a signed request.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check probe |
| GET | `/api/identity` | None | Get registry prefix |
| GET | `/api/identity/kel` | None | Get registry KEL (paginated; `?limit=N&since=SAID`); returns `SignedKeyEventPage {events, hasMore}` |
| POST | `/api/identity/anchor` | None | Anchor a SAID in registry's KEL (creates ixn event) |
| POST | `/api/identity/sign` | None | Sign arbitrary JSON data with current signing key |
| POST | `/api/identity/ecdh` | None | ECDH key agreement using current signing key; accepts base64url peer public key, returns base64url shared secret |
| POST | `/api/identity/rotate` | **Signed request (own KEL)** | Perform key rotation (standard, recovery, or scheduled); updates in-memory builder |

**Notes:**
- Anchor serializes via RwLock — concurrent anchoring is safe but sequential
- KEL endpoint returns paginated `SignedKeyEventPage` — `?limit=N` (default 512) and `?since=SAID` for delta fetch
- Sign returns qb64-encoded signature + public key
- Rotate accepts `SignedRequest<RotateRequest>` — signature verified against own KEL. Mode can be `standard` (signing key), `recovery` (recovery key), or `scheduled` (auto-selects based on rotation count). All rotations go through `perform_rotation()` which updates the builder's key provider in-place, keeping the server in sync. Also called internally by the auto-rotation loop (every 30 days).
- No external network exposure expected

## KELS Service

Key Event Log storage and retrieval. The primary data-plane service that gossip nodes and clients interact with.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| GET | `/ready` | None | Readiness check (checks `kels:gossip:ready` in Redis) |
| POST | `/api/kels/events` | None | Submit signed key events (validates signatures, merges KEL); max 512 events per request |
| GET | `/api/kels/kel/:prefix` | None | Get paginated KEL; `?since=SAID` for delta, `?limit=N` (1-512, default 512); returns `SignedKeyEventPage {events, hasMore}` |
| GET | `/api/kels/kel/:prefix/audit` | None | Get audit records for prefix (recovery/contest archives) |
| GET | `/api/kels/kel/:prefix/effective-said` | None | Get effective SAID for sync comparison (resolving only — not verified) |
| GET | `/api/kels/events/:said/exists` | None | Check if event exists by SAID (200 or 404) |
| POST | `/api/kels/kels` | None | Batch fetch KELs for multiple prefixes (max 64); `prefixes` is a map of prefix → optional since SAID; returns per-prefix `SignedKeyEventPage {events, hasMore}` with max 512 events each |
| POST | `/api/kels/prefixes` | **Signed request** | List prefix states (paginated) for P2P sync |

**Notes:**
- `submit_events`: validates all signatures upfront; enforces dual-signature for recovery events; advisory DB lock per prefix for serialization; returns `{divergedAt, applied}`
- `list_prefixes` requires ECDSA signature verification + peer authorization check against peer allowlist (cached in Redis, refreshed from registry). Timestamp window: 60 seconds.
- `get_kel` returns `SignedKeyEventPage {events, hasMore}`. Uses Redis cache for KELs ≤ 512 events (larger KELs are not cached). The `?since=SAID` parameter returns events after the given SAID. The `?limit=N` parameter controls page size (clamped to 1-512, default 512). If the since SAID doesn't match a real event, the server computes the effective SAID for the prefix — for non-divergent KELs this is the tip SAID, for divergent KELs it's a deterministic Blake3 hash of sorted tip SAIDs. If the effective SAID matches, both sides have the same state and an empty response is returned.
- `get_kel_audit` returns `Vec<KelsAuditRecord>` — archived events from recovery/contest operations, separate from the paginated KEL endpoint.
- `get_effective_said` returns the effective SAID for a prefix — for non-divergent KELs this is the tip event's SAID, for divergent KELs it's a deterministic Blake3 hash of sorted tip SAIDs. This is a **resolving** endpoint (unverified, for sync comparison). Used by gossip anti-entropy.
- `get_kels_batch` returns per-prefix `SignedKeyEventPage {events, hasMore}` with max 512 events per prefix. Callers with `hasMore: true` should loop using `fetch_key_events(prefix, since=lastSAID, limit)` to get remaining events.
- `submit_events` uses a fast path for normal appends (~99% of traffic): bounded metadata query + incremental verification via `KelVerifier`, no full KEL load. Divergence/recovery/overlap paths fall back to paginated full KEL loading.
- `KELS_MAX_VERIFICATION_PAGES` environment variable (default 512) controls maximum pagination loops for callers fetching large KELs.
- Error codes: `BadRequest`, `NotFound`, `Conflict`, `Contested`, `Frozen`, `Unauthorized`, `Gone`, `ContestRequired`, `RateLimited`, `InternalError`

## KELS Registry Service

Peer allowlist management, node registration, federation consensus. Requires a federation of at least 3 registries for peer management (peer approval requires a minimum of 3 votes). Standalone mode is used during bootstrap to generate the registry's identity before federation is configured.

### Standalone Mode

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |

### Federation Mode

All standalone endpoints plus:

#### Node Management (rate-limited)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/nodes/register` | **Signed + allowlisted** | Register a gossip node (peer_prefix must match allowlist entry) |
| POST | `/api/nodes/deregister` | **Signed + allowlisted** | Deregister a node |
| POST | `/api/nodes/status` | **Signed + allowlisted** | Update node status (Bootstrapping/Ready/Unhealthy) |

#### Peer Discovery

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/peers` | None | List peers (from Raft state machine) |
| POST | `/api/member-kels` | None | Batch fetch federation member KELs; body: `BatchKelsRequest { prefixes }` (defaults to all members if empty) |
| POST | `/api/member-kels/events` | **Trusted prefix** | Submit member key events (push model); `?propagate=false` to skip fan-out; rate-limited per prefix and IP |
| GET | `/api/member-kels/kel/:prefix` | None | Get a specific member's KEL; `?limit=N&since=SAID` |
| GET | `/api/member-kels/kel/:prefix/effective-said` | None | Get effective SAID for sync comparison (resolving only — not verified) |

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
| POST | `/api/admin/proposals/:id` | **Signed admin request** | Get specific proposal (returns `ProposalWithVotes` — addition or removal, searches pending + completed) |
| POST | `/api/admin/proposals/:id/vote` | **Federation member + KEL anchoring** | Vote on a proposal (addition or removal); verifies vote SAID and KEL anchoring |

**Notes:**
- Node management endpoints: `verify_and_authorize()` validates ECDSA signature, checks peer_prefix in DB allowlist, verifies `active=true`, and enforces node_id matches the peer's authorized node_id
- Federation RPC: verifies sender_prefix is federation member, then validates signature against sender's KEL (current public key from last establishment event). Refreshes KEL on first failure.
- Admin query API: `verify_admin_request()` validates `SignedRequest<AdminRequest>` against the node's own identity KEL — requires HSM-backed signing via the identity service
- Proposal endpoint verifies: SAID integrity (`verify()`), full chain integrity for withdrawals (`AdditionHistory::verify()` / `RemovalHistory::verify()`), proposer is federation member, each record's SAID anchored in proposer's KEL
- Vote endpoint verifies: vote SAID integrity (`verify_said()`), proposal chain not withdrawn, voter is federation member, vote SAID anchored in voter's KEL
- Withdrawals: POST a v1 `PeerAdditionProposal` with `withdrawn_at` set; only allowed before any votes are cast
- Member KEL submit: events are pushed directly via `POST /api/member-kels/events`. Identity service and completion handlers push with `propagate=true` (default), which fans out to all peers. Fan-out calls and AE pushes use `propagate=false` to prevent loops. Per-prefix and per-IP rate limited.

## KELS Gossip Service

Custom gossip protocol (HyParView + PlumTree) for KEL replication across nodes.

### HTTP

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ready` | None | Readiness check (has bootstrap completed?) |
| GET | `/healthz` | None | Liveness probe |

### Gossip Protocols

| Protocol | Auth | Description |
|----------|------|-------------|
| PlumTree broadcast (`kels/events/v1`) | **Three-DH P-256 + AES-GCM-256** | KEL update announcements (`KelAnnouncement` JSON: prefix, said) |
| HyParView membership | **Three-DH P-256 + AES-GCM-256** | Mesh overlay maintenance (join, shuffle, forward-join) |
| Allowlist verification | **Signature + verified allowlist** | Verifies peer's NodePrefix against verified allowlist post-handshake |

### Peer-to-Peer HTTP (between gossip nodes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/kels/prefixes` | **Signed request** | Fetch paginated prefix list for bootstrap (calls peer's KELS service) |
| POST | `/api/kels/kels` | None | Batch fetch KELs from peer for bootstrap (calls peer's KELS service) |

**Notes:**
- Transport: Three-DH P-256 key exchange (ee + se + es) + AES-GCM-256 session encryption over TCP; NodePrefix (44-char CESR) identifies peers
- Peer verification: handshake signature verified against peer's KEL public key; unknown peers trigger allowlist refresh before rejection
- Allowlist verification: peer record SAID (`verify()`), peer SAID anchored in registry KEL, full DAG verification (`AdditionWithVotes::verify()`) + proposal records anchored in proposer's KEL + approval votes anchored in voter's KEL; threshold and member set derived from compiled-in trusted prefixes

## Authentication Methods Summary

| Method | Where Used | Mechanism |
|--------|-----------|-----------|
| **Signed request** | Node registration, prefix listing, identity rotation | ECDSA P-256 signature over JSON payload; peer_prefix derived from public key; checked against allowlist (or own KEL for identity rotation) |
| **Federation KEL signature** | Raft RPC | Signed payload verified against sender's KEL (current key from last establishment event) |
| **Signed admin request** | Admin API | SignedRequest<AdminRequest> verified against own identity KEL |
| **Federation membership** | Proposals, votes, RPC | `config.is_member(prefix)` — compile-time trusted prefixes |
| **Gossip handshake** | Gossip connections | Three-DH pattern (ee + se + es) with AES-GCM-256; signature verified against peer's KEL; static key operations via HSM |
| **Allowlist** | Gossip connections | NodePrefix checked against verified peer allowlist with full KEL verification |
| **SAID integrity** | Peer records, votes | `SelfAddressed::verify()` — content hash matches declared SAID |
| **KEL anchoring** | Peer records, votes | SAID must appear in an ixn event in the authorizing registry's KEL |
| **Compile-time trust** | All clients | `TRUSTED_REGISTRY_PREFIXES` env var baked at compile time; KEL prefixes must match |
| **No auth** | Health checks, public reads | `/health`, `/ready`, KEL fetches, peer listing, federation status |
