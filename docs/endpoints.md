# KELS Endpoints Reference

Complete inventory of HTTP endpoints, gossip protocols, and internal RPC across all services.

## Identity Service

PKCS#11 HSM-backed key management for cryptographic identity (KEL). Used by both registries and gossip nodes. The identity service loads the PKCS#11 .so directly via cryptoki (`kels-mock-hsm` in development, real HSM in production). Most endpoints have no authentication — internal to the pod. The manage endpoint requires a signed request (the `IdentityClient` handles signing internally).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check probe |
| GET | `/api/v1/identity` | None | Get registry prefix |
| GET | `/api/v1/identity/kel` | None | Get registry KEL (paginated; `?limit=N&since=SAID`); returns `SignedKeyEventPage {events, hasMore}` |
| POST | `/api/v1/identity/anchor` | None | Anchor a SAID in registry's KEL (creates ixn event) |
| POST | `/api/v1/identity/sign` | None | Sign arbitrary JSON data with current signing key |
| GET | `/api/v1/identity/status` | None | Get identity status (initialized, prefix, last SAID, current key handle) |
| POST | `/api/v1/identity/kel/manage` | **Signed request (own KEL)** | Manage KEL (rotate, recover, contest, decommission); updates in-memory builder |

**Notes:**
- Anchor serializes via RwLock — concurrent anchoring is safe but sequential
- KEL endpoint returns paginated `SignedKeyEventPage` — `?limit=N` (default 32) and `?since=SAID` for delta fetch
- Sign returns qb64-encoded signature + public key
- Manage accepts `SignedRequest<ManageKelRequest>` — signature verified against own KEL. Operations: `Rotate` (with mode `standard`, `recovery`, or `scheduled`), `Recover`, `Contest`, `Decommission`. All operations go through `perform_kel_operation()` which updates the builder's key provider in-place, keeping the server in sync. Auto-rotation loop (every 30 days) also uses this path.
- No external network exposure expected

## KELS Service

Key Event Log storage and retrieval. The primary data-plane service that gossip nodes and clients interact with.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| GET | `/ready` | None | Readiness check (checks `kels:gossip:ready` in Redis) |
| POST | `/api/v1/kels/events` | None | Submit signed key events (validates signatures, merges KEL); max 500 events per request |
| GET | `/api/v1/kels/kel/:prefix` | None | Get paginated KEL; `?since=SAID` for delta, `?limit=N` (1-32, default 32); returns `SignedKeyEventPage {events, hasMore}` |
| GET | `/api/v1/kels/kel/:prefix/audit` | None | Get audit records for prefix (recovery/contest archives) |
| GET | `/api/v1/kels/kel/:prefix/effective-said` | None | Get effective SAID for sync comparison (resolving only — not verified) |
| GET | `/api/v1/kels/events/:said/exists` | None | Check if event exists by SAID (200 or 404) |
| POST | `/api/v1/kels/prefixes` | **Signed request** | List prefix states (paginated) for P2P sync |

**Notes:**
- `submit_events`: validates all signatures upfront; enforces dual-signature for recovery events; advisory DB lock per prefix for serialization; returns `{divergedAt, applied}`
- `list_prefixes` requires signature verification + peer authorization check against peer allowlist (cached in Redis, refreshed from registry). Timestamp window: 60 seconds.
- `get_kel` returns `SignedKeyEventPage {events, hasMore}`. Uses Redis cache for KELs ≤ 32 events (larger KELs are not cached). The `?since=SAID` parameter returns events after the given SAID. The `?limit=N` parameter controls page size (clamped to 1-32, default 32). If the since SAID doesn't match a real event, the server computes the effective SAID for the prefix — for non-divergent KELs this is the tip SAID, for divergent KELs it's a deterministic Blake3 hash of sorted tip SAIDs. If the effective SAID matches, both sides have the same state and an empty response is returned.
- `get_kel_audit` returns `Vec<KelsAuditRecord>` — archived events from recovery/contest operations, separate from the paginated KEL endpoint.
- `get_effective_said` returns the effective SAID for a prefix — for non-divergent KELs this is the tip event's SAID, for divergent KELs it's a deterministic Blake3 hash of sorted tip SAIDs. This is a **resolving** endpoint (unverified, for sync comparison). Used by gossip anti-entropy.
- KELs are fetched individually per prefix using paginated `forward_key_events` / `verify_key_events` via the `PagedKelSource` / `PagedKelSink` traits. Each call pages through a single prefix's KEL with bounded memory.
- `submit_events` uses a fast path for normal appends (~99% of traffic): bounded metadata query + incremental verification via `KelVerifier`, no full KEL load. Divergence/recovery/overlap paths fall back to paginated full KEL loading.
- `KELS_MAX_VERIFICATION_PAGES` environment variable (default 64) controls maximum pagination loops for callers fetching large KELs.
- Error codes: `BadRequest`, `NotFound`, `Conflict`, `Contested`, `Frozen`, `Unauthorized`, `Gone`, `ContestRequired`, `RateLimited`, `InternalError`

## KELS Registry Service

Peer allowlist management and federation consensus. Requires a federation of at least 3 registries for peer management (peer approval requires a minimum of 3 votes). Standalone mode is used during bootstrap to generate the registry's identity before federation is configured.

### Standalone Mode

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |

### Federation Mode

All standalone endpoints plus:

#### Peer Discovery

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/peers` | None | List peers (from Raft state machine) |
| POST | `/api/v1/member-kels/events` | **Trusted prefix** | Submit member key events (push model); fans out to other members only when prefix matches the receiving node's own prefix; rate-limited per prefix and IP |
| GET | `/api/v1/member-kels/kel/:prefix` | None | Get a specific member's KEL; `?limit=N&since=SAID` |
| GET | `/api/v1/member-kels/kel/:prefix/effective-said` | None | Get effective SAID for sync comparison (resolving only — not verified) |

#### Federation Protocol

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/federation/rpc` | **Federation member + KEL signature** | Raft RPC endpoint (AppendEntries, Vote, Snapshot) |
| GET | `/api/v1/federation/status` | None | Federation status (leader, term, members) |
| GET | `/api/v1/federation/proposals` | None | Completed proposals with votes (for independent verification) |
| GET | `/api/v1/federation/proposals/:id` | None | Get specific proposal (returns `ProposalWithVotes` — addition or removal, searches pending + completed) |

#### Admin API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/admin/addition-proposals` | **Federation member + KEL anchoring** | Submit an addition proposal (create v0 or withdraw v1); verifies SAID, chain, and KEL anchoring |
| POST | `/api/v1/admin/removal-proposals` | **Federation member + KEL anchoring** | Submit a removal proposal (create v0 or withdraw v1); verifies SAID, chain, and KEL anchoring |
| POST | `/api/v1/admin/proposals/:id/vote` | **Federation member + KEL anchoring** | Vote on a proposal (addition or removal); verifies vote SAID and KEL anchoring |

**Notes:**
- Federation RPC: verifies sender_prefix is federation member, then validates signature against sender's KEL (current public key from last establishment event). Refreshes KEL on first failure.
- Proposal endpoint verifies: SAID integrity (`verify()`), full chain integrity for withdrawals (`AdditionHistory::verify()` / `RemovalHistory::verify()`), proposer is federation member, each record's SAID anchored in proposer's KEL
- Vote endpoint verifies: vote SAID integrity (`verify_said()`), proposal chain not withdrawn, voter is federation member, vote SAID anchored in voter's KEL
- Withdrawals: POST a v1 `PeerAdditionProposal` with `withdrawn_at` set; only allowed before any votes are cast
- Member KEL submit: events are pushed directly via `POST /api/v1/member-kels/events`. Propagation is determined internally — the receiver fans out only when the submitted prefix matches its own prefix (i.e., identity pushed to the local registry). Events for other members' prefixes are stored without further fan-out. Per-prefix and per-IP rate limited.

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
| PlumTree broadcast (`kels/events/v1`) | **ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256** | KEL update announcements (`KelAnnouncement` JSON: prefix, said) |
| HyParView membership | **ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256** | Mesh overlay maintenance (join, shuffle, forward-join) |
| Allowlist verification | **Signature + verified allowlist** | Verifies peer's NodePrefix against verified allowlist post-handshake |

### Peer-to-Peer HTTP (between gossip nodes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/kels/prefixes` | **Signed request** | Fetch paginated prefix list for bootstrap (calls peer's KELS service) |
| GET | `/api/v1/kels/kel/:prefix` | None | Fetch individual KEL from peer for bootstrap (calls peer's KELS service); paginated via `forward_key_events` |

**Notes:**
- Transport: ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication + AES-GCM-256 session encryption over TCP; NodePrefix (44-char CESR) identifies peers; P-256 peers rejected
- Peer verification: handshake signature verified against peer's KEL public key; unknown peers trigger allowlist refresh before rejection
- Allowlist verification: peer record SAID (`verify()`), peer SAID anchored in registry KEL, full DAG verification (`AdditionWithVotes::verify()`) + proposal records anchored in proposer's KEL + approval votes anchored in voter's KEL; threshold and member set derived from compiled-in trusted prefixes

## Authentication Methods Summary

| Method | Where Used | Mechanism |
|--------|-----------|-----------|
| **Signed request** | Prefix listing, identity rotation | Signature (ML-DSA-65/87 for infrastructure) over JSON payload; peer_prefix derived from KEL; checked against allowlist (or own KEL for identity rotation) |
| **Federation KEL signature** | Raft RPC | Signed payload verified against sender's KEL (current key from last establishment event) |
| **Signed admin request** | Admin API | SignedRequest<AdminRequest> verified against own identity KEL |
| **Federation membership** | Proposals, votes, RPC | `config.is_member(prefix)` — compile-time trusted prefixes |
| **Gossip handshake** | Gossip connections | ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication + AES-GCM-256; signature verified against peer's KEL; ML-DSA-65/87 only (P-256 rejected) |
| **Allowlist** | Gossip connections | NodePrefix checked against verified peer allowlist with full KEL verification |
| **SAID integrity** | Peer records, votes | `SelfAddressed::verify()` — content hash matches declared SAID |
| **KEL anchoring** | Peer records, votes | SAID must appear in an ixn event in the authorizing registry's KEL |
| **Compile-time trust** | All clients | `TRUSTED_REGISTRY_PREFIXES` env var baked at compile time; KEL prefixes must match |
| **No auth** | Health checks, public reads | `/health`, `/ready`, KEL fetches, peer listing, federation status |
