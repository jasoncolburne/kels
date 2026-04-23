# SADStore: Replicated Self-Addressed Data Store

A general-purpose replicated store for publicly discoverable, self-addressed data. Deployed as an independent service (`sadstore`) alongside the KELS node services.

## Architecture

Two layers:

- **SAD Object Store** (MinIO) — Content-addressed blob storage. Any `SelfAddressed` JSON object stored/retrieved by SAID. No authentication needed: writes are idempotent (same SAID = identical content by definition). Existence check before writes prevents write amplification under attack. Two-phase compaction prevents resource amplification from nested SADs.
- **SAD Event Logs** (PostgreSQL) — Versioned event chains with deterministic prefix discovery and policy-based ownership. Event metadata references content in the SAD store via `content`. Authorization is via the anchoring model: `write_policy` is consumer-side, endorsing parties anchor the event's SAID in their KELs.

## Data Model

### SadEvent

A chained, self-addressed event. The v0 (inception) event has `content: None`, making the prefix fully deterministic from `write_policy` + `topic` alone. Content is added in v1+ events.

No `created_at` field — intentionally omitted so inception events produce deterministic prefixes.

Fields:
- `said` — Self-addressing identifier (content hash)
- `prefix` — Chain identifier (derived from inception content)
- `previous` — SAID of previous event (None for v0)
- `version` — Monotonically increasing (0, 1, 2, ...)
- `topic` — Record type (e.g., `kels/sad/v1/keys/mlkem`)
- `content` — SAID of the content object in MinIO (None for v0)
- `custody` — SAID of the custody SAD (optional, controls readPolicy/nodes for the chain)
- `write_policy` — SAID of the write policy (denormalized from custody for chain keying). Required on `Icp` (seeds prefix derivation), optional on `Evl` (present only when evolving the policy), forbidden on `Est`/`Upd`/`Rpr`. See `docs/design/sad-events.md` for the per-kind matrix.

### Deterministic Prefix

Chains are keyed by `(write_policy SAID, topic)`. Anyone can compute a SEL prefix offline:

```rust
let prefix = compute_sad_event_prefix(write_policy, topic)?;
```

This constructs the v0 inception record (which has only deterministic fields), derives its prefix via the standard `SelfAddressed` mechanism, and returns it. No server interaction needed.

### Custody

Per-record storage policy. A custody is itself a SAD (with its own SAID), compacted and stored independently in MinIO, referenced by SAID in the parent record. The SAID covers all custody fields, making storage policy tamper-evident.

Fields:
- `writePolicy` — SAID of a policy SAD controlling writes (consumer-side, anchoring model)
- `readPolicy` — SAID of a policy SAD controlling reads (server-enforced at fetch time)
- `ttl` — Seconds until expiry (per-record: `sad_objects.created_at + ttl`)
- `once` — Atomic delete on first successful retrieval
- `nodes` — SAID of a `NodeSet` SAD for selective replication

**Safety valve:** If the custody object contains any unrecognized fields (e.g., from a newer client), all server-side enforcement is disengaged. This ensures forward compatibility without blocking storage.

**Context validation:** `ttl` and `once` are rejected on events (structurally incompatible with chained data). `once: true` requires `nodes` for consistent delete-on-read semantics.

### NodeSet

A set of node prefixes for selective replication. Prefixes are sorted lexicographically before SAID derivation so the same set always produces the same SAID regardless of insertion order.

## Authentication

- **SAD objects**: No authentication. Content is self-verifying via SAID.
- **SAD events**: No signature verification — authorization is via the anchoring model. `write_policy` identifies who can author the chain; endorsing parties anchor the event's SAID in their KELs. Consumers verify the anchoring when they use the data.

## Divergence and Repair

When two conflicting records exist at the same version (e.g., from concurrent writes), both are stored and the chain is **frozen** — no further appends are accepted until the divergence is repaired. v0 divergence is rejected (inception records are fully deterministic).

The **effective SAID** for a chain represents its current state:
- Non-divergent: the tip event's SAID
- Divergent: `hash_effective_said("divergent:{prefix}")` — a synthetic deterministic SAID so all nodes agree on the frozen state

### Repair

The chain owner repairs divergence by submitting a batch that includes a `Rpr` record. The handler auto-detects Rpr records and takes the repair path:

1. The batch starts at the divergent version
2. `truncate_and_replace` deletes all records at and after that version
3. Replacement records are inserted with structural integrity checks (predecessor linkage, sequential versions, consistent topic). `write_policy` may legitimately evolve across versions via `Evl`, so it is not checked for invariance — the verifier tracks its evolution via branch state.

Displaced records are archived to `sad_event_archives` (mirror table). A `sad_event_repairs` entry is created as an audit record, and `sad_event_repair_records` links each repair to the archived records it displaced. Repair history and displaced records are queryable via the chain repair endpoints.

### Repair Propagation

When a repair succeeds, the SADStore publishes the new effective SAID to Redis. Peer gossip nodes fetch the full chain from origin and submit to their local SADStore; the receiving handler auto-detects repair from `Rpr` records in the submitted batch and takes the repair path, replacing their divergent state.

If a node misses the gossip repair message (e.g., it was offline), the owner submits the repair directly to that node.

## Verification

The `SadEventVerification` token (following the `KelVerification` pattern) proves a chain was verified. It can only be obtained through `verify_sad_events()`, which performs single-pass structural verification: pages through the chain verifying SAID integrity, chain linkage, version monotonicity, and consistent topic. `write_policy` may evolve across versions via `Evl`; the verifier tracks its evolution per branch rather than requiring invariance. No signature verification — authorization is via the anchoring model (consumer-side).

Accessors: `current_event()`, `current_content()`, `prefix()`, `write_policy()`, `topic()`, `policy_satisfied()`, `last_governance_version()`, `establishment_version()`. `write_policy()` returns the branch's tracked (effective) policy — seeded by v0 and updated whenever an `Evl` carries a new `write_policy` *and* the evolution was authorized. This reflects policy evolutions, not the tip event's raw field. See [sad-events.md](sad-events.md) for the semantics of the governance-related accessors (chain-wide vs. branch-scoped).

## Policy Evaluation Modes

Two distinct policy evaluation modes exist for different contexts:

### `evaluate_anchored_policy` — Issuance/Endorsement Context

Used for credential issuance and endorsement verification. Evaluates a policy against KEL state for a given credential SAID.

- Checks KEL anchors: each endorser must have anchored the credential SAID in their KEL via an `ixn` event
- Supports `Endorse`, `Weighted`, `Delegate`, and `Policy` (nested) nodes
- `Delegate(delegator, delegate)` verifies the delegation chain: the delegate's KEL must have been incepted via `dip` with the delegator, and the delegator must anchor the delegate's prefix. This supports scaling credential issuance via delegation chains (#77 — delegated signing servers with sub-delegation to minimize KEL length)
- Poison checks: endorsers can withdraw endorsement by anchoring a poison hash; configurable via `poison` expression or `immune` flag

### `evaluate_signed_policy` — Access Control Context (readPolicy)

Used for `readPolicy` enforcement at SAD object fetch time. Evaluates a policy against a verified prefix set from a `SignedRequest`.

- Checks prefix set membership: the caller has already verified the signers' KELs and collected verified prefixes
- Supports `Endorse`, `Weighted`, and `Policy` (nested) nodes only
- **`Delegate` nodes are rejected with an error** — delegation is an issuance concern for scaling credential signing, not an access-control concern. readPolicies should use direct `endorse()` nodes for any party that needs read access
- No poison checks, no async KEL calls — synchronous evaluation against the verified set

## API

All endpoints use POST with JSON request bodies. Identifiers are never placed in URL paths or query parameters (logged by proxies/CDNs).

### SAD Object Store (Layer 1)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sad` | Store a self-addressed object (JSON body with `said` field) |
| `POST` | `/api/v1/sad/fetch` | Retrieve by SAID (body: `{ "said": "..." }`) |
| `POST` | `/api/v1/sad/exists` | Check existence (body: `{ "said": "..." }`) |
| `POST` | `/api/v1/sad/saids` | List SAD object SAIDs (authenticated, paginated) |

### SAD Events (Layer 2)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sad/events` | Submit SAD events (repair auto-detected from `Rpr` records in the batch) |
| `POST` | `/api/v1/sad/events/fetch` | Fetch chain page (body: `{ "prefix": "...", "since": "...", "limit": N }`) |
| `POST` | `/api/v1/sad/events/effective-said` | Effective SAID for sync comparison (body: `{ "prefix": "..." }`) |
| `POST` | `/api/v1/sad/events/exists` | Check event existence (body: `{ "said": "..." }`) |
| `POST` | `/api/v1/sad/events/prefixes` | List SEL prefixes (authenticated, paginated) |
| `POST` | `/api/v1/sad/events/repairs` | Paginated repair history (body: `{ "prefix": "...", "limit": N, "offset": N }`) |
| `POST` | `/api/v1/sad/events/repairs/records` | Archived records for a repair (body: `{ "prefix": "...", "said": "...", "limit": N, "offset": N }`) |

### Client Workflow

1. Create content object, derive its SAID
2. `POST /api/v1/sad` — store content in SAD store
3. Create SAD event with `content` pointing to that SAID
4. `POST /api/v1/sad/events` — submit the SAD event

Authorization is consumer-side: endorsing parties anchor the event's SAID in their KELs. The SADStore does not verify signatures on submission.

## Gossip Replication

SAD data replicates via the existing gossip infrastructure on a separate topic (`kels/sad/v1`).

### Message Types

```rust
enum SadAnnouncement {
    Object { said, origin },
    Event { prefix, said, origin },
}
```

### Gossip Policy

When a custody specifies `nodes`, the gossip policy controls replication:

- No `nodes` field → broadcast to all peers (default)
- `nodes` present → skip gossip (selective multi-node gossip not yet implemented)

**Fail secure:** If the NodeSet can't be resolved (fetch or parse error), gossip is skipped rather than broadcasting restricted data to unauthorized peers.

### Flow

1. KELS SADStore publishes to Redis (`sad_updates` or `sel_updates`)
2. Gossip service subscribes, broadcasts announcement on `kels/sad/v1` topic
3. Peers receive announcement, fetch missing data from origin
4. For objects: fetch blob and PUT locally
5. For chains: fetch SAD events + content, submit to local service

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `80` | HTTP listen port |
| `DATABASE_URL` | `postgres://...` | PostgreSQL connection |
| `REDIS_URL` | (optional) | Redis for pub/sub |
| `KELS_URL` | `http://kels:80` | KELS service for KEL verification |
| `MINIO_ENDPOINT` | `http://minio:9000` | MinIO endpoint |
| `MINIO_REGION` | `us-east-1` | S3 region |
| `MINIO_ACCESS_KEY` | (required) | S3 access key |
| `MINIO_SECRET_KEY` | (required) | S3 secret key |
| `KELS_SAD_BUCKET` | `kels-sad` | S3 bucket name (auto-created on startup) |
| `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` | `8` | Max SAD events per SEL prefix per day |
| `SADSTORE_MAX_WRITES_PER_IP_PER_SECOND` | `256` | Per-IP write rate (token bucket refill) |
| `SADSTORE_IP_RATE_LIMIT_BURST` | `1024` | Per-IP token bucket burst size |
| `SADSTORE_MAX_OBJECT_SIZE` | `1048576` | Max SAD object size in bytes (1 MiB) |
| `SADSTORE_TTL_REAPER_INTERVAL` | `60` | TTL reaper check interval in seconds |

On the gossip service, `BASE_DOMAIN` env var derives both KELS and SADStore URLs for local and peer service discovery.

## CLI

```
kels-cli sad put <file>                          # Store a self-addressed object
kels-cli sad get <said>                          # Retrieve object by SAID
kels-cli sel submit <file>                       # Submit SEL events
kels-cli sel get <prefix>                        # Fetch a SEL
kels-cli sel prefix <write-policy> <topic>       # Compute SEL prefix offline
```

## Use Cases

- **Key publication credentials** — ML-KEM encapsulation keys for ESSR encrypted messaging. Given a recipient's KEL prefix, compute their key publication SEL prefix and look it up on any node.
- **General verifiable data** — Any self-addressed data that needs to be publicly discoverable and replicated across nodes.
- **Ephemeral records** — `once: true` + `readPolicy` for secure one-time delivery (e.g., key material). `ttl` for auto-expiring records.
- **Access-controlled data** — `readPolicy` enforces fetch-time access control via signed requests evaluated against a policy.
