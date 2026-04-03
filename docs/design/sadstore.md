# SADStore: Replicated Self-Addressed Data Store

A general-purpose replicated store for publicly discoverable, self-addressed data. Deployed as an independent service (`sadstore`) alongside the KELS node services.

## Architecture

Two layers:

- **SAD Object Store** (MinIO) — Content-addressed blob storage. Any `SelfAddressed` JSON object stored/retrieved by SAID. No authentication needed: writes are idempotent (same SAID = identical content by definition). Existence check before writes prevents write amplification under attack.
- **Chained Records** (PostgreSQL) — Versioned chains with deterministic prefix discovery and KEL ownership. Chain metadata references content in the SAD store via `content_said`. Authenticated via signature verified against the owner's KEL.

## Data Model

### SadPointer

A chained, self-addressed record. The v0 (inception) record has `content_said: None`, making the prefix fully deterministic from `kel_prefix` + `kind` alone. Content is added in v1+ records.

No `created_at` field — intentionally omitted so inception records produce deterministic prefixes.

Fields:
- `said` — Self-addressing identifier (content hash)
- `prefix` — Chain identifier (derived from inception content)
- `previous` — SAID of previous record (None for v0)
- `version` — Monotonically increasing (0, 1, 2, ...)
- `kel_prefix` — The owning KEL's prefix
- `kind` — Record type (e.g., `kels/v1/mlkem-pubkey`)
- `content_said` — SAID of the content object in MinIO (None for v0)

### Deterministic Prefix

Anyone can compute a chain prefix offline:

```rust
let prefix = compute_sad_prefix(kel_prefix, kind)?;
```

This constructs the v0 inception record (which has only deterministic fields), derives its prefix via the standard `SelfAddressed` mechanism, and returns it. No server interaction needed.

### SignedSadPointer

A SAD record paired with its signature and the server-derived `establishment_serial`, as returned by the chain API. Analogous to `SignedKeyEvent`.

Fields:
- `record` — The `SadPointer`
- `signature` — Signature over the record's SAID
- `establishment_serial` — Which KEL establishment event's key signed this

### SadPointerSubmission

The submission type for creating/updating chains. Contains `record` + `signature` but no `establishment_serial` — the server determines it by finding the most recent establishment event in the owner's KEL.

## Authentication

- **SAD objects**: No authentication. Content is self-verifying via SAID.
- **Chain records**: Each record is signed with the owner's current KEL signing key. The server verifies the signature against the most recent establishment event in the KEL. Only the current key is accepted — old/rotated keys are rejected.

The `establishment_serial` is server-derived and stored in a separate `sad_record_signatures` table (keeping the SAID-driven record table clean).

## Divergence and Repair

When two conflicting records exist at the same version (e.g., from key compromise or concurrent writes), both are stored and the chain is **frozen** — no further appends are accepted until the divergence is repaired. v0 divergence is rejected (inception records are fully deterministic).

The **effective SAID** for a chain represents its current state:
- Non-divergent: the tip record's SAID
- Divergent: `hash_effective_said("divergent:{prefix}")` — a synthetic deterministic SAID so all nodes agree on the frozen state

### Repair

The chain owner repairs divergence by submitting a replacement batch with `?repair=true`:

1. The batch starts at the divergent version
2. `truncate_and_replace` deletes all records at and after that version
3. Replacement records are inserted with chain integrity checks (predecessor linkage, internal chain linkage, sequential versions, consistent kel_prefix/kind)
4. Signatures on replacement records are verified against the owner's KEL

Displaced records are archived to `sad_record_archives` and `sad_record_archive_signatures` (mirror tables). A `sad_chain_repairs` entry is created as an audit record, and `sad_chain_repair_records` links each repair to the archived records it displaced. Repair history and displaced records are queryable via the chain repair endpoints.

### Repair Propagation

When a repair succeeds, the SADStore publishes a gossip message with `repair: true`. Peer nodes that receive this announcement forward the repaired chain to their local SADStore with `?repair=true`, replacing their divergent state.

If a node misses the gossip repair message (e.g., it was offline), the owner submits the repair directly to that node.

## Verification

The `SadPointerVerification` token (following the `KelVerification` pattern) proves a chain was verified. It can only be obtained through `verify_sad_records()`, which performs two-pass O(page_size) verification:

1. **Pass 1 (structure):** Pages through the chain, verifying SAID integrity, chain linkage, version monotonicity, and consistent kel_prefix/kind. Collects establishment serials.
2. **Between:** Verifies the owner's KEL, collecting establishment keys for the referenced serials.
3. **Pass 2 (signatures):** Pages through the chain again, verifying each record's signature against its establishment key.

Accessors: `current_record()`, `current_content_said()`, `establishment_serial()`.

## API

### SAD Object Store (Layer 1)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sad` | Store a self-addressed object (SAID derived from body) |
| `GET` | `/api/v1/sad/:said` | Retrieve by SAID |

### Chain Records (Layer 2)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sad/pointers` | Submit signed chain records; `?repair=true` to repair divergent chain |
| `GET` | `/api/v1/sad/pointers/:prefix` | Fetch chain (returns `SignedSadPointer`s with signatures); `?since=N` for delta |
| `GET` | `/api/v1/sad/pointers/:prefix/effective-said` | Tip SAID for sync comparison |
| `GET` | `/api/v1/sad/pointers/:prefix/repairs` | Paginated repair history (`?limit=N&offset=N`); returns `SadChainRepairPage` |
| `GET` | `/api/v1/sad/pointers/:prefix/repairs/:said/records` | Archived records displaced by a specific repair (`?limit=N&offset=N`); returns `SadPointerPage` |

### Listing (for bootstrap + anti-entropy)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/sad/saids` | List SAD object SAIDs (paginated: `?cursor=&limit=`) |
| `GET` | `/api/v1/sad/pointers/prefixes` | List chain prefixes with tip SAIDs (paginated: `?cursor=&limit=`) |

### Client Workflow

1. Create content object, derive its SAID
2. `POST /api/v1/sad` — store content in SAD store
3. Create chain record with `content_said` pointing to that SAID
4. Sign the record's SAID with current KEL key
5. `POST /api/v1/sad/pointers` — submit the signed chain record

## Gossip Replication

SAD data replicates via the existing gossip infrastructure on a separate topic (`kels/sad/v1`).

### Message Types

```rust
enum SadGossipMessage {
    Object { said, origin },
    Chain { chain_prefix, said, origin, repair },
}
```

The `repair` flag (default `false`) signals that a divergent chain was repaired. Receiving nodes use `?repair=true` to replace their local divergent state.

### Flow

1. KELS SADStore publishes to Redis (`sad_updates` or `sad_chain_updates`)
2. Gossip service subscribes, broadcasts announcement on `kels/sad/v1` topic
3. Peers receive announcement, fetch missing data from origin
4. For objects: fetch blob and PUT locally
5. For chains: fetch chain records + content, submit to local service

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
| `SADSTORE_MAX_RECORDS_PER_PREFIX_PER_DAY` | `16` | Max chain records per prefix per day |
| `SADSTORE_MAX_WRITES_PER_IP_PER_SECOND` | `100` | Per-IP write rate (token bucket refill) |
| `SADSTORE_IP_RATE_LIMIT_BURST` | `500` | Per-IP token bucket burst size |
| `SADSTORE_MAX_OBJECT_SIZE` | `1048576` | Max SAD object size in bytes (1 MiB) |

On the gossip service, `BASE_DOMAIN` env var derives both KELS and SADStore URLs for local and peer service discovery.

## CLI

```
kels-cli sad put <file>              # Store a self-addressed object
kels-cli sad get <said>              # Retrieve object by SAID
kels-cli sad submit <file>           # Submit signed chain record
kels-cli sad pointer <prefix>          # Fetch pointer chain
kels-cli sad prefix <kel-prefix> <kind>  # Compute prefix offline
```

## Use Cases

- **Key publication credentials** — ML-KEM encapsulation keys for ESSR encrypted messaging. Given a recipient's KEL prefix, compute their key publication chain prefix and look it up on any node.
- **General verifiable data** — Any self-addressed data that needs to be publicly discoverable and replicated across nodes.
