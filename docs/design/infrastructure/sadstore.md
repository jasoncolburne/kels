# SADStore: Replicated Self-Addressed Data Store

A general-purpose replicated store for publicly discoverable, self-addressed data. Deployed as an independent service (`sadstore`) alongside the KELS node services.

## Architecture

Two layers:

- **SAD Object Store** (RustFS, S3-compatible) — Content-addressed blob storage. Any `SelfAddressed` JSON object stored/retrieved by SAID. No authentication needed: writes are idempotent (same SAID = identical content by definition). Existence check before writes prevents write amplification under attack. Two-phase compaction prevents resource amplification from nested SADs.
- **SAD Event Logs** (PostgreSQL) — Versioned event chains with deterministic prefix discovery and identity-rooted ownership. Event metadata references content in the SAD store via `content`. Authorization is via the anchoring model: each SEL event's authorization resolves through the bound IEL (`identity` at Icp; `ielEvent` on v1+ events); endorsing parties anchor the event's SAID in their KELs.

## Data Model

### SadEvent

A chained, self-addressed event. The v0 (inception) event has `content: None`, making the prefix fully deterministic from `(identity, topic)` alone. Content is added in v1+ events.

No `createdAt` field — intentionally omitted so inception events produce deterministic prefixes.

Fields:
- `said` — Self-addressing identifier (content hash)
- `prefix` — Chain identifier (derived from inception content)
- `previous` — SAID of previous event (None for v0)
- `serial` — Monotonically increasing (0, 1, 2, ...)
- `topic` — Event type (e.g., `kels/sel/v1/keys/mlkem`)
- `content` — SAID of the content object in the object store (None for v0)
- `identity` — IEL prefix the chain is bound to. Set on `Icp` only; participates in prefix derivation alongside `topic`. Forbidden on every other kind.
- `ielEvent` — SAID of the IEL event whose policy authorizes this SEL event. Forbidden on `Icp` (permissionless inception); required on every v1+ kind. Resolves to `authPolicy` for `Upd` and `governancePolicy` for `Sea` / `Rpr` / `Dec`. See [sel/events.md](../primitives/data/event-logs/sel/events.md) for the full per-kind matrix.

#167: `custody` and `availability` are not part of the `SadEvent` struct, so any inline keys with those names get silently dropped during deserialization — chain events broadcast as a unit and can't carry differential authority/replication across links. The drop is structural (type-system), not an explicit submit-handler rejection: a chain-event JSON body containing those keys parses cleanly with the keys ignored. The `CustodyValidationError::CustodyNotAllowedOnEvent` / `AvailabilityNotAllowedOnEvent` variants exist for a future explicit-rejection path (e.g., `deny_unknown_fields` on `SadEvent` deserialization or boundary JSON-key inspection); they are not raised today.

### Deterministic Prefix

Chains are keyed by `(identity, topic)`. Anyone can compute a SEL prefix offline:

```rust
let prefix = compute_sad_event_prefix(identity, topic)?;
```

This constructs the v0 inception event (which has only deterministic fields), derives its prefix via the standard `SelfAddressed` mechanism, and returns it. No server interaction needed.

### Custody (per-SAD-object authority)

Per-SAD authority via two independent fields, each optional. Inline-on-parent (no separate SAID):

- `ownerIelEvent` — IEL event SAID, the writer's identity at write time. Write attestation derives from this event: a verifier can ask either "was the writer authorized under the `authPolicy` at *this event*?" (historical lookup against the event's policy) or "is the writer's identity still authorized at the *current* tip?" (dereference → extract IEL prefix → walk to tip → resolve current `authPolicy`). Both modes derive from one SAID. `None` for unsigned (anonymous) writes.
- `readPolicy` — policy SAID. At read time, the policy is fetched and evaluated against a verified prefix set from a `SignedRequest`. The policy can compose identities arbitrarily — e.g., `threshold(2, [identity(X), identity(Y), identity(Z)])` permits any 2 of 3 identities without those three needing to form a shared IEL. `None` for publicly readable content.

The asymmetry between the two fields is intentional: writes are single-identity-bound (one writer at one moment); reads are composable (any DSL expression). Typical `readPolicy` uses `identity(X)` leaves to gate by identity-current state; `endorse(KEL)` is allowed but rare since most read-side gating is identity-oriented rather than device-oriented.

Four valid combinations:

| `ownerIelEvent` | `readPolicy` | Pattern |
|-------------------|---------------|---------|
| `None` | `None` | Public, anonymous write |
| `Some` | `None` | Attested write, public read |
| `None` | `Some` | Anonymous write, controlled read (drop-box) |
| `Some` | `Some` | Attested write, controlled read (private message) |

### Availability (per-SAD-object replication + lifecycle)

#167: sibling top-level inline struct, factored apart from custody. Independently optional:

- `nodes` — SAID of a `NodeSet` SAD declaring serving nodes. `None` = default broadcast.
- `ttl` — Seconds until expiry (per-object: `sad_objects.createdAt + ttl`).
- `once` — Atomic delete on first successful retrieval. Only valid when `nodes` references a single-prefix NodeSet matching the accepting node.

**Safety valve:** Unrecognized fields in either struct disengage server-side enforcement (forward compatibility). **Context rejection:** both `custody` and `availability` are forbidden on chain events (replicate as a unit).

### NodeSet

A set of node prefixes for selective replication. Prefixes are sorted lexicographically before SAID derivation so the same set always produces the same SAID regardless of insertion order.

## Authentication

- **SAD objects**: No authentication. Content is self-verifying via SAID.
- **SAD events**: No signature verification — authorization is via the anchoring model. The chain is identity-rooted: every chain binds at inception (Icp) to a specific IEL (`identity` field), and every v1+ event references a specific IEL event by SAID (`ielEvent`). Authorization policies (`authPolicy` for `Upd`; `governancePolicy` for `Sea` / `Rpr`) live on the bound IEL and are resolved on demand. Endorsing parties anchor the event's SAID in their KELs; consumers verify the anchoring when they use the data.

## Chain Lifecycle

A SEL transitions through states (Active → Divergent → Contested / Decommissioned) driven by the events in the chain itself, not external flags. The **effective SAID** for a chain is its gossip-visible identity:
- Linear chain: the tip event's SAID.
- Divergent chain: `hash_effective_said("divergent:{prefix}")` — synthetic, deterministic, cross-node-consistent.
- Contested chain: `hash_effective_said("contested:{prefix}")` — terminal.
- Decommissioned chain: the `Dec` event's SAID — terminal owner-initiated end.

For the full chain lifecycle (divergence detection, repair via discriminator, decommission, evaluation seal, server-observable case taxonomy), see [sel/event-log.md](../primitives/data/event-logs/sel/event-log.md). Repair history and archived events are queryable via the `sad_event_archives`, `sad_event_repairs`, and `sel_repair_events` tables — exposed through the repair endpoints listed below.

### Repair Propagation

When a repair or decommission succeeds, the SADStore publishes the new effective SAID to Redis. Peer gossip nodes fetch the full chain from origin and submit to their local SADStore; the receiving handler auto-detects the lifecycle transition from the kinds present in the batch (`Rpr` / `Dec`) and applies the matching path.

If a node misses the gossip message (e.g., it was offline), the owner submits the events directly to that node.

## Verification

The `SelVerification` token (following the `KelVerification` pattern) proves a chain was verified. It can only be obtained through `verify_sel_events()`, which performs single-pass structural verification: pages through the chain verifying SAID integrity, chain linkage, serial monotonicity, consistent topic, the IEL `identity` binding (set at Icp), and the per-event parent-monotonic check on `ielEvent` (each event's `ielEvent` must be at-or-after its parent event's, applied per branch). Authorization policies are resolved through `IelResolver` — the verifier does not track them per branch. No signature verification — authorization is via the anchoring model (consumer-side).

Accessors: `branches()`, `current_event()`, `current_content()`, `prefix()`, `topic()`, `events_since_evaluation()`, `policy_satisfied()`, `lastSealAdvancingEvent()`, `lastIelEvent()`, `is_contested()`, `is_decommissioned()`, `divergenceAncestor()`. `lastSealAdvancingEvent()` returns the SAID of the most recent `Sea`/`Rpr` (the evaluation seal). `divergenceAncestor()` returns the SAID of `v_{d-1}` on a divergent chain (the unique parent of all events at the divergence point), `None` on a linear chain. `lastIelEvent()` is a derived aggregate — the highest IEL event SAID across all events in the chain. (On a divergent chain it's the max across all branches' tip iel_events.) The `is_contested` / `is_decommissioned` / `divergenceAncestor` accessors expose lifecycle state — see [sel/event-log.md](../primitives/data/event-logs/sel/event-log.md) for the state model.

## Policy Evaluation Modes

Two distinct policy evaluation modes exist for different contexts:

### `evaluate_anchored_policy` — Issuance/Endorsement Context

Used for credential issuance and endorsement verification. Evaluates a policy against KEL state for a given credential SAID.

- Checks KEL anchors: each endorser must have anchored the credential SAID in their KEL via an `ixn` event
- Supports `Endorse`, `Weighted`, `Delegate`, and `Policy` (nested) nodes
- `Delegate(delegator, delegate)` verifies the delegation chain: the delegate's KEL must have been incepted via `dip` with the delegator, and the delegator must anchor the delegate's prefix. This supports scaling credential issuance via delegation chains (#77 — delegated signing servers with sub-delegation to minimize KEL length)
- Poison checks: endorsers can withdraw endorsement by anchoring a poison hash; configurable via `poison` expression or `immune` flag

### `evaluate_signed_policy` — Access Control Context (`readPolicy` enforcement)

Used for SAD-object read enforcement at fetch time, against the policy referenced by `readPolicy`. The policy is fetched and evaluated against the verified prefix set from a `SignedRequest`; `identity(X)` leaves in the policy resolve to X's current `authPolicy` (walk to tip), while `endorse(KEL)` leaves check the KEL's current state.

- Checks prefix set membership: the caller has already verified the signers' KELs and collected verified prefixes
- Supports `Endorse`, `Identity`, `Weighted`, and `Policy` (nested) nodes
- **`Delegate` nodes are rejected with an error** — delegation is an issuance concern for scaling credential signing, not an access-control concern. Read-gating policies should use direct `endorse()` or `identity()` nodes for any party that needs read access
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
| `POST` | `/api/v1/sad/events` | Submit SAD events (repair auto-detected from `Rpr` events in the batch) |
| `POST` | `/api/v1/sad/events/fetch` | Fetch chain page (body: `{ "prefix": "...", "since": "...", "limit": N }`) |
| `POST` | `/api/v1/sad/events/effective-said` | Effective SAID for sync comparison (body: `{ "prefix": "..." }`) |
| `POST` | `/api/v1/sad/events/exists` | Check event existence (body: `{ "said": "..." }`) |
| `POST` | `/api/v1/sad/events/prefixes` | List SEL prefixes (authenticated, paginated) |
| `POST` | `/api/v1/sad/events/repairs` | Paginated repair history (body: `{ "prefix": "...", "limit": N, "offset": N }`) |
| `POST` | `/api/v1/sad/events/repairs/events` | Archived events for a repair (body: `{ "prefix": "...", "said": "...", "limit": N, "offset": N }`) |

### Client Workflow

1. Create content object, derive its SAID
2. `POST /api/v1/sad` — store content in SAD store
3. Create SAD event with `content` pointing to that SAID
4. `POST /api/v1/sad/events` — submit the SAD event

Authorization is consumer-side: endorsing parties anchor the event's SAID in their KELs. The SADStore does not verify signatures on submission.

## Gossip Replication

SAD objects and SEL chain events replicate via the gossip infrastructure on two separate topics:

- `kels/gossip/v1/topics/sad` — SAD object announcements
- `kels/gossip/v1/topics/sel` — SEL chain event announcements

### Message Types

```rust
/// SAD object announcement (on `kels/gossip/v1/topics/sad`)
struct SadAnnouncement {
    said: String,
    origin: String,
}

/// SEL chain event announcement (on `kels/gossip/v1/topics/sel`)
struct SelAnnouncement {
    prefix: String,
    said: String,
    origin: String,
}
```

### Gossip Policy

When a SAD's `availability.nodes` references a NodeSet, the gossip policy controls replication:

- No `availability` / no `nodes` field → broadcast to all peers (default)
- `nodes` present → skip gossip (selective multi-node gossip not yet implemented)

**Fail secure:** If the NodeSet can't be resolved (fetch or parse error), gossip is skipped rather than broadcasting restricted data to unauthorized peers.

### Flow

1. KELS SADStore publishes to Redis (`sad_updates` for SAD objects; `sel_updates` for SEL chain updates)
2. Gossip service subscribes; broadcasts SAD object announcements on `kels/gossip/v1/topics/sad`, SEL chain event announcements on `kels/gossip/v1/topics/sel`
3. Peers receive announcements, fetch missing data from origin
4. For SAD object announcements: fetch blob and PUT locally
5. For SEL chain event announcements: fetch SAD events + content, submit to local service

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `80` | HTTP listen port |
| `DATABASE_URL` | `postgres://...` | PostgreSQL connection |
| `REDIS_URL` | (optional) | Redis for pub/sub |
| `KELS_URL` | `http://kels:80` | KELS service for KEL verification |
| `OBJECTS_ENDPOINT` | `http://objects:9000` | Object store endpoint |
| `OBJECTS_REGION` | `us-east-1` | S3 region |
| `OBJECTS_ACCESS_KEY` | (required) | S3 access key |
| `OBJECTS_SECRET_KEY` | (required) | S3 secret key |
| `KELS_SAD_BUCKET` | `kels-sad` | S3 bucket name (auto-created on startup) |
| `SADSTORE_MAX_SEL_EVENTS_PER_PREFIX_PER_DAY` | `256` | Max SAD events per SEL prefix per day per pod |
| `SADSTORE_MAX_IEL_EVENTS_PER_PREFIX_PER_DAY` | `8` | Max IEL events per identity prefix per day per pod |
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
kels-cli sel prefix <identity> <topic>           # Compute SEL prefix offline
```

## Use Cases

- **Key publication credentials** — ML-KEM encapsulation keys for ESSR encrypted messaging. Given a recipient's KEL prefix, compute their key publication SEL prefix and look it up on any node.
- **General verifiable data** — Any self-addressed data that needs to be publicly discoverable and replicated across nodes.
- **Ephemeral objects** — `availability.once: true` + `readPolicy` for secure one-time delivery (e.g., key material). `availability.ttl` for auto-expiring objects.
- **Access-controlled data** — `readPolicy` enforces fetch-time access control via signed requests evaluated against a composable policy (typically `identity(X)` leaves resolving identity-current state).
