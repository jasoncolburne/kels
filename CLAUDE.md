# KELS - Key Event Log System

## Build & Verify

- Run `make` to verify changes (format, deny, clippy, test, build). Never use naked cargo commands.
- Make targets exist for all cargo commands (`make fmt`, `make clippy`, `make test`, etc.).
- `make all` runs: `fmt-check`, `deny`, `clippy`, `test`, `build` — in that order.
- `make coverage` produces per-file coverage with `cargo-llvm-cov`.
- Dependency crates live at `../verifiable-storage-rs`, `../cacheable`, `../cesr-rs`.

## Code Style

### Imports

Imports go at the top of each file, nested where possible, sorted in three groups separated by blank lines:

1. System/core dependencies (`std`, `tokio`, `serde`, etc.)
2. External crates (`verifiable_storage`, ``, etc.)
3. Local imports (`crate::`, `super::`, things in this repo)

```rust
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use anyhow::Result;
use clap::Parser;
use verifiable_storage::{SelfAddressed, StorageError};

use crate::{handlers::AppState, repository::KelsRepository};
```

Never import inline within function bodies.

### General

- Fail **secure**, not safe. Default to restrictive behavior when state is unknown.
- No unnecessary abstractions or over-engineering, but reuse code where appropriate. It's okay to make traits.
- This is a greenfield project. There are no existing deployments or backwards compatibility concerns.
- When creating database schema migrations, edit the existing initial migrations in place rather than adding new migration files.

## Core Concepts

### Prefix

A persistent identifier for chained data. Derived by hashing the inception event content with both the `said` and `prefix` fields set to placeholders (`"#" * 44`) before computing Blake3. This produces a different value than the SAID (which only blanks the `said` field). Unlike KERI, where the prefix equals the inception SAID, KELS derives them differently. The prefix remains stable across the entire chain lifetime.

### SAID (Self-Addressing Identifier)

A Blake3-256 hash of serialized content, encoded as a 44-character Base64 string via CESR. Computed by setting the `said` field to a placeholder (`"#" * 44`), serializing to JSON, and hashing. Each event has a unique SAID. Used for content-addressable storage and chain linking.

### CESR (Composable Event Streaming Representation)

Binary-safe encoding format for cryptographic primitives. Used for SAIDs, signatures, public keys, and digests. All cryptographic material in the system is CESR-encoded.

### KEL (Key Event Log)

A cryptographically-linked chain of self-addressed key events sharing a prefix. Each event references the previous event's SAID via the `previous` field. The chain contains forward commitments to the next keys via `rotation_hash = Blake3(next_public_key)`, so after key revelation the chain is provable in both directions — backward via `previous` pointers and forward via rotation hash verification.

Event types:
- **`icp`** (incept) — creates a new KEL, establishes initial keys and rotation hash
- **`rot`** (rotate) — rotates keys, reveals previous rotation hash, commits to next keys
- **`ixn`** (interact) — non-key-change event, extends the chain
- **`dip`** (delegated incept) — inception under a delegating prefix
- **`rec`** (recover) — recovery event, requires dual signatures (current + recovery key)
- **`ror`** (rotate recovery) — rotates both signing and recovery keys, requires dual signatures
- **`cnt`** (contest) — permanently freezes a divergent KEL, requires dual signatures
- **`dec`** (decommission) — ends the KEL, requires dual signatures

Delegation trust is NOT verified by the KELS service. KELS accepts any valid KEL starting with `icp` or `dip`. Consumers verify delegation trust chains when needed.

### Divergence

When conflicting events exist at the same serial number in a KEL (e.g., from competing updates or adversarial forks). A divergent KEL is frozen until recovery resolves the conflict. Detected by finding duplicate serial values in the event chain.

### Effective SAID

A single identifier representing the current state of a KEL, including divergent KELs. For non-divergent KELs, this is the tip event's SAID. For divergent KELs (multiple branch tips), this is a deterministic Blake3 hash of the sorted tip SAIDs (`hash_tip_saids`). Used for delta sync: when a `?since=<said>` query doesn't match a real event SAID, the server computes the effective SAID — if it matches, both sides have the same divergent state and no sync is needed. Also used by anti-entropy to compare prefix states across nodes.

### Merge Results

When events are submitted, the KEL merge produces one of:
- **Accepted** — events applied cleanly
- **Recovered** — divergence was resolved by a recovery event
- **Contested** — adversary revealed recovery key, KEL permanently frozen
- **Diverged** — conflicting events detected, awaiting recovery
- **Rejected** — events failed validation
- **Protected** — adversary used recovery key; owner should contest

## Architecture

### Services

- **kels** — Core KEL service. Stores and serves KELs via REST API. Handles event submission with cryptographic verification, advisory locking per prefix, rate limiting, nonce deduplication, and pre-serialized caching via Redis.
- **kels-gossip** — Gossip and federation service. Syncs KELs between peers using a custom gossip protocol (HyParView + PlumTree). Handles bootstrap sync, peer discovery, and allowlist management.
- **kels-registry** — Registry service. Manages peer lifecycle via OpenRaft consensus. Handles multi-party voting for peer addition/removal. Federates state across registries.
- **identity** — Identity service. Manages the registry's own KEL and signing keys.
- **hsm** — Hardware security module interface for key storage and signing operations.

### Libraries

- **kels** (`lib/kels`) — Core library. Types, KEL logic, client, error types, cache.
- **gossip** (`lib/gossip`) — Custom gossip protocol library. HyParView membership + PlumTree broadcast over TCP with three-DH (ee + se + es) P-256 + AES-GCM-256 encryption. Uses 44-char CESR-encoded NodePrefix identities.
- **kels-derive** (`lib/kels-derive`) — Derive macros (`SignedEvents`, etc.).
- **kels-ffi** (`lib/kels-ffi`) — C FFI bindings for cross-language use.

### Clients

- **kels-cli** — Command-line client for interacting with KELS.
- **kels-bench** — Benchmarking tool.
- **kels-client** — Swift client (iOS/macOS).

### Gossip

All peers are equal participants in the gossip mesh. HyParView maintains the mesh overlay and PlumTree handles epidemic broadcast to all connected nodes, deduplicating by message ID. When a node receives an announcement for an unfamiliar SAID, it fetches the missing events from any peer in the allowlist that has the event.

### Federation

Registries form a federated network using OpenRaft consensus for peer management. Adding a peer requires multi-party approval: one registry proposes, then a threshold of registries vote to approve. Registry prefixes are compiled into a trust anchor at build time via `TRUSTED_REGISTRY_PREFIXES`.

### Bootstrap Sync

When a gossip node starts:
1. **Authorization check** — is this peer in the allowlist?
2. **If NOT authorized** — loop: preload KELs from Ready peers via HTTP, sleep, recheck
3. **Once authorized** — discover peers, start gossip swarm
4. **If Ready peers exist** — wait for first `PeerConnected`, resync to catch events missed during transition
5. **If no Ready peers** — skip resync (first/only node)
6. **Mark ready**

The resync step is critical: events occurring between the last preload and joining gossip would otherwise be missed. Bootstrap supports delta fetching via `since` SAID per prefix to avoid re-fetching events the node already has.

An **anti-entropy loop** (default every 10s) provides background repair: Phase 1 retries known-stale prefixes (tracked in Redis), Phase 2 randomly samples prefix pages against a peer to detect and reconcile silent divergence. Previously-attempted remote effective SAIDs are tracked per-prefix in Redis to avoid infinite retry loops when nodes hold different adversary branch pairs (three-way divergence). New remote states (e.g., after recovery) are retried, and successful syncs clear the tracking.

### Security Model

- **Fail secure** — restrictive defaults when state is unknown
- **Advisory locks** — per-prefix PostgreSQL advisory locks serialize all operations on a prefix
- **Dual signatures** — recovery events (`rec`, `ror`, `dec`, `cnt`) require signatures from both current and recovery keys
- **Forward commitments** — rotation hash commits to next key before revelation
- **Rate limiting** — 32 submissions per prefix per minute (fixed window, theoretical max 64 across window boundary)
- **Nonce deduplication** — prevents replay of signed requests within a 60-second window
- **Signed peer requests** — prefix listing requires signed requests with timestamp validation and peer verification
- **Peer allowlist** — gossip peers must be in the allowlist (cached in Redis, refreshed from registry)
- **Three-DH handshake** — gossip uses ee (forward secrecy), se via HSM (static authentication), and es locally (mutual authentication), with session keys derived from all three secrets via BLAKE3
- **Contested KELs** — if an adversary reveals the recovery key, the KEL is permanently frozen
- **Audit records** — recovery operations log removed events for forensic review

### Data Verification Rules

All recorded/persisted data MUST be KEL-backed and verified independently before use. Verification happens at different layers:

- **At ingestion/caching time** — Full verification of the entire trust chain. For peer data: verify peer record chain (SAIDs, prefixes), proposal DAG (SAIDs, chain integrity), vote anchoring in registry KELs, and the peer's own KEL structure. Use existing helpers (`fetch_all_verified_peers()`, `verify_peers_response()`, `verify_peer_votes()`). Never cache or persist data that hasn't been fully verified.
- **At connection/request time** — Verify the signature on signed requests against the peer's current public key from their KEL (already verified and cached). This is a handshake — ephemeral, no anchoring needed.
- **At KEL refresh time** — When re-fetching a peer's KEL, verify the KEL structure before updating the cached version.
- **Never leave verification as a TODO** — If you write code that ingests external data without verification, that is a security vulnerability. Implement verification inline or flag it immediately.
- **Ephemeral data is the only exception** — Handshakes and transient protocol messages don't need anchoring. Everything else does.

### Storage

Events are stored in PostgreSQL via the `verifiable-storage` framework:
- `Stored` derive macro generates CRUD operations, table mappings, and query builders
- `SignedEvents` derive macro generates signature table operations with paginated `get_signed_history(prefix, limit, offset)` returning `(Vec<SignedKeyEvent>, bool)`
- `Chained` trait provides `derive_prefix`, `derive_said`, `increment`, `verify_prefix`, `verify_said`
- `SelfAddressed` trait provides content-addressable storage via SAID
- Transactional operations use `KelTransaction` which wraps a PG transaction with advisory lock. Implements `PageLoader` for advisory-locked paginated reads during verify-then-write operations.
- `KelVerifier` — streaming forward-walking chain verifier for incremental verification without full KEL load. Supports multi-branch divergent KELs via generation-based processing. Produces `Verification` tokens (proof-of-verification) via `into_verification()`. Used by submit handler, `sync_and_verify()`, and all consuming paths.
- `Verification` — proof-of-verification token. Cannot be constructed directly — only via `KelVerifier::into_verification()`. Provides access to verified KEL state (branch tips, divergence, decommission, anchor checking results). Functions that consume KEL data accept `&Verification` to prove the KEL was verified.
- `completed_verification(loader, prefix, page_size, max_pages, anchors)` — guard function that pages through a `PageLoader` with `KelVerifier`, returning a trusted `Verification` token. `max_pages` prevents resource exhaustion.
- `PagedKelSource` / `PagedKelSink` / `sync_and_verify()` — generic streaming pattern for verified KEL transfer between stores.
- Pre-serialized JSON cache in Redis for KELs ≤ 512 events; larger KELs are not cached
- Redis pub/sub for cache invalidation across instances
- All KEL queries use `ORDER BY serial ASC, said ASC` for deterministic pagination across divergent events
- `MAX_EVENTS_PER_KEL_QUERY` (512) — page size for database queries. `MAX_EVENTS_PER_KEL_RESPONSE` derives from this.
- Local KEL stores: gossip service stores registry KELs in PostgreSQL for anchoring verification; registry service persists member KELs alongside Raft state
- Patterns:
    - An identity creates verifiable data (eg for centralized storage/sharing):
        1. No request type is required, the full record is requried to verify the SAID/chain anyway - so send it (full record, or a vec/map of them etc) AS the payload
        2. Creator must create()/increment() and anchor the record by SAID in their KEL
    - An end verifier queries verifiable data (to consume or derive new values from):
        1. No response type is required, the full record is requried to verify the SAID/chain - so send it (full record, or vec/map of them) AS the payload
        2. Verifier must verify the structure of the record(s) (verify() - verifies said or said+prefix), versions increment by 1 (if applicable), verify the chain of records (if applicable), and verify anchoring
