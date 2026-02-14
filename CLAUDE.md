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
- No unnecessary abstractions or over-engineering.
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
- **`icp`** (inception) — creates a new KEL, establishes initial keys and rotation hash
- **`rot`** (rotation) — rotates keys, reveals previous rotation hash, commits to next keys
- **`ixn`** (interaction) — non-key-change event, extends the chain
- **`dip`** (delegated inception) — inception under a delegating prefix
- **`drt`** (delegated rotation) — rotation under a delegating prefix
- **`rec`** (recovery) — recovery event, requires dual signatures (current + recovery key)
- **`ror`** (contest) — contests a recovery, also requires dual signatures

Delegation trust is NOT verified by the KELS service. KELS accepts any valid KEL starting with `icp` or `dip`. Consumers verify delegation trust chains when needed.

### Divergence

When conflicting events exist at the same serial number in a KEL (e.g., from competing updates or adversarial forks). A divergent KEL is frozen until recovery resolves the conflict. Detected by finding duplicate serial values in the event chain.

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

- **kels** — Core registry service. Stores and serves KELs via REST API. Handles event submission with cryptographic verification, advisory locking per prefix, rate limiting, nonce deduplication, and pre-serialized caching via Redis.
- **kels-gossip** — Gossip and federation service. Syncs KELs between peers using libp2p. Handles bootstrap sync, peer discovery, allowlist management, and scope-based routing.
- **kels-registry** — Registry service. Manages peer lifecycle via OpenRaft consensus. Handles multi-party voting for core peer addition/removal. Federates state across registries.
- **kels-identity** — Identity service. Manages the registry's own KEL and signing keys.
- **hsm** — Hardware security module interface for key storage and signing operations.

### Libraries

- **kels** (`lib/kels`) — Core library. Types, KEL logic, client, error types, cache, p2p signatures.
- **kels-derive** (`lib/kels-derive`) — Derive macros (`SignedEvents`, etc.).
- **kels-ffi** (`lib/kels-ffi`) — C FFI bindings for cross-language use.

### Clients

- **kels-cli** — Command-line client for interacting with KELS.
- **kels-bench** — Benchmarking tool.
- **kels-client** — C client with shell-based test scripts.

### Gossip & Scope-Based Routing

Peers have scopes that determine event propagation:
- **Regional** — connected to a single registry, sees events from that registry's network only
- **Core** — connected to all registries, bridges events between regions
- **All** — receives all events

Events flow Regional → Core → All, enabling geographic distribution while maintaining global consistency.

### Federation

Registries form a federated network using OpenRaft consensus for core peer management. Adding a core peer requires multi-party approval: one registry proposes, then a threshold of registries vote to approve. Regional peers are added by a single registry without federation. Registry prefixes are compiled into a trust anchor at build time via `TRUSTED_REGISTRY_PREFIXES`.

### Bootstrap Sync

When a gossip node starts:
1. **Authorization check** — is this peer in the allowlist?
2. **If NOT authorized** — loop: preload KELs from Ready peers via HTTP, sleep, recheck
3. **Once authorized** — discover peers, start gossip swarm
4. **If Ready peers exist** — wait for first `PeerConnected`, resync to catch events missed during transition
5. **If no Ready peers** — skip resync (first/only node)
6. **Mark ready**

The resync step is critical: events occurring between the last preload and joining gossip would otherwise be missed. Bootstrap supports delta fetching via `since` SAID per prefix to avoid re-fetching events the node already has.

### Security Model

- **Fail secure** — restrictive defaults when state is unknown
- **Advisory locks** — per-prefix PostgreSQL advisory locks serialize all operations on a prefix
- **Dual signatures** — recovery events (`rec`, `ror`) require signatures from both current and recovery keys
- **Forward commitments** — rotation hash commits to next key before revelation
- **Rate limiting** — 32 submissions per prefix per minute (sliding window)
- **Nonce deduplication** — prevents replay of signed requests within a 60-second window
- **Signed peer requests** — prefix listing requires signed requests with timestamp validation and peer verification
- **Peer allowlist** — gossip peers must be in the allowlist (cached in Redis, refreshed from registry)
- **Contested KELs** — if an adversary reveals the recovery key, the KEL is permanently frozen
- **Audit records** — recovery operations log removed events for forensic review

### Storage

Events are stored in PostgreSQL via the `verifiable-storage` framework:
- `Stored` derive macro generates CRUD operations, table mappings, and query builders
- `SignedEvents` derive macro generates signature table operations
- `Chained` trait provides `derive_prefix`, `derive_said`, `increment`, `verify_prefix`, `verify_said`
- `SelfAddressed` trait provides content-addressable storage via SAID
- Transactional operations use `KelTransaction` which wraps a PG transaction with advisory lock
- Pre-serialized JSON cache in Redis avoids re-serialization on reads
- Redis pub/sub for cache invalidation across instances
