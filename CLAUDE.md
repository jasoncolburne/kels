# KELS - Key Event Log System

## Build & Verify

- `make` verifies changes (fmt, deny, clippy, test, build). Never use naked cargo commands. Only run when `.rs`, `Cargo.toml`, or `deny.toml` changed.
- `make all` runs: `fmt-check`, `deny`, `clippy`, `test`, `build`. Individual targets exist (`make fmt`, `make clippy`, etc.).
- `make coverage` produces per-file coverage via `cargo-llvm-cov`.
- Dependency crates at `../verifiable-storage-rs`, `../cacheable`, `../cesr-rs` — we may modify them.
- When adding a local `lib/` crate as a dependency to a service or client, also update the Garden config and Dockerfile to include the new lib in the build context. Services' Docker builds only copy explicitly listed lib dirs.
- After substantial changes, verify the full deployment pipeline: deploy → federation → voting → gossip → adversarial tests → gossip tests.

## Code Style

### Imports

Three groups at file top, nested, sorted, separated by blank lines: (1) std/core, (2) external crates, (3) local (`crate::`, `super::`). No inline imports except inside `#[cfg(feature)]` blocks. Fix imports when touching a file.

```rust
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use anyhow::Result;
use verifiable_storage::{SelfAddressed, StorageError};

use crate::{handlers::AppState, repository::KelsRepository};
```

### General

- Fail **secure**, not safe. Default to restrictive behavior when state is unknown.
- Greenfield project — no backwards compatibility concerns. Edit initial migrations in place, don't add new migration files.
- No unnecessary abstractions, but reuse code where appropriate. Traits are fine.
- Never hardcode event kind strings — use `EventKind` enum methods.
- Never `.unwrap()`. Use `.expect("reason")` with `#[allow(clippy::expect_used)]` if truly infallible.
- Use `cesr` types (`Digest256`, `Signature`, `VerificationKey`, `SigningKey`, etc.) for all cryptographic material. Parse at system boundaries, pass typed values throughout.
- Use `create()` not `new()` for `SelfAddressed` types. `new()` leaves SAID as placeholder; `create()` derives SAID + `created_at`.
- Sign the SAID's QB64 bytes, never serialized payloads. Payloads needing signatures must derive `SelfAddressed`. This commits to the CESR type code, gives fixed-size input, and eliminates serialization-order ambiguity.
- All HTTP endpoints use POST with JSON bodies — never encode identifiers in URL paths or query params (logged by proxies/CDNs).

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

A single identifier representing the current state of a KEL. For non-divergent KELs, this is the tip event's SAID. For divergent KELs, this is `hash_effective_said("divergent:{prefix}")`. For contested KELs, `hash_effective_said("contested:{prefix}")`. Used for delta sync and anti-entropy comparison across nodes.

### Merge Results

When events are submitted, the KEL merge produces one of:
- **Accepted** — events applied cleanly
- **Recovered** — divergence was resolved by a recovery event
- **Contested** — adversary revealed recovery key, KEL permanently frozen
- **Diverged** — conflicting events detected, awaiting recovery
- **RecoverRequired** — KEL is divergent, submit recovery to resolve
- **ContestRequired** — recovery key revealed, submit contest to freeze

## Architecture

### Services

- **kels** — Core KEL service. REST API for event submission and KEL retrieval.
- **sadstore** (`services/sadstore`) — Replicated self-addressed data store. Content-addressed objects (MinIO) + authenticated chained records (PostgreSQL). See `docs/design/sadstore.md`.
- **gossip** (`services/gossip`) — Gossip service. Syncs KELs and SAD data between peers (HyParView + PlumTree). See `docs/gossip.md`.
- **registry** (`services/registry`) — Registry service. Peer lifecycle via OpenRaft consensus. See `docs/registry.md`.
- **identity** (`services/identity`) — Identity service. Manages the registry's own KEL and signing keys.

### Libraries

- **kels-core** (`lib/kels`) — Core library. Types, KEL logic, client, error types, cache.
- **kels-gossip-core** (`lib/gossip`) — Custom gossip protocol library (HyParView + PlumTree over TCP with ML-KEM-1024 + ML-DSA-65/ML-DSA-87 + AES-GCM-256).
- **kels-derive** (`lib/derive`) — Derive macros (`SignedEvents`, etc.).
- **kels-ffi** (`lib/ffi`) — C FFI bindings for cross-language use.
- **kels-mock-hsm** (`lib/mock-hsm`) — Mock HSM PKCS#11 cdylib implementing ML-DSA-65 and ML-DSA-87 via fips204. Identity loads it directly via cryptoki. In production, swap the .so path for a real HSM's PKCS#11 library.

### Clients

- **kels-cli** (`clients/cli`) — Command-line client for interacting with KELS.
- **kels-bench** (`clients/bench`) — Benchmarking tool.
- **kels-client** (`clients/ios`) — Swift client (iOS/macOS).

### Event Transfer Helpers

All multi-page event transfers use the `transfer_key_events` infrastructure in `lib/kels/src/types/kel/sync.rs`. Never use single-page `fetch_key_events` in loops or accumulate unbounded events in memory — use these helpers instead.

**Traits:**
- **`PagedKelSource`** — paginated event source (e.g., HTTP endpoint, local DB).
- **`PagedKelSink`** — paginated event destination.

**Implementations:**
- **`HttpKelSource`** / **`HttpKelSink`** — HTTP-based source/sink. Create from `KelsClient` via `as_kel_source()` / `as_kel_sink()`.
- **`StoreKelSource`** — wraps a `KelStore` (local DB) as a `PagedKelSource`.
- **`RepositoryKelStore`** — wraps a repository as a `PagedKelSink` for DB writes.

**Transfer functions** (all page-at-a-time, divergence-aware, memory-bounded):
- **`transfer_key_events`** — Core (private). Pages through source, optionally verifies via `KelVerifier`, sends to sink. Handles divergence-aware ordering across page boundaries (held-back events, deferred fork identification, composite SAID cursors).
- **`forward_key_events`** — Forward without verification. Use for serving/forwarding between services. Supports `since` for delta fetch.
- **`verify_key_events`** — Verify only (discards events). Returns `Verification` token. Use for consuming (security decisions) when you don't need the events.
- **`completed_verification`** — Verify only (offset-based `PageLoader`). Returns `Verification` token. Alternative to `verify_key_events` for DB-backed sources.

**Collecting functions** (accumulate into memory — only use in true clients like CLI, never in services):
- **`collect_key_events`** — Verify + collect. Returns `(Verification, Vec<SignedKeyEvent>)`.
- **`resolve_key_events`** — Collect without verification. Bounded by `max_pages` but accumulates all events. Supports `since`.

### Verification Invariant

The DB cannot be trusted. All operations on KEL data fall into three categories:

1. **Serving** — returning data to a client/peer. No verification needed; the receiver verifies.
2. **Consuming** — using data for security decisions. Requires a `Verification` token, obtainable only via `KelVerifier::into_verification()`. The type system enforces this.
3. **Resolving** — comparing state to decide whether to sync. Wrong answers trigger unnecessary syncs (which verify), not security holes.

### Storage

Events are stored in PostgreSQL via the `verifiable-storage` framework (`Stored`, `SignedEvents`, `Chained`, `SelfAddressed` derive macros). Transactional operations use `KelTransaction` (PG transaction + advisory lock).

- All KEL queries use `ORDER BY serial ASC, CASE kind ... END ASC, said ASC` for deterministic pagination across divergent events. The CASE expression uses `EventKind::sort_priority_mapping()`.
- `MINIMUM_PAGE_SIZE` (64) / `page_size()` — page size for database queries and HTTP responses. Operators may increase via `KELS_PAGE_SIZE` but cannot go below `MINIMUM_PAGE_SIZE`. The minimum defines the security bound for proactive ROR enforcement.
- Pre-serialized JSON cache in Redis for KELs ≤ `page_size()` events (one page); Redis pub/sub for cache invalidation.
- Verifiable data patterns:
    - Creator sends full records as the payload (no wrapper types) and anchors by SAID in their KEL.
    - Verifier receives full records, verifies structure (SAID/prefix), chain integrity, and anchoring.
