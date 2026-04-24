# KELS - Key Event Log System

## Build & Verify

- `make` verifies changes (fmt, deny, clippy, test, build). Never use naked cargo commands.
- When landing a rename, add retired tokens to `.terminology-forbidden` so `make lint-terminology` catches future regressions.
- `make coverage` for per-file coverage. Individual targets: `make fmt`, `make clippy`, etc.
- **`make` is slow (minutes). Run it ONCE and tee output to a file**, then grep/tail the file repeatedly instead of re-running: `make 2>&1 | tee /tmp/make.log`. Do not run `make | tail -N` then `make | grep foo` then `make | head -N` — you just burned 3× the time for one build.
- Dependency crates at `../verifiable-storage-rs`, `../cacheable`, `../cesr-rs`.
- When adding a `lib/` crate dependency, update Garden config and Dockerfile too.
- After substantial changes: deploy → federation → voting → gossip → adversarial tests.

## Code Style

**Imports**: three groups (std, external, local), nested, blank-line separated. `rustfmt` handles sorting within groups. Fix grouping when touching a file.

```rust
use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use verifiable_storage::{SelfAddressed, StorageError};

use crate::{handlers::AppState, repository::KelsRepository};
```

**Rules**:
- Fail **secure**, not safe.
- Greenfield — edit migrations in place, no new migration files.
- Never hardcode event/record kind strings — use enum methods.
- Never `.unwrap()`. Use `.expect("reason")` with `#[allow(clippy::expect_used)]`.
- Use `cesr` types for all cryptographic material. Parse at boundaries, pass typed values.
- `create()` not `new()` for `SelfAddressed` types (`new()` leaves SAID as placeholder).
- Sign the SAID's QB64 bytes, never serialized payloads.
- All HTTP endpoints: POST with JSON bodies. No identifiers in URL paths or query params.

## Core Concepts

**Prefix** — persistent chain identifier. Derived from inception event with both `said` and `prefix` set to placeholders before Blake3. Different from SAID (which only blanks `said`). Stable across chain lifetime.

**SAID** — Blake3-256 hash of content (with `said` field blanked), encoded as 44-char Base64 via CESR. Content-addressable identifier.

**CESR** — binary-safe encoding for cryptographic primitives (SAIDs, signatures, keys, digests).

**KEL** — append-only chain of key events sharing a prefix. Each event links to the previous via SAID. Forward commitments via `rotation_hash = Blake3(next_public_key)`. Recovery/contest/decommission require dual signatures. Delegation trust is NOT verified by the service. See `docs/design/verification.md`, `docs/design/streaming-verification-architecture.md`.

**Divergence** — conflicting events at the same serial. Chain freezes until recovery. See `docs/design/divergence-detection.md`, `docs/design/recovery-workflow.md`, `docs/design/reconciliation.md`.

**Effective SAID** — tip SAID for normal chains; `hash_effective_said("divergent:{prefix}")` for divergent; `hash_effective_said("contested:{prefix}")` for contested. See `docs/design/merge.md`.

**Merge results**: Accepted, Recovered, Contested, Diverged, RecoverRequired, ContestRequired.

**Policy** — DSL for authorization: `endorse`, `credential`, `threshold`, poison, expiry, renew. See `docs/design/policy.md`.

**Credentials** — verifiable claims issued under a policy, anchored in KELs. See `docs/design/creds.md`.

**Exchange** — ESSR authenticated encryption, ML-KEM key publication via SAD Event Logs. See `docs/design/exchange.md`.

**Federation** — peer lifecycle via registries, gossip mesh, secure registration. See `docs/design/federation-state-machine.md`, `docs/design/secure-registration.md`, `docs/design/registry-removal.md`, `docs/design/rejection-threshold.md`.

**SAD Event Log** — append-only, versioned, policy-governed data chain in SADStore. Each event links to the previous via SAID and is authorized by `write_policy`. Governance policy bounds divergence. See `docs/design/sad-events.md`.

## Architecture

### Services

- **kels** — KEL submission and retrieval
- **sadstore** — content-addressed data store (MinIO + PostgreSQL). See `docs/design/sadstore.md`
- **gossip** — KEL/SAD sync between peers (HyParView + PlumTree). See `docs/gossip.md`
- **registry** — peer lifecycle via OpenRaft. See `docs/registry.md`
- **identity** — node KEL and signing keys

### Libraries

- **kels-core** (`lib/kels`) — types, KEL logic, client, cache
- **kels-creds** (`lib/creds`) — credential issuance, verification, schemas
- **kels-policy** (`lib/policy`) — policy DSL evaluation
- **kels-exchange** (`lib/exchange`) — ESSR encryption, ML-KEM key publication, mail client
- **kels-gossip-core** (`lib/gossip`) — gossip protocol (ML-KEM-1024 + ML-DSA + AES-GCM-256)
- **kels-derive** (`lib/derive`) — derive macros
- **kels-ffi** (`lib/ffi`) — C FFI bindings
- **kels-mock-hsm** (`lib/mock-hsm`) — mock PKCS#11 HSM (ML-DSA-65/87 via fips204)

### Clients

- **kels-cli** (`clients/cli`), **kels-bench** (`clients/bench`), **kels-client** (`clients/ios` — Swift)

### Event Transfer

All multi-page transfers use `transfer_key_events` infrastructure in `lib/kels/src/types/kel/sync.rs`. Never use single-page `fetch_key_events` in loops. Key functions: `forward_key_events` (serve), `verify_key_events` / `completed_verification` (consume → `Verification` token), `collect_key_events` / `resolve_key_events` (client-only, accumulates into memory).

### Verification Invariant

The DB cannot be trusted. Three categories:
1. **Serving** — no verification; receiver verifies
2. **Consuming** — requires `Verification` token from `KelVerifier::into_verification()`
3. **Resolving** — wrong answers trigger unnecessary syncs, not security holes

### Storage

PostgreSQL via `verifiable-storage` (`Stored`, `SignedEvents`, `Chained`, `SelfAddressed` derives). Transactional ops use `KelTransaction` (PG transaction + advisory lock). Deterministic pagination: `ORDER BY serial ASC, CASE kind ... END ASC, said ASC`. Min page size 64 (security bound for proactive ROR). Redis cache for single-page KELs; pub/sub for invalidation.

## Getting Started

If you are working in a two-agent flow, ask the user whether you are the **design agent** or the **implementation agent**, then read the corresponding prompt from `prompts/`:
- Design: `prompts/design-agent-init.md`
- Implementation: `prompts/implementation-agent-init.md`
