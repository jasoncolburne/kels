# KELS - Key Event Log System

## System Thesis

Kels is a fail-secure application framework built on **decentralized, tamper-evident, authentic data**. All system state lives in append-only chains of cryptographically-linked events that entities throughout the network hold and verify independently — no central authority, no trust by fiat. Each primitive plays a distinct structural role:

- **KEL** — anchors authenticity to devices. A device's cryptographic chain of custody; signing a SAID under a KEL ixn proves the device produced or endorsed that data. Replicated/served by `services/kels/`.
- **IEL** — governs identities. Aggregates devices and other identities into logical groupings via `auth_policy` and `governance_policy` declarations on its event chain; immunity rules keep past authorizations stable. Identity is the unit at which credentials are issued. Hosted in SADStore alongside SEL.
- **SEL** — content-addressed application data. Identity-rooted chains (each SEL binds at inception to an IEL prefix) carrying domain payloads — exchange-key publications, custody envelopes, etc. Auth resolves through the bound IEL. Hosted in SADStore.
- **Credentials** — verifiable claims that permit access to resources based on authenticated identity. Issued under policies anchored in KELs/IELs; verified by the resource holder against the issuer's chain state.

**Evaluation lens for any gap, deviation, or design choice:** does it preserve or strengthen tamper-evidence? Does it preserve or strengthen authenticity at the device boundary (KEL) or identity boundary (IEL)? Does it preserve fail-secure behavior — i.e., when the system can't determine an answer with confidence, does it default to refusing rather than guessing? Decentralized data systems get attacked at the seams between primitives; every design decision should be evaluated by what it does to the trust graph at those seams. See `docs/deviations/README.md` for the durable record of where implementation diverges from plan and why.

## Build & Verify

- `make` verifies changes (fmt, deny, clippy, test, build). Never use naked cargo commands.
- When landing a rename, add retired tokens to `.terminology-forbidden` so `make lint-terminology` catches future regressions.
- `make coverage` for per-file coverage. Individual targets: `make fmt`, `make clippy`, etc.
- `TEST_ARGS` on `make test` / `make test-verbose` forwards flags to `cargo test` for iterating on one suite (`TEST_ARGS="--test sad_builder_tests"`) or one package (`TEST_ARGS="-p kels-core"`). Use while iterating; still run the full `make` before calling a change done.
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

**KEL** — append-only chain of key events sharing a prefix. Each event links to the previous via SAID. Forward commitments via `rotation_hash = Blake3(next_public_key)`. Recovery/contest/decommission require dual signatures. Delegation trust is NOT verified by the service. See `docs/design/kel/events.md`, `docs/design/kel/verification.md`, `docs/design/streaming-verification-architecture.md`.

**Divergence** — conflicting events at the same serial. Chain freezes until recovery. See `docs/design/kel/event-log.md`, `docs/design/kel/recovery-workflow.md`, `docs/design/kel/reconciliation.md`.

**Effective SAID** — tip SAID for normal chains; `hash_effective_said("divergent:{prefix}")` for divergent; `hash_effective_said("contested:{prefix}")` for contested. See `docs/design/kel/merge.md`.

**Merge results**: Accepted, Recovered, Contested, Diverged, RecoverRequired, ContestRequired.

**Policy** — DSL for authorization: `endorse(PREFIX)`, `delegate(DELEGATOR, DELEGATE)`, `threshold(MIN, [NODES])`, `weighted(MIN_WEIGHT, [NODE:W])`, `policy(SAID)` nesting; per-policy `poison` / `immune` modes. See `docs/design/policy.md`.

**Credentials** — verifiable claims issued under a policy, anchored in KELs. See `docs/design/creds.md`.

**Exchange** — ESSR authenticated encryption, ML-KEM key publication via SAD Event Logs. See `docs/design/exchange.md`.

**Federation** — peer lifecycle via registries, gossip mesh, secure registration. See `docs/design/federation-state-machine.md`, `docs/design/secure-registration.md`, `docs/design/registry-removal.md`, `docs/design/rejection-threshold.md`.

**SAD Event Log (SEL)** — append-only, versioned, identity-rooted data chain in SADStore. Each chain is bound at inception to a specific Identity Event Log via the `identity` field on `Icp`; every v1+ event references a specific IEL event by SAID via `identity_event` to resolve its authorization. SE events do not carry policy fields — auth and governance resolve via `IelResolver` against the bound IEL event (Upd → IEL `auth_policy`; Sea/Rpr/Cnt/Dec → IEL `governance_policy`). Lifecycle: `Icp`/`Upd` (with `[Icp, Upd]` minimum inception batch rule), `Sea` (degenerate seal marker), `Rpr` (repair on unsealed divergence), `Cnt`/`Dec` (terminal). See `docs/design/sel/events.md`, `docs/design/sel/event-log.md`, and the IEL primitive below.

**Identity Event Log (IEL)** — chain primitive that governs an identity. Carries `auth_policy` and `governance_policy` declarations (`Icp`) and evolutions (`Evl`); terminal via `Cnt` (contest, the only divergence resolver — IEL has no `Rpr`) or `Dec` (decommission). Every IEL event — including `Icp` — is governance-authorized (anchored under the chain's `governance_policy`); `auth_policy` is the per-event policy declaration consumed by SEL `Upd` via `identity_event` binding. Every introduced/evolved policy must be `immune: true`. Hosted in `services/sadstore/` alongside SE; `iel_events` table, `/api/v1/iel/events*` routes, `iel_updates` Redis channel, `kels/gossip/v1/topics/iel` gossip topic. See `docs/design/iel/events.md`, `docs/design/iel/event-log.md`, `docs/design/iel/verification.md`, `docs/design/iel/merge.md`.

**Custody** — per-SAD-object authority. Inline `custody.write` (IELSaid; one-time anchored write attestation; satisfied at write time) and `custody.read` (IELPrefix; identity-current; resolved through the IEL's current `auth_policy` at read time). Decoupled from `availability` (replication + lifecycle; sibling top-level field). See `docs/design/sadstore.md` and `docs/design/iel/event-log.md §Cascading effect on dependent SE chains`.

## Architecture

### Services

- **kels** — KEL submission and retrieval
- **sadstore** — content-addressed data store (RustFS + PostgreSQL). Also hosts Identity Event Log routes (`/api/v1/iel/events*`). See `docs/design/sadstore.md`, `docs/design/iel/`
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
