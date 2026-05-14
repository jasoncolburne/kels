# KELS - Key Event Log System

## System Thesis

Kels is a fail-secure application framework built on **decentralized, tamper-evident, authentic data**. All system state lives in append-only chains of cryptographically-linked events that entities throughout the network hold and verify independently — no central authority, no trust by fiat. Each primitive plays a distinct structural role:

- **KEL** — anchors authenticity to devices. A device's cryptographic chain of custody; signing a SAID under a KEL `Ixn` proves the device produced or endorsed that data.
- **IEL** — governs identities. Aggregates devices and other identities into logical groupings via `auth_policy` and `governance_policy` declarations on its event chain; immunity rules keep past authorizations stable. Identity is the unit at which credentials are issued.
- **SEL** — content-addressed application data. Identity-rooted chains (each SEL binds at inception to an IEL prefix) carrying domain payloads — exchange-key publications, custody envelopes, etc. Auth resolves through the bound IEL.
- **Credentials** — verifiable claims that permit access to resources based on authenticated identity. Issued under policies anchored in KELs/IELs; verified by the resource holder against the issuer's chain state.

KEL chains are hosted in `services/kels/`; IEL and SEL chains both live in `services/sadstore/`.

### Evaluation lens

For any gap, deviation, or design choice: does it preserve or strengthen tamper-evidence? Does it preserve or strengthen authenticity at the device boundary (KEL) or identity boundary (IEL)? Does it preserve fail-secure behavior — i.e., when the system can't determine an answer with confidence, does it default to refusing rather than guessing? Decentralized data systems get attacked at the seams between primitives; every design decision should be evaluated by what it does to the trust graph at those seams. See `docs/deviations/README.md` for the durable record of where implementation diverges from plan and why.

### Key Doctrines

- **Compromise is permanent — protocol authority is current-state-only.** Past keys, past policies, past endorsers have zero structural ability to act on a chain. A KEL signing/recovery key rotated out, an IEL `governance_policy` superseded by `Evl`, an SEL `identity_event` binding ratcheted past — none retain protocol authority. See [docs/design/protocol-doctrine.md §Compromise is Permanent](docs/design/protocol-doctrine.md#compromise-is-permanent).
- **Contested termination follows `v_{tip-1}`.** `Cnt`'s parent rule across linear and divergent chain shapes preserves operator recourse against signing-key-only Rot takeover (KEL specifically). The post-seal window is **protocol-bounded** on KEL and SEL (proactive caps); IEL has no post-seal window (every non-terminal event advances the seal), with stale-policy hygiene operator-side via `Evl`. See [docs/design/protocol-doctrine.md §Privileged Divergence is Terminal; Cnt Triggers It Uniformly](docs/design/protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly) and [docs/design/protocol-doctrine.md §Forks are Seal-Bounded](docs/design/protocol-doctrine.md#forks-are-seal-bounded).
- **Defense against current-state compromise is operational.** High thresholds, monitoring, custody separation, frequent device-key rotation, abandon-and-reincept. Multi-party governance must serialize submissions above the protocol (designated submitter, leader election, or consensus over the registry); for high-stakes IEL identities this is load-bearing, not optional. See [docs/design/primitives/iel/event-log.md §Multi-Party Governance Synchronization](docs/design/primitives/iel/event-log.md#multi-party-governance-synchronization).
- **Cascade-reincept honesty.** A contested **IEL** invalidates every SEL bound to it — those SELs reincept under a new prefix. A contested **SEL** is just dead in place. A contested **KEL** is more nuanced: dependents only need to reincept when the contested KEL actually anchored events on them AND the relevant policy lacks threshold redundancy; threshold-redundant policies (`M > N` across distinct custodians) absorb single-member contest via `Evl` rotating the contested KEL out. The expensive case is contesting an **IEL at the root of a dependency tree** — don't put your entire dependent tree under a single root. See [docs/design/protocol-doctrine.md §Adversary Patience and Policy Redundancy](docs/design/protocol-doctrine.md#adversary-patience-and-policy-redundancy).
- **Federation convergence.** Gossip propagation + deterministic effective-SAID resolution ensures every chain converges on the same semantic state across all nodes. Load-bearing for `Cnt Overrides Dec`, the upgrade rule, and end-verifiability over data-from-any-source. Single-node deployments forfeit this property. See [docs/design/protocol-doctrine.md §Federation Convergence](docs/design/protocol-doctrine.md#federation-convergence).

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

**Key Event Log (KEL)** — append-only chain of key events sharing a prefix. Each event links to the previous via SAID. Forward commitments via `rotation_hash = Blake3(next_public_key)`. Recovery/contest/decommission require dual signatures. Delegation trust is NOT verified by the service. See `docs/design/primitives/kel/events.md`, `docs/design/primitives/kel/verification.md`, `docs/design/infrastructure/streaming.md`.

**Divergence** — conflicting events at the same serial. Chain freezes until recovery. See `docs/design/primitives/kel/event-log.md`, `docs/design/primitives/kel/recovery-workflow.md`, `docs/design/primitives/kel/reconciliation.md`.

**Effective SAID** — tip SAID for normal chains; `hash_effective_said("divergent:{prefix}")` for divergent; `hash_effective_said("contested:{prefix}")` for contested. See `docs/design/primitives/kel/merge.md`.

**Merge results**: Accepted, Recovered, Contested, Diverged, RecoverRequired, ContestRequired.

**Policy** — DSL for authorization: `endorse(PREFIX)`, `delegate(DELEGATOR, DELEGATE)`, `threshold(MIN, [NODES])`, `weighted(MIN_WEIGHT, [NODE:W])`, `policy(SAID)` nesting; per-policy `poison` / `immune` modes. See `docs/design/features/policy.md`.

**Credentials** — verifiable claims issued under a policy, anchored in KELs. See `docs/design/features/creds.md`.

**Exchange** — ESSR authenticated encryption, ML-KEM key publication via SAD Event Logs. See `docs/design/features/exchange.md`.

**Federation** — peer lifecycle via registries, gossip mesh, secure registration. See `docs/design/infrastructure/federation-state-machine.md`, `docs/design/infrastructure/secure-registration.md`, `docs/operations/registry-removal.md`, `docs/design/infrastructure/rejection-threshold.md`.

**SAD Event Log (SEL)** — append-only, versioned, identity-rooted data chain in SADStore. Each chain is bound at inception to a specific Identity Event Log via the `identity` field on `Icp`; every v1+ event references a specific IEL event by SAID via `identity_event` to resolve its authorization. SEL events do not carry policy fields — auth and governance resolve via `IelResolver` against the bound IEL event (Est/Upd → IEL `auth_policy`; Sea/Rpr/Cnt/Dec → IEL `governance_policy`). Lifecycle: `Icp` (permissionless v0), `Est` (binding-establishment at v1, tier-2 anchored per anchor-tier-elevation; inception batch `[Icp, Est]` minimum), `Upd` (routine content extension at v2+), `Sea` (re-evaluates IEL binding; may advance `identity_event` to a newer IEL state), `Rpr` (repair on unsealed divergence), `Cnt`/`Dec` (terminal). See `docs/design/primitives/sel/events.md`, `docs/design/primitives/sel/event-log.md`, `docs/design/protocol-doctrine.md §Anchor Tier Elevation`, and the IEL primitive below.

**Identity Event Log (IEL)** — chain primitive that governs an identity. Carries `auth_policy` and `governance_policy` declarations (`Icp`) and evolutions (`Evl`); `Sea` advances the seal without policy evolution (closes the post-exclusion-evolution window per protocol-doctrine §Exclusion Evolutions and the Seal Advance); terminal via `Cnt` (contest — IEL divergence is structurally contested-terminal at first 2-event observation; IEL has no `Rpr`) or `Dec` (decommission). Every IEL event — including `Icp` — is governance-authorized (anchored under the chain's `governance_policy`); `auth_policy` is the per-event policy declaration consumed by SEL `Est`/`Upd` via `identity_event` binding. Every introduced/evolved policy must be `immune: true`. Hosted in `services/sadstore/` alongside SE; `iel_events` table, `/api/v1/iel/events*` routes, `iel_updates` Redis channel, `kels/gossip/v1/topics/iel` gossip topic. See `docs/design/primitives/iel/events.md`, `docs/design/primitives/iel/event-log.md`, `docs/design/primitives/iel/verification.md`, `docs/design/primitives/iel/merge.md`.

**Custody** — per-SAD-object authority. Inline `custody.write` (IELSaid; one-time anchored write attestation; satisfied at write time) and `custody.read` (IELPrefix; identity-current; resolved through the IEL's current `auth_policy` at read time). Decoupled from `availability` (replication + lifecycle; sibling top-level field). See `docs/design/infrastructure/sadstore.md` and `docs/design/primitives/iel/event-log.md §Cascading effect on dependent SELs`.

## Architecture

### Services

- **kels** — KEL submission and retrieval
- **sadstore** — content-addressed data store (RustFS + PostgreSQL). Also hosts Identity Event Log routes (`/api/v1/iel/events*`). See `docs/design/infrastructure/sadstore.md`, `docs/design/primitives/iel/`
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
