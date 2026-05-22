# KELS - Key Event Log System

## System Thesis

Kels is a fail-secure application framework built on **decentralized, tamper-evident, authentic data**. System state lives in append-only chains of cryptographically-linked events that entities throughout the network hold and verify independently — no central authority, no trust by fiat. Each primitive plays a distinct structural role:

- **KEL** — anchors authenticity to devices. A device's cryptographic chain of custody; signing a SAID under a KEL event proves the device produced or endorsed that data.
- **IEL** — governs identities. Aggregates devices and other identities into logical groupings via `authPolicy` and `governancePolicy` declarations on its event chain; immunity rules keep past authorizations stable. Identity is the unit at which credentials are issued.
- **SEL** — content-addressed application data. Identity-rooted chains (each SEL binds at inception to an IEL prefix) carrying domain payloads — exchange-key publications, custody envelopes, etc. Auth resolves through the bound IEL.
- **Credentials** — verifiable claims that permit access to resources based on authenticated identity. Issued under policies anchored in KELs/IELs; verified by the resource holder against the issuer's chain state.

KEL chains are hosted in `services/kels/`; IEL and SEL chains both live in `services/sadstore/`.

### Evaluation lens

For any gap, deviation, or design choice: does it preserve or strengthen tamper-evidence? Does it preserve or strengthen authenticity at the device boundary (KEL) or identity boundary (IEL)? Does it preserve fail-secure behavior — i.e., when the system can't determine an answer with confidence, does it default to refusing rather than guessing? Decentralized data systems get attacked at the seams between primitives; every design decision should be evaluated by what it does to the trust graph at those seams. See `docs/deviations/README.md` for the durable record of where implementation diverges from plan and why.

### Key Doctrines

- **Compromise is permanent — protocol authority is current-state-only.** Authority over a chain belongs only to its currently-tracked state; past keys, past policies, and past endorsers have zero structural ability to act once supplanted. (Example: a KEL signing key rotated out cannot extend the chain even if the adversary still holds it.) See [docs/design/protocol-doctrine.md §Compromise is Permanent](docs/design/protocol-doctrine.md#compromise-is-permanent).

- **Privileged-divergence-is-terminal; universal locking.** A privileged event (KEL: `Ror`/`Dec`; SEL: `Sea`/`Dec`; IEL: `Evl`/`Dec`) landing in a non-privileged divergent set transitions the chain to Contested via the upgrade rule. Once any privileged event has landed at `v_d` on a chain, the seal-cap (`parent_serial >= seal_serial`) rejects every subsequent submission whose parent sits in the locked portion — no carve-outs, no boundary cases. Federation races between concurrent privileged submissions do not structurally converge at the protocol layer; convergence is provided at the infrastructure layer (see [#205](https://github.com/jasoncolburne/kels/issues/205)). See [docs/design/protocol-doctrine.md §Privileged Divergence is Terminal](docs/design/protocol-doctrine.md#privileged-divergence-is-terminal) and [§Limit of the doctrine — concurrent privileged event races](docs/design/protocol-doctrine.md#concurrent-privileged-event-races).

- **Forks are seal-bounded.** A new event's serial must land at-or-after the chain's most-recent privileged-non-terminal event (`lastSealAdvancingEvent`). The bound is protocol-enforced on KEL/SEL via proactive caps; on IEL every non-terminal event advances the seal so there is no post-seal window, and stale-policy hygiene is operator-side via `Evl`. See [docs/design/protocol-doctrine.md §Forks are Seal-Bounded](docs/design/protocol-doctrine.md#forks-are-seal-bounded).

- **Defense against current-state compromise is layered.** KEL's dual-signature requirement on `Rec`/`Ror`/`Dec` blocks signing/rotation-key compromise (exfiltration, brute force, coerced signing, side channels) regardless of where the recovery key is custodied — a single-device deployment is first-class. IEL policy composition (high thresholds, `M > N` redundancy across distinct custodians) handles total device compromise: burn the device, rotate it out via `Evl`. KEL-internal custody separation (recovery key on a different device, HSM, ceremony-gated) is an optional deployment hardening for threat shapes where signing and recovery would otherwise fall together.

- **Operational hardening composes on top of the protocol layer.** Monitoring for unexpected governance/rotation events; fast detect-to-recover response (`Rec`/`Rpr`); abandon-and-reincept as last resort. Multi-party governance must serialize submissions above the protocol (designated submitter, leader election, or consensus over the registry); for high-stakes IEL identities this is load-bearing, not optional. See [docs/operations/multi-party-governance.md](docs/operations/multi-party-governance.md).

- **Cascade-reincept honesty.** Reincept is needed when the *primitive itself* is contested, not when a referenced primitive is:
  - **IEL contested** → every SEL bound to it must reincept under a new prefix.
  - **SEL contested** → the SEL is dead in place; nothing downstream cascades.
  - **KEL contested** → dependents only reincept when the contested KEL actually anchored events on them AND the relevant policy lacks threshold redundancy. Policies with `M > N` across distinct custodians absorb single-member contest via `Evl` rotating the contested KEL out.

  The expensive case is contesting an **IEL at the root of a dependency tree** — partition identity hierarchies so any single contest has bounded blast radius. See [docs/design/protocol-doctrine.md §Adversary Patience and Policy Redundancy](docs/design/protocol-doctrine.md#adversary-patience-and-policy-redundancy).

- **Federation convergence.** Gossip propagation + deterministic effective-SAID resolution ensures every chain converges on the same semantic state across all nodes. Load-bearing for the upgrade rule and end-verifiability over data-from-any-source. Single-node deployments forfeit this property. See [docs/design/protocol-doctrine.md §Federation Convergence](docs/design/protocol-doctrine.md#federation-convergence).

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

## Doc Style

**Diagram annotations.** In ASCII diagrams (chain shapes, scenario walkthroughs, state transitions), keep in-diagram text terse — short pointer labels like `(tip)`, `(adversary)`, `→ contested`, `(terminal)`. Multi-sentence explanations of *why* a step does what it does go in prose above or below the diagram, not inside it. The reader's eye can't track both an ASCII layout and paragraph-length annotations at the same time; separating the two lets the diagram carry shape and the prose carry argument.

## Core Concepts

**Prefix** — persistent chain identifier. Derived from inception event with both `said` and `prefix` set to placeholders before Blake3. Different from SAID (which only blanks `said`). Stable across chain lifetime.

**SAID** — Blake3-256 hash of content (with `said` field blanked), encoded as 44-char Base64 via CESR. Content-addressable identifier.

**CESR** — binary-safe encoding for cryptographic primitives (SAIDs, signatures, keys, digests).

**Key Event Log (KEL)** — append-only chain of key events sharing a prefix. Each event links to the previous via SAID. Forward commitments via `rotationHash = Blake3(next_public_key)`. Recovery/contest/decommission require dual signatures. Delegation trust is NOT verified by the service. See `docs/design/primitives/data/event-logs/kel/events.md`, `docs/design/primitives/data/event-logs/kel/verification.md`, `docs/design/protocol-doctrine.md` §Part 3 (cross-primitive verification doctrine: streaming, tokens, effective-SAID synthetic comparison).

**Divergence** — conflicting events at the same serial. Chain transitions to Divergent (recoverable via `Rec`/`Rpr` when non-privileged) or directly to Contested (terminal — when the divergent set contains a privileged event, per privileged-divergence-is-terminal). See `docs/design/primitives/data/event-logs/kel/event-log.md`, `docs/design/primitives/data/event-logs/kel/recovery-workflow.md`, `docs/design/primitives/data/event-logs/kel/reconciliation.md`.

**Effective SAID** — tip SAID for normal chains (including decommissioned); `hash_effective_said("divergent:{prefix}")` for divergent; `hash_effective_said("contested:{prefix}")` for contested. Under #214 the contested-prefix surface is federation-layer-sourced (per #205), not per-node-state-derived — the service returns the synthetic in the response when it knows the prefix is contested. See `docs/design/primitives/data/event-logs/kel/merge.md`.

**Merge results**: Accepted, Recovered, Diverged, RecoverRequired, ParentLocked.

**Policy** — DSL for authorization: `endorse(PREFIX)`, `identity(PREFIX)`, `delegate(DELEGATOR)`, `threshold(MIN, [NODES])`, `weighted(MIN_WEIGHT, [NODE:W])`, `policy(SAID)` nesting; per-policy `poison` / `immune` modes. `delegate(DELEGATOR)` is the open form — the specific delegate is discovered at policy-evaluation time. See `docs/design/features/policy.md`.

**Credentials** — verifiable claims issued under a policy, anchored in KELs. See `docs/design/features/creds.md`.

**Exchange** — ESSR authenticated encryption, ML-KEM key publication via SAD Event Logs. See `docs/design/features/exchange.md`.

**Federation** — itself an identity. Membership lives on a single shared IEL (the *federation IEL*) whose `authPolicy` declares authorized peers; membership changes are governance-authorized `Evl` events. Each peer publishes its own network endpoints via a per-peer address SEL at a deterministic prefix. Handshake authorization is `evaluate_signed_policy` against the federation IEL's current `authPolicy`. See `docs/design/infrastructure/federation.md`, `docs/design/infrastructure/discovery.md`, `docs/design/infrastructure/peer-identity.md`.

**SAD Event Log (SEL)** — append-only, identity-rooted data chain. Each chain is bound at inception to a specific Identity Event Log (`identity` field on `Icp`); every v1+ event references a specific IEL event by SAID via `ielEvent` to resolve its authorization. SEL events do not carry policy fields — auth and governance resolve via `IelResolver` against the bound IEL event (Est/Upd → IEL `authPolicy`; Sea/Rpr/Dec → IEL `governancePolicy`).

- Kind set (sort-priority order): `Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Dec`.
- Inception: `Icp` is permissionless; `[Icp, Est]` is the minimum inception batch.
- Authorization and evolution: `Est` is tier-2 anchored per anchor-tier-elevation; `Rpr` repairs unsealed divergence; `Sea` re-evaluates the IEL binding and may advance `ielEvent`.

See `docs/design/primitives/data/event-logs/sel/events.md` and `docs/design/primitives/data/event-logs/sel/event-log.md`.

**Identity Event Log (IEL)** — chain primitive that governs an identity. Carries `authPolicy` and `governancePolicy` declarations (`Icp`) and evolutions (`Evl`); `Sea` advances the seal without policy evolution; terminal via `Dec` (decommission). Every IEL event is governance-authorized (anchored under the chain's `governancePolicy`); `authPolicy` is the per-event policy declaration consumed by SEL `Est`/`Upd` via `ielEvent` binding. Every introduced/evolved policy must be `immune: true`. IEL divergence is structurally contested-terminal at first 2-event observation; IEL has no `Rpr`.

Storage: `iel_events` table; `/api/v1/iel/events*` routes; `iel_updates` Redis channel; `kels/gossip/v1/topics/iel` gossip topic.

See `docs/design/primitives/data/event-logs/iel/events.md`, `docs/design/primitives/data/event-logs/iel/event-log.md`, `docs/design/primitives/data/event-logs/iel/verification.md`, `docs/design/primitives/data/event-logs/iel/merge.md`.

**Custody** — per-SAD-object authority via two independent flat top-level fields on the SAD wrapper. `ownerIelEvent` (IEL event SAID; one-time anchored write attestation; satisfied at write time, dereferencable for either point-in-time or identity-current verification) and `readPolicy` (policy SAID; evaluated at read time via `evaluate_signed_policy` against the verified prefix set from a `SignedRequest` — composable across identities via `identity(X)`, `threshold`, etc.). Decoupled from `availability` (replication + lifecycle; sibling top-level field). See `docs/design/infrastructure/sadstore.md` and `docs/design/primitives/data/event-logs/iel/event-log.md §Cascading effect on dependent SELs`.

## Architecture

### Services

- **kels** — KEL submission and retrieval
- **sadstore** — content-addressed data store (RustFS + PostgreSQL). Also hosts Identity Event Log routes (`/api/v1/iel/events*`). See `docs/design/infrastructure/sadstore.md`, `docs/design/primitives/data/event-logs/iel/`
- **gossip** — KEL/SAD sync between peers (HyParView + PlumTree); also hosts the federation IEL locally and walks per-peer address SELs for discovery. See `docs/design/infrastructure/gossip.md`, `docs/design/infrastructure/federation.md`, `docs/design/infrastructure/discovery.md`
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

All multi-page transfers use the `transfer_key_events` infrastructure in `lib/kels/src/types/kel/sync.rs`. Never use single-page `fetch_key_events` in loops.

Key functions:

- `forward_key_events` — server-side fan-out.
- `verify_key_events` / `completed_verification` — consume; returns a `Verification` token.
- `collect_key_events` / `resolve_key_events` — client-only; accumulates the chain into memory.

### Verification Invariant

The DB cannot be trusted. Three categories:
1. **Serving** — no verification; receiver verifies
2. **Consuming** — requires `Verification` token from `KelVerifier::into_verification()`
3. **Resolving** — wrong answers trigger unnecessary syncs, not security holes

### Storage

PostgreSQL via `verifiable-storage` (`Stored`, `SignedEvents`, `Chained`, `SelfAddressed` derives). Transactional ops use `KelTransaction` (PG transaction + advisory lock). Deterministic pagination: `ORDER BY serial ASC, CASE kind ... END ASC, said ASC`. Min page size 64 (security bound for proactive ROR). Redis cache for single-page KELs; pub/sub for invalidation.
