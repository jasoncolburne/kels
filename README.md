# KELS - Key Event Log System

KELS is a federated decentralized key management infrastructure (DKMI), inspired by [KERI](https://github.com/WebOfTrust/keripy). It provides cryptographically verifiable identity management through key event logs with pre-rotation commitment, divergence detection, and recovery mechanisms — offering protection against key compromise without relying on certificate authorities or centralized trust.

## Why a DKMI?

The product of a DKMI is **portable identity** — cryptographic identity that belongs to the individual, not to any service provider.

Today, centralized platforms collect and store vast amounts of personal data, much of which they don't actually need. With portable identity, services only need to verify *that you are who you claim to be* — they don't need to be the source of truth for your identity, your data, or your relationships. The bulk of data storage and compute can be offloaded to consumer devices, where it belongs.

This shifts the balance of power. Data is owned and controlled by individuals, not held hostage by corporations. Your identity travels with you across services. Your keys rotate without anyone's permission. And if a service disappears, your identity doesn't disappear with it.

With [federated registries](docs/federation.md), KELS can also serve as a secure identity backbone for multi-cloud, multi-operator applications — independent organizations each run their own registry while sharing a global trust layer, without depending on any single certificate authority or cloud provider.

## How It Works

KELS implements a key event log system where:

- Each event commits to the *next* signing key before it's needed (**pre-rotation commitment**)
- A separate recovery key enables recovery from signing key compromise (**recovery keys**)
- Conflicting events at the same serial number are detected and stored (**divergence detection**)
- Legitimate owners can recover from adversarial events using their recovery key (**recovery protocol**)
- When both parties perform recovery operations, the KEL is permanently frozen (**contest mechanism**)

All events are self-addressing (content-addressed via SAID) and cryptographically signed, making the entire log tamper-evident and end-verifiable.

### Key Hierarchy

| Level | Key | Purpose |
|-------|-----|---------|
| 1 | **Signing key** | Signs normal events (`ixn`, `rot`) |
| 2 | **Rotation key** | Pre-committed next signing key, revealed during rotation |
| 3 | **Recovery key** | Used only for recovery events, highest authority |

### Event Types

Event kind values are version-qualified in serialized form (e.g. `kels/events/v1/icp`).

| Type | Description | Signatures Required |
|------|-------------|---------------------|
| `icp` | Incept — creates the KEL | Signing key |
| `dip` | Delegated Incept — creates a delegated KEL | Signing key |
| `rot` | Rotate — rotates signing key | Rotation key |
| `ixn` | Interact — anchors external data | Signing key |
| `ror` | Rotate Recovery — rotates recovery key | Rotation + Recovery |
| `rec` | Recover — recovers from divergence | Rotation + Recovery |
| `cnt` | Contest — freezes KEL permanently | Rotation + Recovery |
| `dec` | Decommission — ends the KEL | Rotation + Recovery |

### Compromise Scenarios

| Compromised Key | Adversary Can | Owner Recovery |
|-----------------|---------------|----------------|
| Signing only | Sign `ixn` events | `rec` event recovers KEL |
| Rotation | Sign `rot`, then any events | `rec` event recovers KEL |
| Rotation + Recovery | Full control | `cnt` event freezes KEL |

## Features

### Core

- **Key event logs** with full lifecycle: inception, rotation, interaction, delegation, recovery, contest, decommission
- **Divergence detection and recovery** — conflicting events stored in the KEL with cryptographic resolution
- **Type-safe verification** — `KelVerification` token enforced at compile time; unverified data cannot be used for security decisions
- **Self-addressing identifiers (SAIDs)** — content-addressed via Blake3-256 with CESR encoding

### Credentials and Policy

- **Credential framework** ([kels-creds](docs/design/creds.md)) — issuance, schema-aware compacted disclosure, and verification against KEL anchors
- **Policy engine** ([kels-policy](docs/design/policy.md)) — composable trust policies with `endorse`, `delegate`, `threshold`, `weighted`, and nested `policy` references; soft/hard/immune poisoning
- **Replicated self-addressed data store** ([sadstore](docs/design/sadstore.md)) — content-addressed objects (MinIO) + authenticated chained records (PostgreSQL), gossip-replicated

### Encrypted Exchange

- **ESSR authenticated encryption** ([kels-exchange](docs/design/exchange.md)) — Encrypt-Sender-Sign-Receiver providing four unforgeability properties via ML-KEM + AES-GCM-256 + ML-DSA
- **Credential exchange messaging** — IPEX-style protocol (Apply/Offer/Agree/Grant/Admit/Reject) with chained, self-addressed exchange threads
- **Mail service** ([mail](docs/design/mail.md)) — encrypted message delivery with per-sender/per-IP rate limiting, storage caps, blob integrity verification, and gossip-based metadata replication

### Infrastructure

- **Gossip replication** ([gossip](docs/gossip.md)) — HyParView + PlumTree with ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication + AES-GCM-256 encryption
- **Federated registries** ([federation](docs/federation.md)) — Raft consensus with multi-party voting for peer lifecycle; compile-time trust anchors
- **Automatic key rotation** — HSM-backed services rotate signing keys on a configurable schedule (default 180 days), with every third rotation covering the recovery key
- **Server-side caching** — Redis + W-TinyLFU local caching for high-throughput deployments

### Post-Quantum Cryptography

- **Signing:** ML-DSA-65 or ML-DSA-87 (FIPS 204) for all clients and infrastructure. Mobile clients may use P-256 as a fallback
- **Key exchange:** ML-KEM-768 or ML-KEM-1024 (FIPS 203) with forward secrecy via ephemeral keypairs
- **Gossip transport:** ML-KEM + ML-DSA + BLAKE3 KDF + AES-GCM-256
- **HSM:** PKCS#11 cdylib implementing ML-DSA-65 and ML-DSA-87 (swap the .so path for a real HSM in production)
- **Pre-rotation commitment** is inherently post-quantum secure — the BLAKE3 rotation hash reveals nothing about the next key until rotation occurs

### Platform Support

- **Key providers:** Software keys, macOS/iOS Secure Enclave, PKCS#11 HSMs, extensible `KeyProvider` trait
- **Clients:** Rust CLI, Swift (iOS/macOS), C FFI bindings for any language
- **Targets:** Native (Linux, macOS, Windows), WebAssembly (browser/wasm)

## Quick Start

### Single Node (Development)

A single KELS node provides the full KEL API without gossip or federation — just the kels service, PostgreSQL, and Redis:

```bash
garden deploy --env=standalone
```

`make deploy-fresh-node` deploys in ~2.5 minutes. `make test-node` deploys and runs tests against it.

### Full Federation

`make deploy-fresh-federation` deploys the entire federation (3+1 registries, 6 gossip nodes) in ~10 minutes. `make test-federation` deploys and runs the full test suite in ~35 minutes, leaving a working stack running in Kubernetes.

See [Deployment](docs/deployment.md) for details on the two-phase deployment process (standalone registries, collect prefixes, recompile with trust anchors, federate).

### Building

```bash
make build           # Build all packages
make all             # Full checks: format, deny, clippy, test, build
make fmt             # Format code
make clippy          # Run clippy lints
make test            # Run tests
make deny            # Check dependencies (requires cargo-deny)
make coverage        # Per-file coverage with cargo-llvm-cov
```

### Integration Tests

Requires [Garden](https://garden.io) >= 14.20 and a local Kubernetes cluster (Docker Desktop, minikube, kind, etc).

```bash
make deploy-fresh-node       # Deploy standalone node (~2.5 min)
make deploy-fresh-federation # Deploy full federation (~10 min)
make test-node               # Deploy + test standalone (~5 min)
make test-federation         # Deploy + full test suite (~35 min)

# iOS client (macOS — configure /etc/hosts first)
make ios-simulator
```

## Project Structure

```
kels/
├── lib/
│   ├── kels/           # Core library (types, verification, client, crypto, cache)
│   ├── derive/         # Derive macros for storage traits
│   ├── creds/          # Credential framework (issuance, disclosure, verification)
│   ├── policy/         # Policy framework (composable trust policies, DSL)
│   ├── exchange/       # Exchange protocol (ESSR encryption, messaging, mail types)
│   ├── ffi/            # FFI bindings (Swift/C interop)
│   ├── gossip/         # Custom gossip protocol library (HyParView + PlumTree)
│   └── mock-hsm/       # Mock HSM PKCS#11 cdylib (ML-DSA-65/ML-DSA-87)
├── services/
│   ├── kels/           # KEL HTTP API (event submission, verification, retrieval)
│   ├── sadstore/       # Replicated self-addressed data store (MinIO + PostgreSQL)
│   ├── mail/           # Encrypted message delivery service
│   ├── gossip/         # Gossip service (cross-deployment KEL/SAD/mail sync)
│   ├── registry/       # Federation registry (Raft consensus, peer voting)
│   ├── identity/       # Registry identity service (HSM-backed KEL management)
│   ├── minio/          # MinIO configuration (S3-compatible object storage)
│   ├── postgres/       # PostgreSQL configuration
│   └── redis/          # Redis configuration
├── clients/
│   ├── cli/            # Command-line interface
│   ├── ios/            # Swift client (iOS/macOS)
│   ├── bench/          # Benchmarking tool
│   └── test/           # Integration test scripts/container
└── docs/               # Documentation
```

## Deployed Topology

### Registry Nodes

Each registry runs: `identity`, `registry`, `postgres`, `redis`

### Gossip Nodes

Each gossip node runs: `identity`, `kels` (2 replicas), `gossip`, `sadstore`, `mail`, `postgres`, `redis`, `minio`

## Querying from the Host

To use the CLI or iOS app against a local deployment, configure hostname resolution and ingress.

### /etc/hosts

```text
127.0.0.1 kels.node-a.kels
127.0.0.1 kels.node-b.kels
127.0.0.1 kels.node-c.kels
127.0.0.1 kels.node-d.kels
127.0.0.1 kels.node-e.kels
127.0.0.1 kels.node-f.kels
127.0.0.1 sadstore.node-a.kels
127.0.0.1 sadstore.node-b.kels
127.0.0.1 sadstore.node-c.kels
127.0.0.1 sadstore.node-d.kels
127.0.0.1 sadstore.node-e.kels
127.0.0.1 sadstore.node-f.kels
127.0.0.1 mail.node-a.kels
127.0.0.1 mail.node-b.kels
127.0.0.1 mail.node-c.kels
127.0.0.1 mail.node-d.kels
127.0.0.1 mail.node-e.kels
127.0.0.1 mail.node-f.kels
127.0.0.1 registry.registry-a.kels
127.0.0.1 registry.registry-b.kels
127.0.0.1 registry.registry-c.kels
127.0.0.1 registry.registry-d.kels
```

### Ingress Controller

Certain versions of Garden create the Traefik ingress service as `ClusterIP` instead of `LoadBalancer`. On Docker Desktop, this prevents host access. If you get empty replies from `curl`, run:

```bash
make fix-ingress
```

## Differences from KERI

For a comprehensive comparison, see the [KERI vs KELS Comparative Analysis](docs/keri-comparison.md).

KELS borrows heavily from KERI's core concepts and terminology. The two things I've found most useful after discovering KERI are the creation of tamper-evident data with self-addressing identifiers, and pre-rotation commitment.

I used Base64 CESR to encode data, primarily to make development easier. I may change the encoding in the future.

### Primary difference

If divergence occurs, a single divergent event is accepted into a KEL, rather than rejected. When this happens, appending new events is not permitted until the divergence is resolved.

### Other notable differences

- **Prefix derivation**: The 'prefix' of a KEL was originally named (in KERI) to convey the value was the first SAID in the chain of key events, prefixing the sequence. Now, I've changed the algorithm (in `verifiable-storage-rs`) and they are no longer the same value. Why? Now they are computed almost identically, but the prefix is derived ahead of the said in the algorithm, which means that there is no way to correlate a naked SAID identifiying a key event with the owner of that event - which is a an improvement in some situations. We probably need to revisit the name throughout this codebase. You can still prove the prefix was derived with the said, given the full event.
- **No witnesses or receipts**: KERI relies on designated witness pools that sign receipts for events. KELS replaces this with gossip-based replication and registry-anchored peer allowlists — trust within the gossip network comes from KEL verification against compiled-in registry prefixes.
- **Divergence is observable, not private**: In KERI, duplicity is detected locally by comparing logs from different sources. In KELS, divergence is stored directly in the KEL and propagated to all nodes via gossip — it's a public, network-wide signal.
- **Recovery and contest protocol**: KELS defines explicit `rec` (recover) and `cnt` (contest) event types. Recovery resolves divergence in favor of the legitimate owner. Contest permanently freezes the KEL when both parties hold recovery keys — an outcome KERI doesn't formalize.
- **Gossip replication model**: KEL synchronization happens via gossip announcements (`prefix:said` pairs) with HTTP-based event fetching, rather than KERI's witness receipt protocol.

## Roadmap

1. Optional access control for mail, sadstore and kels
2. Build example applications
3. Add Android SDK
4. Re-visit exhaustive proof of divergence reconciliation in distributed environments
5. Cleanup & self-audit
6. Third-party audit
7. Standards proposal (IETF Internet-Draft or equivalent)
8. DID method specification

## Security Model

### Data Verification Principles

All recorded data in KELS is KEL-backed and verified independently before use:

- **Verify at ingestion**: Any time a service ingests data from an external source (peer, federation, network), it verifies the data's authenticity and provenance before caching or persisting. For peer data, this means full verification of the peer record chain, proposal DAG, vote anchoring in registry KELs, and the peer's own KEL structure.
- **Authenticate at connection**: When a potentially adversarial peer connects, the handshake is backed by already-verified data — the peer's signature is checked against their current public key from their KEL, which was verified at ingestion time.
- **Re-verify on refresh**: When re-fetching a peer's KEL (e.g. after key rotation), the KEL structure is fully verified before updating any cached state.
- **Ephemeral data is the exception**: Only transient protocol messages (handshakes, gossip announcements) are exempt from anchoring. Everything persisted is KEL-backed.

### Automatic Key Rotation

The identity service (used by registries and gossip nodes with HSM-backed keys) runs an automatic rotation loop that periodically checks whether the current HSM key binding is due for rotation. Both the check period (`IDENTITY_ROTATION_CHECK_PERIOD_MINUTES`, default: 360) and rotation interval (`IDENTITY_ROTATION_INTERVAL_DAYS`, default: 180) are configurable. When rotation is due, it uses a scheduled mode that auto-selects the rotation type: every third rotation is a recovery key rotation (`ror`), the rest are standard signing key rotations (`rot`). This ensures both signing and recovery keys are refreshed regularly without manual intervention.

All KEL management operations — automatic and manual — go through a single `perform_kel_operation` code path that updates the in-memory key provider in-place, keeping the server's signing state consistent. The management endpoint (`POST /api/v1/identity/kel/manage`) requires a signed request verified against the identity's own KEL.

### Proactive Protection

- HSM-backed services rotate signing keys automatically (configurable interval, default 180 days) and recovery keys (every third rotation)
- Manual rotation is available via the admin CLI for immediate key refresh
- End-user clients should rotate keys regularly (suggested: signing every 1-3 months, recovery every 3-12 months)
- Use hardware-backed keys (Secure Enclave, HSM) when possible

## Development

### Prerequisites

- Rust 2024 edition
- `cargo-deny` (for dependency auditing): `make install-deny`

For integration tests:
- [Garden](https://garden.io) >= 14.20
- Local Kubernetes cluster (Docker Desktop, minikube, kind, etc)

### IDE Setup

For VSCode with rust-analyzer:

```bash
cp -r .vscode.example .vscode
```

This provides rust-analyzer with required environment variables (like `TRUSTED_REGISTRY_PREFIXES`) for analysis without affecting actual builds.

### Stress Testing

```bash
# Repeats adversarial, gossip, and bootstrap tests
for i in {1..10}; do echo && echo "run $i" && echo &&
    kubectl exec -n node-a -it test-client -- ./test-adversarial.sh &&
    kubectl exec -n node-a -it test-client -- ./test-adversarial-advanced.sh &&
    kubectl exec -n node-a -it test-client -- ./test-gossip.sh &&
    kubectl exec -n node-a -it test-client -- ./test-bootstrap.sh || break
done

# Cross-node consistency check
kubectl exec -n node-a -it test-client -- ./test-consistency.sh
```

### Dev Tools

The CLI includes adversary simulation tools for testing (requires `dev-tools` feature):

```bash
cargo build --package kels-cli --features dev-tools
kels-cli adversary inject --prefix <prefix> --events ixn,rot
```

## Contributing

Best to create an issue and discuss, but PRs are welcome if they are positive additions.

## Documentation

### Architecture and Design

- [KEL Merge Protocol](docs/design/merge.md) — Event submission and merge logic
- [KEL Verification](docs/design/verification.md) — Integrity and authenticity verification
- [Streaming Verification](docs/design/streaming-verification-architecture.md) — Paginated verification without full KEL load
- [Divergence Detection and Recovery](docs/design/divergence-detection.md) — Divergence protocol
- [Recovery Workflow](docs/design/recovery-workflow.md) — Recovery and reconciliation procedures
- [Security Invariant](docs/design/security-invariant.md) — DB trust model and verification categories

### Services and Protocols

- [Gossip Protocol](docs/gossip.md) — Cross-deployment synchronization
- [Node Registry](docs/registry.md) — Node registration, discovery, and bootstrap sync
- [Multi-Registry Federation](docs/federation.md) — Federated registries with Raft consensus
- [Federation State Machine](docs/design/federation-state-machine.md) — Raft log, proposals, and voting
- [Secure Registration](docs/design/secure-registration.md) — HSM-backed identity and peer allowlist
- [API Endpoints](docs/endpoints.md) — Full endpoint reference

### Credentials and Exchange

- [Credential Framework](docs/design/creds.md) — Issuance, compaction, disclosure, and verification
- [Policy Framework](docs/design/policy.md) — Composable trust policies and DSL
- [SAD Store](docs/design/sadstore.md) — Replicated self-addressed data store
- [Exchange Protocol](docs/design/exchange.md) — ESSR authenticated encryption and credential exchange
- [Mail Service](docs/design/mail.md) — Encrypted message delivery

### Operations

- [Deployment](docs/deployment.md) — Trust anchors, federation deployment, and configuration
- [Operations](docs/operations.md) — Day-to-day operational procedures
- [Registry Removal](docs/design/registry-removal.md) — Federation member decommission
- [Rejection Threshold](docs/design/rejection-threshold.md) — Peer proposal rejection mechanics

### Security Analysis

- [Node Attack Surface](docs/analysis/node-attack-surface.md) — Security analysis of KELS data-plane services
- [Registry Attack Surface](docs/analysis/registry-attack-surface.md) — Security analysis of federation and registry
- [Protocol Attack Surface](docs/analysis/protocol-attack-surface.md) — Security analysis of KEL protocol
- [KERI vs KELS Comparative Analysis](docs/keri-comparison.md) — Security, architecture, and deployment comparison

### Other

- [Code Audits](docs/claudit/) — Branch-level code audit history

## Production Readiness

The provided Garden configuration is a test harness, not a production deployment template. This project is a work in progress and the following items would need to be addressed before any production deployment:

### Infrastructure hardening

- **Real HSMs**: The current deployment uses `kels-mock-hsm` (a PKCS#11 cdylib) with hardcoded PINs. Production requires swapping the PKCS#11 .so path (`PKCS11_LIBRARY_PATH`) to a real HSM's PKCS#11 library (CloudHSM, YubiHSM, Thales Luna, etc.)
- **Secrets management**: Database credentials, HSM PINs, and other secrets are hardcoded or passed as plain environment variables. Use a secrets manager (Vault, AWS Secrets Manager, etc.)
- **Database hardening**: PostgreSQL runs with default superuser credentials, no replication, no backup strategy, and no encryption at rest. Connection pool sizing is unconfigured
- **Redis credentials**: Redis uses per-service ACL users with least-privilege command sets and key pattern isolation, and RDB persistence is enabled. However, ACL passwords are configured via Garden template variables — production should use a secrets manager for Redis credentials
- **Container security**: All containers run as root with no `securityContext`, no read-only filesystem, and no resource quotas beyond memory limits
- **Network policies**: No Kubernetes NetworkPolicies are defined — all services are reachable from anywhere in the cluster. The security model does not depend on network isolation for data integrity (all data is end-verifiable), but network policies are still recommended to limit blast radius and protect pod-internal services (identity)
- **TLS for internal services**: Data plane communication is plaintext HTTP, which is acceptable by design — all data is public and end-verifiable (cryptographic signatures + SAID chaining). Federation RPC uses `SignedFederationRpc` for integrity, and gossip uses ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 for authenticated encryption. TLS is only needed for defense-in-depth on internal services that carry secrets (Redis, PostgreSQL connections)

### Operational gaps

- **Audit logging**: No structured audit trail for authentication failures or sensitive operations (peer changes are tracked via Raft log)
- **Observability**: No metrics collection (Prometheus), no distributed tracing
- **Chaos and resilience testing**: DNS-based fault injection (resync/retry queue) is tested. Network partition simulation, node failure recovery, split-brain scenarios, and database failover have not been systematically tested

### Audit

- **Security audit**: The cryptographic protocols and implementation need independent review
- **Zero-trust verification**: All data read from stores (PostgreSQL, Redis, Raft state machine) is cryptographically re-verified before trust decisions. Proposal DAGs are fully verified (structural integrity, KEL anchoring, vote anchoring) at every trust point — gossip allowlist refresh, client discovery, registry `verify_and_authorize`, and Raft log replay. Thresholds and member sets are derived from compiled-in `trusted_prefixes()`, never from responses. This is implemented but has not been independently audited

## License

MIT
