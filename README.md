# KELS - Key Event Log System

KELS is a federated decentralized key management infrastructure (DKMI), inspired by [KERI](https://github.com/WebOfTrust/keripy). It provides cryptographically verifiable identity management through key event logs with pre-rotation commitment, divergence detection, and recovery mechanisms — offering protection against key compromise without relying on certificate authorities or centralized trust.

## Overview

KELS implements a key event log system where:

- Each event commits to the *next* signing key before it's needed (**Pre-rotation commitment**)
- A separate recovery key enables recovery from signing key compromise (**Recovery keys**)
- Conflicting events at the same generation are detected and stored (**Divergence detection**)
- Legitimate owners can recover from adversarial events using their recovery key (**Recovery protocol**)
- When both parties perform recovery operations, the KEL is permanently frozen (**Contest mechanism**)

All events are self-addressing (content-addressed via SAID) and cryptographically signed, making the entire log tamper-evident and end-verifiable. In the event that a divergent KEL is recovered, the removed events
can be requested alongside the recovered KEL in the form of an audit query.

## Why a DKMI?

The product of a DKMI is **portable identity** — cryptographic identity that belongs to the individual, not to any service provider.

Today, centralized platforms collect and store vast amounts of personal data, much of which they don't actually need. With portable identity, services only need to verify *that you are who you claim to be* — they don't need to be the source of truth for your identity, your data, or your relationships. The bulk of data storage and compute can be offloaded to consumer devices, where it belongs.

This shifts the balance of power. Data is owned and controlled by individuals, not held hostage by corporations. Your identity travels with you across services. Your keys rotate without anyone's permission. And if a service disappears, your identity doesn't disappear with it.

With [federated registries](docs/federation.md), KELS can also serve as a secure identity backbone for multi-cloud, multi-operator applications — independent organizations each run their own registry while sharing a global trust layer, without depending on any single certificate authority or cloud provider.

## Differences from KERI (Key Event Receipt Infrastructure)

For a comprehensive comparison of KERI and KELS across security properties, architectural decisions, deployment, and suitability for various DKMI scenarios, see the [KERI vs KELS Comparative Analysis](docs/keri-comparison.md).

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

1. Address GitHub issues
2. Cleanup & self-audit
3. Build some example applications
4. Post-quantum signature support (ML-DSA-65, 192-bit security — supported by Apple Secure Enclave, Thales Luna, AWS KMS)
5. Third party audit

## Project Structure

```
kels/
├── lib/
│   ├── kels/           # Core library (libkels)
│   ├── kels-derive/    # Derive macros for storage traits
│   ├── kels-ffi/       # FFI bindings (Swift/C interop)
│   └── gossip/         # Custom gossip protocol library
├── services/
│   ├── kels/           # HTTP API server
│   ├── kels-gossip/    # Gossip protocol for cross-deployment sync
│   ├── kels-registry/  # Node registration and discovery service
│   ├── identity/       # Registry identity service (single replica)
│   ├── hsm/            # HSM service (SoftHSM2 wrapper)
│   ├── postgres/       # PostgreSQL configuration
│   └── redis/          # Redis configuration
├── clients/
│   ├── kels-cli/       # Command-line interface
│   ├── kels-client/    # Swift client (iOS/macOS)
│   ├── kels-bench/     # Benchmarking tool
│   └── test/           # Integration test scripts/container
└── docs/               # Documentation
```

## Features

- **Multiple key providers**:
  - `SoftwareKeyProvider` - In-memory keys for development/testing
  - `HardwareKeyProvider` - macOS/iOS Secure Enclave backed keys
  - `KeyProvider` trait - Extensible interface for HSMs or other key management

- **Platform support**:
  - Native (Linux, macOS, Windows)
  - WebAssembly (browser/wasm targets)

- **Server-side caching**: Optional Redis + W-TinyLFU local caching for high-throughput deployments (enabled by default for the garden example)

- **Cross-deployment gossip**: Custom gossip protocol (HyParView + PlumTree) synchronizes KELs between independent deployments for high availability

- **Secure node registration**: HSM-backed identities with cryptographic peer allowlist - only authorized nodes can register and participate in gossip

## Event Types

Event kind values are version-qualified in serialized form (e.g. `kels/v1/icp`).

| Type | Description | Signatures Required |
|------|-------------|---------------------|
| `icp` | Incept - creates the KEL | Signing key |
| `dip` | Delegated Incept - creates a delegated KEL | Signing key |
| `rot` | Rotate - rotates signing key | Rotation key |
| `ixn` | Interact - anchors external data | Signing key |
| `ror` | Rotate Recovery - rotates recovery key | Rotation + Recovery |
| `rec` | Recover - recovers from divergence | Rotation + Recovery |
| `cnt` | Contest - freezes KEL permanently | Rotation + Recovery |
| `dec` | Decommission - ends the KEL | Rotation + Recovery |

## Quick Start

### Minimal Development Setup

For development, a single KELS node can run without gossip or registries — just the kels service, PostgreSQL, and Redis. This provides the full KEL API (event submission, verification, divergence handling, recovery, contest) without replication, and is comparable in complexity to a single-service setup.

```bash
garden deploy kels --env=node-a
```

### Full Federation

`make test-comprehensive` deploys the entire federation (3 registries, 6 gossip nodes, integration tests) in ~25 minutes and leaves a working stack running in Kubernetes. See [Deploying with Garden](#deploying-with-garden) below.

### Building

```bash
# Build all packages
make build

# Run all checks (format, deny, clippy, test)
make all

# Individual targets
make fmt          # Format code
make fmt-check    # Check formatting
make clippy       # Run clippy lints
make test         # Run tests
make deny         # Check dependencies (requires cargo-deny)
make clean        # Clean build artifacts

# Comprehensive integration tests (requires Garden + Kubernetes)
make test-comprehensive   # Deploy all services and run full test suite
```

`make test-comprehensive` leaves a working stack running in Kubernetes. You can play with it, or
bring it down entirely with:

```bash
make clean-garden
```

### Deploying with Garden

Deploy to a local Kubernetes cluster using [Garden](https://garden.io):

#### Host Configuration

First, add the following entries to `/etc/hosts` to enable local hostname resolution:

```text
127.0.0.1 kels.kels-node-a.kels
127.0.0.1 kels.kels-node-b.kels
127.0.0.1 kels.kels-node-c.kels
127.0.0.1 kels.kels-node-d.kels
127.0.0.1 kels.kels-node-e.kels
127.0.0.1 kels.kels-node-f.kels
127.0.0.1 kels-registry.kels-registry-a.kels
127.0.0.1 kels-registry.kels-registry-b.kels
127.0.0.1 kels-registry.kels-registry-c.kels
127.0.0.1 kels-registry.kels-registry-d.kels
```

This allows the CLI and iOS app to connect to the local KELS nodes and registries using their service names.

#### Ingress Controller

Certain versions of Garden mistakenly create the Traefik ingress service as `ClusterIP` instead of
`LoadBalancer`. On Docker Desktop, this prevents host access to services. If you get empty replies
from `curl`, run:

```bash
make fix-ingress
```

#### Deployment

We won't duplicate the deployment commands here. Examine the `test-comprehensive` make target. This
deploys 9 independent Kubernetes namespaces.

This is the flow:

1. Deploy all registries
2. Gather their prefixes
3. Rebuild all software to bake prefixes in
4. Update environment variables as required
5. Re-deploy registries
6. Deploy peers
7. Gather peer prefixes
8. Propose peers
9. Approve peers

This system assumes operators of registries are coordinated.

## Security Model

### Key Hierarchy

1. **Signing Key** - Signs normal events (`ixn`, `rot`)
2. **Rotation Key** - Pre-committed next signing key, revealed during rotation
3. **Recovery Key** - Used only for recovery events, highest authority

### Compromise Scenarios

| Compromised Key | Adversary Can | Owner Recovery |
|-----------------|---------------|----------------|
| Signing only | Sign `ixn` events | `rec` event recovers KEL |
| Rotation | Sign `rot`, then any events | `rec` event recovers KEL |
| Rotation + Recovery | Full control | `cnt` event freezes KEL |

### Data Verification Principles

All recorded data in KELS is KEL-backed and verified independently before use:

- **Verify at ingestion**: Any time a service ingests data from an external source (peer, federation, network), it verifies the data's authenticity and provenance before caching or persisting. For peer data, this means full verification of the peer record chain, proposal DAG, vote anchoring in registry KELs, and the peer's own KEL structure.
- **Authenticate at connection**: When a potentially adversarial peer connects, the handshake is backed by already-verified data — the peer's signature is checked against their current public key from their KEL, which was verified at ingestion time.
- **Re-verify on refresh**: When re-fetching a peer's KEL (e.g. after key rotation), the KEL structure is fully verified before updating any cached state.
- **Ephemeral data is the exception**: Only transient protocol messages (handshakes, gossip announcements) are exempt from anchoring. Everything persisted is KEL-backed.

### Automatic Key Rotation

The identity service (used by registries and gossip nodes with HSM-backed keys) runs an automatic rotation loop that checks every 6 hours whether the current HSM key binding is older than 30 days. When rotation is due, it uses a scheduled mode that auto-selects the rotation type: every third rotation is a recovery key rotation (`ror`), the rest are standard signing key rotations (`rot`). This ensures both signing and recovery keys are refreshed regularly without manual intervention.

All KEL management operations — automatic and manual — go through a single `perform_kel_operation` code path that updates the in-memory key provider in-place, keeping the server's signing state consistent. The management endpoint (`POST /api/identity/kel/manage`) requires a signed request verified against the identity's own KEL.

### Proactive Protection

- HSM-backed services rotate signing keys automatically (every 30 days) and recovery keys (every ~90 days)
- Manual rotation is available via the admin CLI for immediate key refresh
- End-user clients should rotate keys regularly (suggested: signing every 1-3 months, recovery every 3-12 months)
- Use hardware-backed keys (Secure Enclave, HSM) when possible

### Post-Quantum Considerations

Pre-rotation commitment is inherently post-quantum secure — the BLAKE3 rotation hash (128-bit effective security under Grover's algorithm) reveals nothing about the next key until rotation occurs, so a quantum adversary cannot derive future keys from the current KEL. Regular key rotation forces a quantum adversary to start from scratch with each new key, limiting their window of attack to the current rotation period.

The current signing keys (ECDSA/P-256) are quantum-vulnerable — a sufficiently powerful quantum computer could derive the private key from the exposed public key without needing physical access. Breaking a single P-256 key via Shor's algorithm requires ~2,330 logical qubits (millions of physical qubits with error correction) and ~1.26 × 10^11 Toffoli gates (Roetteler et al., 2017), translating to hours to weeks per key depending on gate speed:

| Error-corrected gate speed | Time to break one P-256 key |
|---|---|
| 100 ns (very optimistic) | ~3.5 hours |
| 1 μs (optimistic) | ~35 hours |
| 10 μs (more realistic) | ~15 days |

Even in the most optimistic quantum scenario, a monthly rotation period provides an enormous safety margin — the adversary breaks one key only to find the next is behind a fresh BLAKE3 hash they can't touch.

While these protocols could be upgraded with quantum-safe signature algorithms, such algorithms are not yet widely supported by hardware security modules. Today, hardware-backed keys with pre-commitment provide the strongest practical security against classical adversaries, while frequent rotation provides meaningful mitigation against future quantum threats until PQ hardware support matures.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check (gossip sync status) |
| `POST` | `/api/kels/events` | Submit signed events |
| `GET` | `/api/kels/kel/:prefix` | Fetch paginated KEL; `?since=SAID` for delta, `?limit=N` (1-512) |
| `GET` | `/api/kels/kel/:prefix/audit` | Fetch audit records (recovery/contest archives) |
| `GET` | `/api/kels/kel/:prefix/effective-said` | Get effective SAID for sync comparison (resolving only) |
| `GET` | `/api/kels/events/:said/exists` | Check if event exists by SAID |
| `POST` | `/api/kels/kels` | Batch fetch multiple KELs (max 64 prefixes) |
| `POST` | `/api/kels/prefixes` | List prefixes (authenticated, for bootstrap sync) |

## Deploying Locally

### Prerequisites

- [Garden](https://garden.io) >= 14.20 (for Kubernetes deployment)
- Local Kubernetes cluster (Docker Desktop, minikube, kind, etc)

### Getting Started

```shell
make test-comprehensive
```

Comprehensive tests take a while to run (~20m on my laptop), but they are an easy way to protect against regression and set up a development environment. They leave your kubernetes cluster in this state:

#### Registries (Federation Members)

Namespaces
- kels-registry-a,
- kels-registry-c,
- kels-registry-d

Children per Namespace
- hsm
- identity
- kels-registry
- postgres
- redis

#### Gossip Nodes

Namespaces
- kels-node-a
- kels-node-b
- kels-node-c
- kels-node-d
- kels-node-e
- kels-node-f

Children per Namespace
- hsm
- identity
- kels (2)
- kels-gossip
- postgres
- redis

#### Special cases

- Some nodes are built with the `dev-tools` feature flag enabled. This turns off authentication on the /prefixes endpoint, so an adversary can't scan for known prefixes. This allows inspection of prefixes during consistency checking (`test-consistency.sh`) and other testing. 

Nodes built with `dev-tools` enabled:
- `node-a`
- `node-b`
- `node-d`

- The `test-client` pod is only available in the `node-a` namespace (`kels-node-a`).

This pod is used for running various scripts and curl commands during integration/regression tests.

## Development

### Prerequisites
- Rust 2024 edition
- `cargo-deny` (for dependency auditing)

#### For Validation
- [Garden](https://garden.io) >= 14.20 (for Kubernetes deployment)
- Local Kubernetes cluster (Docker Desktop, minikube, kind, etc)

```bash
# Install cargo-deny
make install-deny
```

### IDE Setup

For VSCode with rust-analyzer, copy the example settings to enable proper linting:

```bash
cp -r .vscode.example .vscode
```

This provides rust-analyzer with required environment variables (like `TRUSTED_REGISTRY_PREFIXES`) for analysis without affecting actual builds.

### Testing

```bash
# Full integration test suite (requires Garden + Kubernetes)
make && make test-comprehensive

# Stress test (repeats adversarial, gossip, and bootstrap tests)
for i in {1..10}; do echo && echo "run $i" && echo &&
    kubectl exec -n kels-node-a -it test-client -- ./test-adversarial.sh &&
    kubectl exec -n kels-node-a -it test-client -- ./test-adversarial-advanced.sh &&
    kubectl exec -n kels-node-a -it test-client -- ./test-gossip.sh &&
    kubectl exec -n kels-node-a -it test-client -- ./test-bootstrap.sh || break
done

# Cross-node consistency check (run separately after stress tests)
kubectl exec -n kels-node-a -it test-client -- ./test-consistency.sh
```

### Dev Tools

The CLI includes adversary simulation tools for testing (requires `dev-tools` feature):

```bash
# Build with dev-tools
cargo build --package kels-cli --features dev-tools

# Simulate adversary injecting events
kels-cli adversary inject --prefix <prefix> --events ixn,rot
```

## Documentation

- [KEL Merge Protocol](docs/kel-merge.md) - Event submission and merge logic
- [KEL Verification](docs/kel-verification.md) - Integrity and authenticity verification
- [Divergence Detection and Recovery](docs/divergence-detection.md) - Detailed protocol documentation
- [Gossip Protocol](docs/gossip.md) - Cross-deployment synchronization
- [Node Registry](docs/registry.md) - Node registration, discovery, and bootstrap sync
- [Secure Registration](docs/secure-registration.md) - HSM-backed identity and peer allowlist
- [Multi-Registry Federation](docs/federation.md) - Federated registries with Raft consensus
- [Federation State Machine](docs/federation-state-machine.md) - Raft log, proposals, and voting
- [Deployment](docs/deployment.md) - Trust anchors, federation deployment, and configuration
- [API Endpoints](docs/endpoints.md) - Full endpoint reference
- [Node Attack Surface](docs/node-attack-surface.md) - Security analysis of KELS data-plane services
- [Registry Attack Surface](docs/registry-attack-surface.md) - Security analysis of federation and registry
- [Protocol Attack Surface](docs/protocol-attack-surface.md) - Security analysis of KEL protocol
- [Registry Removal](docs/registry-removal.md) - Federation member decommission procedure
- [Rejection Threshold](docs/rejection-threshold.md) - Peer proposal rejection mechanics
- [Security Invariant](docs/security-invariant.md) - DB trust model and verification categories
- [Streaming Verification](docs/streaming-verification-architecture.md) - Paginated verification without full KEL load
- [KERI vs KELS Comparative Analysis](docs/keri-comparison.md) - Security, architecture, and deployment comparison
- [Credential Framework Design](docs/design/kels-creds.md) - kels-creds issuance, compaction, disclosure, and verification
- [Code Audits](docs/claudit/) - Branch-level code audit history

## Production Readiness

The provided Garden configuration is a test harness, not a production deployment template. This project is a work in progress and the following items would need to be addressed before any production deployment:

### Infrastructure hardening

- **Real HSMs**: The current deployment uses SoftHSM2 with hardcoded PINs. Production requires hardware-backed key storage (CloudHSM, YubiHSM, Thales, etc.)
- **Secrets management**: Database credentials, HSM PINs, and other secrets are hardcoded or passed as plain environment variables. Use a secrets manager (Vault, AWS Secrets Manager, etc.)
- **Database hardening**: PostgreSQL runs with default superuser credentials, no replication, no backup strategy, and no encryption at rest. Connection pool sizing is unconfigured
- **Redis credentials**: Redis uses per-service ACL users with least-privilege command sets and key pattern isolation, and RDB persistence is enabled. However, ACL passwords are configured via Garden template variables — production should use a secrets manager for Redis credentials
- **Container security**: All containers run as root with no `securityContext`, no read-only filesystem, and no resource quotas beyond memory limits
- **Network policies**: No Kubernetes NetworkPolicies are defined — all services are reachable from anywhere in the cluster. The security model does not depend on network isolation for data integrity (all data is end-verifiable), but network policies are still recommended to limit blast radius and protect pod-internal services (HSM, identity)
- **TLS for internal services**: Data plane communication is plaintext HTTP, which is acceptable by design — all data is public and end-verifiable (cryptographic signatures + SAID chaining). Federation RPC uses `SignedFederationRpc` for integrity, and gossip uses three-DH P-256 + AES-GCM-256 for authenticated encryption. TLS is only needed for defense-in-depth on internal services that carry secrets (HSM, Redis, PostgreSQL connections)

### Operational gaps

- **Audit logging**: No structured audit trail for authentication failures or sensitive operations (peer changes are tracked via Raft log)
- **Observability**: No metrics collection (Prometheus), no distributed tracing
- **Chaos and resilience testing**: DNS-based fault injection (resync/retry queue) is tested. Network partition simulation, node failure recovery, split-brain scenarios, and database failover have not been systematically tested

### Audit

- **Security audit**: The cryptographic protocols and implementation need independent review
- **Zero-trust verification**: All data read from stores (PostgreSQL, Redis, Raft state machine) is cryptographically re-verified before trust decisions. Proposal DAGs are fully verified (structural integrity, KEL anchoring, vote anchoring) at every trust point — gossip allowlist refresh, client discovery, registry `verify_and_authorize`, and Raft log replay. Thresholds and member sets are derived from compiled-in `trusted_prefixes()`, never from responses. This is implemented but has not been independently audited

## Contributing

The core logic lives in `KelVerifier` (`lib/kels/src/types/verifier.rs`) for streaming verification and the submit handler (`services/kels/src/handlers.rs`) for merge routing. Correct replication across all scenarios — divergence, recovery, contest, decommission, and their interactions with gossip propagation timing — is the hardest thing to verify. If you can think of interesting scenarios or race conditions, check the adversarial test scripts in `clients/test/scripts/` first — they may already cover what you have in mind. If not, please submit a pull request or open an issue.

## License

MIT
