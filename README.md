# KELS - Key Event Log Storage

KELS is a decentralized key management infrastructure (DKMI). It provides cryptographically verifiable identity management through key event logs with pre-rotation commitment, divergence detection, and recovery mechanisms — offering protection against key compromise without relying on certificate authorities or centralized trust.

## Overview

KELS implements a key event log system where:

- **Pre-rotation commitment**: Each event commits to the *next* signing key before it's needed
- **Recovery keys**: A separate recovery key enables recovery from signing key compromise
- **Divergence detection**: Conflicting events at the same generation are detected and stored
- **Recovery protocol**: Legitimate owners can recover from adversarial events using their recovery key
- **Contest mechanism**: When both parties perform recovery operations, the KEL is permanently frozen

All events are self-addressing (content-addressed via SAID) and cryptographically signed, making the entire log tamper-evident and end-verifiable. In the event that a divergent KEL is recovered, the removed events
can be requested alongside the recovered KEL in the form of an audit query.

## Why a DKMI?

The product of a DKMI is **portable identity** — cryptographic identity that belongs to the individual, not to any service provider.

Today, centralized platforms collect and store vast amounts of personal data, much of which they don't actually need. With portable identity, services only need to verify *that you are who you claim to be* — they don't need to be the source of truth for your identity, your data, or your relationships. The bulk of data storage and compute can be offloaded to consumer devices, where it belongs.

This shifts the balance of power. Data is owned and controlled by individuals, not held hostage by corporations. Your identity travels with you across services. Your keys rotate without anyone's permission. And if a service disappears, your identity doesn't disappear with it.

With [federated registries](docs/federation.md), KELS can also serve as a secure identity backbone for multi-cloud, multi-operator applications — independent organizations each run their own registry while sharing a global trust layer, without depending on any single certificate authority or cloud provider.

## Differences from KERI (Key Event Receipt Infrastructure)

KELS borrows heavily from KERI's core concepts and terminology. The two things I've found most useful after discovering KERI are the creation of tamper-evident data with globally unique identifiers, and pre-rotation commitment.

I used Base64 CESR to encode data, primarily to make development easier. I may change the encoding in the future.

### Primary difference

If divergence occurs, a single divergent event is accepted into a KEL, rather than rejected. When this happens, appending new events is not permitted until the divergence is resolved.

### Other notable differences

- **No witnesses or receipts**: KERI relies on designated witness pools that sign receipts for events. KELS replaces this with gossip-based replication and registry-anchored peer allowlists — trust comes from KEL verification against compiled-in registry prefixes, not witness receipts.
- **Divergence is observable, not private**: In KERI, duplicity is detected locally by comparing logs from different sources. In KELS, divergence is stored directly in the KEL and propagated to all nodes via gossip — it's a public, network-wide signal.
- **Recovery and contest protocol**: KELS defines explicit `rec` (recover) and `cnt` (contest) event types. Recovery resolves divergence in favor of the legitimate owner. Contest permanently freezes the KEL when both parties hold recovery keys — an outcome KERI doesn't formalize.
- **Gossip replication model**: KEL synchronization happens via gossip announcements (`prefix:said` pairs) with HTTP-based event fetching, rather than KERI's witness receipt protocol.

## Roadmap

1. Replace libp2p with gossip based on kels crypto
2. Build some example applications

## Project Structure

```
kels/
├── lib/
│   ├── kels/           # Core library (libkels)
│   ├── kels-derive/    # Derive macros for storage traits
│   └── kels-ffi/       # FFI bindings (Swift/C interop)
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

- **Server-side caching**: Optional Redis + Local LRU caching for high-throughput deployments (enabled by default for the garden example)

- **Cross-deployment gossip**: libp2p-based gossip protocol synchronizes KELs between independent deployments for high availability

- **Secure node registration**: HSM-backed identities with cryptographic peer allowlist - only authorized nodes can register and participate in gossip

## Event Types

| Type | Description | Signatures Required |
|------|-------------|---------------------|
| `icp` | Incept - creates the KEL | Signing key |
| `rot` | Rotate - rotates signing key | Rotation key |
| `ixn` | Interact - anchors external data | Signing key |
| `ror` | Rotate Recovery - rotates recovery key | Rotation + Recovery |
| `rec` | Recover - recovers from divergence | Rotation + Recovery |
| `cnt` | Contest - freezes KEL permanently | Rotation + Recovery |
| `dec` | Decommission - ends the KEL | Rotation + Recovery |

## Quick Start

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

### Deploying with Garden

Deploy to a local Kubernetes cluster using [Garden](https://garden.io):

#### Host Configuration

First, add the following entries to `/etc/hosts` to enable local hostname resolution:

```
127.0.0.1 kels.kels-node-a.kels
127.0.0.1 kels.kels-node-b.kels
127.0.0.1 kels.kels-node-c.kels
127.0.0.1 kels.kels-node-d.kels
127.0.0.1 kels.kels-node-e.kels
127.0.0.1 kels.kels-node-f.kels
127.0.0.1 kels-registry.kels-registry-a.kels
127.0.0.1 kels-registry.kels-registry-b.kels
127.0.0.1 kels-registry.kels-registry-c.kels
```

This allows the CLI and iOS app to connect to the local KELS nodes and registries using their service names.

#### Deployment

We won't duplicate the deployment commands here. Examine the `test-comprehensive` make target. This
deploys 9 independent Kubernetes namespaces.

This is the flow:

1. Deploy all registries
2. Gather their prefixes
3. Rebuild all software to bake prefixes in
4. Update environment variables as required
5. Re-deploy registries
6. Deploy core nodes
7. Gather node ids
8. Propose core nodes
9. Approve core nodes
10. Deploy regional nodes
11. Add regional nodes to respective registries

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

### Proactive Protection

- Rotate signing keys regularly (suggested: every 1-3 months)
- Rotate recovery keys periodically (suggested: every 3-12 months)
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
| `GET` | `/api/kels/kel/:prefix` | Fetch KEL by prefix |
| `GET` | `/api/kels/kel/:prefix?audit=true` | Fetch KEL with audit records |
| `POST` | `/api/kels/kels` | Batch fetch multiple KELs |
| `POST` | `/api/kels/prefixes` | List prefixes (authenticated, for bootstrap sync) |

## Development

### Prerequisites

- Rust 2024 edition
- PostgreSQL (for server)
- Redis (optional, for caching)
- `cargo-deny` (for dependency auditing)
- [Garden](https://garden.io) (for Kubernetes deployment)
- Local Kubernetes cluster (Docker Desktop, minikube, or kind)

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
- [Attack Surface](docs/attack-surface.md) - Security analysis
- [Gossip Protocol](docs/gossip.md) - Cross-deployment synchronization
- [Node Registry](docs/registry.md) - Node registration, discovery, and bootstrap sync
- [Secure Registration](docs/secure-registration.md) - HSM-backed identity and peer allowlist
- [Multi-Registry Federation](docs/federation.md) - Federated registries with Raft consensus

## Production Readiness

This project is a work in progress. The following items would need to be addressed before any production deployment:

- **Real HSMs**: The current deployment uses SoftHSM2 with hardcoded PINs. Production requires hardware-backed key storage (CloudHSM, YubiHSM, Thales, etc.)
- **TLS everywhere**: All inter-service communication (KELS, gossip, registry, HSM, Redis, PostgreSQL) is currently plaintext HTTP. Production requires TLS/mTLS between all services
- **Secrets management**: Database credentials, HSM PINs, and other secrets are hardcoded or passed as plain environment variables. Use a secrets manager (Vault, AWS Secrets Manager, etc.)
- **Database hardening**: PostgreSQL runs with default superuser credentials, no replication, no backup strategy, and no encryption at rest. Connection pool sizing is unconfigured
- **Redis authentication and persistence**: Redis runs with no authentication and no persistence (`--appendonly no`)
- **Rate limiting**: No rate limiting exists on any endpoint — the service is vulnerable to denial-of-service
- **Container security**: All containers run as root with no `securityContext`, no read-only filesystem, and no resource quotas beyond memory limits
- **Network policies**: No Kubernetes NetworkPolicies are defined — all services are reachable from anywhere in the cluster
- **Audit logging**: No structured audit trail for authentication failures, peer changes, or sensitive operations
- **Observability**: No metrics collection (Prometheus), no distributed tracing, default log level is DEBUG
- **Authenticated endpoints**: The `/api/kels/prefixes` endpoint is unauthenticated (or bypassed with `dev-tools`). Public endpoints like `/api/kels/events` and `/api/kels/kel/:prefix` have no access control
- **Chaos and resilience testing**: Network partition simulation, node failure recovery, split-brain scenarios, and database failover have not been systematically tested
- **Security audit**: The cryptographic protocols and implementation need independent review

## Contributing

The core logic lives in `Kel::merge()` and `Kel::verify()` in `lib/kels/src/types/kel.rs`. Correct replication across all scenarios — divergence, recovery, contest, decommission, and their interactions with gossip propagation timing — is the hardest thing to verify. If you can think of interesting scenarios or race conditions not covered by the existing integration test scripts, please submit a pull request or open an issue.

## License

MIT
