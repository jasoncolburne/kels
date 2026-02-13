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

## TODO

**caveat: this is a work in progress, and needs to be audited by another**

1. Re-implement gossip with kels crypto to remove dependence on libp2p.
2. Clean up/refactor/optimize (this kind of happens naturally during dev but I like a final pass)
3. Build a complete example with a use case that kels solves

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

I won't duplicate the deployment commands here. Examine the `test-comprehensive` make target. This
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

## License

MIT
