# KELS - Key Event Log Storage

A Rust implementation of a Key Event Log Storage service and client with pre-rotation key commitment, divergence detection, and recovery mechanisms. KELS provides cryptographically verifiable identity management with protection against key compromise.

## Overview

KELS implements a key event log system where:

- **Pre-rotation commitment**: Each event commits to the *next* signing key before it's needed
- **Recovery keys**: A separate recovery key enables recovery from signing key compromise
- **Divergence detection**: Conflicting events at the same generation are detected and stored
- **Recovery protocol**: Legitimate owners can recover from adversarial events using their recovery key
- **Contest mechanism**: When both parties perform recovery operations, the KEL is permanently frozen

All events are self-addressing (content-addressed via SAID) and cryptographically signed, making the entire log tamper-evident and end-verifiable. In the event that a divergent KEL is recovered, the removed events
can be requested alongside the recovered KEL in the form of an audit query.

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

### Running the Server

```bash
# Start the KELS server (requires PostgreSQL and optionally Redis)
cargo run --package kels --release
```

Environment variables:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string (optional, for caching)
- `PORT` - HTTP port (default: 8091)

### Using the CLI

```bash
# Create a new KEL
kels-cli -u http://localhost:8091 incept

# Rotate signing key
kels-cli -u http://localhost:8091 rotate --prefix <prefix>

# Anchor data in the KEL
kels-cli -u http://localhost:8091 anchor --prefix <prefix> --said <said>

# Rotate recovery key (proactive security)
kels-cli -u http://localhost:8091 rotate-recovery --prefix <prefix>

# Fetch a KEL
kels-cli -u http://localhost:8091 get <prefix>

# Check local status
kels-cli -u http://localhost:8091 status --prefix <prefix>

# List local KELs
kels-cli -u http://localhost:8091 list

# Recover from divergence (if adversary attacked)
kels-cli -u http://localhost:8091 recover --prefix <prefix>

# Decommission a KEL (permanent)
kels-cli -u http://localhost:8091 decommission --prefix <prefix>

# Reset local state (clear keys and KEL cache)
kels-cli reset --prefix <prefix>     # Reset specific prefix
kels-cli reset                        # Reset all local state (prompts for confirmation)
kels-cli reset -y                     # Reset all without confirmation
```

### Deploying with Garden

Deploy to a local Kubernetes cluster using [Garden](https://garden.io):

#### Host Configuration

First, add the following entries to `/etc/hosts` to enable local hostname resolution:

```
127.0.0.1 kels.kels-node-a.local
127.0.0.1 kels.kels-node-b.local
```

This allows the CLI and iOS app to connect to the local KELS nodes using their service names.

#### Deployment

```bash
# Set up a local Kubernetes environment (e.g., Docker Desktop, minikube, kind), then:
garden deploy --env=registry   # Deploy shared registry service first
garden deploy                  # Deploy node-a (default)
garden deploy --env=node-b     # Deploy node-b (separate namespace)

# Both node deployments include kels-gossip for cross-deployment KEL synchronization
# Nodes register with the registry and bootstrap sync from existing peers

# Run the full test suite
kubectl exec -n kels-node-a -it test-client -- /tests/run-all-tests.sh

# Run gossip synchronization tests (requires both nodes deployed)
kubectl exec -n kels-node-a -it test-client -- /tests/test-gossip.sh

# Run bootstrap sync tests (requires registry and both nodes)
kubectl exec -n kels-node-a -it test-client -- /tests/test-bootstrap.sh

# Run benchmarks (40 concurrent connections, 10 second duration)
kubectl exec -n kels-node-a -it test-client -- /tests/bench-kels.sh 40 10

# Clean up and start fresh
garden cleanup deploy --env=node-b     # Remove node-b deployment
garden cleanup deploy                  # Remove node-a deployment
garden cleanup deploy --env=registry   # Remove registry deployment last
```

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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/kels/events` | Submit signed events |
| `GET` | `/api/kels/kel/:prefix` | Fetch KEL by prefix |
| `GET` | `/api/kels/kel/:prefix?audit=true` | Fetch KEL with audit records |
| `POST` | `/api/kels/kels` | Batch fetch multiple KELs |
| `GET` | `/api/kels/prefixes` | List prefixes (for bootstrap sync) |

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

This provides rust-analyzer with required environment variables (like `REGISTRY_PREFIX`) for analysis without affecting actual builds.

### Testing

```bash
# Unit tests
make test

# Integration tests (requires running server - use garden for an easy setup)
./clients/test/scripts/test-kels.sh
./clients/test/scripts/test-adversarial.sh
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

## License

MIT
