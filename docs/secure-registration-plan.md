# Implementation Plan: Secure Node Registration with HSM-backed Identity

## Overview

Secure the kels-registry by requiring cryptographically signed registration requests from authorized nodes. Each node uses a persistent secp256r1 identity stored in an HSM service (SoftHSM2), and the registry verifies signatures against an allowlist of authorized PeerIds.

**Goal:** In addition to implementation, create `docs/registration.md` documenting the secure registration architecture.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         kels-registry                                │
│  ┌─────────────────┐    ┌──────────────────────────────────────┐    │
│  │  Allowlist      │    │  Registration Verification           │    │
│  │  (PostgreSQL)   │───>│  - Verify signature on payload       │    │
│  │  [PeerId list]  │    │  - Check PeerId in allowlist         │    │
│  └─────────────────┘    └──────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │ Signed HTTP requests
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│   node-a      │           │   node-b      │           │   node-c      │
│ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
│ │kels-gossip│◄├───────────┤►│kels-gossip│◄├───────────┤►│kels-gossip│ │
│ └─────┬─────┘ │           │ └─────┬─────┘ │           │ └─────┬─────┘ │
│       │       │           │       │       │           │       │       │
│       ▼       │           │       ▼       │           │       ▼       │
│ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
│ │    HSM    │ │           │ │    HSM    │ │           │ │    HSM    │ │
│ │(SoftHSM2) │ │           │ │(SoftHSM2) │ │           │ │(SoftHSM2) │ │
│ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │
└───────────────┘           └───────────────┘           └───────────────┘
```

## Key Changes Summary

1. **libp2p: Ed25519 → secp256r1** - Switch key type to work with SoftHSM2/PKCS#11
2. **HSM service** - Deploy per-node HSM service for persistent key storage
3. **Signed registration** - All registry API requests signed with node identity
4. **PeerId allowlist** - Registry only accepts registrations from known nodes

## Components

### 1. HSM Service (New - copy from authentic-ddi)

Copy the HSM service from `../authentic-ddi/services/hsm/` with minimal modifications.

**Purpose:** Provide persistent secp256r1 key storage via REST API backed by SoftHSM2.

**Endpoints:**
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/hsm/keys` | Generate or get existing key (idempotent) |
| `GET` | `/api/hsm/keys` | List all key labels |
| `GET` | `/api/hsm/keys/{label}/public` | Get public key |
| `POST` | `/api/hsm/keys/{label}/sign` | Sign data with key |
| `GET` | `/health` | Health check |

**Files to create:**
- `services/hsm/` (copy from authentic-ddi, adapt as needed)
- `services/hsm/garden.yml` - Garden module
- `services/hsm/manifests.yml.tpl` - K8s deployment with PVC

### 2. kels-gossip: HSM Client

Add HTTP client to interact with HSM service for key operations.

**File:** `services/kels-gossip/src/hsm_client.rs`

```rust
pub struct HsmClient {
    base_url: String,
    client: reqwest::Client,
}

impl HsmClient {
    pub async fn get_or_create_key(&self, label: &str) -> Result<PublicKey>;
    pub async fn sign(&self, label: &str, data: &[u8]) -> Result<Signature>;
    pub async fn get_public_key(&self, label: &str) -> Result<PublicKey>;
}
```

### 3. kels-gossip: secp256r1 Identity

Switch from Ed25519 to secp256r1 using HSM-backed keys.

**Changes to `services/kels-gossip/src/gossip.rs`:**

```rust
// Before:
let swarm = SwarmBuilder::with_new_identity()

// After:
let keypair = load_or_create_identity_from_hsm(&hsm_client, &node_id).await?;
let swarm = SwarmBuilder::with_existing_identity(keypair)
```

**New function to add:**
```rust
async fn load_or_create_identity_from_hsm(
    hsm: &HsmClient,
    node_id: &str,
) -> Result<libp2p::identity::Keypair> {
    let label = format!("kels-gossip-{}", node_id);

    // Get or create key in HSM
    let public_key_bytes = hsm.get_or_create_key(&label).await?;

    // Create libp2p ECDSA keypair wrapper that delegates signing to HSM
    // Note: libp2p doesn't support external signers directly, so we need
    // to create a signing wrapper
    ...
}
```

**Cargo.toml changes:**
```toml
[dependencies]
libp2p = { version = "0.54", features = [..., "ecdsa"] }
```

### 4. Registry: Signed Request Verification

Add signature verification to all mutating registry endpoints.

**Request format change:**
```rust
#[derive(Deserialize)]
struct SignedRequest<T> {
    payload: T,
    peer_id: String,           // Base58 PeerId
    signature: String,         // Base64 signature over JSON(payload)
}
```

**Verification flow:**
1. Parse `peer_id` from request
2. Check `peer_id` is in allowlist (PostgreSQL)
3. Verify `signature` over `payload` using public key derived from `peer_id`
4. If valid, process request; otherwise return 403

**Files to modify:**
- `services/kels-registry/src/handlers.rs` - Add signature verification
- `services/kels-registry/src/lib.rs` - PostgreSQL pool, allowlist queries

### 5. Registry: PeerId Allowlist (PostgreSQL + Admin CLI)

Store authorized PeerIds in PostgreSQL, managed via `kels-registry-admin` CLI.

**Admin CLI commands:**
```bash
# Add a peer to allowlist
kels-registry-admin peer add --peer-id 12D3KooWAbc... --node-id node-a

# Remove a peer from allowlist
kels-registry-admin peer remove --peer-id 12D3KooWAbc...

# List all authorized peers
kels-registry-admin peer list
```

The CLI creates a new allowlist version and anchors its SAID in the registry's KEL after each change. See "Registry PostgreSQL Schema" section for table definitions.

### 6. kels-gossip: Signed Registry Client

Update registry client to sign all requests with HSM key.

**Changes to `lib/kels/src/registry_client.rs`:**

```rust
impl KelsRegistryClient {
    pub fn with_signer(base_url: String, signer: Arc<dyn Signer>) -> Self;

    async fn sign_request<T: Serialize>(&self, payload: &T) -> SignedRequest<T> {
        let payload_json = serde_json::to_vec(payload)?;
        let signature = self.signer.sign(&payload_json).await?;
        SignedRequest {
            payload: payload.clone(),
            peer_id: self.peer_id.to_string(),
            signature: base64::encode(signature),
        }
    }
}
```

## Implementation Order

### Phase 1: Fork libp2p-identity
1. Add `external-signer` feature flag to `rust-libp2p/identity/Cargo.toml`
2. Create `identity/src/external.rs` with ExternalSigner trait
3. Create `identity/src/ecdsa_external.rs` with external signer wrapper
4. Update `keypair.rs` with ExternalEcdsa variant and methods
5. Update `lib.rs` exports
6. Test: build with `cargo build --features external-signer,ecdsa,peerid`

### Phase 2: HSM Service
6. Copy HSM service from `../authentic-ddi/services/hsm/`
7. Adapt for kels (minimal changes needed)
8. Add Garden deployment configuration for both registry and node environments
9. Deploy and test manually with curl

### Phase 3: Registry Database + Allowlist API + Admin CLI
10. Add PostgreSQL to registry deployment (Garden + manifests)
11. Add verifiable-storage-postgres dependency to kels-registry
12. Create PeerAllowlist Versioned model with SelfAddressed derive
13. Create Stored repository with auto-generated migrations
14. Add HSM client to kels-registry
15. Implement `/api/allowlist` endpoint (GET allowlist)
16. Create `kels-registry-admin` CLI binary with peer add/remove/list commands (anchors SAID in KEL)
17. Test: CLI peer management, SAID verification, KEL anchoring

### Phase 4: kels-gossip HSM Integration
18. Update Cargo.toml to use forked libp2p-identity
19. Create HSM client wrapper in kels-gossip
20. Update gossip.rs to use HSM-backed identity
21. Test: verify PeerId is consistent across restarts

### Phase 5: libp2p Connection Filtering
22. Implement AllowlistBehaviour in kels-gossip
23. Add allowlist refresh from registry (with SAID + signature verification)
24. Integrate AllowlistBehaviour into swarm
25. Test: unauthorized peers disconnected immediately

### Phase 6: Registry Signed Registration
26. Update registration API to require signed requests
27. Verify signatures against allowlist PeerIds
28. Update registry client to sign requests via HSM
29. End-to-end test: only authorized nodes can register

### Phase 7: Deployment & Documentation
30. Update Garden configs for HSM + PostgreSQL in registry namespace
31. Update Garden configs for HSM in node namespaces
32. Create `.kels/.gitkeep` and add `.kels/registry_prefix` to `.gitignore`
33. Create `docs/registration.md` documenting the secure registration architecture
34. Document node onboarding workflow (HSM key → PeerId → CLI add)
35. Create utility for PeerId derivation from HSM public key

## Key Files

**Fork files (rust-libp2p/identity):**
- `identity/Cargo.toml` - Add `external-signer` feature
- `identity/src/external.rs` - NEW: ExternalSigner trait
- `identity/src/ecdsa_external.rs` - NEW: External signer ECDSA wrapper
- `identity/src/keypair.rs` - Add ExternalEcdsa variant
- `identity/src/lib.rs` - Export external module

**New files (kels):**
- `services/hsm/` (copy from authentic-ddi, adapt)
- `services/kels-gossip/src/hsm_signer.rs` - HsmSigner impl ExternalSigner for libp2p
- `services/kels-gossip/src/hsm_client.rs` - HSM HTTP client wrapper
- `services/kels-gossip/src/allowlist.rs` - AllowlistBehaviour for connection filtering
- `services/kels-registry/src/bin/kels-registry-admin.rs` - kels-registry-admin CLI binary
- `services/kels-registry/src/peer.rs` - Peer Versioned model (SelfAddressed derive)
- `services/kels-registry/src/peers.rs` - GET /api/peers handler
- `services/kels-registry/src/registry_kel.rs` - Registry KEL endpoints (GET /api/registry-kel)
- `services/kels-registry/src/registry_identity.rs` - Registry's own KELS identity management
- `services/kels-registry/src/hsm_provider.rs` - ExternalKeyProvider impl for HSM
- `services/kels-registry/src/repository.rs` - Stored repository combining all tables
- `.kels/.gitkeep` - Ensure .kels directory exists in version control
- `.kels/registry_prefix` - Saved registry prefix (trust anchor, created by fetch-registry-prefix)
- `garden.yml` (project root) - read-registry-prefix task
- `docs/registration.md` - Documentation of secure registration architecture

**Modified files (git):**
- `.gitignore` - Add `.kels/registry_prefix` (environment-specific, not checked in)

**Modified files (kels):**
- `services/kels-gossip/Cargo.toml` - Use forked libp2p-identity with external-signer feature
- `services/kels-gossip/src/gossip.rs` - HSM-backed identity creation, AllowlistBehaviour
- `services/kels-gossip/src/lib.rs` - HSM client + allowlist refresh integration
- `services/kels-gossip/manifests.yml.tpl` - Add REGISTRY_PREFIX env var from .kels/registry_prefix
- `services/kels-registry/Cargo.toml` - Add verifiable-storage-postgres, clap, libp2p (for gossip), kels lib, [[bin]] for kels-registry-admin, serde_json with preserve_order feature
- `services/kels-registry/src/handlers.rs` - Signature verification on registration
- `services/kels-registry/src/lib.rs` - PostgreSQL pool, allowlist management
- `services/kels-registry/src/server.rs` - Add allowlist GET route
- `lib/kels/src/registry_client.rs` - Sign requests with HSM, fetch allowlist
- `project.garden.yml` - HSM service reference
- `services/kels-registry/garden.yml` - Add postgres + HSM dependencies, fetch-registry-prefix task
- `services/kels-registry/manifests.yml.tpl` - Add postgres container/volume
- `services/kels-registry/Dockerfile` - Include kels-registry-admin binary in image

## Verification

```bash
# 1. Deploy registry with HSM + PostgreSQL
garden deploy --env=registry

# 2. Deploy HSM service in node-a namespace
garden deploy --env=node-a hsm

# 3. Deploy kels-gossip, get the PeerId
garden deploy --env=node-a kels-gossip
# Check logs for PeerId (e.g., 12D3KooWXyz...)

# 4. Add node-a to allowlist via admin CLI
kubectl exec -n kels-registry kels-registry-0 -- \
  kels-registry-admin peer add --peer-id 12D3KooWXyz... --node-id node-a

# 5. Verify peer is available and SAID is anchored
curl http://kels-registry.kels-registry.local/api/peers
# Should return peer records including node-a
# Verify each peer's SAID is anchored in registry KEL:
curl http://kels-registry.kels-registry.local/api/registry-kel | jq '.anchors'

# 6. Restart kels-gossip, verify PeerId is consistent
kubectl rollout restart deployment/kels-gossip -n kels-node-a
# Check logs - PeerId should be the same

# 7. Test unauthorized registration (deploy node without adding to allowlist)
# Expected: connection rejected at libp2p layer, registration fails with 403

# 8. Test peer removal
kubectl exec -n kels-registry kels-registry-0 -- \
  kels-registry-admin peer remove --peer-id 12D3KooWXyz...
# Node should be disconnected on next allowlist refresh
```

## Fork: libp2p-identity with External Signer Support

**Repository:** `/Users/jason/github.com/jasoncolburne/rust-libp2p/identity`

### Design: Trait-based Decoupling

Instead of putting the HSM client directly in libp2p-identity, we define a trait that any external signer can implement:

```
rust-libp2p/identity/src/external.rs   <- ExternalSigner trait (in fork)
kels-gossip/src/hsm_signer.rs          <- impl ExternalSigner for HsmSigner (in kels)
```

This follows the same pattern as kels' `ExternalKeyProvider` trait.

### Fork Changes

#### 1. Add external-signer feature flag

**File:** `identity/Cargo.toml`
```toml
[features]
external-signer = []  # No extra deps - trait only
```

#### 2. Create ExternalSigner trait

**New file:** `identity/src/external.rs`

```rust
//! External signer trait for delegating signing to external systems (HSM, TPM, etc.)

use crate::error::SigningError;

/// Trait for external signing implementations.
///
/// Implementors must provide blocking sign operations since libp2p's
/// Keypair::sign() is synchronous.
pub trait ExternalSigner: Send + Sync {
    /// Sign data and return DER-encoded ECDSA signature.
    /// This must be a blocking operation.
    fn sign_blocking(&self, data: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// Get the public key bytes (uncompressed SEC1 format for secp256r1).
    fn public_key_bytes(&self) -> &[u8];
}
```

#### 3. Create ExternalEcdsa keypair wrapper

**New file:** `identity/src/ecdsa_external.rs`

```rust
//! ECDSA keypair backed by an external signer.

use crate::error::DecodingError;
use crate::external::ExternalSigner;
use std::sync::Arc;

/// ECDSA keypair that delegates signing to an external implementation.
#[derive(Clone)]
pub struct Keypair {
    signer: Arc<dyn ExternalSigner>,
    public: super::ecdsa::PublicKey,
}

impl Keypair {
    pub fn from_external(signer: Arc<dyn ExternalSigner>) -> Result<Self, DecodingError> {
        let public = super::ecdsa::PublicKey::try_from_bytes(signer.public_key_bytes())?;
        Ok(Self { signer, public })
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signer.sign_blocking(msg)
            .expect("External signing failed")
    }

    pub fn public(&self) -> &super::ecdsa::PublicKey {
        &self.public
    }
}
```

#### 4. Add ExternalEcdsa variant to KeyPairInner

**File:** `identity/src/keypair.rs`

```rust
#[derive(Clone)]
enum KeyPairInner {
    // ... existing variants ...
    #[cfg(feature = "external-signer")]
    ExternalEcdsa(ecdsa_external::Keypair),
}

impl Keypair {
    #[cfg(feature = "external-signer")]
    pub fn from_external(signer: Arc<dyn external::ExternalSigner>) -> Result<Self, DecodingError> {
        Ok(Keypair {
            keypair: KeyPairInner::ExternalEcdsa(ecdsa_external::Keypair::from_external(signer)?),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self.keypair {
            // ... existing variants ...
            #[cfg(feature = "external-signer")]
            KeyPairInner::ExternalEcdsa(ref pair) => Ok(pair.sign(msg)),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self.keypair {
            // ... existing variants ...
            #[cfg(feature = "external-signer")]
            KeyPairInner::ExternalEcdsa(ref pair) => PublicKey {
                publickey: PublicKeyInner::Ecdsa(pair.public().clone()),
            },
        }
    }
}
```

#### 5. Update lib.rs exports

**File:** `identity/src/lib.rs`

```rust
#[cfg(feature = "external-signer")]
pub mod external;
#[cfg(feature = "external-signer")]
pub mod ecdsa_external;

#[cfg(feature = "external-signer")]
pub use external::ExternalSigner;
```

### HSM Implementation in kels-gossip

**File:** `services/kels-gossip/src/hsm_signer.rs`

```rust
use libp2p_identity::{ExternalSigner, error::SigningError};

pub struct HsmSigner {
    hsm_url: String,
    key_label: String,
    public_key: Vec<u8>,
    client: reqwest::Client,
}

impl HsmSigner {
    pub async fn new(hsm_url: String, key_label: String) -> Result<Self, Error> {
        let client = reqwest::Client::new();

        // Get or create key, fetch public key
        let public_key = Self::get_or_create_key(&client, &hsm_url, &key_label).await?;

        Ok(Self { hsm_url, key_label, public_key, client })
    }

    async fn sign_async(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        // POST /api/hsm/keys/{label}/sign
        // Returns DER-encoded signature
    }
}

impl ExternalSigner for HsmSigner {
    fn sign_blocking(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.sign_async(data))
        })
    }

    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}
```

**Usage in kels-gossip:**
```rust
use libp2p_identity::Keypair;
use std::sync::Arc;

// Create HSM signer
let hsm_signer = HsmSigner::new(hsm_url, key_label).await?;
let signer: Arc<dyn ExternalSigner> = Arc::new(hsm_signer);

// Create libp2p keypair backed by HSM
let keypair = Keypair::from_external(signer)?;

// Use with SwarmBuilder
let swarm = SwarmBuilder::with_existing_identity(keypair)
    .with_tokio()
    // ...
```

### PeerId Consistency

Since the HSM keypair uses the same `PublicKey` type as regular ECDSA, PeerId derivation works identically:
- `keypair.public().to_peer_id()` returns the same PeerId for the same public key
- PeerId is stable across restarts (same HSM key = same public key = same PeerId)

## libp2p Connection Filtering (Allowlist Enforcement)

In addition to registry API authentication, we'll enforce the allowlist at the libp2p layer by disconnecting unauthorized peers immediately after connection.

### How libp2p Connection Events Work

1. Noise handshake completes → peer identity verified
2. `NetworkBehaviour::on_swarm_event` receives `FromSwarm::ConnectionEstablished { peer_id, ... }`
3. Behaviour can emit `ToSwarm::CloseConnection { peer_id, connection: CloseConnection::All }`

### Implementation: AllowlistBehaviour

**New file:** `services/kels-gossip/src/allowlist.rs`

```rust
use libp2p::swarm::{NetworkBehaviour, ToSwarm, FromSwarm, CloseConnection};
use libp2p::PeerId;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// NetworkBehaviour that disconnects peers not in the allowlist
pub struct AllowlistBehaviour {
    allowlist: Arc<RwLock<HashSet<PeerId>>>,
    pending_disconnects: Vec<PeerId>,
}

impl AllowlistBehaviour {
    pub fn new(allowlist: Arc<RwLock<HashSet<PeerId>>>) -> Self {
        Self {
            allowlist,
            pending_disconnects: Vec::new(),
        }
    }
}

impl NetworkBehaviour for AllowlistBehaviour {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = Void;  // No events to emit

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionEstablished(conn) = event {
            // Check allowlist (blocking read is OK here - fast operation)
            let allowed = self.allowlist.blocking_read().contains(&conn.peer_id);
            if !allowed {
                tracing::warn!(
                    peer_id = %conn.peer_id,
                    "Unauthorized peer connected, disconnecting"
                );
                self.pending_disconnects.push(conn.peer_id);
            }
        }
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, _>> {
        if let Some(peer_id) = self.pending_disconnects.pop() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::All,
            });
        }
        Poll::Pending
    }

    // ... other required methods with default/dummy implementations
}
```

### Composing with Existing Behaviours

Use libp2p's behaviour composition to add the allowlist check:

```rust
#[derive(NetworkBehaviour)]
struct KelsBehaviour {
    gossipsub: gossipsub::Behaviour,
    request_response: request_response::Behaviour<JsonCodec>,
    identify: identify::Behaviour,
    allowlist: AllowlistBehaviour,  // NEW: filters unauthorized peers
}
```

### Allowlist Distribution (Registry-Signed)

The **registry is the authoritative source** for the peer allowlist. It maintains, signs, and distributes the allowlist to all nodes.

**Registry Allowlist API:**
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/allowlist` | Get signed allowlist (public, no auth) |

**Admin CLI (kels-registry-admin):**
A simple CLI tool for managing the peer allowlist. Requires direct access to the registry database and HSM.

```bash
# Add a peer
kels-registry-admin peer add --peer-id 12D3KooW... --node-id node-a

# Remove a peer
kels-registry-admin peer remove --peer-id 12D3KooW...

# List all peers
kels-registry-admin peer list

# Show current allowlist
kels-registry-admin allowlist show

# Show registry identity status (prefix, key version)
kels-registry-admin identity status
# With JSON output (for scripting):
kels-registry-admin identity status -j

# Key rotation (normal)
kels-registry-admin identity rotate

# Recovery rotation (use recovery key to rotate)
kels-registry-admin identity recovery-rotate

# Disaster recovery: recover (claim control with recovery key)
kels-registry-admin identity recover

# Disaster recovery: contest (challenge a recovery within contest period)
kels-registry-admin identity contest

# Decommission: permanently end the registry's identity
kels-registry-admin identity decommission
```

The CLI connects directly to PostgreSQL and HSM to manage the allowlist. Anyone with kubectl exec access to the registry pod can run these commands.

**CLI Implementation (services/kels-registry/src/bin/kels-registry-admin.rs):**
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
}

#[derive(Subcommand)]
enum PeerAction {
    Add { peer_id: String, node_id: String },
    Remove { peer_id: String },
    List,
}

#[derive(Subcommand)]
enum AllowlistAction {
    Show,     // Show current allowlist (latest version)
    History,  // Show all versions (audit trail)
}

#[derive(Subcommand)]
enum IdentityAction {
    Status,          // Show registry identity status (prefix, current key version)
    Rotate,          // Normal key rotation
    RecoveryRotate,  // Rotate using recovery key
    Recover,         // Disaster recovery: claim control with recovery key
    Contest,         // Disaster recovery: challenge a recovery within contest period
    Decommission,    // Permanently end the registry's identity
}

// Example: Adding a peer creates new record and anchors in KEL
async fn add_peer(repo: &Repository, kel_builder: &KeyEventBuilder, peer_id: &str, node_id: &str) -> Result<()> {
    // Check if peer already exists
    let prefix = format!("peer-{}", peer_id);  // Derive prefix from peer_id
    if let Some(existing) = repo.peer.get_latest(&prefix).await? {
        if existing.active {
            println!("Peer {} already authorized", peer_id);
            return Ok(());
        }
        // Reactivate: create new version with active=true
        let mut peer = existing.clone();
        peer.active = true;
        peer.increment()?;
        repo.peer.insert(&peer).await?;
        kel_builder.anchor(&peer.said).await?;
        println!("Reactivated peer {} (node: {})", peer_id, node_id);
        println!("Version: {} (SAID: {})", peer.version, peer.said);
        return Ok(());
    }

    // Create new peer record
    let peer = Peer::create(peer_id.to_string(), node_id.to_string());
    repo.peer.insert(&peer).await?;

    // Anchor the peer SAID in registry's KEL
    kel_builder.anchor(&peer.said).await?;

    println!("Added peer {} (node: {})", peer_id, node_id);
    println!("Version: {} (SAID: {})", peer.version, peer.said);
    Ok(())
}

// Example: Removing a peer creates new version with active=false
async fn remove_peer(repo: &Repository, kel_builder: &KeyEventBuilder, peer_id: &str) -> Result<()> {
    let prefix = format!("peer-{}", peer_id);
    let existing = repo.peer.get_latest(&prefix).await?
        .ok_or_else(|| anyhow!("Peer not found: {}", peer_id))?;

    if !existing.active {
        println!("Peer {} already inactive", peer_id);
        return Ok(());
    }

    // Create new version with active=false
    let mut peer = existing.clone();
    peer.active = false;
    peer.increment()?;
    repo.peer.insert(&peer).await?;

    // Anchor the peer SAID in registry's KEL
    kel_builder.anchor(&peer.said).await?;

    println!("Removed peer {} (node: {})", peer_id, peer.node_id);
    println!("Version: {} (SAID: {})", peer.version, peer.said);
    Ok(())
}
```

**Peers API Response:**

The `/api/peers` endpoint returns all peer records with their full version history:

```rust
// Response is Vec<PeerChain> - each peer includes its complete version history
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerChain {
    pub prefix: String,                  // Stable lineage ID (unique per peer)
    pub records: Vec<Peer>,              // Complete history, newest first
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    pub said: String,                    // Content hash (verifiable)
    pub prefix: String,                  // Stable lineage ID
    pub previous: Option<String>,        // SAID of previous version
    pub version: u64,                    // Version number
    pub created_at: StorageDatetime,     // Timestamp
    pub peer_id: String,                 // libp2p PeerId
    pub node_id: String,                 // Human-readable node name
    pub active: bool,                    // Current authorization status
}

// GET /api/peers returns Vec<PeerChain>
// Clients cache chains and can detect rollback attacks
```

**Important:** Registry must use `serde_json` with `preserve_order` feature to ensure deterministic JSON serialization. Without this, field order may change between serialization passes, causing SAID verification to fail.

Nodes verify each peer chain:
1. **Chain integrity**: Verify each record's SAID, confirm `previous` links correctly
2. **Authenticity**: Verify each record's SAID is anchored in registry's KEL
3. **Rollback detection**: Compare chain length with cached version, warn if shorter
4. **Authorization**: Use latest record's `active` field to determine if peer is authorized

**Registry's Identity (KELS-backed, Direct Mode):**

The registry has its own KELS identity, managed the same way as other identities:

- Registry maintains a KEL in its database (using KeyEventBuilder)
- HSM-backed key provider for signing (HSM key label: `kels-registry`)
- **Trust anchor:** Registry's prefix distributed to nodes via env var `REGISTRY_PREFIX`
- **Direct mode:** Nodes fetch registry's KEL via HTTP, not gossip

```
GET /api/registry-kel          -> Returns registry's full KEL
GET /api/registry-kel/current  -> Returns current signing public key
```

**Node verification flow:**
1. Node has `REGISTRY_PREFIX=Eabc123...` from environment
2. Fetches `GET /api/registry-kel`
3. Verifies KEL chain (inception prefix matches, signatures valid)
4. Fetches `GET /api/peers` (returns full chains)
5. For each peer chain:
   - Verify chain integrity (SAIDs and previous links)
   - Check all records anchored in registry's KEL
   - Compare with cached chain length (rollback detection)
   - Cache chain for future comparison
6. Build authorized peer set from latest `active=true` records

**Benefits:**
- Consistent security model (everything uses KELS with KEL anchoring)
- Registry can rotate keys (nodes verify via KEL chain)
- Only trust anchor is prefix, not a specific public key
- No separate signatures needed - SAID anchoring in KEL provides authenticity

**Registry Deployment:**
```
kels-registry namespace:
├── hsm (SoftHSM2 service)
├── postgres (NEW - for allowlist + admin)
├── redis (existing - for node registrations)
└── kels-registry (uses HSM for signing)
```

**Registry Data Model (Versioned Repository):**

Each peer is its own versioned entity, individually anchored in the KEL:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "peer")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    #[said]
    pub said: String,                    // Content hash (CESR Blake3)

    #[prefix]
    pub prefix: String,                  // Stable lineage ID (unique per peer_id)

    #[previous]
    pub previous: Option<String>,        // SAID of previous version

    #[version]
    pub version: u64,                    // Version number

    #[created_at]
    pub created_at: StorageDatetime,

    // Application fields
    pub peer_id: String,                 // libp2p PeerId
    pub node_id: String,                 // Human-readable node name
    pub active: bool,                    // Whether peer is currently authorized
}
```

**PostgreSQL Schema (auto-generated by Stored derive):**
```sql
CREATE TABLE peer (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    peer_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    active BOOLEAN NOT NULL
);

CREATE INDEX idx_peer_prefix ON peer(prefix);
CREATE INDEX idx_peer_version ON peer(prefix, version DESC);
CREATE INDEX idx_peer_active ON peer(peer_id, active) WHERE active = true;
```

**Operations:**
- `create(peer_id, node_id)` - Creates version 0 with active=true
- `get_latest(prefix)` - Gets current state of a peer
- `get_active_peers()` - Gets all peers where active=true (latest version per prefix)
- `deactivate(prefix)` - Creates new version with active=false
- `get_history(prefix)` - Gets all versions for audit trail

**Security Note:** If registry is compromised, it could serve stale records. This is not fully solvable without external consensus. Mitigations:
- Each record is anchored in KEL (provides ordering within registry's view)
- Full chains returned: clients cache and detect rollback by comparing chain lengths
- Gossip protocol naturally distributes latest state across honest nodes
- Nodes reject shorter chains than what they've cached, requiring restart to accept rollback

**Node Onboarding Workflow:**
```
Phase 1: Node starts (unauthorized)
1. Deploy new node with HSM service
2. HSM generates key: POST /api/hsm/keys {"label": "kels-gossip-x"}
3. kels-gossip starts, creates libp2p identity from HSM key
4. Node fetches KELS data from registry via HTTP (read-only, no auth required)
5. Node tries to register with registry → FAILS (not in allowlist)
6. Node tries to connect to gossip peers → DISCONNECTED (not in allowlist)
7. Node continues fetching KELS updates via HTTP (read-only mode)

Phase 2: Admin authorizes node
8. Get node's PeerId from logs or derive from HSM public key
9. Admin adds PeerId via CLI: kubectl exec -n kels-registry kels-registry-0 -- \
     kels-registry-admin peer add --peer-id 12D3KooW... --node-id node-x
10. CLI creates new allowlist version and anchors SAID in registry's KEL

Phase 3: Node becomes authorized
11. Node retries registration → SUCCEEDS (now in allowlist)
12. Existing nodes fetch updated allowlist on next poll
13. Node connects to gossip peers → ACCEPTED (now in allowlist)
14. Node fully operational: gossip + registry registration + KELS data
```

**Key Points:**
- **Read APIs (unauthenticated):** GET /api/kels/*, GET /api/nodes, GET /api/registry-kel, GET /api/peers
- **Write APIs (authenticated):** POST /api/nodes/register, POST /api/kels/*
- **Gossip (authenticated):** Only authorized peers can connect

**Peer Update Notification (Registry Gossip):**

Since the registry has a KELS identity, it can join the gossip network:
1. Registry's PeerId (derived from its KELS key) is in the peer list
2. Registry joins gossip network as a peer
3. On peer change, registry broadcasts: `PeerUpdated { peer_id, said }`
4. Nodes receive broadcast, poll `GET /api/peers` to fetch updated list
5. Nodes verify each peer's SAID is anchored in registry's KEL

```rust
// Gossip message type for peer notifications
#[derive(Serialize, Deserialize)]
enum RegistryMessage {
    PeerUpdated { peer_id: String, said: String },
}
```

This gives near-instant notification while keeping the actual peer fetch via HTTP (direct mode).

**Node Allowlist Refresh:**
```rust
// On startup: fetch and verify registry's KEL (direct mode)
async fn init_registry_verifier(registry_url: &str, registry_prefix: &str) -> Result<Kel> {
    let kel: Kel = reqwest::get(format!("{}/api/registry-kel", registry_url))
        .await?.json().await?;

    // Verify KEL chain and prefix matches trust anchor
    kel.verify()?;
    if kel.prefix() != Some(registry_prefix) {
        return Err("Registry prefix mismatch");
    }

    Ok(kel)
}

// Periodically (e.g., every 60s): refresh peer list
async fn refresh_peers(
    registry_url: &str,
    registry_kel: &Kel,
    cached_chains: &mut HashMap<String, Vec<Peer>>,  // prefix -> chain
) -> Result<HashSet<PeerId>> {
    let chains: Vec<PeerChain> = reqwest::get(format!("{}/api/peers", registry_url))
        .await?.json().await?;

    let mut authorized = HashSet::new();
    for chain in chains {
        // 1. Verify chain integrity (each record's SAID and previous links)
        if !verify_chain(&chain.records)? {
            tracing::warn!(prefix = %chain.prefix, "Chain integrity check failed - skipping");
            continue;
        }

        // 2. Verify all records are anchored in registry's KEL
        let all_anchored = chain.records.iter()
            .all(|r| registry_kel.is_anchored(&r.said).unwrap_or(false));
        if !all_anchored {
            tracing::warn!(prefix = %chain.prefix, "Not all records anchored - skipping");
            continue;
        }

        // 3. Rollback detection: compare with cached chain length
        if let Some(cached) = cached_chains.get(&chain.prefix) {
            if chain.records.len() < cached.len() {
                tracing::warn!(
                    prefix = %chain.prefix,
                    cached_len = cached.len(),
                    received_len = chain.records.len(),
                    "Possible rollback attack detected!"
                );
                // Keep using cached version (longer chain)
                if let Some(latest) = cached.first() {
                    if latest.active {
                        if let Ok(peer_id) = latest.peer_id.parse::<PeerId>() {
                            authorized.insert(peer_id);
                        }
                    }
                }
                continue;
            }
        }

        // 4. Update cache and check authorization
        if let Some(latest) = chain.records.first() {
            if latest.active {
                if let Ok(peer_id) = latest.peer_id.parse::<PeerId>() {
                    authorized.insert(peer_id);
                }
            }
        }
        cached_chains.insert(chain.prefix.clone(), chain.records);
    }

    Ok(authorized)
}

fn verify_chain(records: &[Peer]) -> Result<bool> {
    for (i, record) in records.iter().enumerate() {
        // Verify SAID
        if !record.verify_said()? {
            return Ok(false);
        }
        // Verify previous link (except for version 0)
        if i + 1 < records.len() {
            let prev = &records[i + 1];
            if record.previous.as_deref() != Some(&prev.said) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// Periodically: also refresh registry KEL to pick up key rotations
async fn refresh_registry_kel(registry_url: &str, current_kel: &mut Kel) -> Result<()> {
    let new_kel: Kel = reqwest::get(format!("{}/api/registry-kel", registry_url))
        .await?.json().await?;
    new_kel.verify()?;
    *current_kel = new_kel;
    Ok(())
}
```

**Initial Bootstrap (One-Time Setup):**
```
1. Deploy registry namespace with HSM + PostgreSQL
2. Deploy kels-registry service
3. Registry incepts its KELS identity on first startup:
   - HSM generates key (label: "kels-registry")
   - Creates inception event, stores KEL in database
4. Run `garden run fetch-registry-prefix` to save prefix to .kels/registry_prefix
5. Node deployments automatically include this prefix in their environment
```

**Garden Tasks for Registry Prefix Distribution:**

Similar to authentic-ddi's authority prefix pattern, we add Garden tasks to fetch and distribute the registry's KEL prefix.

**New file:** `services/kels-registry/garden.yml` (additions)

```yaml
---
kind: Run
name: fetch-registry-prefix
type: exec

dependencies:
  - deploy.kels-registry

spec:
  command:
    - bash
    - -c
    - |
      mkdir -p ../../.kels
      RESPONSE=$(kubectl exec -n ${environment.namespace} deploy/kels-registry -c kels-registry -- \
        kels-registry-admin identity status -j 2>/dev/null)
      PREFIX=$(echo "$RESPONSE" | jq -r '.prefix // empty')
      if [ -z "$PREFIX" ]; then
        echo "Error: Could not fetch registry prefix. Is kels-registry initialized?"
        echo "Response: $RESPONSE"
        exit 1
      fi
      echo -n "$PREFIX" > "../../.kels/registry_prefix"
      echo "Registry prefix saved: $PREFIX"
```

**New file:** `garden.yml` (project root)

```yaml
kind: Run
name: read-registry-prefix
type: exec

include:
  - .kels/registry_prefix

spec:
  command:
    - cat
    - .kels/registry_prefix
```

**Node deployment uses the saved prefix:**

```yaml
# In services/kels-gossip/manifests.yml.tpl
env:
  - name: REGISTRY_PREFIX
    value: "{{ (readFile \"../../.kels/registry_prefix\") | trim }}"
```

This is the **only static configuration** needed. The prefix never changes (it's derived from inception). Key rotations are handled via KEL events that nodes verify.

### Security Flow

```
1. Unknown peer connects via TCP
2. Noise handshake authenticates peer identity → PeerId known
3. ConnectionEstablished event fires
4. AllowlistBehaviour checks peer_id against allowlist
5. If not authorized → CloseConnection emitted → peer disconnected
6. If authorized → connection proceeds normally
```

This provides defense in depth:
- **libp2p layer**: Unauthorized peers can't participate in gossip or request data
- **Registry layer**: Even if connection check is bypassed, can't register as a node

## Open Questions (Resolved)

1. **HSM key label convention:** `kels-gossip-{node_id}` - consistent with authentic-ddi pattern ✓
2. **Signature algorithm:** ECDSA with SHA-256 over canonical JSON ✓
3. **Allowlist updates:** Admin CLI with direct database/HSM access (no API auth needed) ✓
4. **Identity binding:** PeerId is derived from HSM public key (bound together) ✓

## Security Considerations

- HSM keys never leave the HSM service
- PeerId is cryptographically bound to the HSM key (via KELS identity)
- Registry validates both signature AND allowlist membership for write operations
- Each node has isolated HSM with separate PVC
- Admin CLI requires kubectl exec access to registry pod (same trust boundary as full cluster access)
- No separate admin authentication - anyone with deployment access can manage the allowlist
- Allowlist changes create versioned records with SAIDs anchored in registry's KEL (cryptographic audit trail)
- Read APIs remain unauthenticated (nodes can fetch KELS data before authorization)
- Write APIs require signed requests from allowlisted peers
- Gossip connections require peer to be in allowlist (verified after Noise handshake)
- Registry has its own KELS identity, its PeerId is in the allowlist (bootstrap: registry adds itself)
- Trust anchor is registry prefix (immutable), not a public key (supports key rotation)
- Nodes fetch registry KEL via direct mode HTTP, verify chain before trusting signatures
