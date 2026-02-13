# Registry Attack Surface

Analysis of attack vectors against the KELS registry federation and gossip network.

## Trust Model

The system's root of trust is **compile-time trusted registry prefixes** (`TRUSTED_REGISTRY_PREFIXES`). Every verification chain terminates at a KEL whose prefix matches one of these values. Changing the trust anchors requires recompiling the binary.

**Assumptions:**
- HSM service is not network-accessible outside its pod
- Identity service is not network-accessible outside its pod
- Docker/Kubernetes network policies enforce pod isolation
- Registry, KELS, and gossip services are exposed to the overlay network

## Rogue Federation Leader

A compromised leader controls what enters the Raft log.

**Attack:** Leader writes `AddPeer` entries for peers that were never approved through the proposal/voting process.

**Mitigations:**
- **State machine verification**: On Raft log replay, `apply()` checks every `AddPeer` with `PeerScope::Core` against completed proposals. Each approval vote must pass `vote.verify()` (SAID integrity) and have its SAID anchored in the voter's KEL. If verified voters < threshold, the entry is silently rejected.
- **Gossip allowlist**: `refresh_allowlist()` independently fetches completed proposals and re-verifies every core peer's votes (SAID integrity + KEL anchoring). Peers without sufficient verified votes are excluded from the allowlist.
- **Defense-in-depth**: Even if a rogue leader inserts a peer, followers reject it during apply, and gossip nodes reject it during allowlist refresh.

**Residual risk:** A leader could manipulate `ProposeCorePeer` or `VoteCorePeer` entries in the Raft log. However, votes are verified by SAID (tamper-evident) and anchored in voter KELs (unforgeable without the voter's signing key).

## Rogue Federation Member (Non-Leader)

A compromised follower cannot directly write to the Raft log but could:

**Attack 1 — Vote manipulation:** Submit forged votes through the admin API.
- **Mitigation:** Votes are `SelfAddressed` records. The state machine verifies `vote.verify()` (SAID matches content). The vote SAID must be anchored in the voter's KEL, which requires the voter's actual signing key.

**Attack 2 — Serve stale/modified data:** Return outdated or tampered peer lists, KELs, or proposal responses.
- **Mitigation:** All peer records are `SelfAddressed` (SAID integrity). Peer SAIDs must be anchored in a trusted registry's KEL. Gossip nodes verify this on every allowlist refresh.

**Attack 3 — Refuse to participate:** Withhold votes or go offline.
- **Mitigation:** Raft handles this via leader election and quorum. The approval threshold is designed so a minority of members cannot block consensus (ceil(n/3) for 10+ members).

## Compromised HSM

If an attacker gains access to the HSM service:

**Attack:** Sign arbitrary data as the registry, forge KEL events, create fraudulent peer records.
- **Mitigation:** HSM is pod-internal only (not exposed to the overlay network). Compromise requires pod-level access.
- **Detection:** KEL history is append-only and chained. Unauthorized events create observable forks that other registries would detect during KEL verification.
- **Recovery:** Key rotation (via `rot` event) invalidates the compromised key. Recovery keys (via `rec`/`ror`) can be used if signing keys are compromised.

## Network-Level Attacks

### Man-in-the-Middle (Federation RPC)

**Attack:** Intercept and modify Raft messages between registries.
- **Mitigation:** All federation RPC is wrapped in `SignedFederationRpc` — payload signed with sender's current key (from KEL). Receiver verifies signature against sender's KEL. Modifying the payload invalidates the signature.

### Man-in-the-Middle (Gossip)

**Attack:** Intercept gossip messages between nodes.
- **Mitigation:** libp2p Noise protocol provides authenticated encryption. Messages are signed with `MessageAuthenticity::Signed`. PeerId is cryptographically derived from the node's public key.

### Denial of Service — Allowlist Refresh Trigger

**Attack:** Flood the gossip network with connections from unknown PeerIds, triggering repeated allowlist refreshes.
- **Mitigation:** The `refresh_tx` channel has capacity 1 — multiple triggers coalesce into a single refresh. However, there is no rate limiting on inbound connections at the application level.
- **Residual risk:** Pending verification set is bounded (max 200 peers, 300s TTL) but a sustained flood could still cause legitimate peers to be evicted before verification completes.

### Denial of Service — KEL Fetch Amplification

**Attack:** Cause a node to repeatedly fetch and verify KELs by submitting requests with unknown prefixes.
- **Mitigation:** KEL fetches are cached (with refresh-on-failure). The `retry_once!` macro limits retries to one. But a large number of distinct prefixes could cause many cache misses.

## Gossip Protocol Attacks

### Announcement Injection

**Attack:** Publish gossip announcements for non-existent or stale KELs.
- **Mitigation:** Receivers fetch the actual KEL via HTTP and verify it. False announcements waste bandwidth but don't corrupt state. The `event_exists()` check prevents processing announcements for already-stored events.

### Scope Confusion

**Attack:** A regional node publishes an announcement with `destination: All`, bypassing scope boundaries.
- **Mitigation:** Only core nodes rebroadcast cross-scope. Regional nodes' messages are filtered by scope at the receiving end. However, the gossipsub mesh does not enforce scope — filtering is application-level.

### Selective Message Dropping

**Attack:** A core node selectively drops announcements, preventing propagation to certain regions.
- **Mitigation:** gossipsub mesh redundancy (mesh target 3, min 2). Periodic allowlist refresh and bootstrap reconciliation eventually fill gaps. No real-time detection mechanism.

## Admin API

### Localhost Bypass

**Attack:** If an attacker can reach the registry from localhost (e.g., SSRF, container escape), they can use the admin API.
- **Mitigation:** `is_localhost()` checks `SocketAddr.ip().is_loopback()`. This is a network-level check, not an application-level authentication.
- **Residual risk:** Container networking or reverse proxy misconfiguration could expose localhost. There is no additional authentication on admin endpoints.

### Missing Localhost Check on Proposal Endpoints

`admin_propose_peer` and `admin_vote_proposal` check federation membership but not localhost. They are exposed on the federation-mode router at `/api/admin/proposals` (POST) and `/api/admin/proposals/:id/vote` (POST).
- **Concern:** Any network client that can reach the registry can submit proposals and votes, as long as the proposer/voter prefix is a federation member. The actual security relies on vote SAID anchoring in the voter's KEL — you need the voter's signing key to create a valid vote.

## Unauthenticated Endpoints

These endpoints have no authentication and return potentially sensitive information:

| Endpoint | Risk | Justification |
|----------|------|---------------|
| `GET /api/peers` | Enumerates all active peers with peer_ids, node_ids, multiaddrs | Needed for peer discovery; peer_ids are public (derived from public keys) |
| `GET /api/registry-kel` | Exposes full KEL history | KELs are public by design — verifiability requires availability |
| `GET /api/registry-kels` | Exposes all federation member KELs | Same as above; HA design requires any registry to serve all KELs |
| `GET /api/federation/status` | Reveals leader, term, member list | Status information; member prefixes are compile-time constants |
| `GET /api/federation/proposals` | Exposes completed proposals and votes | Required for independent verification by gossip nodes |
| `POST /api/kels/events` | Accepts event submissions from anyone | Events are cryptographically validated (signatures checked against KEL) |
| `GET /api/kels/kel/:prefix` | Exposes any stored KEL | KELs are public; this is the data-plane read path |

These are intentionally public. The security model relies on cryptographic verification, not access control.

## Supply Chain / Build-Time

### Trusted Prefixes Manipulation

**Attack:** Modify `TRUSTED_REGISTRY_PREFIXES` at build time to add a rogue registry.
- **Mitigation:** This is a compile-time constant. Build pipeline integrity is the defense.

### Dependency Confusion

**Attack:** Substitute a malicious crate for `verifiable-storage`, `cesr`, or `openraft`.
- **Mitigation:** `cargo deny` checks are in the Makefile (`deny-check` target). Cargo.lock pins exact versions.

## Summary of Residual Risks

1. **Admin API lacks authentication beyond localhost check** — relies on network isolation
2. **Proposal/vote endpoints missing localhost check** — relies on KEL anchoring for security
3. ~~**Allowlist pending set unbounded**~~ — mitigated: max 200 pending peers with 300s TTL, oldest evicted at capacity
4. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (GovernorLayer), 5 MiB body limit
5. **No TLS at application level** — relies on overlay network encryption or external termination
6. **gossipsub scope filtering is application-level** — protocol layer doesn't enforce boundaries

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### Rate limiting (addresses residual risks 3, 4)

No application-level rate limiting exists on any endpoint. The allowlist pending verification set has no TTL or max size, so a connection flood can grow it unboundedly.

- [x] Add rate limiting middleware to the registry HTTP server (per-IP via GovernorLayer on write endpoints: 200 req/s sustained, 1000 burst; 5 MiB body limit)
- [x] Add TTL and max size cap to the pending verification set in `AllowlistBehaviour` (max 200 pending peers, 300s TTL, oldest evicted at capacity)

### Admin API authentication (addresses residual risks 1, 2)

The admin API relies solely on `is_localhost()` for access control. Proposal and vote endpoints don't check localhost at all — they rely on KEL anchoring for security, which is sound but means any network client can submit proposals.

- [ ] Add localhost check to `admin_propose_peer` and `admin_vote_proposal` endpoints — this is a simple fix that limits proposal submission to the local operator while KEL anchoring remains the cryptographic backstop
- [ ] Evaluate whether admin endpoints need an additional authentication layer (e.g., bearer token, mTLS) for defense-in-depth beyond localhost — relevant if container networking or reverse proxy misconfiguration could expose loopback

### TLS between services (addresses residual risk 5)

No TLS at the application level. Inter-service HTTP traffic (registry ↔ identity, registry ↔ HSM, gossip ↔ registry) relies on overlay network encryption or external termination.

- [ ] Add mTLS or service mesh sidecar for inter-service communication within the cluster
- [ ] Add TLS termination for federation RPC between registries (currently relies on `SignedFederationRpc` for integrity but not confidentiality)

### Gossip scope enforcement (addresses residual risk 6)

Scope filtering (Regional vs Core vs All) is application-level. The gossipsub mesh delivers all messages to all subscribers; filtering happens after receipt.

- [ ] Evaluate per-scope gossipsub topics (e.g., `kels/events/v1/regional`, `kels/events/v1/core`) so the protocol layer enforces scope boundaries — trade-off is increased mesh complexity and potential message duplication at bridging nodes
