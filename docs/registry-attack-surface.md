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
- **Mitigation:** Raft handles this via leader election and quorum. The approval threshold has a minimum floor of 3 votes regardless of federation size, scaling to ceil(n/3) for 10+ members.

## Compromised HSM

If an attacker gains access to the HSM service:

**Attack:** Sign valid events as the registry — add rogue peers, cast fraudulent votes, anchor malicious data. Because the attacker holds the real signing key, events chain perfectly from the current tail with valid signatures. There is no cryptographic distinction between attacker-signed and operator-signed events.
- **Mitigation:** HSM is pod-internal only (not exposed to the overlay network). Compromise requires pod-level access. Critically, compromising a single registry's HSM is insufficient to add rogue peers to the federation — core peer approval requires a minimum of 3 votes regardless of federation size, each anchored in the voter's KEL. Adding a rogue peer requires colluding with at least 3 independently operated registries (and compromising their HSMs), which represents a significant operational barrier.
- **Detection:** No cryptographic detection — events are indistinguishable from legitimate ones. Detection is necessarily out-of-band: operators noticing unexpected events in their registry's KEL, or other federation members observing unauthorized proposals, votes, or peer additions that nobody initiated. A rational attacker would not create divergence (which freezes the KEL and is immediately visible) but instead silently extend the chain.
- **Recovery:** Once detected, the operator submits a `rec` event (requires rotation + recovery key). The merge protocol truncates the attacker's events from the active chain (archiving them for audit) and resumes from the pre-compromise state under a new key. If the attacker has also compromised the rotation key, recovery still works as long as they don't hold the recovery key. If both rotation and recovery keys are compromised, `cnt` (contest) permanently freezes the KEL — the correct outcome when key compromise is total.

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

### Proposal/Vote Endpoints (No Localhost Check — By Design)

`admin_propose_peer` and `admin_vote_proposal` check federation membership but not localhost. They are exposed on the federation-mode router at `/api/admin/proposals` (POST) and `/api/admin/proposals/:id/vote` (POST).
- **By design:** These are the federation RPC path — remote registries submit proposals and votes over the network. A localhost check would break federation. Security relies on vote SAID anchoring in the voter's KEL — you need the voter's signing key to create a valid vote, which is unforgeable.

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
2. ~~**Proposal/vote endpoints missing localhost check**~~ — not a risk: these are federation RPC endpoints that remote registries must reach; KEL anchoring is the correct security mechanism
3. ~~**Allowlist pending set unbounded**~~ — mitigated: max 200 pending peers with 300s TTL, oldest evicted at capacity
4. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (GovernorLayer), 5 MiB body limit
5. ~~**No TLS at application level**~~ — not required: all data is public by design and end-verifiable. Federation RPC uses `SignedFederationRpc` for integrity. The gossip layer uses libp2p Noise for authenticated encryption
6. ~~**gossipsub scope filtering is application-level**~~ — not a security concern: scope is a routing optimization, not a security boundary. All nodes replicate the same data

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### Rate limiting (addresses residual risks 3, 4)

No application-level rate limiting exists on any endpoint. The allowlist pending verification set has no TTL or max size, so a connection flood can grow it unboundedly.

- [x] Add rate limiting middleware to the registry HTTP server (per-IP via GovernorLayer on write endpoints: 200 req/s sustained, 1000 burst; 5 MiB body limit)
- [x] Add TTL and max size cap to the pending verification set in `AllowlistBehaviour` (max 200 pending peers, 300s TTL, oldest evicted at capacity)

### Admin API authentication (addresses residual risk 1)

The admin API relies solely on `is_localhost()` for access control. Proposal and vote endpoints intentionally have no localhost check — they are the federation RPC path used by remote registries to submit proposals and votes. KEL anchoring (vote SAID must be signed by the voter's key and anchored in their KEL) is the correct security mechanism for these endpoints.

- [ ] Evaluate whether non-federation admin endpoints need an additional authentication layer (e.g., bearer token, mTLS) for defense-in-depth beyond localhost — relevant if container networking or reverse proxy misconfiguration could expose loopback

### ~~TLS between services (addresses residual risk 5)~~

~~No TLS at the application level.~~ Not required — all data is public by design (KELs must be accessible for verification) and end-verifiable (cryptographic signatures + SAID chaining). Federation RPC is wrapped in `SignedFederationRpc` for integrity. The gossip layer uses libp2p Noise for authenticated encryption. TLS would add confidentiality for non-confidential data and redundant transport-level integrity.

### ~~Gossip scope enforcement (addresses residual risk 6)~~

~~Scope filtering (Regional vs Core vs All) is application-level.~~ Not a security concern — scope is a routing optimization, not a security boundary. All nodes replicate the same data. Scope violations at worst cause redundant fetches, handled by existing dedup.
