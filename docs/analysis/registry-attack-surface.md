# Registry Attack Surface

Analysis of attack vectors against the KELS registry federation and gossip network. See also [protocol-attack-surface.md](protocol-attack-surface.md) for KEL/event-level attacks and [node-attack-surface.md](node-attack-surface.md) for data-plane deployment attacks.

## Trust Model

The system's root of trust is **compile-time trusted registry prefixes** (`TRUSTED_REGISTRY_PREFIXES`). Every verification chain terminates at a KEL whose prefix matches one of these values. Changing the trust anchors requires recompiling the binary.

**Zero-trust storage:** Data read from any store (PostgreSQL, Redis, Raft state machine) is treated as untrusted input. Every consumer independently re-verifies structural integrity (SAIDs, chain linkage), proposal DAGs (votes, threshold, withdrawal status), and KEL anchoring before making trust decisions. Stores are persistence layers, not trust anchors.

**Assumptions:**
- Identity service (which loads PKCS#11 .so directly) is not network-accessible outside its pod
- Docker/Kubernetes network policies enforce pod isolation
- Registry, KELS, and gossip services are exposed to the overlay network

## Rogue Federation Leader

A compromised leader controls what enters the Raft log.

**Attack:** Leader writes `AddPeer` entries for peers that were never approved through the proposal/voting process, or strips withdrawal records from proposal chains to make withdrawn proposals appear approved.

**Mitigations:**
- **State machine verification**: On Raft log replay, `apply()` checks every `AddPeer` against completed proposals. Each approval vote must pass `vote.verify_said()` (SAID integrity) and have its SAID anchored in the voter's KEL. If verified voters < threshold, the entry is silently rejected.
- **Registry node authorization**: `verify_and_authorize()` independently verifies peers on every signed request (register, deregister, status update). Full DAG verification: `AdditionWithVotes::verify()` for structural integrity, explicit withdrawal check, proposal record anchoring in proposer's KEL, and vote anchoring in voters' KELs. Data read from the database is never trusted — it is always re-verified.
- **Gossip allowlist**: `refresh_allowlist()` independently fetches completed proposals and performs full DAG verification (`AdditionWithVotes::verify()`), verifies proposal anchoring in proposer's KEL, and verifies each approval vote's anchoring in the voter's KEL. Threshold and member set are derived from compiled-in `trusted_prefixes()`, not from registry responses. Peers without sufficient verified votes are excluded from the allowlist.
- **Defense-in-depth**: Even if a rogue leader inserts a peer into the database, every consumer independently re-verifies the full proposal chain, votes, and anchoring before trusting it.

**Residual risk:** A leader colluding with voters could add fake votes to a proposal that the proposer intended to withdraw, then strip the withdrawal record. The vote anchoring catches fake votes (they must be anchored in each voter's KEL), but if the colluding voters submitted real anchored votes before the proposer could withdraw, the withdrawal cannot be enforced. The system prevents withdrawal once votes have been cast as a design invariant.

## Rogue Federation Member (Non-Leader)

A compromised follower cannot directly write to the Raft log but could:

**Attack 1 — Vote manipulation:** Submit forged votes through the admin API.
- **Mitigation:** Votes are `SelfAddressed` records. The proposal handler verifies `vote.verify_said()` (SAID matches content) and `verify_anchoring()` (SAID anchored in voter's KEL) before submitting to Raft. Even if a vote bypasses the handler (e.g., via a rogue leader inserting it directly), every consumer independently re-verifies vote SAID integrity and KEL anchoring.

**Attack 2 — Serve stale/modified data:** Return outdated or tampered peer lists, KELs, or proposal responses.
- **Mitigation:** No consumer trusts stored data. `verify_and_authorize()` re-verifies the full proposal DAG on every signed request — data read from the database is treated as untrusted input. Gossip nodes independently fetch completed proposals and perform full verification using compiled-in `trusted_prefixes()` for the member set and threshold. The Raft state machine re-verifies on log replay. A compromised follower serving tampered data cannot influence any consumer's trust decisions.

**Attack 3 — Refuse to participate:** Withhold votes or go offline.
- **Mitigation:** Raft handles this via leader election and quorum. The approval threshold has a minimum floor of 3 votes regardless of federation size, scaling to ceil(n/3) for 10+ members.

## Compromised HSM

If an attacker gains access to the HSM (via the identity service's PKCS#11 interface):

**Attack:** Sign valid events as the registry — add rogue peers, cast fraudulent votes, anchor malicious data. Because the attacker holds the real signing key, events chain perfectly from the current tail with valid signatures. There is no cryptographic distinction between attacker-signed and operator-signed events.
- **Mitigation:** The HSM is loaded directly by the identity service via PKCS#11 (no separate HSM service exposed to the network). Compromise requires pod-level access. Critically, compromising a single registry's HSM is insufficient to add rogue peers to the federation — peer approval requires a minimum of 3 votes regardless of federation size, each anchored in the voter's KEL. Adding a rogue peer requires colluding with at least 3 independently operated registries (and compromising their HSMs), which represents a significant operational barrier. Even if a rogue peer were somehow inserted into the database, every consumer (`verify_and_authorize`, gossip allowlist, Raft replay) independently re-verifies the full proposal chain and vote anchoring before trusting it.
- **Detection:** No cryptographic detection — events are indistinguishable from legitimate ones. Detection is necessarily out-of-band: operators noticing unexpected events in their registry's KEL, or other federation members observing unauthorized proposals, votes, or peer additions that nobody initiated. A rational attacker would not create divergence (which freezes the KEL and is immediately visible) but instead silently extend the chain.
- **Recovery:** Once detected, the operator submits a `rec` event (requires rotation + recovery key). The merge protocol truncates the attacker's events from the active chain (archiving them for audit) and resumes from the pre-compromise state under a new key. If the attacker has also compromised the rotation key, recovery still works as long as they don't hold the recovery key. If both rotation and recovery keys are compromised, `cnt` (contest) permanently freezes the KEL — the correct outcome when key compromise is total.

## Network-Level Attacks

### Man-in-the-Middle (Federation RPC)

**Attack:** Intercept and modify Raft messages between registries.
- **Mitigation:** All federation RPC is wrapped in `SignedFederationRpc` — payload signed with sender's current key (from KEL). Receiver verifies signature against sender's KEL. Modifying the payload invalidates the signature.

### Man-in-the-Middle (Gossip)

**Attack:** Intercept gossip messages between nodes.
- **Mitigation:** The gossip protocol uses ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication with AES-GCM-256 authenticated encryption. Session keys are derived from the ML-KEM shared secret via BLAKE3 KDF. Handshake signatures (ML-DSA-65/87) are verified against the peer's KEL public key. Only ML-DSA-65/87 peers are accepted. NodePrefix is derived from the node's identity KEL. The protocol provides post-quantum security.

### Denial of Service — Allowlist Refresh Trigger

**Attack:** Flood the gossip network with connections from unknown PeerPrefixes, triggering repeated allowlist refreshes.
- **Mitigation:** Allowlist refresh is triggered synchronously via `retry_once!` — on an unknown peer, the allowlist is refreshed once and rechecked. Subsequent connections from the same unknown peer hit the refreshed allowlist without triggering another refresh. However, there is no rate limiting on inbound connections at the application level.
- **Residual risk:** A flood of connections from many distinct unknown PeerPrefixes could cause repeated allowlist refreshes, each involving HTTP calls to the registry.

### Denial of Service — KEL Fetch Amplification

**Attack:** Cause a node to repeatedly fetch and verify KELs by submitting requests with unknown prefixes.
- **Mitigation:** KEL fetches are cached (with refresh-on-failure). The `retry_once!` macro limits retries to one. But a large number of distinct prefixes could cause many cache misses.

## Gossip Protocol Attacks

### Announcement Injection

**Attack:** Publish gossip announcements for non-existent or stale KELs.
- **Mitigation:** Receivers fetch the actual KEL via HTTP and verify it. False announcements waste bandwidth but don't corrupt state. The `event_exists()` check prevents processing announcements for already-stored events.

### Selective Message Dropping

**Attack:** A compromised node selectively drops announcements, preventing propagation to certain peers.
- **Mitigation:** PlumTree broadcast redundancy with lazy push repair. Periodic allowlist refresh and bootstrap reconciliation eventually fill gaps. Failed gossip fetches are recorded as stale prefixes and repaired by the anti-entropy loop (default 10s cycle), recovering missed events from alternative peers. Anti-entropy loop (default 10s) detects and repairs silent divergence via prefix page sampling. No real-time detection mechanism.

## Admin API

### ~~Localhost Bypass~~

~~**Attack:** If an attacker can reach the registry from localhost (e.g., SSRF, container escape), they can use the admin API.~~
- **Mitigated:** Admin write endpoints (proposals, votes) use KEL anchoring — you need the actual signing key to create a valid record. The proposal query endpoint is now at `GET /api/v1/federation/proposals/:id` (unauthenticated, alongside the proposals listing).

### Proposal/Vote Endpoints (No Localhost Check — By Design)

`admin_submit_addition_proposal`, `admin_submit_removal_proposal`, and `admin_vote_proposal` are exposed at `/api/v1/admin/addition-proposals` (POST), `/api/v1/admin/removal-proposals` (POST), and `/api/v1/admin/proposals/:id/vote` (POST) without a localhost check.
- **By design:** These are the federation RPC path — remote registries submit proposals and votes over the network. A localhost check would break federation. Both handlers verify SAID integrity (`verify()` / `verify_said()`) and KEL anchoring (`verify_anchoring()`) before submitting to Raft — you need the proposer's or voter's actual signing key to create a valid record with an anchored SAID, which is unforgeable.

## Unauthenticated Endpoints

These endpoints have no authentication and return potentially sensitive information:

| Endpoint | Risk | Justification |
|----------|------|---------------|
| `GET /api/v1/peers` | Enumerates all active peers with peer_prefixes, node_ids, gossip addresses | Needed for peer discovery; peer_prefixes are public (derived from identity KELs) |
| `GET /api/v1/member-kels/:prefix` | Exposes a member's full KEL history | KELs are public by design — verifiability requires availability |
| `POST /api/v1/member-kels` | Exposes all federation member KELs | Same as above; HA design requires any registry to serve all KELs |
| `GET /api/v1/federation/status` | Reveals leader, term, member list | Status information; member prefixes are compile-time constants |
| `GET /api/v1/federation/proposals` | Exposes completed proposals and votes | Required for independent verification by gossip nodes |
| `GET /api/v1/federation/proposals/:id` | Exposes a specific proposal with votes | Same data available via proposals listing; needed by admin CLI |
| `POST /api/v1/kels/events` | Accepts event submissions from anyone | Events are cryptographically validated (signatures checked against KEL) |
| `GET /api/v1/kels/kel/:prefix` | Exposes any stored KEL | KELs are public; this is the data-plane read path |

These are intentionally public. The security model relies on cryptographic verification, not access control.

## Supply Chain / Build-Time

### Trusted Prefixes Manipulation

**Attack:** Modify `TRUSTED_REGISTRY_PREFIXES` at build time to add a rogue registry.
- **Mitigation:** This is a compile-time constant. Build pipeline integrity is the defense.

### Dependency Confusion

**Attack:** Substitute a malicious crate for `verifiable-storage`, `cesr`, or `openraft`.
- **Mitigation:** `cargo deny` checks are in the Makefile (`deny-check` target). Cargo.lock pins exact versions.

## Summary of Residual Risks

1. ~~**Admin API lacks authentication beyond localhost check**~~ — mitigated: admin write endpoints use KEL anchoring; read-only proposal query is unauthenticated (data is public)
2. ~~**Proposal/vote endpoints missing localhost check**~~ — not a risk: these are federation RPC endpoints that remote registries must reach; KEL anchoring is the correct security mechanism
3. ~~**Allowlist refresh flood**~~ — mitigated: `retry_once!` limits refresh to one attempt per unknown peer; subsequent connections use the cached allowlist
4. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (token bucket), 5 MiB body limit
5. ~~**No TLS at application level**~~ — not required: all data is public by design and end-verifiable. Federation RPC uses `SignedFederationRpc` for integrity. The gossip layer uses ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 for authenticated encryption
6. (removed)

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### ~~Rate limiting (addresses residual risks 3, 4)~~

No application-level rate limiting exists on any endpoint. The allowlist pending verification set has no TTL or max size, so a connection flood can grow it unboundedly.

- [x] Add rate limiting to the registry HTTP server (per-IP token bucket on write endpoints: 200 req/s refill, 1000 burst; 5 MiB body limit)
- [x] Allowlist refresh uses `retry_once!` — single synchronous refresh per unknown peer, with cached allowlist for subsequent checks

### ~~Admin API authentication (addresses residual risk 1)~~

~~The admin API relies solely on `is_localhost()` for access control.~~ Mitigated: proposal and vote endpoints use KEL anchoring (SAID anchored in proposer/voter KEL) as the security mechanism. The proposal query endpoint is unauthenticated since proposal data is already public.

- [x] Replace `is_localhost()` with KEL anchoring for write endpoints; proposal query is read-only and unauthenticated

### ~~TLS between services (addresses residual risk 5)~~

~~No TLS at the application level.~~ Not required — all data is public by design (KELs must be accessible for verification) and end-verifiable (cryptographic signatures + SAID chaining). Federation RPC is wrapped in `SignedFederationRpc` for integrity. The gossip layer uses ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 for authenticated encryption. TLS would add confidentiality for non-confidential data and redundant transport-level integrity.

