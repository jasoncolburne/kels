# KELS Node Attack Surface

Analysis of attack vectors against the KELS data-plane services (KELS, gossip, bootstrap) and client-side key management.

## Trust Model

The KELS service has no identity or signing authority. It stores and serves KELs but cannot forge events. All data is tamper-evident, signed, and end-verifiable. The security model relies entirely on cryptographic verification, not access control — any valid signed event is accepted regardless of source.

**Assumptions:**
- HSM and identity services are pod-internal only (not exposed to the overlay network)
- Clients hold private keys in hardware-backed storage (Secure Enclave, HSM)
- The signing algorithm is secp256r1 (ECDSA P-256), providing 128 bits of security
- Network isolation between pods enforces service boundaries
- Events are version-qualified (`kels/v1/icp`) for future protocol evolution

## Key Compromise

A controller of an identity has 3 keys to protect. It's advised that clients only be deployed to mobile with hardware-backed keys, or services with HSM-backed keys.

### Key Hierarchy

| Key | Purpose | Exposure |
|-----|---------|----------|
| **Signing** | Signs `ixn` and `rot` events | Active — used for every operation |
| **Rotation** | Pre-committed next key; revealed during rotation, becomes the new signing key | Semi-dormant — only needed for key rotation |
| **Recovery** | Revealed during recovery events; dual-signed with rotation key | Dormant — only needed for emergency recovery |

### Compromise Scenarios

**Signing key compromised:**
- **Attack:** Adversary can sign `ixn` events (anchor arbitrary data) and submit them to any KELS node.
- **Impact:** Limited to interaction events. Cannot rotate keys, cannot take over the identity.
- **Recovery:** Owner rotates signing key (`rot`). If adversary submits conflicting events before rotation propagates, divergence occurs. Owner submits `rec` (requires rotation + recovery key). KEL resumes normally.
- **Detection:** Divergence is detected automatically when events with the same `previous` but different SAIDs appear.

**Rotation key compromised:**
- **Attack:** Adversary can submit a `rot` event (taking over the signing key) and subsequently sign unlimited `ixn` and `rot` events.
- **Impact:** Full control of the signing chain. Adversary can anchor data, rotate keys repeatedly.
- **Recovery:** Owner submits `rec` (requires the pre-compromised rotation key + recovery key, dual-signed). After recovery, adversary events are archived. If the adversary rotated and the owner did not, an extra `rot` is needed post-recovery to escape the compromised key.
- **Detection:** Same as signing key — divergence detection.

**Recovery key compromised (along with rotation key):**
- **Attack:** Adversary has full administrative control — can submit `rec`, `ror`, `dec`, or `cnt` events.
- **Impact:** Total identity compromise. Adversary can recover from owner's recovery attempts.
- **Recovery:** Owner's only recourse is `cnt` (contest), which permanently freezes the KEL. Neither party can add further events. This is the correct outcome when key compromise is total.
- **Detection:** If adversary submits a recovery-revealing event, the merge protocol detects it and marks the KEL as requiring contest.

**Recovery key compromised (without rotation key):**
- **Impact:** Recovery key alone is useless — all recovery-revealing events require dual signatures (rotation + recovery). No action possible without both keys.

## Event Submission Attacks

### Forged Event Injection

**Attack:** Submit events with invalid or forged signatures.
- **Mitigation:** `submit_events` validates all signatures upfront before any merge. Each signature is parsed via `Signature::from_qb64()` and verified during the KEL merge against the public key from the latest establishment event. Invalid signatures cause immediate rejection.

### Dual-Signature Bypass

**Attack:** Submit a recovery-revealing event (`rec`, `ror`, `dec`, `cnt`) with only one signature.
- **Mitigation:** `submit_events` explicitly checks `requires_dual_signature()` and rejects events with fewer than 2 signatures. The merge protocol also verifies both signatures independently.

### Event Replay

**Attack:** Re-submit previously valid events to trigger unexpected behavior.
- **Mitigation:** Before merging, `submit_events` builds a set of existing SAIDs and filters out duplicates. Duplicate events are silently accepted (idempotent). The advisory lock per prefix serializes concurrent submissions.

### Prefix Spoofing

**Attack:** Submit an event with a prefix that doesn't match the KEL it chains from.
- **Mitigation:** KEL verification checks that all events in a KEL share the same prefix. A mismatched prefix fails validation.

### SAID Manipulation

**Attack:** Submit an event where the SAID doesn't match the content hash.
- **Mitigation:** `event.verify()` recomputes the SAID from the event content and compares it to the declared SAID. Any mismatch is rejected.

### Chain Gap Exploitation

**Attack:** Submit events that reference a `previous` SAID not present in the KEL, attempting to create a phantom chain.
- **Mitigation:** The merge protocol validates that every event's `previous` field references an existing event in the KEL. Missing predecessors cause rejection with "Events not contiguous."

### Advisory Lock Contention

**Attack:** Submit many concurrent events for the same prefix to cause advisory lock contention and slow down the service.
- **Mitigation:** PostgreSQL advisory locks serialize operations per-prefix, which prevents data corruption but does mean high concurrency on a single prefix causes queuing.
- **Residual risk:** Per-prefix rate limiting (32 submissions/min) mitigates sustained floods, but advisory lock contention still causes queuing under burst traffic within the rate limit window.

## KEL Merge Exploitation

### Divergence Flooding

**Attack:** With a compromised signing key, submit divergent events to many different KELS nodes simultaneously, hoping to maximize the window where the KEL is frozen.
- **Mitigation:** Gossip propagates both branches of a divergent KEL. All nodes converge on the same divergent state. The owner can submit `rec` to any single node, and recovery propagates via gossip to all nodes.
- **Residual risk:** Window of frozen KEL depends on gossip propagation speed and owner response time.

### Recovery Race

**Attack:** Adversary (who also has the recovery key) races the owner to submit `rec` first.
- **Mitigation:** If the adversary submits a recovery-revealing event, the merge protocol returns `RecoveryProtected`. The owner must `cnt` (contest) instead, which permanently freezes the KEL. This is the correct security outcome — it prevents an attacker with the recovery key from winning a recovery race.

### Re-divergence After Recovery

**Attack:** After the owner recovers, adversary re-submits events at the same generation to re-diverge.
- **Mitigation:** Recovery protection — any recovery-revealing event at generation N protects generation N and all earlier generations. Events at generation <= N are rejected with `RecoveryProtected` (except `cnt`). This is an important security invariant that prevents recovery battles.

### Contested KEL Bypass

**Attack:** Submit events to a contested (permanently frozen) KEL.
- **Mitigation:** Pre-merge validation checks `is_contested()` and immediately rejects all submissions. A contested KEL is truly permanent — there is no bypass.

### Decommissioned KEL Bypass

**Attack:** Submit events to a decommissioned KEL.
- **Mitigation:** The merge protocol checks for decommission and rejects appends. Only divergence at earlier generations is possible (with a compromised signing key from before decommission), which would still be caught by recovery protection if `dec` was the decommissioning event.

## Gossip Protocol Attacks

### Announcement Injection

**Attack:** Publish gossip announcements for non-existent prefixes or stale SAIDs, causing nodes to waste bandwidth fetching data.
- **Mitigation:** Receivers check `event_exists()` before fetching — if the announced SAID already exists locally, the announcement is ignored. For unknown SAIDs, the node fetches the KEL via HTTP and KELS validates all signatures during merge. False announcements waste a single HTTP round-trip but cannot corrupt state.
- **Residual risk:** Per-peer rate limiting (8192 fetches/min) bounds the damage from sustained injection, but a verified peer could still cause significant HTTP fetch load within the limit.

### Selective Message Dropping

**Attack:** A compromised gossip node selectively drops announcements, preventing propagation to certain peers or regions.
- **Mitigation:** gossipsub mesh redundancy (mesh target 3, min 2). Announcements propagate through multiple paths. Bootstrap resync catches events missed during the gap. Periodic bootstrap from Ready peers fills gaps.
- **Residual risk:** No real-time detection of selective dropping. If a core node drops all messages for a specific region, that region may be delayed until the next resync cycle.

### Scope Confusion

**Attack:** A regional node publishes an announcement with `destination: All`, bypassing scope boundaries.
- **Mitigation:** Scope filtering is application-level — the `handle_announcement` method checks `announcement.destination` against `local_scope` and ignores messages not addressed to its scope. Only core nodes rebroadcast regional-to-core announcements as core-to-all.
- **Residual risk:** The gossipsub mesh itself does not enforce scope. All peers on the same topic receive all messages; filtering is purely application-level. A rogue node on the mesh sees all announcements regardless of scope.

### Gossipsub Message ID Collision

**Attack:** Craft two different announcements with the same content hash to cause message deduplication to drop the legitimate message.
- **Mitigation:** Message ID is derived from `DefaultHasher::hash` of the raw message data. Two messages with identical content produce the same ID and are deduplicated, which is correct behavior. Different content produces different IDs. The hash is not cryptographic but collision resistance at 64 bits is sufficient for deduplication.

### Feedback Loop Amplification

**Attack:** Trigger a feedback loop where gossip writes to KELS → KELS publishes to Redis → Redis subscriber re-announces to gossip.
- **Mitigation:** `RecentlyStoredFromGossip` tracks `prefix:said` pairs stored via gossip for 60 seconds. The Redis subscriber skips messages matching recently stored pairs. The mark is set *before* submitting to KELS to prevent race conditions.

## Bootstrap Attacks

### Malicious Bootstrap Peer

**Attack:** A compromised peer serves corrupted or incomplete KELs during bootstrap sync.
- **Mitigation:** All fetched events are submitted to the local KELS service, which validates all signatures and enforces merge invariants. Corrupted events fail validation. Incomplete KELs are partially synced; subsequent gossip fills the gaps.
- **Residual risk:** A malicious peer could serve a valid but outdated snapshot, delaying initial sync. The resync phase (step 4 in bootstrap) catches events missed between preload and gossip connection.

### Bootstrap Prefix Enumeration

**Attack:** Use the `list_prefixes` endpoint to enumerate all prefixes stored on a node.
- **Mitigation:** `list_prefixes` requires a signed request (ECDSA P-256 signature over the JSON payload). The signer's peer_id must be in the authorized peer allowlist. A 60-second timestamp window prevents replay. Unknown peer_ids trigger an allowlist refresh and recheck.
- **Residual risk:** Any authorized gossip peer can enumerate all prefixes. KELs are public by design, so this is information disclosure but not a confidentiality breach.

### Bootstrap Response Size Explosion

**Attack:** Request batch KEL fetches for many prefixes to generate large responses.
- **Mitigation:** Batch requests are capped at 50 prefixes (`MAX_BATCH_PREFIXES`). Pagination limit is clamped to `1..=1000`.
- **Residual risk:** 50 large KELs could still produce a substantial response. No per-request byte limit.

## Network-Level Attacks

### Man-in-the-Middle (HTTP)

**Attack:** Intercept HTTP traffic between gossip nodes and KELS services.
- **Mitigation:** Events are signed at the application layer — modifying event data invalidates signatures. However, HTTP responses (KEL fetches) are not signed at the transport level.
- **Residual risk:** No TLS at the application level. Relies on overlay network encryption or external TLS termination. A MITM could observe KEL data (which is public) or inject invalid events (which fail signature validation).

### Man-in-the-Middle (libp2p)

**Attack:** Intercept gossip traffic between nodes.
- **Mitigation:** libp2p Noise protocol provides authenticated encryption. PeerId is cryptographically derived from the node's public key (secp256r1 via HSM). Messages use `MessageAuthenticity::Signed`. Modifying messages invalidates both the Noise encryption and the gossipsub signature.

### Replay Attack (Gossip)

**Attack:** Replay old gossip announcements to trigger unnecessary KEL fetches.
- **Mitigation:** `event_exists()` check — if the announced SAID is already stored locally, the announcement is ignored. Old announcements for events the node already has are dropped immediately.

### Replay Attack (Signed Requests)

**Attack:** Replay a captured `list_prefixes` signed request.
- **Mitigation:** 60-second timestamp window via `validate_timestamp()`. Requests older than 60 seconds are rejected.
- **Residual risk:** Within the 60-second window, replay is possible. Since `list_prefixes` is a read-only operation, replay has no side effects beyond repeated reads.

### Denial of Service — Event Submission Flood

**Attack:** Flood `POST /api/kels/events` with valid-looking but ultimately invalid events.
- **Mitigation:** Signature format validation happens upfront (before acquiring advisory lock). Invalid signatures are rejected quickly. Per-IP rate limiting (GovernorLayer: 200 req/s sustained, 1000 burst) on write endpoints prevents volumetric floods. Per-prefix rate limiting (32 submissions/min) prevents targeted abuse of a single prefix. Max event count per submission (500) and body size limit (5 MiB) bound individual request cost.
- **Residual risk:** Valid-format signatures that fail later verification still consume database resources within the rate limits.

### Denial of Service — Batch Request Abuse

**Attack:** Send many batch KEL requests to exhaust memory or database connections.
- **Mitigation:** Batch size capped at 50 prefixes. Redis cache reduces database load for frequently accessed KELs. Body size limit (5 MiB) bounds response processing cost.
- **Residual risk:** Read endpoints are not per-IP rate limited (idempotent and cache-backed). Concurrent batch requests from many distinct sources could still exhaust database connections.

## Redis Attacks

### Pub/Sub Injection

**Attack:** If an attacker can access Redis, inject fake `kel_updates` messages to trigger spurious gossip announcements.
- **Mitigation:** Redis is assumed to be pod-internal. The gossip node validates events it fetches via HTTP before storing them — injected Redis messages cause HTTP fetches but don't corrupt state.
- **Residual risk:** A compromised Redis could trigger many wasted HTTP fetches. No authentication on the Redis pub/sub channel.

### Cache Poisoning

**Attack:** Modify cached KEL data in Redis to serve stale or incorrect KELs.
- **Mitigation:** Cache is used for read performance only. KEL writes always go through the database with full validation. Cache invalidation is pub/sub-based. Verified peer records in Redis (`kels:verified-peer:*`) are refreshed from the registry on cache miss.
- **Residual risk:** A compromised Redis could serve stale KEL data from cache until the next cache refresh. However, all consumers re-verify KELs cryptographically, so stale data is detected.

### Gossip Ready Flag Manipulation

**Attack:** Set `kels:gossip:ready` to `true` prematurely, causing the node to report ready before bootstrap is complete.
- **Mitigation:** The `/ready` endpoint reads this flag. A premature `ready` could cause load balancers to route traffic to an incompletely synced node.
- **Residual risk:** No authentication on Redis state flags.

## Client-Side Attacks

### Key Extraction

**Attack:** Extract private keys from client storage.
- **Mitigation:** Hardware-backed keys (Secure Enclave on iOS, SoftHSM2 for services) are designed to be non-extractable. The `kels-ffi` library interfaces with Apple's Secure Enclave; the HSM service wraps SoftHSM2 via PKCS#11.
- **Residual risk:** Software-only key storage (e.g., file-based `KelStore`) is vulnerable to filesystem access. This is acceptable for development but not production.

### Local State Manipulation

**Attack:** Modify the client's local KEL state (SQLite database or file store) to desynchronize from the server.
- **Mitigation:** The client always fetches the current KEL from the server before creating events. The `KeyEventBuilder` chains from the owner's tail, which is tracked server-side. Local state manipulation causes the client to submit events that fail server-side validation.
- **Residual risk:** A manipulated client could be tricked into signing events based on false local state, but those events would fail validation when submitted.

### Owner Tail Confusion

**Attack:** Trick the client into chaining from the wrong tail, creating an event that doesn't properly connect to the KEL.
- **Mitigation:** The `owner_tail` is tracked via `save_owner_tail()` / `load_owner_tail()` on the `KelStore`. The builder syncs with the server KEL before creating events. Events that don't chain from a valid previous are rejected by the server.

## KEL Verification Bypass Attempts

### Forward Pass Bypass

**Attack:** Submit events that pass structure verification but have broken cryptographic properties.
- **Mitigation:** KEL verification is two-phase. Phase 1 (forward pass) checks structure, chaining, and SAID integrity. Phase 2 (backward pass) walks from each tail backward, verifying pre-rotation commitments, recovery key commitments, and all signatures. Both phases must pass.

### Pre-rotation Commitment Violation

**Attack:** Submit a rotation event whose public key doesn't match the rotation hash committed in the previous establishment event.
- **Mitigation:** The backward pass explicitly verifies `rotation_hash` commitments — `compute_rotation_hash(future_event.public_key)` must equal the committed `rotation_hash`. Violations are rejected.

### Recovery Key Commitment Violation

**Attack:** Submit a recovery event with a recovery key that doesn't match the committed recovery hash.
- **Mitigation:** Same mechanism as rotation — `recovery_hash` is verified against the revealed recovery key. Violations are rejected.

## Summary of Residual Risks

1. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (GovernorLayer), per-prefix rate limiting on `submit_events` (32/min), max 500 events per submission, 5 MiB body limit
2. **No TLS at application level** — relies on overlay network encryption or external termination
3. ~~**Advisory lock contention under high concurrency**~~ — mitigated: per-prefix rate limiting (32/min) bounds contention
4. **Bootstrap peer can serve outdated snapshots** — caught by resync but creates a delay window
5. **Gossip scope filtering is application-level** — protocol layer doesn't enforce boundaries
6. **60-second replay window on signed requests** — acceptable for read-only operations
7. **Redis state flags lack authentication** — relies on pod-level network isolation
8. **No real-time detection of selective message dropping** — relies on mesh redundancy and periodic resync
9. ~~**Sustained announcement injection causes repeated HTTP fetches**~~ — mitigated: per-peer rate limiting (8192 fetches/min) on gossip processing

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### Rate limiting (addresses residual risks 1, 3, 9)

No application-level rate limiting exists on any KELS endpoint. Advisory lock contention under high concurrency has no fairness guarantee. Gossip announcement processing has no per-peer or per-prefix throttling, so sustained injection causes repeated HTTP fetches.

- [x] Add rate limiting middleware to the KELS HTTP server (per-IP for write endpoints via GovernorLayer: 200 req/s sustained, 1000 burst; per-prefix for `submit_events`: 32/min; max 500 events per submission; 5 MiB body limit)
- [x] Add per-peer rate limiting on gossip announcement processing (8192 fetches/min per peer)
- [x] Add per-prefix submission throttle to `submit_events` (32 submissions/min per prefix, in-memory via DashMap)

### TLS between services (addresses residual risk 2)

No TLS at the application level. HTTP traffic between gossip nodes and KELS services, and between KELS and Redis, relies on overlay network encryption or external termination.

- [ ] Add mTLS or service mesh sidecar for inter-service communication within the cluster
- [ ] Add TLS for gossip node ↔ KELS HTTP fetches (currently events are signed but transport is unencrypted)

### Gossip protocol hardening (addresses residual risks 5, 8, 9)

Scope filtering is application-level. There is no real-time detection of selective message dropping. Announcement injection causes unbounded HTTP fetches.

- [ ] Evaluate per-scope gossipsub topics (e.g., `kels/events/v1/regional`, `kels/events/v1/core`) to enforce scope at the protocol layer
- [ ] Add gossip liveness monitoring — periodic heartbeat announcements from core nodes, with alerts when a region stops receiving updates for a configurable interval
- [ ] Add negative caching for failed KEL fetches — if an HTTP fetch for an announced `prefix:said` fails (404, timeout), cache the failure for a short TTL to avoid repeated fetches of the same non-existent data

### Bootstrap integrity (addresses residual risk 4)

A malicious bootstrap peer can serve a valid but outdated snapshot. The resync phase catches the gap but creates a window where the node has stale data.

- [ ] Cross-validate bootstrap data against multiple peers — compare prefix counts and tip SAIDs from at least 2 peers before accepting the snapshot, falling back to the peer with the most recent data

### Redis authentication (addresses residual risk 7)

Redis state flags (`kels:gossip:ready`, `kels:verified-peer:*`) have no authentication. A compromised Redis can manipulate node readiness or peer verification cache.

- [ ] Enable Redis AUTH (password or ACL) for all Redis connections
- [ ] Evaluate signing Redis state values with the node's HSM key — allows consumers to verify state integrity even if Redis is compromised

### Signed request replay window (addresses residual risk 6)

`list_prefixes` signed requests have a 60-second replay window. While the endpoint is read-only, reducing the window or adding nonce-based deduplication would eliminate replay entirely.

- [ ] Add server-side nonce tracking — reject requests with previously seen `(peer_id, nonce)` pairs within the timestamp window. Trade-off is additional state per peer, but the peer set is small and bounded by the allowlist
