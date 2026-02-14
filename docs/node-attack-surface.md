# KELS Node Attack Surface

Analysis of attack vectors against the KELS node deployment — gossip, bootstrap, network, and storage layers. For protocol-level attacks (key compromise, event submission, KEL merge, verification bypass), see [protocol-attack-surface.md](protocol-attack-surface.md).

## Trust Model

The KELS service has no identity or signing authority. It stores and serves KELs but cannot forge events. All data is tamper-evident, signed, and end-verifiable. The security model relies entirely on cryptographic verification, not access control.

**Zero-trust storage:** Data read from any store (PostgreSQL, Redis) is treated as untrusted input. All KEL data is cryptographically re-verified (signatures, SAID chains) before use. Peer allowlists are verified via the full proposal DAG with thresholds computed from compiled-in `trusted_prefixes()`. Stores are persistence layers, not trust anchors.

**Assumptions:**
- HSM and identity services are pod-internal only (not exposed to the overlay network) - **THIS IS INSUFFICIENT FOR A PRODUCTION DEPLOYMENT**
- Network isolation between pods enforces service boundaries

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
- **Mitigation:** All fetched events are submitted to the local KELS service, which validates all signatures and enforces merge invariants. Corrupted events fail validation. Incomplete KELs are partially synced; subsequent gossip fills the gaps. The peer itself must be in the verified allowlist (proposal DAG verified, threshold met from compiled-in `trusted_prefixes()`).
- **Residual risk:** A malicious peer could serve a valid but outdated snapshot, delaying initial sync. The resync phase (step 4 in bootstrap) catches events missed between preload and gossip connection.

### Bootstrap Prefix Enumeration

**Attack:** Use the `list_prefixes` endpoint to enumerate all prefixes stored on a node.
- **Mitigation:** `list_prefixes` requires a signed request (ECDSA P-256 signature over the JSON payload). The signer's peer_id must be in the authorized peer allowlist — which is itself verified via the full proposal DAG (structural integrity, KEL anchoring, threshold from compiled-in `trusted_prefixes()`). A 60-second timestamp window prevents replay. Unknown peer_ids trigger an allowlist refresh and recheck.
- **Residual risk:** Any authorized gossip peer can enumerate all prefixes. KELs are public by design, so this is information disclosure but not a confidentiality breach.

### Bootstrap Response Size Explosion

**Attack:** Request batch KEL fetches for many prefixes to generate large responses.
- **Mitigation:** Batch requests are capped at 50 prefixes (`MAX_BATCH_PREFIXES`). Pagination limit is clamped to `1..=1000`.
- **Residual risk:** 50 large KELs could still produce a substantial response. No per-request byte limit.

## Network-Level Attacks

### Man-in-the-Middle (HTTP)

**Attack:** Intercept HTTP traffic between gossip nodes and KELS services.
- **Mitigation:** Events are signed at the application layer — modifying event data invalidates signatures. All data is public by design (KELs must be accessible for verification) and end-verifiable (SAID chaining + cryptographic signatures). A MITM can observe public data or inject modified events that fail signature validation. TLS is not required because there is no confidential data to protect and integrity is already guaranteed at the application layer.

### Man-in-the-Middle (libp2p)

**Attack:** Intercept gossip traffic between nodes.
- **Mitigation:** libp2p Noise protocol provides authenticated encryption. PeerId is cryptographically derived from the node's public key (secp256r1 via HSM). Messages use `MessageAuthenticity::Signed`. Modifying messages invalidates both the Noise encryption and the gossipsub signature.

### Replay Attack (Gossip)

**Attack:** Replay old gossip announcements to trigger unnecessary KEL fetches.
- **Mitigation:** `event_exists()` check — if the announced SAID is already stored locally, the announcement is ignored. Old announcements for events the node already has are dropped immediately.

### Replay Attack (Signed Requests)

**Attack:** Replay a captured `list_prefixes` signed request.
- **Mitigation:** 60-second timestamp window via `validate_timestamp()`. Each request includes a cryptographic nonce (BLAKE3 hash of 32 random bytes). The server tracks nonces within the timestamp window and rejects duplicates. Expired nonces are evicted on each request.

### Denial of Service — Event Submission Flood

**Attack:** Flood `POST /api/kels/events` with valid-looking but ultimately invalid events.
- **Mitigation:** Signature format validation happens upfront (before acquiring advisory lock). Invalid signatures are rejected quickly. Per-IP rate limiting (GovernorLayer: 200 req/s sustained, 1000 burst) on write endpoints prevents volumetric floods. Per-prefix rate limiting (32 submissions/min) prevents targeted abuse of a single prefix. Max event count per submission (500) and body size limit (5 MiB) bound individual request cost.
- **Residual risk:** Valid-format signatures that fail later verification still consume database resources within the rate limits.

### Denial of Service — Batch Request Abuse

**Attack:** Send many batch KEL requests to exhaust memory or database connections.
- **Mitigation:** Batch size capped at 50 prefixes. Redis cache reduces database load for frequently accessed KELs. Body size limit (5 MiB) bounds response processing cost.
- **Residual risk:** Read endpoints are not per-IP rate limited (idempotent and cache-backed). Concurrent batch requests from many distinct sources could still exhaust database connections.

### Advisory Lock Contention

**Attack:** Submit many concurrent events for the same prefix to cause advisory lock contention and slow down the service.
- **Mitigation:** PostgreSQL advisory locks serialize operations per-prefix, which prevents data corruption but does mean high concurrency on a single prefix causes queuing.
- **Residual risk:** Per-prefix rate limiting (32 submissions/min) mitigates sustained floods, but advisory lock contention still causes queuing under burst traffic within the rate limit window.

## Redis Attacks

### Pub/Sub Injection

**Attack:** If an attacker can access Redis, inject fake `kel_updates` messages to trigger spurious gossip announcements.
- **Mitigation:** Redis is assumed to be pod-internal. The gossip node validates events it fetches via HTTP before storing them — injected Redis messages cause HTTP fetches but don't corrupt state. All fetched KEL data is cryptographically verified (signatures, SAID chains) regardless of source.
- **Residual risk:** A compromised Redis could trigger many wasted HTTP fetches. No authentication on the Redis pub/sub channel.

### Cache Poisoning

**Attack:** Modify cached KEL data in Redis to serve stale or incorrect KELs, or tamper with verified peer records.
- **Mitigation:** Cache is used for read performance only. KEL writes always go through the database with full validation. Cache invalidation is pub/sub-based. Critically, no consumer trusts cached data — all data read from Redis (KELs, peer records, allowlists) is cryptographically re-verified before use. KELs are verified via signature chains and SAID integrity. Peer records are verified via the full proposal DAG (structural integrity, proposal anchoring in proposer's KEL, vote anchoring in voters' KELs, threshold from compiled-in `trusted_prefixes()`). A compromised Redis cannot influence trust decisions.
- **Residual risk:** A compromised Redis could serve stale data, causing temporary inconsistency (e.g., a node not seeing a recently added peer until the next refresh). This is an availability concern, not a security one — stale data passes re-verification if it was valid when cached, but the node may miss recent updates.

### Gossip Ready Flag Manipulation

**Attack:** Set `kels:gossip:ready` to `true` prematurely, causing the node to report ready before bootstrap is complete.
- **Mitigation:** The `/ready` endpoint reads this flag. A premature `ready` could cause load balancers to route traffic to an incompletely synced node. This is an availability concern — the node would serve incomplete data, but all data it does serve is cryptographically verified.
- **Residual risk:** No authentication on Redis state flags.

## Summary of Residual Risks

1. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (GovernorLayer), per-prefix rate limiting on `submit_events` (32/min), max 500 events per submission, 5 MiB body limit
2. ~~**No TLS at application level**~~ — not required: all data is public by design and end-verifiable via signatures and SAID chaining. TLS would add confidentiality for non-confidential data and integrity for data that is already tamper-evident
3. ~~**Advisory lock contention under high concurrency**~~ — mitigated: per-prefix rate limiting (32/min) bounds contention
4. ~~**Bootstrap peer can serve outdated snapshots**~~ — accepted risk: caught by resync, all data cryptographically verified, worst case is temporary delay
5. ~~**Gossip scope filtering is application-level**~~ — not a security concern: scope is a routing optimization, not a security boundary. All nodes replicate the same data
6. ~~**60-second replay window on signed requests**~~ — mitigated: nonce-based deduplication within the 60s timestamp window eliminates replay
7. **Redis state flags lack authentication** — relies on pod-level network isolation; impact limited to availability (all data from Redis is cryptographically re-verified)
8. **No real-time detection of selective message dropping** — relies on mesh redundancy and periodic resync
9. ~~**Sustained announcement injection causes repeated HTTP fetches**~~ — mitigated: per-peer rate limiting (8192 fetches/min) on gossip processing

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### Rate limiting (addresses residual risks 1, 3, 9)

No application-level rate limiting exists on any KELS endpoint. Advisory lock contention under high concurrency has no fairness guarantee. Gossip announcement processing has no per-peer or per-prefix throttling, so sustained injection causes repeated HTTP fetches.

- [x] Add rate limiting middleware to the KELS HTTP server (per-IP for write endpoints via GovernorLayer: 200 req/s sustained, 1000 burst; per-prefix for `submit_events`: 32/min; max 500 events per submission; 5 MiB body limit)
- [x] Add per-peer rate limiting on gossip announcement processing (8192 fetches/min per peer)
- [x] Add per-prefix submission throttle to `submit_events` (32 submissions/min per prefix, in-memory via DashMap)

### ~~TLS between services (addresses residual risk 2)~~

~~No TLS at the application level.~~ Not required — all inter-service data is public by design (KELs must be accessible for verification) and end-verifiable (cryptographic signatures + SAID chaining). TLS would add confidentiality for non-confidential data and transport-level integrity for data whose integrity is already guaranteed at the application layer. The gossip layer uses libp2p Noise for authenticated encryption on the p2p transport.

### Gossip protocol hardening (addresses residual risks 8, 9)

Scope filtering is application-level. There is no real-time detection of selective message dropping. Announcement injection causes unbounded HTTP fetches.

- [x] Fix event partitioning for contest propagation — `partition_events` now places contest events (`cnt`) in the second (recovery) batch, ensuring the non-contest fork event establishes divergence first. Previously, `dec + cnt` pairs could be partitioned with `cnt` first, which was rejected by merge ("Contest requires divergence")
- ~~Evaluate per-scope gossipsub topics~~ — not a security concern: scope filtering is a routing optimization, not a security boundary. All nodes replicate the same data. Scope violations at worst cause redundant fetches, which `event_exists` dedup already handles
- [ ] Add negative caching for timed-out KEL fetches — if an HTTP fetch for an announced `prefix:said` times out, cache `(prefix, said)` with a 30s TTL (`DashMap<(String, String), Instant>`, lazy eviction on lookup) to avoid hammering a struggling peer with repeated fetches

### ~~Bootstrap integrity (addresses residual risk 4)~~

~~A malicious bootstrap peer can serve a valid but outdated snapshot. The resync phase catches the gap but creates a window where the node has stale data.~~ Accepted risk. Cross-validating against multiple peers is expensive at scale (merging prefix sets across all nodes). The resync phase already catches the gap, and all fetched data is cryptographically verified — the worst case is a temporary delay, not state corruption.

### Redis authentication (addresses residual risk 7)

Redis state flags (`kels:gossip:ready`, `kels:verified-peer:*`) have no authentication. A compromised Redis can manipulate node readiness or peer verification cache. Impact is limited to availability — all data read from Redis is cryptographically re-verified before use, so a compromised Redis cannot influence trust decisions. The remaining risk is stale data or premature readiness signals.

- [ ] Enable Redis AUTH (password or ACL) for all Redis connections
- [ ] Evaluate signing Redis state values with the node's HSM key — allows consumers to verify state integrity even if Redis is compromised

### Signed request replay window (addresses residual risk 6)

~~`list_prefixes` signed requests have a 60-second replay window. While the endpoint is read-only, reducing the window or adding nonce-based deduplication would eliminate replay entirely.~~

- [x] Add server-side nonce tracking — each `PrefixesRequest` includes a BLAKE3-hashed cryptographic nonce. The server rejects duplicate nonces within the 60s timestamp window, evicting expired entries on each request. Nonce storage is bounded by `max_peers × max_requests_per_peer_per_minute`.
