# KELS Node Attack Surface

Analysis of attack vectors against the KELS node deployment — gossip, bootstrap, network, and storage layers. For protocol-level attacks (key compromise, event submission, KEL merge, verification bypass), see [protocol-attack-surface.md](protocol-attack-surface.md).

## Trust Model

The KELS service has no identity or signing authority. It stores and serves KELs but cannot forge events. All data is tamper-evident, signed, and end-verifiable. The security model relies entirely on cryptographic verification, not access control.

**Zero-trust storage:** Data read from any store (PostgreSQL, Redis) is treated as untrusted input. All KEL data is cryptographically re-verified (signatures, SAID chains) before use. Peer allowlists are verified via the full proposal DAG with thresholds computed from compiled-in `trusted_prefixes()`. Stores are persistence layers, not trust anchors.

**Assumptions (INSUFFICENT FOR PRODUCTION):**
- Identity service is pod-internal only (not exposed to the overlay network)
- Network isolation between pods enforces service boundaries

## Gossip Protocol Attacks

### Announcement Injection

**Attack:** Publish gossip announcements for non-existent prefixes or stale SAIDs, causing nodes to waste bandwidth fetching data.
- **Mitigation:** Receivers check `event_exists()` before fetching — if the announced SAID already exists locally, the announcement is ignored. For unknown SAIDs, the node fetches the KEL via HTTP and KELS validates all signatures during merge. False announcements waste a single HTTP round-trip but cannot corrupt state.
- **Residual risk:** Per-peer rate limiting (8192 fetches/min) bounds the damage from sustained injection, but a verified peer could still cause significant HTTP fetch load within the limit.

### Selective Message Dropping

**Attack:** A compromised gossip node selectively drops announcements, preventing propagation to certain peers.
- **Mitigation:** PlumTree broadcast tree redundancy with lazy push (IHave messages via backup peers). Announcements propagate through eager push peers with lazy repair from other peers. Bootstrap resync catches events missed during the gap. Anti-entropy loop detects and repairs silent divergence via periodic random sampling.
- **Residual risk:** No real-time detection of selective dropping. Affected peers may be delayed until the next anti-entropy cycle. Failed gossip fetches are recorded as stale prefixes and repaired by anti-entropy Phase 1 (default 10s cycle), recovering missed events from alternative peers. Phase 2 repairs unknown mismatches via random prefix page comparison.

### Gossip Message ID Collision

**Attack:** Craft two different announcements with the same message ID to cause deduplication to drop the legitimate message.
- **Mitigation:** PlumTree message IDs are derived from content hashing. Two messages with identical content produce the same ID and are deduplicated, which is correct behavior. Different content produces different IDs.

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
- **Mitigation:** `list_prefixes` requires a signed request (signature over the JSON payload). The signer's peer_prefix must be in the authorized peer allowlist — which is itself verified via the full proposal DAG (structural integrity, KEL anchoring, threshold from compiled-in `trusted_prefixes()`). A 60-second timestamp window prevents replay. Unknown peer_prefixes trigger an allowlist refresh and recheck.
- **Residual risk:** Any authorized gossip peer can enumerate all prefixes. KELs are public by design, so this is information disclosure but not a confidentiality breach.

### Bootstrap Response Size Explosion

**Attack:** Request KEL fetches that generate large responses.
- **Mitigation:** KELs are fetched individually per prefix using paginated `forward_key_events` / `verify_key_events` via `PagedKelSource` / `PagedKelSink` traits. Each page is bounded by `MAX_EVENTS_PER_KEL_QUERY` (64 events). Pagination limit is clamped to `1..=64`.
- **Residual risk:** A single large KEL could still require many pages. No per-request byte limit.

## Network-Level Attacks

### Man-in-the-Middle (HTTP)

**Attack:** Intercept HTTP traffic between gossip nodes and KELS services.
- **Mitigation:** Events are signed at the application layer — modifying event data invalidates signatures. All data is public by design (KELs must be accessible for verification) and end-verifiable (SAID chaining + cryptographic signatures). A MITM can observe public data or inject modified events that fail signature validation. TLS is not required because there is no confidential data to protect and integrity is already guaranteed at the application layer.

### Man-in-the-Middle (Gossip)

**Attack:** Intercept gossip traffic between nodes.
- **Mitigation:** The gossip protocol uses ML-KEM-768/1024 key exchange + ML-DSA-65/87 mutual authentication with AES-GCM-256 authenticated encryption. Session keys are derived from the ML-KEM shared secret via BLAKE3 KDF. Each peer's handshake signature (ML-DSA-65/87) is verified against their KEL public key via the verified allowlist. Only ML-DSA-65/87 peers are accepted. Modifying messages invalidates the AES-GCM authentication tag. The protocol provides post-quantum security.

### Replay Attack (Gossip)

**Attack:** Replay old gossip announcements to trigger unnecessary KEL fetches.
- **Mitigation:** `event_exists()` check — if the announced SAID is already stored locally, the announcement is ignored. Old announcements for events the node already has are dropped immediately.

### Replay Attack (Signed Requests)

**Attack:** Replay a captured `list_prefixes` signed request.
- **Mitigation:** 60-second timestamp window via `validate_timestamp()`. Each request includes a cryptographic nonce (BLAKE3 hash of 32 random bytes). The server tracks nonces within the timestamp window and rejects duplicates. Expired nonces are evicted on each request.

### Denial of Service — Event Submission Flood

**Attack:** Flood `POST /api/v1/kels/events` with valid-looking but ultimately invalid events.
- **Mitigation:** Signature format validation happens upfront (before acquiring advisory lock). Invalid signatures are rejected quickly. Per-IP rate limiting (token bucket: 200 req/s refill, 1000 burst) on write endpoints prevents volumetric floods. Per-prefix rate limiting (32 submissions/min) prevents targeted abuse of a single prefix. Max event count per submission (500) and body size limit (5 MiB) bound individual request cost.
- **Residual risk:** Valid-format signatures that fail later verification still consume database resources within the rate limits.

### Denial of Service — Read Request Abuse

**Attack:** Send many concurrent KEL read requests to exhaust memory or database connections.
- **Mitigation:** KELs are fetched individually per prefix with paginated responses (max 64 events per page). Redis cache reduces database load for frequently accessed KELs. Body size limit (5 MiB) bounds response processing cost.
- **Residual risk:** Read endpoints are not per-IP rate limited (idempotent and cache-backed). Concurrent requests from many distinct sources could still exhaust database connections.

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

1. ~~**No rate limiting on any endpoint**~~ — mitigated: per-IP rate limiting on write endpoints (token bucket), per-prefix rate limiting on `submit_events` (32/min), max 500 events per submission, 5 MiB body limit
2. ~~**No TLS at application level**~~ — not required: all data is public by design and end-verifiable via signatures and SAID chaining. TLS would add confidentiality for non-confidential data and integrity for data that is already tamper-evident
3. ~~**Advisory lock contention under high concurrency**~~ — mitigated: per-prefix rate limiting (32/min) bounds contention
4. ~~**Bootstrap peer can serve outdated snapshots**~~ — accepted risk: caught by resync, all data cryptographically verified, worst case is temporary delay
5. ~~**60-second replay window on signed requests**~~ — mitigated: nonce-based deduplication within the 60s timestamp window eliminates replay
7. ~~**Redis state flags lack authentication**~~ — mitigated: per-service Redis ACL users with least-privilege command sets and key pattern isolation; `volatile-lru` eviction protects operational keys (no TTL) from eviction while cache keys (with TTL) are eviction candidates
8. **No real-time detection of selective message dropping** — mitigated by mesh redundancy, anti-entropy stale prefix repair (failed fetches recorded and retried within the next AE cycle), but delayed detection remains
9. ~~**Sustained announcement injection causes repeated HTTP fetches**~~ — mitigated: per-peer rate limiting (8192 fetches/min) on gossip processing

## Roadmap

Unmitigated attack vectors and planned improvements, roughly ordered by impact.

### ~~Rate limiting (addresses residual risks 1, 3, 9)~~

No application-level rate limiting exists on any KELS endpoint. Advisory lock contention under high concurrency has no fairness guarantee. Gossip announcement processing has no per-peer or per-prefix throttling, so sustained injection causes repeated HTTP fetches.

- [x] Add rate limiting to the KELS HTTP server (per-IP token bucket for write endpoints: 200 req/s refill, 1000 burst; per-prefix for `submit_events`: 32/min; max 500 events per submission; 5 MiB body limit)
- [x] Add per-peer rate limiting on gossip announcement processing (8192 fetches/min per peer)
- [x] Add per-prefix submission throttle to `submit_events` (32 submissions/min per prefix, in-memory via DashMap)

### ~~TLS between services (addresses residual risk 2)~~

~~No TLS at the application level.~~ Not required — all inter-service data is public by design (KELs must be accessible for verification) and end-verifiable (cryptographic signatures + SAID chaining). TLS would add confidentiality for non-confidential data and transport-level integrity for data whose integrity is already guaranteed at the application layer. The gossip layer uses ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 for authenticated encryption on the p2p transport.

### ~~Gossip protocol hardening (addresses residual risks 8, 9)~~

There is no real-time detection of selective message dropping. Announcement injection causes unbounded HTTP fetches.

- [x] Fix event partitioning for contest propagation — `partition_events` now places contest events (`cnt`) in the second (recovery) batch, ensuring the non-contest fork event establishes divergence first. Previously, `dec + cnt` pairs could be partitioned with `cnt` first, which was rejected by merge ("Contest requires divergence")
- [x] Failed gossip fetches recorded as stale prefixes for anti-entropy repair (consolidated from former retry queue into the anti-entropy loop)

### ~~Bootstrap integrity (addresses residual risk 4)~~

~~A malicious bootstrap peer can serve a valid but outdated snapshot. The resync phase catches the gap but creates a window where the node has stale data.~~ Accepted risk. Cross-validating against multiple peers is expensive at scale (merging prefix sets across all nodes). The anti-entropy loop already catches the gap, and all fetched data is cryptographically verified — the worst case is a temporary delay, not state corruption.

### ~~Redis authentication (addresses residual risk 7)~~

~~Redis state flags (`kels:gossip:ready`, `kels:verified-peer:*`) have no authentication.~~ Mitigated: per-service ACL users (`kels`, `gossip`, `registry`) with least-privilege command sets and key pattern isolation. The `default` user is disabled. Cache keys have 1-hour TTLs and `volatile-lru` eviction ensures operational keys (no TTL) are never evicted. All data read from Redis is still cryptographically re-verified before use.

- [x] Enable Redis AUTH + per-service ACLs for all Redis connections
- [ ] ~~Evaluate signing Redis state values with the node's HSM key — allows consumers to verify state integrity even if Redis is compromised~~ Overkill given auth

### ~~Signed request replay window (addresses residual risk 6)~~

~~`list_prefixes` signed requests have a 60-second replay window. While the endpoint is read-only, reducing the window or adding nonce-based deduplication would eliminate replay entirely.~~

- [x] Add server-side nonce tracking — each `PaginatedSelfAddressedRequest` includes a BLAKE3-hashed cryptographic nonce. The server rejects duplicate nonces within the 60s timestamp window, evicting expired entries on each request. Nonce storage is bounded by `max_peers × max_requests_per_peer_per_minute`.
