# Scale

## Frame

Scale in kels is structural, not protocol. A fail-secure decentralized framework has no central coordinator to bottleneck — the limits live in gossip mesh size, per-node bandwidth, and per-node verification cost. This doc maps the ceiling at each layer and the partitioning patterns that move it.

**Scope**: this doc covers network-scale concerns — federation size, gossip mesh ceilings, planet-scale partitioning. Operational scale within a single deployment (Postgres pool exhaustion, multi-replica HA, object-store throughput, bench tooling) lives under tracker #159. The two compose: receiver-side operational resilience is what lets the network-scale ceilings actually be reached.

## Today: Raft-bound (pre-#83)

- Registries cap at ~5–7. Raft's write-latency degrades super-linearly with quorum size.
- Peer-nodes are capped indirectly by Raft proposal/vote rate: hundreds to low thousands before voting throughput dominates.
- Coordinated consensus is the binding constraint.

## Post-#83: identity + policy replaces voting

- Peer admission becomes local verification against an IEL + policy view. No global coordination, no Raft cap.
- Limits relocate down the stack to gossip and per-node cost.

## Federation membership as identity-rooted SEL

- Federation IEL declares `authPolicy` (admit) and `governancePolicy` (evict / contested-terminal).
- Peer admission: SEL `Icp` / `Upd` on the federation chain, content = peer record (KEL prefix, base_domain, gossip_addr, role).
- Eviction: SEL `Dec`. Adversarial: contested-terminal via privileged-divergence-is-terminal — any privileged event landing in a divergent set fires the rule; there is no dedicated `Cnt`/contest event.
- Concurrent admit races resolve through the same divergence / contested-terminal machinery as other SELs.
- Discovery: a node bootstraps from the federation IEL prefix and walks the SEL to learn the membership graph.

### What this buys vs Raft

- No leader election, no quorum dance.
- Fork-of-authority is first-class — two admin factions disagreeing on a peer manifest as divergence and (when a privileged event lands in the divergent set) resolve via contested-terminal via privileged-divergence-is-terminal.
- Federations compose. A node can be a member of multiple federations by following multiple SELs; with Raft, each registry is its own world.

### What it costs

- Listing peers is O(chain length). Two candidate shapes:
  - **Snapshot-on-Sea** — `Sea` events anchor a membership snapshot; cold start resumes from the most recent `Sea` rather than walking from genesis.
  - **Per-peer SEL** — one chain per peer, identity-rooted on the federation IEL, indexed via SAD object lookup. Loses global ordering; gains short chains.
- Decision deferred to a query-pattern sweep before locking in.

## Layered ceilings (post-#83)

1. **Gossip mesh** (HyParView + PlumTree via iroh). ~10K nodes per topic with stable performance; ~100K with tuning (active-view size, passive-view refresh interval). Beyond that, topic partitioning is required.
2. **Per-node bandwidth**. Broadcast cost is O(N × E). At N=100K nodes and E=10 events/s/topic, each node fans 1M event-deliveries/sec across the mesh — bandwidth, not protocol, becomes the limit.
3. **Per-node verification**. CPU-bound, per-node. Caps individual memberships but doesn't add to global cost.

## Planet-scale shape: identity-namespace partitioning

Beyond single-federation ceilings, partition by identity-namespace — each identity gets its own gossip swarm for its events. There is no single "federation size" anymore: the network is an emergent graph of overlapping policy-defined membership sets. Different policies, different membership sets, different gossip topics. Per-topic limits, not global.

This pattern parallels how BitTorrent and IPFS scale past 10M peers: partition the topic space.

## Dependencies and adjacent work

- **#160** (tracker) — voting → credentials. Coordinates the workstream containing #83 (federation voting → endorsement), #82 (access control), #134 (identity policy primitive), #135 (cred identity binding), #153. The whole tracker is the gate to everything past Raft-bound limits.
- **#153** — SAD object discovery at scale (CascadingSadStore) lets per-peer SEL discovery work without an O(N) snapshot fetch. Lives under #160.
- **#156** — cross-chain dependency race + deferred-deps mechanism. Receiver-side resilience under gossip race; without it, per-node verification destabilizes under load before the network-scale ceilings even surface. Lives under #159.
- **#162** — client-side dep-graph caching strategy. Reduces per-node verification cost by amortizing repeated dep-walks within a client session.
- **#159** (tracker) — operational scaling within one deployment (Postgres pool, multi-replica HA, object store, bench tooling, multi-pod gossip horizontal scaling). Independent of network-scale concerns; lives one layer down.

## Open questions

- **Membership shape**: single SEL with snapshot-on-`Sea`, or per-peer SELs? Depends on the dominant query pattern (cold-start enumeration vs. targeted lookup).
- **Topic-partitioning trigger**: at what node count does partitioning start, and what's the partitioning key (identity-namespace, geographic, role-based)?
- **Cold-start cost budget**: how expensive is it to join a federation, and where does that budget bind first (chain walk, SAD object fetch, gossip handshake)?
