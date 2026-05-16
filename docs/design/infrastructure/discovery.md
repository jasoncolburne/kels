# Node-Side Peer Discovery

A gossip node needs two things to participate in the mesh: a list of **who** is currently authorized as a federation member, and the network endpoint **where** each of those members can be reached. This document describes how a gossip node resolves both, entirely from primitives it holds locally.

The full federation model is in [federation.md](federation.md). This doc covers the node-side mechanics.

## The two layers

| Layer | Source | What it answers |
|---|---|---|
| Membership (who) | Federation IEL `auth_policy` | Which peer identities are currently authorized to participate? |
| Address resolution (where) | Per-peer address SELs | For each authorized peer, what are its current network endpoints? |

Both layers live in primitives every gossip node already replicates: the federation IEL through normal IEL gossip, and the per-peer address SELs through normal SEL gossip. No separate replication mechanism, no separate authority, no deployment beyond the gossip service itself.

## Steady-state discovery flow

When a node refreshes its peer view (on startup, on a configurable interval, or on demand):

1. **Read the federation IEL's tip locally.** The federation IEL prefix is configured (compile-time default + runtime `FEDERATION_IEL_PREFIX` env-var override — see [federation.md §Configuration](federation.md#configuration)). Verify the chain via `IelVerifier`, take the current `auth_policy`.
2. **Enumerate authorized identities.** Walk the `auth_policy` expression and collect the set of `identity(...)` leaves. Each leaf is a peer-identity prefix.
3. **For each peer identity, compute the address SEL prefix.**
   ```
   address_sel_prefix = compute_sel_prefix(peer_identity_prefix, "kels/sel/v1/peer/address")
   ```
   The topic string `"kels/sel/v1/peer/address"` is a protocol constant; the resulting prefix is fully deterministic given the peer identity.
4. **Walk each address SEL to its tip.** Verify the chain via `SelVerifier`. The current address SAD is the `content` field on the latest accepted `Upd` (or `Icp` if no `Upd` has landed yet).
5. **Connect.** The node now has the authorized peer set with current endpoints. Filter by liveness / region preference / policy as needed, then initiate gossip handshakes (which themselves re-check the federation IEL `auth_policy`; see [peer-identity.md](peer-identity.md)).

All four reads (federation IEL, address SELs) hit local storage; no network calls are needed for the discovery itself. The freshness of the answer is the freshness of the local chains, which the gossip mesh keeps current — primarily through announcement-driven propagation (PlumTree), with dependency tracking for out-of-order arrivals and anti-entropy as a fallback for events the primary path missed.

## Where initial state comes from

A node that just came up needs the federation IEL and every member's address SEL locally before the steady-state discovery flow above can run. That state arrives via `transfer_*_events` — the existing point-to-point event-transfer abstractions — invoked with the source node's store addresses as a CLI argument. The flow is operator-coordinated, not runtime-config-driven:

- **Federation bootstrap.** All founding nodes receive the federation IEL and the founding members' address SELs from the coordinator's `kels`/`sadstore` services via `transfer_*_events`. See [federation.md §Bootstrap](federation.md#bootstrap-one-time-ceremony).
- **Peer onboarding (new member added post-bootstrap).** The new member receives federation IEL state from any existing peer via `transfer_*_events`, coordinated out-of-band as part of the onboarding ceremony.
- **Single-node disaster recovery (node lost local state).** Same shape: re-pull from any current peer via `transfer_*_events`.

There is no service env var for "initial peer addresses" — the bootstrap source is a CLI argument at the moment of transfer, not a long-lived gossip-service config item. Once a node has the federation IEL and the address SELs, the steady-state discovery flow above takes over and the mesh forms on its own. Gossip cannot do the initial pull itself, by chicken-and-egg: gossip handshakes are authorized against the federation IEL, which is exactly what the new node doesn't have yet.

A node with no federation IEL is not yet a federation participant. The bootstrap is the moment when an operator transitions a node *into* the federation, and bootstrap is always operator-coordinated.

## Refresh cadence

A node refreshes its discovery view in three situations:

- **On startup**, after bootstrap or after a normal restart against an existing local state.
- **On gossip-driven invalidation**, when a new federation IEL event (`Evl`) lands locally — the membership view may have changed.
- **On a slow background interval**, as a defense against missed invalidations.

Per-peer address SEL refreshes are also gossip-driven: when a new `Upd` lands on an address SEL the node holds, the node updates its cached endpoints for that peer.

Stale endpoints for a still-authorized peer cause connection failures, not authorization failures — the gossip mesh routes around them, and the latest address SEL state arrives on the next announcement (or anti-entropy fallback) and is merged locally.

## Removed members

When a federation `Evl` removes a peer from `auth_policy`:

- The peer's identity remains a structurally valid identity (the peer's own IEL is unchanged). The peer can still operate, just not as a federation member.
- The peer's address SEL stays readable. The discovery flow simply doesn't enumerate that peer anymore, because step 2 reads the new `auth_policy`.
- Existing gossip connections to the removed peer are torn down at the next handshake re-check (or sooner, on an explicit policy-refresh tick). New handshakes from the removed peer fail authorization.

The federation IEL's current `auth_policy` is the single source of truth; what's not in it is not authorized.

## Failure modes

| Failure | What the node does |
|---|---|
| Federation IEL prefix mismatch (env override differs from compile-time default) | Logs a startup warning; treats the env value as authoritative. See [federation.md §Configuration](federation.md#configuration). |
| Federation IEL not yet present locally (cold start, before bootstrap completes) | Discovery flow blocks; node uses `INITIAL_PEER_ADDRESSES` to bootstrap. |
| Federation IEL chain fails verification | Discovery rejects the chain; node refuses to participate. Operator intervention required. |
| Federation IEL is contested-terminal | Federation is dead under that prefix. Recovery is via a fresh federation IEL inception + runtime override repoint. See [federation.md §Recovery](federation.md#recovery). |
| Address SEL missing for an authorized peer | Peer is treated as unreachable. Anti-entropy will fetch the address SEL on its next chance. |
| Address SEL endpoints stale (peer not reachable at published addresses) | Connection failures only. Gossip mesh routes via other peers; the affected peer is effectively offline until it publishes new endpoints. |

In all cases the failure mode is **fail-secure**: an unverifiable or contested chain causes the node to refuse rather than to fall back to a less-trusted source.

## References

- [federation.md](federation.md) — full federation-as-identity design.
- [peer-identity.md](peer-identity.md) — handshake-time authorization check against the federation IEL.
- [gossip.md](gossip.md) — gossip protocol mechanics, anti-entropy, transport layer.
- [primitives/iel/event-log.md](../primitives/iel/event-log.md) — IEL chain semantics.
- [primitives/sel/event-log.md](../primitives/sel/event-log.md) — SEL chain semantics; address SELs follow the standard SEL pattern.
