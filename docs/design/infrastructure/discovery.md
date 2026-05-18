# Node-Side Peer Discovery

A gossip node needs two things to participate in the mesh: a list of **who** is currently authorized as a federation member, and the network endpoint **where** each of those members can be reached. This document describes how a gossip node resolves both — entirely from the local kels and sadstore services on the same node, which are gossip's sources of truth.

The full federation model is in [federation.md](federation.md). This doc covers the node-side mechanics.

## The two layers

Anchoring KELs are the trust substrate that makes both layers below verifiable — every IEL and SEL event resolves authorization through KEL anchors.

| Layer | Source | What it answers |
|---|---|---|
| Membership (who) | Federation IEL [conforming policy pair](federation.md#federation-policy-shape-verification) (member identities must appear in both) | Which peer identities are currently authorized to participate? |
| Address resolution (where) | Per-peer address SELs | For each authorized peer, what are its current network endpoints? |

Both layers — and the anchoring KELs they verify against — live in primitives every gossip node already replicates: the KELs, the federation and peer IELs, the peer address SELs. No separate replication mechanism, no separate authority, no deployment beyond the gossip service itself.

## Steady-state discovery flow

When a node refreshes its peer view (on startup, on a configurable interval, or on demand):

1. **Read the federation IEL's tip locally.** The federation IEL prefix is configured (compile-time default + runtime `FEDERATION_IEL_PREFIX` env-var override — see [federation.md §Configuration](federation.md#configuration)). Verify the chain via `IelVerifier`, take the current `authPolicy`.
2. **Enumerate authorized identities.** Walk the `authPolicy` expression and collect the set of `identity(...)` leaves. Each leaf is a peer-identity prefix.
3. **For each peer identity, compute the address SEL prefix.**
   ```
   address_sel_prefix = compute_sel_prefix(peer_identity_prefix, "kels/sel/v1/peer/addresses")
   ```
   The topic string `"kels/sel/v1/peer/addresses"` is a protocol constant; the resulting prefix is fully deterministic given the peer identity.
4. **Walk each address SEL to its tip.** Verify the chain via `SelVerifier`. The current address SAD is the `content` field on the latest accepted `Upd`. Per the federation address-SEL application convention, that `Upd` is sealed by a trailing `Sea` — conforming tooling never produces an Upd-tailed chain. A chain whose tip is an unsealed `Upd` is structurally invalid under the convention and rejected by discovery.
5. **Connect.** The node now has the authorized peer set with current endpoints. Filter by liveness / region preference / policy as needed, then initiate gossip handshakes (which themselves re-check the federation IEL `authPolicy`; see [peer-identity.md](peer-identity.md)).

All reads (anchoring KELs, federation and peer IELs, address SELs) go to the local sadstore and kels services on the same node — gossip doesn't query peers or external infrastructure for discovery state. The freshness of the answer is the freshness of the chain state the local sadstore and kels holds, which the gossip mesh keeps current — primarily through announcement-driven propagation (PlumTree), with dependency tracking for out-of-order arrivals and anti-entropy as a fallback for events the primary path missed.

## Where initial state comes from

### Bootstrapping the federation

Assumption: `FEDERATION_IEL_PREFIX` is unset for all nodes.

A new federation is created by, first, bringing at least three nodes online. Once a minimum of three nodes are running, each with an incepted identity KEL and IEL, bootstrapping can begin. One node is designated as the **coordinator** for the ceremony; the others are non-coordinating peers. All syncs are performed using `transfer_*_events()`; the `sync --sync-identity-to={DOMAIN}` CLI verb pushes the invoker's local identity state to the named domain's `kels`/`sadstore` services.

1. The federation IEL `Icp` event is drafted in the [allowed shape](federation.md#same-membership-different-thresholds), composed of the peer IELs, using identity service CLI tooling on the coordinating node.
2. All peers invoke their identity service CLI to anchor the `Icp` SAID in their KEL via a `Rot` (tier-2). The `Icp` event is delivered out of band.
3. All peers invoke their identity service CLI to create and anchor address SEL events `[Icp, Upd, Sea]`. The tooling should enforce batched submission of all three events. Shape:
  - `Icp(identity_prefix, "kels/sel/v1/peer/addresses")` — unsigned; chain prefix is `compute_sel_prefix(identity_prefix, "kels/sel/v1/peer/addresses")`
  - `Upd(address_object_prefix)` — tier-1; `address_object_prefix` is the SAID of the address SAD object (endpoints list) stored in the sadstore
  - `Sea` — tier-2 (see [protocol-doctrine.md §Sea-after-Upd ratchet](../protocol-doctrine.md#sea-after-upd-ratchet-application-pattern))
4. Non-coordinating peers invoke their identity service CLI with the parameters `sync --sync-identity-to={COORDINATING DOMAIN}`, pushing their identity KELs, IELs, and address SELs to the coordinator's services.
5. The coordinating node submits the original federation IEL `Icp`. The peers' KEL `Rot` anchors are already on the coordinator from step 4, so the `Icp` is accepted on submission.
6. The coordinating node enumerates the `identity(...)` leaves of the federation IEL's `authPolicy` and runs `transfer_*_events` (`seed-all`), transferring the entire bundle (all KELs, IELs, and SELs involved) to each peer, using the peer's address SEL to resolve the destination.
7. `FEDERATION_IEL_PREFIX` is set for all nodes and all gossip services are restarted.

### Adding a new peer

Assumption: `FEDERATION_IEL_PREFIX` is set for all nodes, including the new one. As it starts, if it has no knowledge of the prefix in the local sadstore, it sleeps for 5 seconds before polling again. When it succeeds, it performs the normal startup sync.

1. The new peer invokes their identity service CLI to create and anchor an address SEL `[Icp, Upd, Sea]` for their node, with the same shape as above.
2. The new peer invokes their identity service CLI with the parameters `sync --sync-identity-to={COORDINATING DOMAIN}`, pushing their identity KEL/IEL and address SEL to another node so federation members can resolve them at gossip-up time.
3. The peer is added to the federation with an `Evl` on the federation identity, endorsed by >= M(n) federation members per `governancePolicy` (see [federation.md §Threshold formula](federation.md#threshold-formula-application-level); each member anchors the `Evl` SAID in their KEL via a `Rot`, tier-2).
4. Another node then transfers the entire bundle (all KELs, IELs, and SELs involved) to the new member of the federation IEL policy using another identity service CLI command (`seed-one`).

### Identity as source of truth

The identity service is the source of truth for the node's own identity — it holds the node's KEL, IEL, and address SEL in its own DB, alongside the HSM key bindings. The kels and sadstore services hold infrastructure-distributed copies; identity creates and pushes, infrastructure replicates. The recovery procedures below proceed from this model.

### Recovering a node: local stores lost, identity DB intact

Assumption: `FEDERATION_IEL_PREFIX` is set; the node's identity is in current `authPolicy`; the identity service's DB and HSM material are intact, but the local `kels` and `sadstore` services lost their state.

1. Operator on any current federation peer invokes `seed-one --to={RECOVERING DOMAIN}`, pushing the full bundle (federation IEL + all member KELs + all member address SELs) to the recovering node's `kels`/`sadstore`.
2. Gossip starts; handshakes succeed because the identity is still in `authPolicy`. No federation `Evl` needed.

### Recovering a node: identity DB lost, HSM material intact

Operators back up identity DB state alongside HSM material.

1. Operator on any current federation peer invokes `seed-one --to={RECOVERING DOMAIN}`, repopulating local kels/sadstore including the recovering node's own KEL/IEL/address-SEL.
2. Operator restores identity database with latest snapshot.
3. Operator restarts identity service; gossip starts; handshakes succeed. No federation `Evl` needed.

### Recovering a node: identity material lost

Assumption: identity material is unrecoverable (HSM lost; or no backup of identity DB and HSM handles can't be re-discovered; or `label_prefix` itself is lost). The node's lost identity remains in `authPolicy` but no one can sign as it.

1. Stand up a fresh node and re-incept a new identity (new KEL, new IEL, new prefix). The federation continues operating under the existing `authPolicy` minus the lost identity's effective authority.
2. Federation members coordinate a single `Evl` on the federation IEL that simultaneously **removes** the lost identity and **adds** the new identity. Endorsed by >= M(n) members per the prior `governancePolicy` (see [federation.md §Threshold formula](federation.md#threshold-formula-application-level); the lost identity cannot participate, so remaining members must meet the threshold without it).
3. The exclusion `Evl` is **immediately batched with a `Sea`** to close the structural window the exclusion opens. Without a trailing `Sea`, the chain's highest-serial event is the exclusion `Evl` at `v_N`; any `Cnt` constructed against this chain has `Cnt.previous = v_{N-1}.said` (per the locked-portion bound — see [protocol-doctrine.md §Privileged Divergence is Terminal §Repair-event conditions](../protocol-doctrine.md#privileged-divergence-is-terminal)). `v_{N-1}` predates the exclusion, so its `governancePolicy` is `P_old`, which any rotated-out party can still satisfy; their `Cnt` at `v_N` is structurally valid. Cnt is privileged, so privileged-divergence-is-terminal fires and the federation IEL becomes contested-terminal. The trailing `Sea` extends the chain to `v_{N+1}`: any subsequent `Cnt` has `Cnt.previous = v_N.said`, whose `governancePolicy` is `P_new` (declared by the exclusion `Evl`), which no rotated-out party can satisfy by definition. The `Sea` itself is authorized under `P_new`, so the operator can land it but the rotated-out party cannot. This concern is specific to **exclusion** evolutions (member removed or replaced); pure additions or threshold-decreases that keep prior membership open up no rotated-out position and do not need the trailing `Sea`. See [protocol-doctrine.md §Exclusion Evolutions and the Seal Advance](../protocol-doctrine.md#exclusion-evolutions-and-the-seal-advance). The federation-membership CLI should bake `[Evl, Sea]` into every exclusion evolution.
4. From here, the §Adding a new peer flow for the new identity (steps 1–4).

For federation-IEL-contested recovery (a different, harder case — the federation IEL itself is dead under its current prefix), see [federation.md §Recovery](federation.md#recovery).

Gossip cannot do the initial pull itself in any of these modes: handshakes authorize against the federation IEL, which is exactly what a fresh node doesn't have. `transfer_*_events` is the bootstrap channel; gossip takes over once the node has the federation IEL and the address SELs locally.

## Refresh cadence

A node refreshes its discovery view in three situations:

- **On startup**, after bootstrap or after a normal restart against an existing local state.
- **On gossip-driven invalidation**, when a new federation IEL event (`Evl`) lands locally — the membership view may have changed.
- **On a slow background interval**, as a defense against missed invalidations.

Per-peer address SEL refreshes are also gossip-driven: when a new `Upd` lands on an address SEL the node holds, the node updates its cached endpoints for that peer.

Stale endpoints for a still-authorized peer cause connection failures, not authorization failures — the gossip mesh routes around them, and the latest address SEL state arrives on the next announcement (or anti-entropy fallback) and is merged locally.

## Removed members

When a federation `Evl` removes a peer from the policy set:

- The peer's identity remains a structurally valid identity (the peer's own IEL is unchanged). The peer can still operate, just not as a federation member.
- The peer's address SEL stays readable. The discovery flow simply doesn't enumerate that peer anymore, because step 2 reads the new `authPolicy`.
- Existing gossip connections to the removed peer are torn down at the next handshake re-check (or sooner, on an explicit policy-refresh tick). New handshakes from the removed peer fail authorization.

The federation IEL's current [conforming policy pair](federation.md#federation-policy-shape-verification) is the source of truth; what's not enumerated in it is not authorized.

## Failure modes

| Failure | What the node does |
|---|---|
| Federation IEL prefix mismatch (env override differs from compile-time default) | Logs a startup warning; treats the env value as authoritative. See [federation.md §Configuration](federation.md#configuration). |
| Federation IEL not yet present locally (cold start, before bootstrap completes) | Node sleeps and polls the local sadstore for the configured prefix; participates as soon as state arrives via operator-coordinated `transfer_*_events`. See [§Bootstrapping the federation](#bootstrapping-the-federation) and [§Recovering a node: local stores lost, identity DB intact](#recovering-a-node-local-stores-lost-identity-db-intact). |
| Federation IEL chain fails verification | Discovery rejects the chain; node refuses to participate. Operator intervention required. |
| Federation IEL is contested-terminal | Federation is dead under that prefix. Recovery is via a fresh federation IEL inception + runtime override repoint. See [federation.md §Recovery](federation.md#recovery). |
| Address SEL missing for an authorized peer | Peer is treated as unreachable. Anti-entropy will fetch the address SEL on its next chance. |
| Address SEL endpoints stale (peer not reachable at published addresses) | Connection failures only. Gossip mesh routes via other peers; the affected peer is effectively offline until it publishes new endpoints. |

In all cases the failure mode is **fail-secure**: an unverifiable or contested chain causes the node to refuse rather than to fall back to a less-trusted source.

## References

- [federation.md](federation.md) — full federation-as-identity design.
- [peer-identity.md](peer-identity.md) — handshake-time authorization check against the federation IEL.
- [gossip.md](gossip.md) — gossip protocol mechanics, anti-entropy, transport layer.
- [primitives/data/event-logs/iel/event-log.md](../primitives/data/event-logs/iel/event-log.md) — IEL chain semantics.
- [primitives/data/event-logs/sel/event-log.md](../primitives/data/event-logs/sel/event-log.md) — SEL chain semantics; address SELs follow the standard SEL pattern.
