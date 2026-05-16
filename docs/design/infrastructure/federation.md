# Federation

A KELS federation is **itself an identity**. Membership lives on a single shared IEL — the *federation IEL* — and membership changes are governance-authorized `Evl` events on that chain. Discovery, authorization, and burn semantics all reduce to operations on that one identity.

This document explains the model and its load-bearing properties. For node-side discovery mechanics see [discovery.md](discovery.md); for the handshake-time authorization check see [secure-registration.md](secure-registration.md).

## Why federation reduces to identity

The federation answers three operational questions:

- *Who is allowed to participate in the gossip mesh?*
- *How does that set change over time?*
- *Where do I reach them on the network?*

Identity primitives already answer the first two:

- An IEL's `auth_policy` declares a set of identities — that is exactly a membership set.
- An IEL's `governance_policy` constrains how the `auth_policy` evolves — that is exactly a membership-change protocol.
- The IEL policy-immunity rule ([primitives/iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../primitives/iel/event-log.md#evaluation-seal-and-anchor-non-poisonability)) guarantees that past authorizations stay final — so a former member's past gossip cannot be retroactively repudiated.

The third question — network addresses — is answered by per-peer SELs, one per member identity, each peer publishing its own current endpoints under its own authority. Nothing federation-wide needs to track addresses centrally.

## Architecture at a glance

```
                 FEDERATION IEL  (prefix: F)
                 ──────────────
            governance_policy: how membership evolves
                 auth_policy: { node_a, node_b, node_c, ... }
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
   ┌────────┐      ┌────────┐      ┌────────┐
   │ node_a │◄────►│ node_b │◄────►│ node_c │       gossip mesh
   │ gossip │      │ gossip │      │ gossip │   (HyParView + PlumTree
   └───┬────┘      └───┬────┘      └───┬────┘    over PQ transport)
       │               │               │
       ▼               ▼               ▼
   address SEL    address SEL     address SEL    (one per peer, under
   (peer-owned)   (peer-owned)    (peer-owned)    that peer's identity)
```

- The **federation IEL** is a single IEL whose `auth_policy` enumerates member identities. Every gossip node holds a local copy and syncs it through the normal anti-entropy machinery.
- Each member identity is a **gossip-service identity** — a KEL holding the gossip service's HSM-backed signing key, wrapped in a single-KEL IEL (`auth_policy = endorse(gossip_kel_prefix)`). "Peer" throughout this doc means a gossip-service instance.
- Each member publishes its current network endpoints via a **per-peer address SEL**, owned and signed by that member.

The mesh is symmetric: every peer holds the federation IEL, every peer's own identity is listed in the IEL's `auth_policy`, every peer manages its own address SEL. No node has a special role.

## The federation IEL

### Membership = `auth_policy`

The current `auth_policy` of the federation IEL **is** the membership list. Typical shape:

```
auth_policy = threshold(M, [
  identity(F_node_a),
  identity(F_node_b),
  identity(F_node_c),
  ...
])
```

- `identity(X)` is satisfied when an event is anchored under the current `auth_policy` of IEL `X`. So an `auth_policy` over `identity()` leaves over member identities means "this federation event is authorized if M of N member identities currently endorse it."
- The same `auth_policy` is consulted at the handshake (does this connecting peer's identity appear?) and at every `Evl` (does the proposed change carry M endorsements?).
- There is **no denormalized member list** — the policy itself is the canonical record. Anything that wants to enumerate members reads the current `auth_policy`.

### `governance_policy` controls how membership evolves

An `Evl` event evolving `auth_policy` (or `governance_policy` itself) must satisfy the federation IEL's current `governance_policy`. Typical operator choice is to make `governance_policy = auth_policy` — the same M-of-N quorum that authorizes federation operations also authorizes membership changes — but the two can be set independently if an operator wants a different bar for governance vs. authorization (e.g., a higher threshold for membership changes than for routine operations).

### Immunity is mandatory

The IEL policy-immunity rule requires every policy referenced as `auth_policy` or `governance_policy` to have `immune: true`. The federation IEL is no exception. Two consequences:

- **No poisoning of past authorizations.** A peer whose endorsements appeared on past federation `Evl`s cannot retroactively repudiate them, even after the peer is removed.
- **Revocation happens by evolution, not by poison.** To drop a member, evolve `auth_policy` to a new SAID that excludes them. The dropped member's past endorsements remain final; new endorsements from them are simply not counted against the new policy.

## Gossip-service identity

Each node runs a gossip service. That service is a **degenerate single-KEL identity**:

- One KEL holds the gossip service's signing key (HSM-backed; ML-DSA-65 or ML-DSA-87).
- One IEL declares `auth_policy = endorse(gossip_kel_prefix)` and a `governance_policy` of the operator's choosing.
- The IEL prefix is the **peer identity** referenced from the federation IEL's `auth_policy`.

The gossip service is the only service on a node that participates in federation authentication. Other services on the same node (`sadstore`, `mail`, the `kels` service, identity service) are workers; they don't carry federation identities and don't authenticate with peers themselves. When this doc says "peer," it means a gossip-service instance — not a host, not a deployment, not an operator.

The HSM ceremony is documented in [secure-registration.md](secure-registration.md).

## Per-peer address publication

Address publication is **per-peer, self-managed**, using a SEL chain bound to each peer's identity. The federation IEL holds *who is authorized*; the per-peer SELs hold *where to reach them*.

### Why a SEL, not a federation-wide record

- Each peer can update its own endpoints (IP rotation, scale events, region migration) without needing federation-wide governance approval. Auth on each `Upd` is the peer's own `auth_policy`.
- Cross-peer auth concerns disappear: peer A cannot publish addresses for peer B because the address SEL is bound to peer B's own identity.
- The federation IEL's `auth_policy` stays the sole authoritative source for membership. The address SEL is an **address resolution mechanism for an already-authorized peer**, not an additional authorization mechanism.

### Deterministic SEL prefix

Each peer's address SEL prefix is:

```
compute_sel_prefix(peer_identity_prefix, "kels/sad/v1/peers/address")
```

This is fully deterministic. Given the peer's identity prefix (which the federation IEL's `auth_policy` lists), any node can compute the address SEL prefix and fetch the chain — no separate lookup, no directory service.

### Address SAD schema

The `content` field of each `Upd` on the address SEL carries:

```
{
  "endpoints": [
    { "addr": "203.0.113.4:4001", "region": "us-east" },
    { "addr": "[2001:db8::4]:4001", "region": "us-east" }
  ]
}
```

- `endpoints` is an array. Multi-address support is first-class — peers commonly publish IPv4/IPv6 pairs, regional alternates, or transitional endpoints during a migration.
- `addr` is a TCP gossip endpoint, `host:port`. Gossip carries its own transport (ML-KEM-1024 key exchange, ML-DSA-65/87 signatures, AES-GCM-256 sessions); the published address is the network endpoint only.
- `region` is optional, opaque, free-form (`"us-east"`, `"eu-west"`, etc.). Latency-aware clients may prefer in-region endpoints; absence is meaningful (peer didn't tag region).
- **No `role` field, by design.** Role-bearing self-declarations would let an identity holder elevate their own privileges without going through the federation `governance_policy`. Capabilities are determined by what the federation IEL authorizes the peer to do; a peer cannot self-declare additional capabilities.

The current address is whatever the latest accepted `Upd` on the chain says. Address rotation is a standard SEL `Upd`; revocation is implicit (publish a new `Upd`).

## Discovery flow

When a node joins or refreshes its peer view:

1. Read the federation IEL's current `auth_policy` to enumerate authorized member identities.
2. For each member identity, compute the address SEL prefix (`compute_sel_prefix(peer_identity, "kels/sad/v1/peers/address")`).
3. Walk that address SEL to its tip and read the current `endpoints` array.
4. Connect.

The federation IEL is held locally on every gossip node, so step 1 is a local read. The address SELs are SADs in the sadstore; step 3 is a normal SEL read.

This steady-state flow assumes the node already holds the federation IEL and every member's address SEL. Initial state arrives during the federation ceremony (or during a peer onboarding) via `transfer_*_events` — see [§Bootstrap](#bootstrap-one-time-ceremony) below. There is no runtime-config-driven cold-start discovery surface; if a node has no state at all, it isn't yet a federation participant.

## Handshake authorization

When a connecting peer initiates a gossip handshake:

1. The connecting peer presents its identity prefix and a signature over the handshake transcript with its gossip signing key.
2. The accepting peer evaluates the connecting peer's identity against the current federation IEL `auth_policy` via `evaluate_signed_policy`.
3. If the policy is satisfied (i.e., the connecting identity is currently authorized), the handshake proceeds. Otherwise it's rejected.

For the cryptographic handshake (prefix exchange, ML-KEM-1024 KEM, mutual ML-DSA signature, BLAKE3-derived AES-GCM-256 session key), see [gossip.md §HSM-backed gossip identity](gossip.md#hsm-backed-gossip-identity).

## Membership evolution

Adding or removing a member is the same primitive in both directions: an `Evl` event on the federation IEL evolving `auth_policy`, satisfying the current `governance_policy`.

### Symmetric add/remove

There is no asymmetry between add and remove. Both use `Evl` against `governance_policy`. The procedural difference is operational, not structural:

- **Adding peer X:** M of the current N members endorse an `Evl` that includes `identity(X)` in the new `auth_policy`. X itself does not need to endorse.
- **Removing peer X:** M of the *other* `N − 1` members endorse an `Evl` that excludes `identity(X)` from the new `auth_policy`. X itself, predictably, does not endorse its own removal.

Whether the burn is a clean drop ("X retired, please remove") or an adversarial expulsion ("X compromised, drop now") is the same chain operation; only the operator urgency differs.

### No withdrawal, no poison

The federation `auth_policy` and `governance_policy` are `immune: true` (mandatory under the IEL policy-immunity rule). There is no withdrawal primitive and no poison-based revocation on the federation IEL. **All revocation goes through `Evl`.** This is not an inconvenience; it is the structural guarantee that past authorizations stay final — every endorsement a peer made while a member remains valid forever, by construction.

### Threshold formula (application-level)

The threshold `M` in `threshold(M, [identity(...)])` is operator/tooling convention, not protocol. The node and CLI tooling that constructs membership-change `Evl`s uses:

```
M = max(3, ceil(N / 3))
```

| N | M |
|---|---|
| 3 | 3 |
| 9 | 3 |
| 10 | 4 |
| 21 | 7 |
| 25 | 9 |

- Floor of 3 prevents trivial collusion in small federations.
- One-third-quorum scaling at larger sizes is KERI-inspired (`F+1` immunity bound).
- When `N` crosses a formula boundary (e.g., 9 → 10 brings M from 3 to 4), the same `Evl` that adds the new peer also evolves `governance_policy` to encode the new threshold value. Both changes batch into one event.

**The IEL verifier does not enforce the formula.** A federation that chose a different `M` would still produce structurally valid IEL chains; the verifier checks only chain-validity invariants (immunity, signatures, `governance_policy` satisfaction). The formula lives in the node/gossip application layer and the CLI tooling — operator convention, not protocol surface. A federation operator who needs a different threshold can configure one without forking the protocol.

### Multi-peer simultaneous compromise

If `N − M` or more member identities are compromised at once, normal governance cannot evolve — the honest members cannot reach the threshold. Recovery is the contested-federation procedure (see [§Recovery](#recovery) below). This is the operationally catastrophic case; it is also the case the threshold formula is sized to make rare.

## Bootstrap (one-time ceremony)

A new federation is born via a single Icp event on a fresh federation IEL. The ceremony is point-to-point HTTP between founding nodes — the gossip mesh doesn't exist yet, and the `auth_policy`/`governance_policy` shape that would gate gossip is exactly what the ceremony is producing.

### Roles and procedure

- **Coordinator** — one founding peer is designated coordinator for the ceremony. Coordinator is an operational role (one-shot, ceremony-scoped), not a protocol role.
- **Founding members** — each prepares a signature on the proposed federation IEL Icp event using its founding identity (KEL+IEL prepared in advance).
- The coordinator's `kels` and `sadstore` services are reachable over HTTP at a domain known out-of-band to the founding operators (chat, ticketing, runbook — not a runtime config of the gossip service).
- **Signature collection.** Each founding member submits its signature on the Icp candidate to the coordinator's `kels` and `sadstore` services via standard HTTP submit endpoints. When all required signatures are present, the Icp event is accepted on the coordinator's node.
- **Redistribution.** The coordinator pushes the accepted federation IEL to every other founding node via the `transfer_*_events` CLI (the existing point-to-point event-transfer abstractions, parameterized with the coordinator's stores as the source).
- **Address SELs.** Each founding member's address SEL (`Icp` + initial `Upd` carrying that member's endpoints) flows through the same `transfer_*_events` mechanism — either bundled with the federation IEL push, or as a follow-up pass.
- **Mesh formation.** Once every founding node holds the federation IEL and every other member's address SEL, each node can compute peer SEL prefixes and resolve endpoints locally. The HyParView initial-view set populates from this resolution, and gossip mesh formation proceeds normally. Subsequent syncing flows through anti-entropy.

The Icp's `auth_policy` and `governance_policy` are agreed out-of-band by the founding operators. There is no protocol-level "voting" on the Icp — the chain begins with whatever shape its founders cryptographically commit to, and consumers of the federation accept that shape on the strength of the founders' identities.

### Why not gossip for the redistribution

The natural question is whether the federation IEL itself could be redistributed via gossip rather than via `transfer_*_events`. It can't, by chicken-and-egg: gossip handshake authorization depends on the federation IEL's `auth_policy`, but the federation IEL doesn't exist on the non-coordinator nodes yet. The only authorization context the non-coordinator nodes have at this point is what their compile-time-default (or runtime-override) federation IEL prefix tells them to *expect* — they don't have the chain to evaluate handshakes against. Point-to-point HTTP via `transfer_*_events`, parameterized with the coordinator's address, is the bootstrap channel; gossip takes over once every node has the federation IEL locally and `IelVerifier` has accepted it under the expected prefix.

The same chicken-and-egg applies to peer onboarding (adding a new member post-bootstrap) and to single-node disaster recovery — both cases use `transfer_*_events` from an existing peer, coordinated out-of-band, until the recovering/joining node has enough chain state to participate in the mesh.

## Configuration

Each node needs to know which federation IEL is its federation. The prefix is configured in two layers:

- **Compile-time default**: a federation IEL prefix is baked into the binary at build. This is the federation-as-shipped — the prefix the binary was tested and audited against.
- **Runtime override** (`FEDERATION_IEL_PREFIX`): optional env var. When set, the binary uses the env var as authoritative. If it differs from the compile-time default, the binary logs a startup warning so operators are aware the deployment has been redirected.

The runtime override exists for recovery: operators can repoint a federation to a fresh IEL prefix on existing binaries when the federation IEL becomes contested, then align the compile-time default at the next release.

HSM and gossip identity config: see [gossip.md](gossip.md) and [secure-registration.md](secure-registration.md).

Bootstrap and onboarding flows use `transfer_*_events` parameterized with the coordinator-of-the-moment's store addresses at invocation time — a CLI argument, not a service env var. See [§Bootstrap](#bootstrap-one-time-ceremony).

## Concurrent-Evl coordination

The federation IEL is exposed to the same divergence risk as any IEL: two governance-authorized parties submitting concurrent `Evl` events at the same serial diverge the chain, and IEL divergence is structurally contested-terminal (see [primitives/iel/event-log.md §Divergence and Contest-Only Resolution](../primitives/iel/event-log.md#divergence-and-contest-only-resolution)). Federation IEL divergence is catastrophic — the federation dies under that prefix.

The protocol does not prevent this. The defense is operational:

- **Federation `Evl`s are infrequent.** Adding or removing a peer is a meaningful operational event, not a routine action.
- **Each `Evl` already requires multi-party coordination.** Collecting M endorsements is itself a coordination point; operators naturally serialize this through whatever out-of-band channel they use (chat, ticketing, change management).
- **No protocol-level leader election.** A "primary" is whoever is driving the change; the role is not protocol-enforced, and any peer that holds enough endorsements can submit.
- **Single-submitter convention at submission time.** Once endorsements are collected, one designated submitter posts the `Evl`. Operators must not collect endorsements for two competing `Evl`s in parallel.

Multi-party governance guidance is generic across IEL identities (federation root, identity-hierarchy roots, any high-stakes IEL); see [../../operations/multi-party-governance.md](../../operations/multi-party-governance.md).

## Recovery

If the federation IEL goes contested (concurrent `Evl`s land, divergence is detected, the chain becomes contested-terminal), the federation under that prefix is dead. Recovery is a same-shape ceremony as the original bootstrap.

### Runbook

1. **Confirm contest.** Multiple nodes report the federation IEL as contested via the standard IEL contested-state surface. (Gossip will have propagated the divergent set; every node will see the same contest.)
2. **Convene currently-trusted operators.** Out-of-band coordination among the operators who collectively can incept a replacement. This is operator policy, not protocol-pinned — it's whoever the operator community trusts to satisfy the new IEL's `governance_policy`. In the most common case, this is the surviving honest members of the contested federation.
3. **Bootstrap a fresh federation IEL.** Same ceremony as initial bootstrap: choose a primary, collect Icp signatures from the participating operators, assemble the new Icp, distribute the new federation IEL to all founding nodes via `transfer_*_events`.
4. **Distribute the new prefix as runtime override.** Every gossip node sets `FEDERATION_IEL_PREFIX` to the new prefix and restarts. Each node logs a startup warning (runtime value differs from compile-time default); this is expected and acknowledged.
5. **Verify mesh comes up against new prefix.** Discovery flow on each node now reads the new federation IEL's `auth_policy`, walks the founding members' address SELs (unchanged — they're under the peers' own identities, not under the federation IEL), and reconnects.
6. **Schedule a binary rebuild.** At leisure, rebuild binaries with the compile-time default updated to the new prefix and roll the deployment. Once defaults align, `FEDERATION_IEL_PREFIX` can be unset.

### What survives recovery

- **Each peer's identity.** Peer identity IELs are independent of the federation IEL. No re-inception of peer identities is needed.
- **Each peer's address SEL.** Address SELs are bound to each peer's own identity, not to the federation. They continue working as-is.
- **Per-peer KEL state, HSM keys, gossip transport state.** All independent of the federation IEL.

What changes: the federation IEL prefix, the binaries' `auth_policy` lookup target, and (eventually) the compiled default. The application-level data on each node — KELs, IELs, SELs, anchoring, custody — is preserved.

### What does not survive

A contested federation IEL stays contested forever — that is the structural meaning of contested-terminal. The replacement federation IEL is a *different* identity under a different prefix; consumers that pinned the old prefix (e.g., long-running client deployments) must be updated. For internal infrastructure this is mechanical; for external clients it is the cost of the contest.

## References

- [primitives/iel/event-log.md](../primitives/iel/event-log.md) — IEL chain semantics, policy immunity, divergence, contest.
- [primitives/iel/events.md](../primitives/iel/events.md) — event kinds (`Icp`, `Evl`, `Sea`, `Cnt`, `Dec`).
- [protocol-doctrine.md §Federation Convergence](../protocol-doctrine.md#federation-convergence) — the cross-node convergence guarantee the federation relies on.
- [protocol-doctrine.md §Multi-Party Governance Synchronization](../protocol-doctrine.md#multi-party-governance-synchronization) — out-of-band serialization of IEL `Evl` submissions.
- [features/policy.md](../features/policy.md) — policy DSL (`threshold`, `identity`, `endorse`, immunity).
- [discovery.md](discovery.md) — node-side discovery (`auth_policy` enumeration + address SEL walks).
- [secure-registration.md](secure-registration.md) — HSM-backed gossip identity ceremony + handshake authorization against the federation IEL.
- [gossip.md](gossip.md) — gossip protocol mechanics (HyParView+PlumTree, PQ transport).
- [../../operations/multi-party-governance.md](../../operations/multi-party-governance.md) — operator playbook for serializing high-stakes governance submissions.
