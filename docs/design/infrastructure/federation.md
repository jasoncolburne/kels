# Federation

A KELS federation is **itself an identity**. Membership lives on a single shared IEL — the *federation IEL* — and membership changes are governance-authorized `Evl` events on that chain. Discovery, authorization, and burn semantics all reduce to operations on that one identity.

This document explains the model and its load-bearing properties. For node-side discovery mechanics see [discovery.md](discovery.md); for the handshake-time authorization check see [peer-identity.md](peer-identity.md).

## Why federation reduces to identity

The federation answers three operational questions:

- *Who is allowed to participate in the gossip mesh?*
- *How does that set change over time?*
- *Where do I reach them on the network?*

Identity primitives already answer the first two:

- An IEL's `authPolicy` is the policy a chain event must satisfy to be authoritative at the moment of evaluation. Under the federation convention, `authPolicy` is shaped as `any(iel(X_1), …, iel(X_n))` — any single member identity may speak for the federation at handshake time. The set of `iel(...)` leaves *is* the membership set.
- An IEL's `governancePolicy` is the policy an `Evl` must satisfy to evolve `authPolicy` (or `governancePolicy` itself). Under the federation convention, `governancePolicy` is shaped as `threshold(M(n), iel(X_1), …, iel(X_n))` over the *same* member set, where M(n) is a stair function of federation size (see [§Threshold formula](#threshold-formula-application-level)). The membership-change protocol is exactly this threshold check.
- The IEL policy-immunity rule ([primitives/iel/event-log.md §Evaluation Seal and Anchor Non-Poisonability](../primitives/iel/event-log.md#evaluation-seal-and-anchor-non-poisonability)) guarantees past authorizations stay final — a former member's past endorsements cannot be retroactively repudiated.

The third question — network addresses — is answered by per-peer SELs, one per member identity, each peer publishing its own current endpoints under its own authority. Nothing federation-wide needs to track addresses centrally.

## Architecture at a glance

```
                 FEDERATION IEL  (prefix: F)
                 ──────────────
            governancePolicy: how membership evolves
                 authPolicy: { node_a, node_b, node_c, ... }
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
   peer SELs      peer SELs       peer SELs      (services + gossip, one
   (peer-owned)   (peer-owned)    (peer-owned)    pair per peer, under that
                                                  peer's identity)
```

- The **federation IEL** is a single IEL whose `authPolicy` enumerates member identities. On each node, the federation IEL is replicated into the local sadstore service; the supporting member KELs (used for anchor checks during verification) live in the local kels service. Both are gossip's sources of truth for federation state. Propagation uses the normal gossip mechanics: PlumTree announcement-driven primary path, dependency tracking for events whose parents haven't arrived yet, and anti-entropy as fallback for gaps.
- Each member identity is a **gossip-service identity** — a KEL holding the gossip service's HSM-backed signing key, wrapped in a single-KEL IEL (`authPolicy = kel(gossip_kel_prefix)`). "Peer" throughout this doc means a gossip-service instance.
- Each member publishes via **two per-peer SELs** — public `peer/services` (service base domain) and federation-gated `peer/gossip` (mesh `host:port`) — owned and signed by that member.

The mesh is symmetric: every peer holds the federation IEL, every peer's own identity is listed in the IEL's `authPolicy`, every peer manages its own per-peer SELs. No node has a special role.

## The federation IEL

### Same membership, different thresholds

The federation IEL follows a strict policy-shape convention:

```
authPolicy       = any(iel(X_1), …, iel(X_n))                     // = threshold(1, …)
governancePolicy = threshold(M(n),
                              iel(X_1), …, iel(X_n))
```

Same membership set in both. Different thresholds:

- **`authPolicy = any(...)`** — any single member can act for the federation. Used at every handshake. Low bar, high frequency.
- **`governancePolicy = threshold(M, ...)`** — M of n members must endorse changes to `authPolicy` (or `governancePolicy` itself). High bar, low frequency.

The two policies share the same member set and differ only in threshold shape. This is the property a consumer can structurally verify (see [§Federation policy shape verification](#federation-policy-shape-verification) below).

### The `iel(...)` leaf

`iel(X)` is a DSL leaf that is satisfied when an event is anchored under the current `authPolicy` of IEL `X`. It resolves through the IEL prefix at evaluation time, so member identities can evolve their internal `authPolicy` (e.g., rotating gossip-service keys) without invalidating the federation `authPolicy` that references them.

`iel(X)` is distinct from `kel(KEL_PREFIX)`, which checks a direct KEL `Ixn` anchor. Federation member references go through `iel(...)` because a member is an *identity* (an IEL prefix), not a single KEL.

### Membership is the policy

There is **no denormalized member list**. Enumeration of the current membership walks the `iel(...)` leaves of the current `authPolicy`. Anything that wants to know "who's currently a member" reads the policy and extracts the leaves.

### Immunity is mandatory

The IEL policy-immunity rule requires every policy referenced as `authPolicy` or `governancePolicy` to have `immune: true`. The federation IEL is no exception. Two consequences:

- **No poisoning of past authorizations.** A peer whose endorsements appeared on past federation `Evl`s cannot retroactively repudiate them, even after the peer is removed.
- **Revocation happens by evolution, not by poison.** To drop a member, evolve `authPolicy` to a new SAID that excludes them. The dropped member's past endorsements remain final; new endorsements from them are simply not counted against the new policy.

## Gossip-service identity

Each node runs a gossip service. That service is a **degenerate single-KEL identity**:

- One KEL holds the gossip service's signing key (HSM-backed; ML-DSA-65 or ML-DSA-87).
- One IEL declares `authPolicy = kel(gossip_kel_prefix)` and a `governancePolicy` of the operator's choosing.
- The IEL prefix is the **peer identity** referenced from the federation IEL's `authPolicy`.

The gossip service is the only service on a node that participates in federation authentication. Other services on the same node (`sadstore`, `mail`, the `kels` service, identity service) are workers; they don't carry federation identities and don't authenticate with peers themselves. When this doc says "peer," it means a gossip-service instance — not a host, not a deployment, not an operator.

The HSM ceremony is documented in [peer-identity.md](peer-identity.md).

## Per-peer publication

Per-peer publication is **per-peer, self-managed**, using SEL chains bound to each peer's identity. The federation IEL holds *who is authorized*; the per-peer SELs hold *where to reach them*.

A peer publishes **two SEL chains**, separated by custody asymmetry: public service endpoints belong on a public chain, federation-private gossip endpoints belong on a federation-gated chain. Mixing the two on one SAD would force either over-disclosure (gossip endpoints leak publicly) or under-disclosure (service endpoints become federation-only). Two chains separate the audiences cleanly:

- `kels/sel/v1/peer/services` — **public**. SAD body `{ said, domain }`. No `readPolicy`. End-user clients and federation members both read this chain.
- `kels/sel/v1/peer/gossip` — **federation-gated**. SAD body `{ said, readPolicy, address }`. `readPolicy` SAID resolves to `iel(FEDERATION_IEL_PREFIX)`, so only currently-authorized federation members can fetch the body.

Both chains are bound to the peer's own identity; the peer authors and rotates both under its own authority. The federation IEL's `authPolicy` stays the sole authoritative source for membership — the per-peer chains are address-resolution mechanisms for an already-authorized peer, not additional authorization mechanisms.

### Why two chains

- Each peer can update its own endpoints (IP rotation, scale events, region migration) without federation-wide governance approval. Auth on each `Upd` is the peer's own `authPolicy`.
- Cross-peer auth concerns disappear: peer A cannot publish endpoints for peer B because each chain is bound to the publishing peer's identity.
- Custody asymmetry maps to topic structure, not to fields on a single SAD — the SAD store can apply a single chain-wide read policy without splitting bodies by field sensitivity.
- End-user clients (e.g. mobile or browser KELS consumers) walk only the public `peer/services` chain; they don't need to fetch — and aren't authorized to fetch — `peer/gossip`.

### Deterministic SEL prefixes

Each chain prefix is fully deterministic:

```
peer/services prefix = compute_sel_prefix(peer_identity_prefix, "kels/sel/v1/peer/services")
peer/gossip   prefix = compute_sel_prefix(peer_identity_prefix, "kels/sel/v1/peer/gossip")
```

Given the peer's identity prefix (which the federation IEL's `authPolicy` lists), any node can compute either prefix and fetch the chain — no directory service.

### `peer/services` SAD — public service domain

The `content` field of each `Upd` on the `peer/services` SEL is the SAID of a SAD with shape:

```
{
  "said": "K...",
  "domain": "node-a.example.net"
}
```

Service URLs are derived by the **subdomain convention**:

```
http://kels.{domain}      — KELS service
http://sadstore.{domain}  — SAD store service
http://mail.{domain}      — Mail service (if deployed)
```

The protocol is `http://` per the convention; deployments running behind TLS terminate at a reverse proxy and present the same subdomain shape. The convention is structural — readers of `peer/services` apply it directly without further indirection. No `path` overrides, no protocol negotiation; a future service extension introduces a new subdomain rather than altering the SAD shape.

`peer/services` chains and SADs are public: no `readPolicy`, the SAD body is fetchable by anyone. The chain itself (`Icp` / `Upd` / `Sea`) was already public per `sadstore.md` (custody is forbidden on chain events).

### `peer/gossip` SAD — federation-gated mesh endpoint

The `content` field of each `Upd` on the `peer/gossip` SEL is the SAID of a SAD with shape:

```
{
  "said": "K...",
  "readPolicy": "K...",
  "address": "203.0.113.4:4001"
}
```

- `address` is a TCP gossip endpoint, `host:port` (IPv4, bracketed IPv6, or hostname). Gossip carries its own transport (ML-KEM-1024 key exchange, ML-DSA-65/87 signatures, AES-GCM-256 sessions); the published address is the network endpoint only.
- `readPolicy` is the SAID of a policy SAD with expression `iel(FEDERATION_IEL_PREFIX)`. Per [sadstore.md §Custody](sadstore.md#custody-per-sad-object-authority), this gates fetch-time access via `evaluate_signed_policy` against a `SignedRequest`'s verified prefix set — `iel(FED_IEL)` resolves to the federation IEL's current `authPolicy`, so only currently-authorized federation members can fetch the body. The SEL chain itself (`Icp`, `Upd`, `Sea`) still gossips publicly; only the per-object SAD content is gated. External observers can verify the chain shape and the federation IEL but cannot enumerate gossip endpoints.
- **One address per SAD.** Rotation is the mechanism for changing endpoints — a peer publishes a fresh SAD whose `Upd` references the new address. Multi-homing within a single SAD would couple unrelated dimensions (which endpoint is current? which has higher priority?) onto an unordered field; chain rotation keeps a single linear "current address" and a chain-walkable history.
- **No `role` field, by design.** Role-bearing self-declarations would let an identity holder elevate their own privileges without going through the federation `governancePolicy`. Capabilities are determined by what the federation IEL authorizes the peer to do; a peer cannot self-declare additional capabilities.

### Common chain shape

Both chains follow `[Icp, Upd, Sea]` at inception and `[Upd, Sea]` at rotation, per the Sea-after-Upd ratchet (see [protocol-doctrine.md §Sea-after-Upd ratchet](../protocol-doctrine.md#sea-after-upd-ratchet-application-pattern)). Conforming tooling never produces an Upd-tailed chain on either topic. The current published value is whatever the latest accepted `Upd` on the chain says, sealed by its trailing `Sea`.

## Discovery flow

When a node joins or refreshes its peer view:

1. Read the federation IEL's current `authPolicy` to enumerate authorized member identities.
2. For each member identity, compute the two SEL prefixes (`compute_sel_prefix(peer_identity, "kels/sel/v1/peer/services")` and `compute_sel_prefix(peer_identity, "kels/sel/v1/peer/gossip")`).
3. Walk each SEL to its tip and read the tip `Upd`'s content SAID. Fetch the SAD body; apply the subdomain convention to the `peer/services` SAD's `domain` to derive service URLs.
4. Connect.

End-user clients (non-federation consumers) walk only the public `peer/services` chain — they need service URLs but not gossip mesh endpoints, and the `peer/gossip` `readPolicy` would reject their unauthorized fetch anyway. Federation members walk both.

The federation IEL is replicated to the sadstore on every gossip node, so step 1 is a local-service read (gossip → sadstore over HTTP, same-node). The per-peer SELs are also in the sadstore; step 3 is a normal SEL read against the same local service. Chain verification (IEL/SEL anchor checks) additionally reads the supporting member KELs from the local kels service — also same-node HTTP.

This steady-state flow assumes the node already holds the federation IEL and every member's per-peer SELs. Initial state arrives during the federation ceremony (or during a peer onboarding) via `transfer_*_events` — see [§Bootstrap](#bootstrap-one-time-ceremony) below. There is no runtime-config-driven cold-start discovery surface; if a node has no state at all, it isn't yet a federation participant.

## Handshake authorization

When a connecting peer initiates a gossip handshake:

1. The connecting peer presents its identity prefix and a signature over the handshake transcript with its gossip signing key.
2. The accepting peer evaluates the connecting peer's identity against the current federation IEL `authPolicy` via `evaluate_signed_policy`.
3. If the policy is satisfied (i.e., the connecting identity is currently authorized), the handshake proceeds. Otherwise it's rejected.

For the cryptographic handshake (prefix exchange, ML-KEM-1024 KEM, mutual ML-DSA signature, BLAKE3-derived AES-GCM-256 session key), see [gossip.md §HSM-backed gossip identity](gossip.md#hsm-backed-gossip-identity).

## Membership evolution

Adding or removing a member is the same primitive in both directions: an `Evl` event on the federation IEL evolving `authPolicy`, satisfying the current `governancePolicy`.

### Symmetric add/remove

There is no asymmetry between add and remove. Both use `Evl` against `governancePolicy`. The procedural difference is operational, not structural:

- **Adding peer X:** M(n) of the current n members endorse an `Evl` that includes `iel(X)` in the new `authPolicy` and updates `governancePolicy`'s threshold value if n crossed a stair boundary. X itself does not need to endorse.
- **Removing peer X:** M(n−1) of the *other* `n − 1` members endorse an `Evl` that excludes `iel(X)` from both `authPolicy` and `governancePolicy` (and updates the threshold value if `n − 1` crossed a stair boundary). X itself, predictably, does not endorse its own removal.

Whether the burn is a clean drop ("X retired, please remove") or an adversarial expulsion ("X compromised, drop now") is the same chain operation; only the operator urgency differs.

### No withdrawal, no poison

The federation `authPolicy` and `governancePolicy` are `immune: true` (mandatory under the IEL policy-immunity rule). There is no withdrawal primitive and no poison-based revocation on the federation IEL. **All revocation goes through `Evl`.** This is not an inconvenience; it is the structural guarantee that past authorizations stay final — every endorsement a peer made while a member remains valid forever, by construction.

### Threshold formula (application-level)

The threshold value in the federation's `governancePolicy` is a stair function of the federation size n. The `authPolicy` stays at `any(...)` regardless of n — any single member can act at handshake time. The governance threshold is what scales with federation size.

```
governance threshold M(n) =
  3            if n ≤ 5
  4            if 6 ≤ n ≤ 9
  ⌈n / 3⌉      if n ≥ 10
```

| n | M(n) |
|---|---|
| 3 | 3 |
| 5 | 3 |
| 6 | 4 |
| 9 | 4 |
| 10 | 4 |
| 21 | 7 |
| 25 | 9 |

- Floor of 3 prevents trivial collusion in small federations.
- The 6-member step bumps the bar to 4 before one-third scaling takes over.
- One-third-quorum scaling at larger sizes is KERI-inspired (`F+1` immunity bound, where `F` is the max number of byzantine members the threshold tolerates — the policy is satisfied as long as `n − F` honest members remain).
- When n crosses a stair boundary (5 → 6 or 9 → 10), the same `Evl` that adds the new peer also evolves `governancePolicy` to encode the new threshold value. Both changes batch into one event.

**The IEL verifier does not enforce the formula.** A federation that chose a different M(n) would still produce structurally valid IEL chains; the verifier checks only chain-validity invariants (immunity, signatures, `governancePolicy` satisfaction). The formula lives in the node/gossip application layer and the libkels federation-policy-shape helper (next subsection) — operator convention, not protocol surface. A federation operator who needs a different threshold can configure one without forking the protocol, at the cost of consumers no longer being able to verify the standard shape.

### Federation policy shape verification

libkels provides a helper that verifies a federation IEL's `(authPolicy, governancePolicy)` pair conforms to the convention. The helper:

- Walks `authPolicy`; confirms it's `any(...)` (i.e., `threshold(1, ...)`) over `iel(...)` leaves only; extracts the member set.
- Walks `governancePolicy`; confirms it's `threshold(M, ...)` over `iel(...)` leaves only; extracts the member set and M.
- Confirms set equality between the two member sets.
- Confirms `M == M(n)` where `n = |members|` (per the stair function defined above).
- Confirms both policies have `immune: true`.

Application code calls this helper on every federation IEL it loads (compile-time default at startup; runtime override on env-var set). A federation that doesn't conform fails the check and the node refuses to start.

Consumer-side: anyone evaluating a federation's trust posture runs the same helper and additionally verifies that the identities they care about appear in the member set. The structural conformance check + member-set inspection is the full "should I trust this federation?" workflow — no need to reason about arbitrary policy shapes.

The general policy DSL stays unconstrained — other IELs (user identities, organizational identities, etc.) use whatever shape they need. Only the federation IEL is structurally restricted to this convention.

### Multi-peer simultaneous compromise

If `n − M` or more member identities are compromised at once, normal governance cannot evolve — the honest members cannot reach the threshold. Recovery is the contested-federation procedure (see [§Recovery](#recovery) below). This is the operationally catastrophic case; the threshold formula is sized so that blocking governance requires compromising a non-trivial fraction of the federation, which raises the operational hardness of mounting the attack — but it is operational hardness, not protocol-level prevention.

## Bootstrap (one-time ceremony)

A new federation is born via a single Icp event on a fresh federation IEL. The ceremony is point-to-point HTTP between founding nodes — the gossip mesh doesn't exist yet, and the `authPolicy`/`governancePolicy` shape that would gate gossip is exactly what the ceremony is producing.

### Roles and procedure

The ceremony has two roles and four logical phases. Concrete CLI mechanics — which commands run where, in what order — live in [discovery.md §Bootstrapping the federation](discovery.md#bootstrapping-the-federation). This subsection gives the design-level overview.

- **Coordinator** — one founding peer is designated coordinator for the ceremony. Coordinator is an operational role (one-shot, ceremony-scoped), not a protocol role.
- **Founding members** — each holds a prepared founding identity (KEL + IEL) and participates in producing the federation IEL `Icp` event.

Logical phases:

1. **Anchor.** Each founding member anchors the proposed federation IEL `Icp` SAID in its own KEL via a tier-2 `Rot`. This is the cryptographic act that constitutes the member's endorsement of the `Icp`.
2. **Gather.** Each founding member pushes its identity bundle (KEL + IEL + per-peer SELs) to the coordinator's local kels/sadstore services so the coordinator can verify the `Icp`'s anchor checks.
3. **Submit.** The coordinator submits the `Icp` to its own kels/sadstore; the anchor checks succeed because the contributing KELs are now present locally.
4. **Redistribute.** The coordinator pushes the accepted federation IEL plus every founding member's per-peer SEL bundle to every other founding node, after which gossip mesh formation proceeds normally — PlumTree announcements drive primary propagation, dependency tracking handles out-of-order arrivals, anti-entropy fills any remaining gaps.

The Icp's `authPolicy` and `governancePolicy` are agreed out-of-band by the founding operators. There is no protocol-level "voting" on the Icp — the chain begins with whatever shape its founders cryptographically commit to, and consumers of the federation accept that shape on the strength of the founders' identities.

### Why not gossip for the redistribution

The natural question is whether the federation IEL itself could be redistributed via gossip rather than via `transfer_*_events`. It can't, by chicken-and-egg: gossip handshake authorization depends on the federation IEL's `authPolicy`, but the federation IEL doesn't exist on the non-coordinator nodes yet. The only authorization context the non-coordinator nodes have at this point is what their compile-time-default (or runtime-override) federation IEL prefix tells them to *expect* — they don't have the chain to evaluate handshakes against. Point-to-point HTTP via `transfer_*_events`, parameterized with the coordinator's address, is the bootstrap channel; gossip takes over once every node has the federation IEL locally and `IelVerifier` has accepted it under the expected prefix.

The same chicken-and-egg applies to peer onboarding (adding a new member post-bootstrap) and to single-node disaster recovery — both cases use `transfer_*_events` from an existing peer, coordinated out-of-band, until the recovering/joining node has enough chain state to participate in the mesh.

## Configuration

Each node needs to know which federation IEL is its federation. The prefix is configured in two layers:

- **Compile-time default**: a federation IEL prefix is baked into the binary at build. This is the federation-as-shipped — the prefix the binary was tested and audited against.
- **Runtime override** (`FEDERATION_IEL_PREFIX`): optional env var. When set, the binary uses the env var as authoritative. If it differs from the compile-time default, the binary logs a startup warning so operators are aware the deployment has been redirected.

The runtime override exists for recovery: operators can repoint a federation to a fresh IEL prefix on existing binaries when the federation IEL becomes contested, then align the compile-time default at the next release.

HSM and gossip identity config: see [gossip.md](gossip.md) and [peer-identity.md](peer-identity.md).

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
2. **Convene currently-trusted operators.** Out-of-band coordination among the operators who collectively can incept a replacement. This is operator policy, not protocol-pinned — it's whoever the operator community trusts to satisfy the new IEL's `governancePolicy`. In the most common case, this is the surviving honest members of the contested federation.
3. **Bootstrap a fresh federation IEL.** Same ceremony as initial bootstrap: choose a primary, collect Icp signatures from the participating operators, assemble the new Icp, distribute the new federation IEL to all founding nodes via `transfer_*_events`.
4. **Distribute the new prefix as runtime override.** Every gossip node sets `FEDERATION_IEL_PREFIX` to the new prefix and restarts. Each node logs a startup warning (runtime value differs from compile-time default); this is expected and acknowledged.
5. **Verify mesh comes up against new prefix.** Discovery flow on each node now reads the new federation IEL's `authPolicy`, walks the founding members' per-peer SELs (unchanged — they're under the peers' own identities, not under the federation IEL), and reconnects.
6. **Each peer publishes a fresh `peer/gossip` `[Upd, Sea]`** whose SAD `readPolicy` references the *new* federation IEL prefix. Existing `peer/gossip` SADs reference a `readPolicy` SAD naming the old (now contested-terminal) federation IEL; `iel(OLD_FED_IEL)` resolves to a dead policy, so the old SAD bodies become unreadable to anyone post-recovery. The `peer/gossip` SEL chain itself continues unchanged (per §What survives recovery); only the SAD content needs republication. The `peer/services` chain is unaffected — it has no `readPolicy` and remains publicly fetchable across the recovery boundary. Until each peer's `peer/gossip` republish lands, that peer's gossip endpoint is not fetchable by other federation members.
7. **Schedule a binary rebuild.** At leisure, rebuild binaries with the compile-time default updated to the new prefix and roll the deployment. Once defaults align, `FEDERATION_IEL_PREFIX` can be unset.

### What survives recovery

- **Each peer's identity.** Peer identity IELs are independent of the federation IEL. No re-inception of peer identities is needed.
- **Each peer's per-peer SELs.** Both `peer/services` and `peer/gossip` chains are bound to each peer's own identity, not to the federation. They continue working as-is (`peer/gossip` SAD bodies need a one-time republish under the new `readPolicy` per step 6 above; the chains themselves don't reincept).
- **Per-peer KEL state, HSM keys, gossip transport state.** All independent of the federation IEL.

What changes: the federation IEL prefix, the binaries' `authPolicy` lookup target, and (eventually) the compiled default. The application-level data on each node — KELs, IELs, SELs, anchoring, custody — is preserved.

### What does not survive

A contested federation IEL stays contested forever — that is the structural meaning of contested-terminal. The replacement federation IEL is a *different* identity under a different prefix; consumers that pinned the old prefix (e.g., long-running client deployments) must be updated. For internal infrastructure this is mechanical; for external clients it is the cost of the contest.

## References

- [primitives/iel/event-log.md](../primitives/iel/event-log.md) — IEL chain semantics, policy immunity, divergence, contest.
- [primitives/iel/events.md](../primitives/iel/events.md) — event kinds (`Icp`, `Evl`, `Sea`, `Cnt`, `Dec`).
- [protocol-doctrine.md §Federation Convergence](../protocol-doctrine.md#federation-convergence) — the cross-node convergence guarantee the federation relies on.
- [primitives/iel/event-log.md §Multi-Party Governance Synchronization](../primitives/iel/event-log.md#multi-party-governance-synchronization) — out-of-band serialization of IEL `Evl` submissions.
- [features/policy.md](../features/policy.md) — policy DSL (`threshold`, `identity`, `endorse`, immunity).
- [discovery.md](discovery.md) — node-side discovery (`authPolicy` enumeration + per-peer SEL walks).
- [peer-identity.md](peer-identity.md) — HSM-backed gossip identity ceremony + handshake authorization against the federation IEL.
- [gossip.md](gossip.md) — gossip protocol mechanics (HyParView+PlumTree, PQ transport).
- [../../operations/multi-party-governance.md](../../operations/multi-party-governance.md) — operator playbook for serializing high-stakes governance submissions.
