# AddressResolver

**Canonical name:** `AddressResolver`

Resolves a peer identity to its current network endpoints by walking that peer's per-peer address SEL at the deterministic prefix `compute_sel_prefix(peer_identity, "kels/sel/v1/peer/addresses")`. Lands in #195.

**Consumers:** gossip discovery (federation IEL `authPolicy` enumeration + per-peer address SEL walks); CLI peer-introspection.

**Dependencies:** [`../verifiers/sel-verifier.md`](../verifiers/sel-verifier.md), [`../../data/event-logs/sel/event-log.md`](../../data/event-logs/sel/event-log.md), [`../../../infrastructure/discovery.md`](../../../infrastructure/discovery.md).

Stub. Detailed content lands iteratively.
