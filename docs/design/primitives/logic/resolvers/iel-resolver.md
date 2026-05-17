# IelResolver

**Canonical name:** `IelResolver`

The trait that resolves an IEL event SAID to its tracked governance / auth context plus IEL chain-order positions used by the SEL per-event parent-monotonic ratchet. Landed in #194 as the trait + `UnavailableIelResolver` stub; concrete implementations are wired by callers that hold IEL state (sadstore, gossip).

**Consumers:** [`SelVerifier`](../verifiers/sel-verifier.md) (authorization resolution + parent-monotonic), [`AnchoredPolicyChecker`](../verifiers/anchored-policy-checker.md) for IEL-bound policy lookups.

**Dependencies:** [`../verifiers/iel-verifier.md`](../verifiers/iel-verifier.md), [`../../data/event-logs/iel/event-log.md`](../../data/event-logs/iel/event-log.md).

Stub. Detailed content lands iteratively.
