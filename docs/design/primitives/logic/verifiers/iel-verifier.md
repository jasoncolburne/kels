# IelVerifier

**Canonical name:** `IelVerifier`

The IEL chain-walker. Streams events page by page in generations, tracks per-branch `governancePolicy` / `authPolicy` state and the seal, and produces an `IelVerification` token. Resolves policy satisfaction via an [`AnchoredPolicyChecker`](anchored-policy-checker.md) against the bound KEL anchors. Caller-bounded SAID querying via `queried_saids` mirrors KEL's inline anchor checking.

**Consumers:** sadstore IEL submit handler; SEL authorization resolution (via [`IelResolver`](../resolvers/iel-resolver.md)); federation gossip.

**Dependencies:** [`../../data/event-logs/iel/verification.md`](../../data/event-logs/iel/verification.md), [`../../data/event-logs/iel/event-log.md`](../../data/event-logs/iel/event-log.md), [`anchored-policy-checker.md`](anchored-policy-checker.md).

Stub. Detailed content lands iteratively.
