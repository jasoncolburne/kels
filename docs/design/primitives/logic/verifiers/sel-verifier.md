# SelVerifier

**Canonical name:** `SelVerifier`

The SEL chain-walker. Streams events page by page in generations, tracks per-branch tip `ielEvent` for the per-event parent-monotonic check, and produces a `SelVerification` token. Resolves authorization via the bound IEL event using [`IelResolver`](../resolvers/iel-resolver.md). Enforces the inception-batch rule (`IncompleteInception` whenever any branch tip is still `Icp`).

**Consumers:** sadstore SEL submit handler; address-SEL discovery walks; credential issuance verification.

**Dependencies:** [`../../data/event-logs/sel/verification.md`](../../data/event-logs/sel/verification.md), [`../../data/event-logs/sel/event-log.md`](../../data/event-logs/sel/event-log.md), [`../resolvers/iel-resolver.md`](../resolvers/iel-resolver.md).

Stub. Detailed content lands iteratively.
