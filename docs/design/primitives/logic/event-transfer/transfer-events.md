# Transfer Events (`transfer_*_events` family)

**Canonical names:** `transfer_*_events`, `forward_*_events`, `verify_*_events`.

The point-to-point event-transfer family for moving KEL / IEL / SEL events between services (bootstrap, peer onboarding, disaster recovery). Every transfer pairs a `source` (paginated-fetch role) with a `sink` (accept-events role); the verifier consumes pages incrementally and produces the primitive's `Verification` token, so transferred data is end-verified inline rather than trusted from the source.

`source` and `sink` are **roles** scoped to this pattern — parameter-shape contracts, not standalone primitives with their own files.

**Consumers:** every cross-process event movement — gossip catch-up, identity-service KEL hand-off, disaster recovery, bootstrap.

**Dependencies:** the per-primitive verifiers ([`../verifiers/kel-verifier.md`](../verifiers/kel-verifier.md), [`../verifiers/iel-verifier.md`](../verifiers/iel-verifier.md), [`../verifiers/sel-verifier.md`](../verifiers/sel-verifier.md)); the data-layer event-log docs ([`../../data/event-logs/`](../../data/event-logs/)).

Stub. Detailed content lands iteratively. Per `project_kels_transfer_abstractions.md`: any cross-process event-data movement uses this family; never reach for manual pagination loops.
