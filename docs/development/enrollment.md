# Application-Developer Enrollment Patterns

How applications should structure user enrollment so the brand-new SEL chain race described in [../design/primitives/data/event-logs/iel/event-log.md §Brand-new chain races](../design/primitives/data/event-logs/iel/event-log.md#brand-new-chain-races-contested-terminal--mutual-destruction-at-v1) doesn't disrupt a live user.

## The race

Before any legitimate v1+ event lands on a user's SEL, a party with `auth_policy` authority on the bound IEL — or any party able to compute the predictable `(identity, topic)` prefix — can submit `[Icp, Est_camper]` first, establishing the chain with their content at v=1. The legitimate operator's enrollment-time response is to submit `[Icp, Est_operator]` extending `Icp` via dedup-equivalence (never extending `Est_camper`).

`Est` is privileged at tier 2. The resulting 2-event privileged divergent set at v=1 is contested-terminal: privileged-divergence-is-terminal fires at first observation, and the chain becomes Contested. No `Rpr` resolution path exists at this prefix. Operator recourse is reincept under a new `(identity, topic)` tuple.

The structural property the protocol gives you: race-incept is mutually destructive. The camper pays tier-2 anchor cost (per contributing policy member) to deny the operator a tuple they can both abandon. The application's job is to make sure mutual destruction at an unannounced prefix doesn't disrupt a live user.

## Operational pattern

Until enrollment completes, the user is treated as inactive in the system, and no consumers honor authorizations rooted in their in-progress chains. Application developers structure enrollment to take advantage of this:

- **Don't publicize a user's `(identity, topic)` tuples before submission.** The race surface is targeting-driven — adversaries pay the tier-2 cost only against valuable, predictable tuples. Keep new tuples unobservable until the operator's `[Icp, Est_operator]` lands.
- **Register all required well-known SEL topics atomically within the enrollment flow.** Submit each topic's `[Icp, Est_operator]` batch within the enrollment window; do not partially-enroll a user.
- **Detect contested-terminal outcomes per topic.** If a `(identity, topic)` lands contested-terminal (race lost), the enrollment retries under a different `(identity, topic)` — typically a different `identity` (fresh IEL prefix) since `topic` is application-determined.
- **Treat the user as inactive until enrollment completes.** No consumers honor authorizations rooted in the in-progress chains; the user's chains gain trust grounding only after enrollment finishes successfully.
- **Keep PII out of public SAD content.** SAD content is replicated through gossip and is structurally readable by anyone with read access. For private messaging, use [exchange](../design/features/exchange.md) (ESSR envelopes — end-to-end encrypted). For SADs that need restricted access, use SAD custody (access controls on the SAD body). Reducing the identifying attributes exposed in public chains bounds the adversary's ability to single out a user as a valuable camping target.

This pattern keeps the brand-new chain race from disrupting live users: any race lost during enrollment is invisible (no consumers honored anything yet), and reincept under a new tuple is the standard enrollment retry.

## See also

- [../design/primitives/data/event-logs/iel/event-log.md §What parent-monotonic blocks](../design/primitives/data/event-logs/iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt) — the protocol-mechanics analysis this pattern operationally defuses.
- [../design/primitives/data/event-logs/sel/events.md §Inception batch rule](../design/primitives/data/event-logs/sel/events.md#inception-batch-rule) — the `[Icp, Est]` minimum that makes the race well-defined.
- [multi-party-governance](../operations/multi-party-governance.md) — operator-side synchronization for high-stakes IEL identities.
