# Application-Developer Enrollment Patterns

How applications should structure user enrollment to defuse the brand-new SEL chain race described in [../design/primitives/iel/event-log.md §What parent-monotonic blocks (and what it doesn't)](../design/primitives/iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt).

## The race

Before any legitimate v1+ event lands on a user's SEL, a party with `auth_policy` authority on the bound IEL can submit `[Icp, Est_stale]` first, establishing the chain with their content at v1. The legitimate operator's enrollment-time response is to submit `[Icp, Est_legit]` — Icp dedups (same content, same SAID across submitters), and `Est_legit` lands at v=1 with parent = Icp.said, creating a non-privileged divergent set with `Est_stale` (Est-Est race shape). The operator then submits `Rpr` (governance-authorized via the bound IEL's current `governance_policy`) extending their `Est_legit` branch; `Rpr` archives `Est_stale` and the chain becomes the operator's.

`Rpr` resolves the divergence cleanly because `governance_policy` is structurally a higher bar than `auth_policy` — the operator's current governance authority outranks any auth-only competing submission.

## Operational pattern

The race is bounded by the user's enrollment window: until enrollment completes, the user is treated as inactive in the system, and no consumers honor authorizations rooted in their in-progress chains. Application developers must structure enrollment to take advantage of this:

- **Register all required well-known SEL topics atomically.** Submit one batch per topic, with all topics together within the enrollment flow; do not partially-enroll a user.
- **For each topic, detect and resolve prior chain content.** If the chain at the derived prefix already exists with content the operator didn't author, enrollment submits `Rpr` extending the operator's legitimate `Est`. `Rpr` archives the competing branch.
- **Treat the user as inactive until enrollment completes** (including any `Rpr` cleanup). During the inactive enrollment window, no consumers honor authorizations rooted in the in-progress chains; the user's chains gain trust grounding only after enrollment finishes.

This pattern eliminates the brand-new chain race as an authorization-bearing concern: a competing party's race-won v1 has no consumers honoring it during the inactive window, and `Rpr` archives it before the user becomes active.

## See also

- [../design/primitives/iel/event-log.md §What parent-monotonic blocks](../design/primitives/iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt) — the protocol-mechanics analysis this pattern operationally defuses.
- [../design/primitives/sel/events.md §Inception batch rule](../design/primitives/sel/events.md#inception-batch-rule) — the `[Icp, Est]` minimum that makes the race well-defined.
- [multi-party-governance](../operations/multi-party-governance.md) — operator-side synchronization for high-stakes IEL identities.
