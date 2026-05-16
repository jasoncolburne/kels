# Multi-Party Governance Synchronization

How operators of IEL chains with multi-party governance prevent accidental divergence from concurrent submissions.

## The race

For IEL chains with multi-party governance — an `auth_policy` or `governance_policy` that multiple parties can satisfy — races between concurrent submissions create divergence even when all parties are legitimately authorized. Two operators independently signing and submitting `Evl` events without coordination produces two events at the same serial: divergence on IEL → contested-terminal immediately (every IEL event is privileged, so any divergent set on IEL fires the privileged-divergence rule — see [../design/protocol-doctrine.md §Privileged Divergence is Terminal](../design/protocol-doctrine.md#privileged-divergence-is-terminal-cnt-triggers-it-uniformly)).

## Why this is load-bearing for high-stakes identities

Synchronization above the protocol is required, not optional, for:

- A federation's root identity that issues credentials to many nodes.
- An identity hierarchy's root.
- Any identity whose reincept would cascade through many dependent chains.

For these cases, accidental divergence kills the identity and forces operational reincept. Without synchronization, any race takes the identity offline.

## Synchronization mechanisms

Mitigation is a mechanism that serializes governance submissions so two parties don't reach the chain concurrently. Concrete options:

- **Designated submitter.** One party assembles signatures from the other governance parties offline, then submits the assembled event. Other parties don't submit directly.
- **Leader election among governance parties.** A primary submitter is designated; leadership transfers via out-of-band coordination when needed.
- **Sequential signing rounds.** Parties sign in turn; the final signer submits.
- **Consensus protocol (e.g., Raft) over the registry.** The KELS reference federation deployment uses the Raft registry for this purpose. The registry's commit log serializes governance submissions to the federation's identity chain, so two operators committing concurrently are serialized by Raft before reaching the chain. See [../design/infrastructure/registry.md](../design/infrastructure/registry.md).

The choice of synchronization mechanism is operational, not protocol-level — the IEL's protocol rules apply uniformly regardless of how submissions are serialized.

## What synchronization does and does not defend

Synchronization protects against **accidental** races, not against **compromise**. A second governance-authorized party who acquired authority via threshold compromise can author submissions regardless of any synchronization mechanism — that threat is the same with or without synchronization.

Defense against threshold compromise is a separate concern, addressed via operational hardening: high thresholds, geographic and organizational distribution of operators, custody discipline, monitoring for unexpected governance activity. **Threshold redundancy** is the operator's per-anchor recovery option for partial compromise: an anchored policy with `M > N` identities tolerates loss of `M − N` while remaining satisfiable, and a new anchor using a different threshold-satisfying subset re-establishes authorization without changing the policy itself (see [../design/features/policy.md §Threshold Redundancy](../design/features/policy.md#threshold-redundancy)).

## See also

- [../design/primitives/iel/event-log.md §Divergence and Contest-Only Resolution](../design/primitives/iel/event-log.md#divergence-and-contest-only-resolution) — the protocol mechanics that make multi-party-governance races terminal.
- [../design/infrastructure/registry.md](../design/infrastructure/registry.md) — the Raft registry architecture used as a serialization mechanism in the reference deployment.
- [enrollment](../development/enrollment.md) — application-developer side of the brand-new chain race.
