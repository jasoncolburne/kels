# AnchoredPolicyChecker

**Canonical name:** `AnchoredPolicyChecker`

Evaluates whether an IEL/SEL event's SAID is anchored under a given policy via KEL `Ixn` / `Rot` / `Ror` references that satisfy the tier required by the event's operation class (see [protocol-doctrine.md §Anchor Tier Elevation](../../../protocol-doctrine.md#anchor-tier-elevation)). Consumed by [`IelVerifier`](iel-verifier.md), [`SelVerifier`](sel-verifier.md), and any caller that resolves policy satisfaction.

**Consumers:** IEL/SEL verifiers; policy-resolution paths in the credentials and exchange features.

**Dependencies:** the policy DSL ([`../policies/policy-dsl.md`](../policies/policy-dsl.md)), the policy evaluator ([`../policies/policy-evaluator.md`](../policies/policy-evaluator.md)), and the KEL verifier ([`kel-verifier.md`](kel-verifier.md)) for the underlying anchor checks.

Stub. Detailed content lands iteratively.
