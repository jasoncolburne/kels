# PolicyResolver

**Canonical name:** `PolicyResolver`

Resolves a policy reference (by SAID or by IEL `ielEvent` binding) to its concrete DSL tree for evaluation. Bridges policy lookups across the IEL chain (via [`IelResolver`](iel-resolver.md)) and any local policy registries.

**Consumers:** [`AnchoredPolicyChecker`](../verifiers/anchored-policy-checker.md); credential issuance / verification; exchange-message auth.

**Dependencies:** [`../policies/policy-dsl.md`](../policies/policy-dsl.md), [`iel-resolver.md`](iel-resolver.md).

Stub. Detailed content lands iteratively.

(Placement note per #202 Open Questions: PolicyResolver lives under `resolvers/` rather than `policies/` because policy DSL + evaluator share scope under `policies/`; this resolver bridges IEL-event lookups to that DSL surface and reads more naturally as a chain-resolution role.)
