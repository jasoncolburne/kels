# Policy Evaluator

**Canonical name:** the policy evaluator.

Evaluation semantics for the kels-policy DSL: cycle guards (nested-policy resolution can't loop), per-evaluation cache, the trust model, and loud-fail behavior (an unresolvable subtree fails the whole policy rather than silently degrading).

**Consumers:** [`AnchoredPolicyChecker`](../verifiers/anchored-policy-checker.md) and any caller composing policy decisions outside an IEL/SEL verifier walk.

**Dependencies:** [`policy-dsl.md`](policy-dsl.md). Cross-reference: [`../../../features/policy.md`](../../../features/policy.md).

Stub. Detailed content lands iteratively. Per `feedback_no_security_fallback.md`: never silently downgrade a policy decision; loud-fail is the only acceptable mode.
