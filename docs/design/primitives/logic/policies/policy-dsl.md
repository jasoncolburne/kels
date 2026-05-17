# Policy DSL

**Canonical name:** the kels-policy DSL.

The composable trust-policy language: parser, AST, and leaf / composition nodes. Leaves: `endorse`, `delegate`, `identity`. Composers: `any` / `all` / `threshold` / `weighted` / nested `policy`. Per-policy modes: `poison` / `immune`.

**Consumers:** every policy-bearing surface — IEL `authPolicy` / `governancePolicy`, credential issuance, exchange-message auth.

**Dependencies:** none — DSL is standalone. Evaluated via [`policy-evaluator.md`](policy-evaluator.md). Cross-reference: [`../../../features/policy.md`](../../../features/policy.md).

Stub. Detailed content lands iteratively.
