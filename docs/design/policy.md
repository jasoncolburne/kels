# kels-policy: Policy Framework Design

A composable trust policy framework for defining multi-party endorsement requirements on credentials. Policies replace the single-issuer model — instead of one KEL prefix that must anchor a credential's SAID, a policy defines arbitrary conditions involving multiple endorsers, thresholds, weighted voting, delegation, and nested composition.

## Core Concepts

### Policy

An immutable, self-addressed document with a DSL expression defining trust conditions. Policies travel with credentials (like schemas) and are evaluated consumer-side — the KELS service knows nothing about policies.

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    #[said]
    pub said: String,
    pub expression: String,                    // DSL string (FFI-friendly)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poison: Option<String>,                // who can poison (DSL); absent = any endorser (soft)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immune: Option<bool>,                  // if true, no poison checks
}
```

The common case (any endorser can soft-poison) serializes as just `{ said, expression }`.

### Poisoning Modes

Controlled by two mutually exclusive optional fields:

| State | Poison checks | Effect of poisoning |
|-------|--------------|---------------------|
| Neither set (default) | Yes, all endorsers | Poisoned endorsements don't count toward threshold (soft withdrawal) |
| `poison` set | Yes, per DSL expression | If poison expression is satisfied, entire policy is unsatisfied |
| `immune: true` | No | Endorsements are permanent; poison hashes ignored |

`poison` and `immune` cannot both be set.

### Poison Expression

When `poison` is absent, any endorser in the main expression can soft-poison (their endorsement doesn't count toward the threshold, but the policy may still be satisfied if enough other endorsers remain). When `poison` is set, it defines a DSL expression controlling who can poison and under what conditions — enabling requirements like "2-of-3 admins must agree to poison." When the poison expression is satisfied, the entire policy is unsatisfied.

## DSL

Five composable node types:

```
endorse(PREFIX)                    # leaf: this prefix must anchor the credential SAID
delegate(DELEGATOR, DELEGATE)      # delegated endorsement (see below)
threshold(MIN, [NODE, ...])        # M-of-N children must be satisfied
weighted(MIN_WEIGHT, [NODE:W, ...])# sum of satisfied weights >= min_weight
policy(SAID)                       # resolve + evaluate another policy by SAID
```

Nodes nest freely:

```
threshold(2, [
  endorse(KBfd1234...),
  weighted(3, [endorse(KAbc5678...):2, endorse(KCde9012...):1]),
  policy(KHij3456...)
])
```

### Delegation

`delegate(DELEGATOR, DELEGATE)` verifies:
1. DELEGATE's KEL was incepted via `dip` with DELEGATOR as delegating prefix
2. DELEGATOR's KEL anchors DELEGATE's prefix
3. DELEGATE anchors the credential SAID

This supports fleet scaling — an HSM-backed service delegates to rotating software-key services. When a delegate rotates, re-issue the credential with a new policy naming the new delegate.

### Policy Compaction

Same pattern as credential compaction. Strip variable parts (delegates), recompute SAID:

- `delegate(DELEGATOR, DELEGATE)` compacts to `delegate(DELEGATOR)`
- `endorse(PREFIX)` stays as-is
- `threshold`, `weighted`, `policy` recursively compact children
- `poison` expression is also compacted

Edges reference **compacted policy SAIDs**. The edge says "I accept any credential whose policy compacts to this SAID." The credential carries the full policy (with specific delegates). Verification: compact the credential's policy, check `compacted.said == edge.policy`. The edge doesn't need updating when delegates rotate — only the credential is re-issued with a new full policy that compacts to the same SAID.

## AST

```rust
pub enum PolicyNode {
    Endorse(String),                          // specific prefix
    Delegate(String, String),                 // delegator, delegate
    Threshold(usize, Vec<PolicyNode>),        // min, children
    Weighted(u64, Vec<(PolicyNode, u64)>),    // min_weight, (child, weight)
    Policy(String),                           // nested policy SAID
}
```

`Display` produces canonical DSL output; `parse()` → `Display` → `parse()` is identity (round-trip safe). `compact()` strips delegates for compaction.

## Parser

Hand-written recursive descent (no external parser deps). Validates:
- Threshold min >= 1 and <= child count
- Weighted min_weight >= 1 and <= total weight
- Non-empty child lists
- Weight >= 1 per item

## Poisoning

Endorsers poison by anchoring the **poison hash** in their KEL:

```
poison_hash = Blake3(b"kels/revocation:" || credential_said.as_bytes()).qb64()
```

The domain separator is shared with the legacy revocation hash for backward compatibility.

**Endorsement status per endorser:**

| Poison hash | SAID anchored | Status |
|-------------|--------------|--------|
| Present | Either | `Poisoned` |
| Absent | Present | `Endorsed` |
| Absent | Absent | `NotEndorsed` |

Poison hash presence always results in `Poisoned`, even without prior endorsement (proactive poisoning).

## PolicyVerification

Proof token for policy evaluation:

```rust
pub struct PolicyVerification {
    pub policy: String,
    pub is_satisfied: bool,
    pub endorsements: BTreeMap<String, EndorsementStatus>,
    pub nested_verifications: BTreeMap<String, PolicyVerification>,
}

pub enum EndorsementStatus {
    Endorsed,
    NotEndorsed,
    Poisoned,
    KelError(String),
}
```

## PolicyResolver

Trait for resolving nested `policy(SAID)` references:

```rust
#[async_trait]
pub trait PolicyResolver: Sync {
    async fn resolve_policy(&self, said: &str) -> Result<Policy, PolicyError>;
}
```

`InMemoryPolicyResolver` wraps a `BTreeMap<String, Policy>` for tests and simple use cases.

## Evaluation

`evaluate_policy(policy, credential_said, source, resolver)` walks the AST:

1. For `Endorse(prefix)`: verify prefix's KEL, check for credential SAID anchoring and (unless immune) poison hash
2. For `Delegate(delegator, delegate)`: verify delegation relationship, then check delegate's endorsement
3. For `Threshold(min, children)`: count satisfied children, compare to min
4. For `Weighted(min_weight, pairs)`: sum weights of satisfied children, compare to min_weight
5. For `Policy(said)`: resolve via `PolicyResolver`, parse, evaluate recursively

Cycle detection via visited-set on policy SAIDs. Max nesting depth = 10.

When `poison` is set:
- Main expression evaluates without poison checks (only endorsement)
- Poison expression evaluates separately using the poison hash as the anchor
- If poison expression is satisfied, the entire policy is unsatisfied

Per-endorser results are cached to avoid redundant KEL verification.

## Integration with kels-creds

### Credential

The `issuer: String` field has been replaced with `policy: String` (a policy SAID). The `irrevocable: Option<bool>` field has been removed (now expressed via policy `immune: true`).

```rust
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: String,
    pub policy: String,              // policy SAID (was: issuer prefix)
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    // ... (nonce, claims, expires_at, edges, rules)
}
```

`Credential::issue()` takes a `&Policy` and one `KeyEventBuilder` — anchoring one endorsement. Additional endorsers anchor separately via their own builders.

### CredentialVerification

Replaced single-issuer fields with policy verification:

```rust
pub struct CredentialVerification {
    pub credential: String,
    pub policy: String,
    pub policy_verification: PolicyVerification,
    pub subject: Option<String>,
    pub is_expired: bool,
    pub schema_validation: SchemaValidationReport,
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}
```

`is_valid()` checks `policy_verification.is_satisfied` (instead of `is_issued && !is_revoked`).

### Edge

The `issuer: Option<String>` field has been replaced with `policy: Option<String>` (a policy SAID constraint). The `delegated: Option<bool>` field has been removed (delegation is now expressed in the policy DSL via `delegate()`).

Edge verification compacts the presented credential's policy and checks `compacted.said == edge.policy` — not exact match. This allows delegate flexibility without updating the edge.

## Module Structure

```
lib/kels-policy/
├── Cargo.toml
├── deny.toml
└── src/
    ├── lib.rs              # public API re-exports
    ├── ast.rs              # PolicyNode enum + Display + compact()
    ├── parser.rs           # recursive descent parser + canonicalize()
    ├── policy.rs           # Policy struct + build() + helpers
    ├── resolver.rs         # PolicyResolver trait + InMemoryPolicyResolver
    ├── evaluator.rs        # evaluate_policy() + poison_hash()
    ├── verification.rs     # PolicyVerification + EndorsementStatus
    └── error.rs            # PolicyError
```

Dependencies: `kels` (core types, `KelVerifier`, `verify_key_events`), `cesr` (`Digest`, `Matter`), `verifiable-storage` (`SelfAddressed` derive), `serde`, `serde_json`, `async-trait`, `thiserror`.
