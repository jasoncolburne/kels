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

Six composable node types:

```
endorse(PREFIX)                    # leaf: this KEL prefix must anchor the credential SAID
identity(PREFIX)                   # leaf: resolve PREFIX's IEL tip, evaluate its current auth_policy here
delegate(DELEGATOR, DELEGATE)      # delegated endorsement (see below)
threshold(MIN, [NODE, ...])        # M-of-N children must be satisfied
weighted(MIN_WEIGHT, [NODE:W, ...])# sum of satisfied weights >= min_weight
policy(SAID)                       # resolve + evaluate another policy by SAID
```

Nodes nest freely:

```
threshold(2, [
  endorse(KBfd1234...),
  identity(EAliceIdentity...),
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

### Identity Resolution

`identity(PREFIX)` resolves PREFIX as an IEL (identity-chain) prefix. At evaluation time the evaluator walks PREFIX's IEL chain to its current tip, reads the tip's tracked `auth_policy` SAID, resolves that policy, and evaluates it in place — the `identity(X)` leaf is, semantically, the current `auth_policy` of X expanded at the position the leaf occupies. This is the load-bearing primitive that lets every other subsystem hold a stable reference to a user-facing identity: devices come and go under X's IEL, but a policy `identity(X)` keeps resolving to whatever endorsers X currently authorizes, with no edit to the referencing policy.

Identity resolution composes. The policy at X's tip may itself contain `identity(...)` leaves naming other identities; those resolve through the same mechanism. A policy expressing "X plus any 2-of-3 federation members, where each member is itself an identity" nests transparently.

**Cycle guard.** The evaluator carries a stack of identity prefixes currently being resolved. Visiting an identity already on the stack is rejected as a cycle — `identity(X)` cannot, directly or transitively through other identities, expand to a policy that names X again.

**Per-evaluation cache.** Resolutions are cached keyed by `(identity_prefix, chain_tip_SAID)` for the duration of a single evaluation. Repeated `identity(X)` references within one policy walk hit the cache; the same key in a later evaluation invalidates naturally once X's IEL advances, because the tip SAID changes.

**Trust model.** Resolving `identity(X)` requires an IEL/SEL source. For consumers running with the standard `AnchoredPolicyChecker` wiring, that source is provided alongside the KEL source. For offline contexts (CLI tools computing a prefix from inputs that don't reach the network), `identity(X)` is unresolvable: callers must surface the error rather than treat unresolved leaves as `false` — silently false would let a policy be "satisfied" by an evaluator that simply couldn't see the truth. Fail loudly.

**DSL examples.**

```
# Single-identity endorsement: anyone alice's current auth_policy admits.
identity(EAliceIdentity...)

# Threshold of identities: any 2 of 3 named identities.
threshold(2, [
  identity(EAliceIdentity...),
  identity(EBobIdentity...),
  identity(ECarolIdentity...),
])

# Mixed identity + raw KEL leaves: identity-current authority for alice,
# pinned device authority for a specific service node.
threshold(2, [
  identity(EAliceIdentity...),
  endorse(KServiceNodePrefix...),
])
```

### Policy Compaction

Same pattern as credential compaction. Strip variable parts (delegates), recompute SAID:

- `delegate(DELEGATOR, DELEGATE)` compacts to `delegate(DELEGATOR)`
- `endorse(PREFIX)` stays as-is
- `identity(PREFIX)` stays as-is — the identity prefix is structurally stable (chosen at IEL inception, fixed for the chain's life); only the *resolved* `auth_policy` evolves, and that's fetched at evaluation, not baked into the policy
- `threshold`, `weighted`, `policy` recursively compact children
- `poison` expression is also compacted

Edges reference **canonical policy SAIDs**. The edge says "I accept any credential whose policy compacts to this canonical SAID." The credential carries the full policy (with specific delegates). Verification: compact the credential's policy to canonical form, check `canonical.said == edge.policy`. The edge doesn't need updating when delegates rotate — only the credential is re-issued with a new full policy that compacts to the same canonical SAID.

### Threshold Redundancy

A `threshold(N, id_1, ..., id_M)` policy with `M > N` tolerates loss of up to `M − N` identities' authority while remaining satisfiable. If an anchor was originally satisfied by some subset of `N` identities and one of those identities is later contested (per [kel/event-log.md](../primitives/kel/event-log.md) / [iel/event-log.md](../primitives/iel/event-log.md)), the original anchor loses authority — but a new anchor under the same policy can be created using a different subset that excludes the contested identity, satisfying the threshold again. The underlying SAID's authorization is re-established without changing the policy itself.

This is a structural feature of anchored policies: threshold satisfaction depends on which identities anchor at any given moment, not which identities ever anchored historically. Policies themselves are immune SADs with fixed content — they don't evolve. Re-anchoring is bounded only by the operator's continued control of enough identities to meet the threshold.

Operators designing governance / authorization policies should set thresholds with `M − N >= expected partial-compromise tolerance`.

For the operator-facing intuition behind redundancy — adversary patience, the cost of accumulating sufficient authority, and the truck-roll cost of reincept-as-default — see [protocol-doctrine.md §Limit of the Doctrine → §Adversary Patience and Policy Redundancy](../protocol-doctrine.md#adversary-patience-and-policy-redundancy). The DSL section above covers the mechanics; the doctrine section covers the threat model and operational stakes.

## AST

```rust
pub enum PolicyNode {
    Endorse(String),                          // specific KEL prefix
    Identity(String),                         // IEL prefix; resolves to its current auth_policy at evaluation
    Delegate(String, String),                 // delegator, delegate
    Weighted(u64, Vec<(PolicyNode, u64)>),    // min_weight, (child, weight)
    Policy(String),                           // nested policy SAID
}
```

`threshold(M, [A, B, C])` in the DSL parses to `Weighted(M, [(A, 1), (B, 1), (C, 1)])` — threshold is syntactic sugar for equal-weight weighted. `Display` produces `threshold()` syntax when all weights are 1, preserving round-trip identity. `compact()` strips delegates for compaction; `Identity` variants pass through unchanged (the prefix is the stable handle, the resolved policy isn't part of the compacted form).

## Parser

Hand-written recursive descent (no external parser deps). Accepts `identity(PREFIX)` as a leaf alongside `endorse(PREFIX)` and `delegate(DELEGATOR, DELEGATE)`. Validates:
- Weighted/threshold min_weight >= 1 and <= total weight
- Non-empty child lists
- Weight >= 1 per item

## Poisoning

Endorsers poison by anchoring the **poison hash** in their KEL:

```
poison_hash = Blake3(b"kels/poison:" || credential_said.as_bytes()).qb64()
```

The domain separator `kels/poison:` is purpose-named to distinguish poison hashes from other anchored SAIDs.

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

For `Identity(prefix)` resolution, the evaluator additionally takes an IEL source — the same shape that `AnchoredPolicyChecker` uses for IEL access, parallel to its KEL source. The IEL source supplies "tip event + tracked `auth_policy` at the tip" for an identity prefix; the resulting `auth_policy` SAID is then passed through the same `PolicyResolver`. Tests can in-memory both sources side by side; production wires them to the live KEL/IEL infrastructure.

## Evaluation

`evaluate_policy(policy, credential_said, source, resolver)` walks the AST:

1. For `Endorse(prefix)`: verify prefix's KEL, check for credential SAID anchoring and (unless immune) poison hash
2. For `Identity(prefix)`: walk prefix's IEL chain to its current tip via the IEL source, read the tip's tracked `auth_policy` SAID, resolve that policy via `PolicyResolver`, evaluate it recursively in place. Push `prefix` onto the identity-resolution stack before the recursive call and pop after; reject as a cycle if `prefix` is already on the stack. Results are memoized for the remainder of the evaluation under the key `(prefix, chain_tip_SAID)`.
3. For `Delegate(delegator, delegate)`: verify delegation relationship, then check delegate's endorsement
4. For `Weighted(min_weight, pairs)`: sum weights of satisfied children, compare to min_weight (threshold is weighted with unit weights)
5. For `Policy(said)`: resolve via `PolicyResolver`, parse, evaluate recursively

Cycle detection runs on two independent stacks: policy SAIDs (for `Policy(said)` nesting) and identity prefixes (for `Identity(prefix)` nesting). Max nesting depth = 10 on each. Unresolvable identities (no IEL source available; IEL fetch failed) surface as evaluation errors, never as silent `false`.

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

`Credential::build()` takes a `&Policy` and returns the credential with its canonical SAID. The caller anchors the SAID in endorser KELs separately (e.g., via `KeyEventBuilder::interact()`).

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
lib/policy/
├── Cargo.toml
├── deny.toml
└── src/
    ├── lib.rs              # public API re-exports
    ├── ast.rs              # PolicyNode enum (Endorse, Identity, Delegate, Weighted, Policy) + Display + compact()
    ├── parser.rs           # recursive descent parser + canonicalize(); threshold() is sugar for Weighted
    ├── policy.rs           # Policy struct + build() + compact() + helpers
    ├── resolver.rs         # PolicyResolver trait + InMemoryPolicyResolver; IelSource trait for identity() resolution
    ├── evaluator.rs        # evaluate_policy() + poison_hash(); identity-resolution stack + per-evaluation cache
    ├── json_api.rs         # JSON-boundary functions (build, compact, poison_hash)
    ├── verification.rs     # PolicyVerification + EndorsementStatus
    └── error.rs            # PolicyError
```

Dependencies: `kels` (core types, `KelVerifier`, `verify_key_events`), `cesr` (`Digest`, `Matter`), `verifiable-storage` (`SelfAddressed` derive), `serde`, `serde_json`, `async-trait`, `thiserror`.
