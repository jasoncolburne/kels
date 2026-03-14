# kels-creds: Credential Framework Design

A purely computational library for issuing, compacting, selectively disclosing, and verifying credentials anchored in KELs. Defines a storage trait (`SADStore`) but provides only an in-memory implementation — production storage is the caller's responsibility. All data (credentials, schemas, claims, edges, rules) lives in the `SADStore` as content-addressable chunks keyed by SAID.

All JSON-serializable types use `#[serde(rename_all = "camelCase")]` for consistent field naming across the FFI boundary.

## Core Types

### Compactable\<T\>

A generic enum representing a field that can be either fully expanded or compacted to its SAID string. Uses `#[serde(untagged)]` so a SAID serializes as a bare JSON string and an expanded value serializes as its object form.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compactable<T> {
    Said(String),
    Expanded(T),
}
```

This enables `Credential<T>` to hold fields in either state at the type level, including for the generic claims type `T` which cannot otherwise be swapped for a string.

### Credential\<T\>

Typed credential for issuance. `T` is the claims payload (must satisfy the `Claims` trait alias: `Serialize + DeserializeOwned + SelfAddressed + Clone`). Fields that are `SelfAddressed` use `Compactable<T>` to represent either the expanded object or a compacted SAID string.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Claims", rename_all = "camelCase")]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: Compactable<CredentialSchema>,
    pub issuer: String,
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    pub claims: Compactable<T>,
    pub expires_at: Option<StorageDatetime>,
    pub irrevocable: Option<bool>,
    pub edges: Option<Compactable<Edges>>,
    pub rules: Option<Compactable<Rules>>,
}
```

The `said` is computed over the fully compacted canonical form — all nested `SelfAddressed` fields replaced by their SAIDs, then the credential's own SAID derived. This means a verifier can always recover the credential SAID from any disclosure state by compacting back down.

Implements `FromStr` for JSON deserialization, which is the primary way credentials are constructed from external input (applications, FFI).

### Untyped Operations

Disclosure and verification operate on `serde_json::Value` directly — no wrapper type needed. The verifier doesn't need the issuer's Rust types; they work with raw JSON objects that have a `"said"` field.

### CredentialSchema

Defines the expected shape of a credential's `claims` field, along with constraints on edges, rules, and expiration. SelfAddressed so it can be compacted to its SAID.

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    #[said]
    pub said: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
    pub expires: bool,
    pub edges: Option<BTreeMap<String, SchemaEdge>>,
    pub rules: Option<BTreeMap<String, SchemaRule>>,
}

pub enum SchemaField {
    String,
    Integer,
    Float,
    Boolean,
    Object {
        fields: BTreeMap<String, SchemaField>,
        compactable: bool,
    },
    Array(Box<SchemaField>),
    Said,       // a CESR SAID reference
    Prefix,     // a CESR prefix
}
```

`Object` fields have a `compactable` flag: when `true`, the object has a `said` field and can appear as a SAID string when compacted. When `false`, the object is always fully expanded and must not have a `said` field.

`expires` controls whether credentials using this schema must have an `expires_at` timestamp. If `true`, `expires_at` is required and must be after `issued_at`. If `false`, `expires_at` must be absent.

Implements `FromStr` for JSON deserialization.

#### Schema-Level Edge and Rule Constraints

```rust
pub struct SchemaEdge {
    pub schema: String,      // required — expected schema SAID
    pub issuer: Option<String>,
    pub credential: Option<String>,
    pub delegated: Option<bool>,
}

pub struct SchemaRule {
    pub condition: Option<String>,
}
```

When a schema defines edges or rules, `Credential::create()` validates that the provided edges/rules match: same labels, and each field constraint (where defined) matches the actual value. The reserved label `"said"` is rejected for edge and rule labels.

#### Schema Validation

Four validation functions enforce schema correctness at issuance time:

- `validate_schema(&schema)` — rejects `said` as a field name anywhere (it's implicit for compactable objects), rejects `said` as an edge or rule label
- `validate_claims(&schema, &claims_value)` — closed-schema validation: all fields must be present, no extra fields allowed, types must match. Float fields accept integer literals.
- `validate_edges(&schema, edges)` — if schema defines edges, provided edges must match labels and constraints
- `validate_rules(&schema, rules)` — same pattern for rules

### Edge/Edges

A labeled reference to another credential. SelfAddressed and compactable, enabling graduated disclosure of relationships.

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Edge {
    #[said]
    pub said: String,
    pub schema: String,                // schema SAID (what kind of credential)
    pub issuer: Option<String>,        // issuer prefix (who issued it)
    pub credential: Option<String>,    // credential SAID (a specific one)
    pub delegated: Option<bool>,       // self.credential.issuer must be delegated by self.edge.issuer
}
```

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Edges {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub edges: BTreeMap<String, Edge>
}
```

`Edges` uses a custom `Deserialize` impl via a `RawEdges` intermediary with `TryFrom` conversion that calls `validate_labels` during deserialization. This ensures the reserved label `"said"` is rejected on both the `new_validated()` and deserialization paths.

`Edges::new_validated()` derives SAIDs on all inner `Edge` values before deriving the container's SAID.

Disclosure levels (by expanding/compacting the edge):

| Disclosed fields | What it reveals |
|---|---|
| Compact (SAID only) | Nothing — proves edge exists |
| `schema` only | "I have a credential of type X" |
| `schema` + `issuer` | "I have a type X credential from this authority" |
| `schema` + `credential` + `issuer` | Full specifics — verifier can fetch and check |
| Any combination + `delegated: true` | Referenced credential's issuer must be a delegate of `edge.issuer` |

### Rule/Rules

Plain language rules for things like terms of use. Self-addressed and compactable.

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[said]
    pub said: String,
    pub condition: String,   // A text string for encoding things like terms of use
}
```

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Rules {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub rules: BTreeMap<String, Rule>
}
```

Same deserialization guard pattern as `Edges` — `RawRules` with `TryFrom` enforcing reserved label validation. `Rules::new_validated()` derives SAIDs on all inner `Rule` values before deriving the container's SAID.

### SADStore

Content-addressable store for all SelfAddressed JSON data (credentials, schemas, claims, edges, rules, etc.), keyed by SAID. The single source of truth for all credential data. Batch operations are the required trait methods; single-item convenience methods are provided as defaults.

```rust
#[async_trait]
pub trait SADStore: Send + Sync {
    async fn store_chunks(&self, chunks: &HashMap<String, Value>) -> Result<(), CredentialError>;
    async fn get_chunks(&self, saids: &HashSet<String>) -> Result<HashMap<String, Value>, CredentialError>;

    // Default convenience methods (delegate to batch operations)
    async fn get_chunk(&self, said: &str) -> Result<Option<Value>, CredentialError>;
    async fn store_chunk(&self, said: &str, value: &Value) -> Result<(), CredentialError>;
}
```

An `InMemorySADStore` (`tokio::sync::RwLock<HashMap>`-based) is provided for tests, CLI tools, and lightweight use cases.

## Compaction and Expansion

### States

Any `SelfAddressed` field within a credential can be in one of two states, represented at the type level by `Compactable<T>`:

**Expanded** (`Compactable::Expanded(T)`) — the full object is present, including its `said` field:
```json
{
  "address": {
    "said": "EAbc...",
    "city": "Toronto",
    "province": "Ontario"
  }
}
```

**Compacted** (`Compactable::Said(String)`) — replaced by its SAID string:
```json
{
  "address": "EAbc..."
}
```

### Algorithm

**Compact (bottom-up, depth-first):**
1. Walk the JSON tree depth-first (post-order)
2. At each node that is an object with a `said` field:
   a. Recursively compact all of its children first
   b. Derive the node's SAID over its current form (children are now SAIDs)
   c. Replace the object with its SAID string
3. The credential's own top-level SAID is derived last, over the fully compacted body, but the top-level object is not itself replaced (it remains an object with a `said` field)

Each SAID is a function of its compacted children — a leaf object's SAID is over its raw fields, a parent's SAID is over a mix of raw fields and child SAIDs. This makes every SAID in the tree independently verifiable.

All compaction uses `compact_value_bounded` with depth limits (`MAX_RECURSION_DEPTH = 32`) to bound stack usage for deeply nested or malicious inputs. When compacting inside an already-recursive context (e.g., verification), the remaining depth is passed through rather than using the maximum constant.

**Expand (two-pass batch fetch, bottom-up SAID recomputation):**

Expansion uses a two-pass approach at each level for efficient store access:

1. **Pass 1** — Collect all candidate SAID strings from the current object's children (or array elements)
2. **Batch fetch** — Fetch all candidates in a single `get_chunks()` call
3. **Pass 2** — Replace fetched SAIDs with their expanded objects, recurse into children
4. **SAID recomputation** — After all children are expanded, recompute the parent's `said` field via `compute_said_from_value`. This ensures expanded objects have SAIDs consistent with their expanded content, not stale compacted SAIDs.

The library provides:
- `expand_field(path, value)` — replace a SAID string at `path` with the full object, verify the object's SAID matches
- `expand_all(sad_store)` — expand all compacted fields using a `SADStore` for lookup, with batch fetching and SAID recomputation

Root-level SAID strings are also handled — if the value itself is a SAID, it is looked up and replaced, making `compact` and `expand_all` true inverses.

**Invariant:** A credential's SAID is always computed over the fully compacted canonical form. From any disclosure state, `compact()` recovers the canonical form and its SAID. Expanding fields then re-compacting must produce the same SAID.

A `could_be_said()` filter skips store lookups for strings that obviously aren't SAIDs — checks for 44-character length, `E` prefix (Blake3-256 CESR digest code), and URL-safe base64 characters.

### Composability

Because each SAID in the tree is independently verifiable, compacted chunks are self-contained and decoupled from their parent credential:

- **Independent storage** — Schemas, data objects, and edges can be stored as separate blobs, keyed by SAID. There is no requirement to store a credential as a single document. A holder might keep the compact credential in one place and the expanded chunks elsewhere.

- **Schema reuse** — A `CredentialSchema` with a given SAID can be shared across many credentials. Verifiers can cache validated schemas by SAID and skip re-validation when they encounter the same schema in a different credential.

- **Chunk caching** — Any verifier can cache a verified chunk by its SAID. If the same SAID appears in another credential (or another edge of the same credential), the cached verification result is reusable. SAID equality guarantees content equality.

- **Forward references** — An edge can reference a credential SAID that the holder doesn't possess yet. The edge is structurally valid (its own SAID is derivable), and the referenced credential can be supplied later for verification. This enables workflows where credential requirements are declared before the credentials are obtained.

- **Selective transmission** — A holder can send the compact credential first (small payload), then transmit individual expanded chunks on demand as the verifier requests them. Each chunk is independently verifiable against the SAID already present in the compact form.

- **Cross-credential composition** — The same expanded object (e.g., an address, a qualification) can appear in multiple credentials. Since its SAID is content-derived, identical content produces identical SAIDs regardless of which credential contains it. Verifiers can recognize and deduplicate across credentials without the issuers coordinating.

## Disclosure Path DSL

A string expression controlling which fields are expanded vs. compacted in a disclosed credential. Designed as a plain string for FFI friendliness (`*const c_char`).

### Grammar

```
expression = token (SPACE token)*
token      = ["-"] path
path       = segment ("." segment)* [".*"]
segment    = identifier
```

**Normalization:** Before parsing, `*` is rewritten to `.*` and `-*` to `-.*`. This makes the grammar uniform — every recursive operation is a `.*` suffix. A bare `.*` means "recursively from root."

The `.*` suffix means "expand/compact this field and all compactable fields within it recursively." Without `.*`, only the field itself is affected (nested SelfAddressed fields stay as-is).

### Evaluation

1. Start with everything compacted (all compactable fields replaced by SAIDs)
2. Process tokens left to right:
   - `.*` — expand all compactable fields at every level
   - `path` — expand only the field at that path (children stay compacted)
   - `path.*` — expand the field at that path and all compactable fields within it
   - `-.*` — compact all compactable fields at every level
   - `-path` — compact the field at that path
   - `-path.*` — compact the field at that path and all compactable fields within it

`compact_at_path` returns an error if the target field is not a compactable object (missing `said` field). Already-compacted strings are allowed through.

### Examples

| Expression | Effect |
|---|---|
| `.*` | Fully expanded — all fields visible |
| `-.*` | Fully compacted — only SAIDs visible |
| `claims` | Expand only the `claims` field (nested fields stay compacted) |
| `claims.*` | Expand `claims` and everything inside it |
| `.* -claims.address` | Expand everything except `claims.address` |
| `schema edges.license` | Expand schema and the `license` edge only (edge internals stay compacted) |
| `schema edges.license.*` | Expand schema and the `license` edge with all its contents |
| `.* -edges` | Expand everything except edges |

### AST

```rust
pub enum PathToken {
    Expand(Vec<String>),            // path (expand this field only)
    ExpandRecursive(Vec<String>),   // path.* (expand field and all children; empty vec = root)
    Compact(Vec<String>),           // -path (compact this field only)
    CompactRecursive(Vec<String>),  // -path.* (compact field and all children; empty vec = root)
}
// .* parses to ExpandRecursive(vec![])
// -.* parses to CompactRecursive(vec![])

pub fn parse_disclosure(expr: &str) -> Result<Vec<PathToken>, CredentialError>;
pub async fn apply_disclosure(said: &str, tokens: &[PathToken], sad_store: &dyn SADStore) -> Result<serde_json::Value, CredentialError>;
```

## Issuance Flow

1. Issuer constructs `Credential<T>` via `Credential::create()`, which takes a `&dyn SADStore` and stores all compacted chunks automatically
2. Credential is compacted to canonical form (all nested fields replaced by SAIDs bottom-up), then the credential's SAID is computed over this compact form. All chunks (including the compacted credential itself) are stored in the `SADStore`
3. The credential is reconstructed from the store by expanding from the compacted SAID — this ensures all inner SAIDs are correctly derived without requiring callers to pre-populate them
4. `create()` returns `(Credential<T>, String)` — the expanded credential with all SAIDs set, plus the compacted SAID for KEL anchoring
5. Issuer creates an `ixn` event anchoring the compacted credential SAID
6. Credential delivered to holder (out of band)

Validation at issuance time:
- `validate_schema` — schema structure is well-formed
- `validate_claims` — claims conform to schema fields (closed-schema validation)
- `validate_edges` — edges match schema edge definitions (if defined)
- `validate_rules` — rules match schema rule definitions (if defined)
- `expires_at` is validated against `schema.expires`

```rust
// Issuance
let (credential, said) = Credential::create(
    schema, issuer, subject, claims, edges, rules, irrevocable, expires_at, &sad_store
).await?;
builder.interact(&said)?;  // anchor in KEL
```

## Revocation

Anchor-only, no separate revocation registry. Credentials with `irrevocable: Some(true)` skip revocation checks entirely — the issuer committed to irrevocability at issuance time (it's covered by the credential's SAID).

**Revocation hash** = `Blake3(b"kels/revocation:" || credential_said.as_bytes()).qb64()`

The domain separation prefix `kels/revocation:` prevents a credential SAID from colliding with its revocation hash.

- **Issued:** credential SAID is anchored in issuer's KEL
- **Revoked:** revocation hash is also anchored in issuer's KEL (only checked when `irrevocable` is not `Some(true)`)

During KEL verification, `check_anchors` is called with the credential SAID and (unless irrevocable) its revocation hash. After verification:

```rust
let revocation_hash = revocation_hash(&credential_said);
kel_verifier.check_anchors([credential_said.clone(), revocation_hash.clone()]);

// ... verify KEL ...

let verification = kel_verifier.into_verification()?;
let is_issued = verification.is_said_anchored(&credential_said);
let is_revoked = verification.is_said_anchored(&revocation_hash);
// credential is valid iff is_issued && !is_revoked
```

To revoke:
```rust
let revocation_hash = revocation_hash(&credential.said);
builder.interact(&revocation_hash)?;  // anchor revocation hash in KEL
```

## Credential Verification

Verification combines structural checks with KEL-anchored trust. Anchoring in the issuer's KEL is the proof of issuance — no separate signature verification is needed since the anchor proves the issuer committed to the credential SAID.

### Depth Bounds

All recursive operations share a single depth constant:
- `MAX_RECURSION_DEPTH = 32` — maximum depth for compaction, expansion, schema validation, and claims validation

### Batched KEL Verification

Before any structural checks, the verifier walks the entire credential graph (top-level credential + all edge credentials from the `SADStore`) to collect every `(issuer_prefix, credential_said, revocation_hash)` tuple, plus any delegation relationships (delegating prefix must anchor delegated prefix). These are grouped by prefix, and a single `verify_key_events` call is made per unique prefix with all that prefix's SAIDs registered via `check_anchors`. This avoids redundant KEL walks when multiple credentials share an issuer or delegating authority.

Cycle detection is enforced via a `visited` set of credential SAIDs during graph traversal.

### Steps

1. **Collect anchors** — Walk the credential tree, pulling `issuer`, `said`, and (unless irrevocable) `revocation_hash` from each credential. Look up edge credentials from `SADStore` by SAID. Group by issuer prefix. Also collect delegation relationships from delegated edges.
2. **Batch KEL verification** — One `verify_key_events` per unique prefix (issuers + delegating prefixes) on the `KelStore`, with all anchors for that prefix registered via `check_anchors`. Store the resulting `KelVerification` per prefix. KEL verification errors are captured per-prefix rather than failing the entire operation.
3. **Structure** — For each credential, compact to canonical form, verify `said` matches
4. **Schema** — If schema is expanded, validate `claims` conforms to schema fields
5. **Anchoring** — From the issuer's `KelVerification`: `is_said_anchored(&said)` = issued
6. **Revocation** — Unless `irrevocable == Some(true)`, check `!is_said_anchored(&revocation_hash)`
7. **Expiration** — Check if `expires_at` is present and in the past. Reported as `is_expired` data, not a verification gate — consumers make policy decisions.
8. **Edges** — For each expanded edge, check schema/issuer/delegation constraints against the referenced credential's verification results

### Delegation Verification

When an edge has `delegated: true`, three checks are performed:

1. The referenced credential's issuer KEL must be a `dip` (delegated inception) whose `delegating_prefix` matches the edge's `issuer` field
2. The delegating KEL (edge's `issuer`) is cryptographically verified
3. The delegating KEL must anchor the delegated prefix — confirming the delegation was authorized

This closes the delegation trust chain: the delegated issuer claims to be delegated, and the delegating authority confirms it by anchoring the delegated prefix in their KEL.

### API

```rust
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub kel_error: Option<KelsError>,
    pub schema_valid: Option<bool>,
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

/// Verify a credential, its anchoring in the issuer's KEL, and any edges recursively.
pub async fn verify_credential(
    said: &str,
    sad_store: &dyn SADStore,
    kel_store: &dyn KelStore,
) -> Result<CredentialVerification, CredentialError>;
```

`kel_error` surfaces why KEL verification failed for this credential's issuer, if applicable. When KEL verification fails, `is_issued` and `is_revoked` are `false` (fail-secure) but the caller can distinguish "issuer has no KEL" from "issuer's KEL is cryptographically invalid."

Verification is fully self-contained — it looks up the credential from `SADStore` by SAID, verifies the issuer's KEL internally via `KelStore`, looks up edge credentials from `SADStore`, and recurses. The caller does not need to pre-verify any KELs or supply credential values directly.

### Credential Graph Structure

A credential with edges forms a DAG rooted at the top-level credential, with edges pointing to other credentials, ultimately tracing back to KEL inception events. All credential data lives in the `SADStore` — edge credentials are looked up by their SAID. Insertion order doesn't matter since the store is content-addressable.

## Edge / Chaining Verification

When an edge is expanded and includes a `credential` SAID:

1. Look up the referenced credential from `SADStore` by SAID
2. If the edge has a `schema`, verify the referenced credential's schema SAID matches
3. If the edge has an `issuer` and `delegated` is not set, verify the referenced credential's issuer matches directly
4. If `delegated` is `true`, perform full delegation verification (see Delegation Verification above)
5. Build the verification result for the referenced credential using the shared KEL verification results (no redundant KEL re-verification)

When an edge is compacted (SAID only), the verifier can only confirm the edge exists — they cannot verify the referenced credential without the holder expanding it.

## FFI Surface

Exposed through `kels-ffi`, not through a separate crate. All credential operations use C-compatible types.

```c
// Credential operations
KelsCredentialResult kels_credential_issue(
    KelsContext* ctx,
    const char* schema_json,
    const char* subject_prefix,
    const char* claims_json,
    const char* edges_json,         // nullable
    const char* rules_json,         // nullable
);

KelsCredentialResult kels_credential_compact(
    const char* credential_json
);

KelsCredentialResult kels_credential_disclose(
    const char* credential_json,
    const char* disclosure_expr      // DSL expression string
);

KelsVerifyResult kels_credential_verify(
    KelsContext* ctx,
    const char* credential_json
);

KelsRevokeResult kels_credential_revoke(
    KelsContext* ctx,
    const char* credential_said
);

void kels_free_credential_result(KelsCredentialResult result);
```

Result struct:
```c
typedef struct {
    KelsStatus status;
    const char* credential_json;    // owned, caller must free
    const char* said;               // owned
    const char* error;              // owned, nullable
} KelsCredentialResult;
```

The disclosure DSL is a plain `const char*` — no structured types cross the FFI boundary for disclosure expressions.

## Module Structure

```
lib/kels-creds/
├── Cargo.toml
└── src/
    ├── lib.rs              # public API re-exports
    ├── credential.rs       # Compactable<T>, Credential<T>, Claims trait
    ├── schema.rs           # CredentialSchema, SchemaField, SchemaEdge, SchemaRule, validation
    ├── edge.rs             # Edge, Edges types (with deserialization guards)
    ├── rule.rs             # Rule, Rules types (with deserialization guards)
    ├── store.rs            # SADStore trait + InMemorySADStore
    ├── disclosure.rs       # DSL parser, AST, apply_disclosure
    ├── compaction.rs       # compact, expand, round-trip (depth-bounded)
    ├── verification.rs     # verify_credential, CredentialVerification
    ├── revocation.rs       # revocation_hash (domain-separated)
    └── error.rs            # CredentialError
```

Dependencies: `kels` (core types, `KelVerification`, `KelsError`), `cesr` (CESR encoding, `Digest`), `verifiable-storage` (`SelfAddressed` derive, `compact_value_bounded`), `serde`, `serde_json` (with `preserve_order` for deterministic serialization), `tokio` (sync primitives), `async-trait`.

FFI bindings added to existing `lib/kels-ffi/src/lib.rs` — no separate FFI crate.
