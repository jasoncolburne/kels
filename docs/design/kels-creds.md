# kels-creds: Credential Framework Design

A purely computational library for issuing, compacting, selectively disclosing, and verifying credentials anchored in KELs. Defines a storage trait (`SADStore`) but provides only an in-memory implementation — production storage is the caller's responsibility. All data (credentials, schemas, claims, edges, rules) lives in the `SADStore` as content-addressable chunks keyed by SAID.

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
#[serde(bound = "T: Claims")]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: Compactable<CredentialSchema>,
    pub issuer: String,
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    pub claims: Compactable<T>,
    pub irrevocable: Option<bool>,
    pub edges: Option<Compactable<Edges>>,
    pub rules: Option<Compactable<Rules>>,
}
```

The `said` is computed over the fully compacted canonical form — all nested `SelfAddressed` fields replaced by their SAIDs, then the credential's own SAID derived. This means a verifier can always recover the credential SAID from any disclosure state by compacting back down.

### Untyped Operations

Disclosure and verification operate on `serde_json::Value` directly — no wrapper type needed. The verifier doesn't need the issuer's Rust types; they work with raw JSON objects that have a `"said"` field.

### CredentialSchema

Defines the expected shape of a credential's `claims` field. SelfAddressed so it can be compacted to its SAID.

```rust
#[derive(SelfAddressed)]
pub struct CredentialSchema {
    #[said]
    pub said: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
}

pub enum SchemaField {
    String,
    Integer,
    Float,
    Boolean,
    Object(BTreeMap<String, SchemaField>),
    Array(Box<SchemaField>),
    Said,       // a CESR SAID reference
    Prefix,     // a CESR prefix
}
```

### Edge/Edges

A labeled reference to another credential. SelfAddressed and compactable, enabling graduated disclosure of relationships.

```rust
#[derive(SelfAddressed)]
pub struct Edge {
    #[said]
    pub said: String,
    pub schema: String,                // schema SAID (what kind of credential)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,        // issuer prefix (who issued it)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,    // credential SAID (a specific one)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,       // self.credential.issuer must be delegated by self.edge.issuer
}
```

```rust
#[derive(SelfAddressed)]
pub struct Edges {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub edges: BTreeMap<String, Edge>
}
```

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
pub struct Rule {
    #[said]
    pub said: String,
    pub condition: String,   // A text string for encoding things like terms of use
}
```

```rust
#[derive(SelfAddressed)]
pub struct Rules {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub rules: BTreeMap<String, Rule>
}
```

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

An `InMemorySADStore` (HashMap-based) is provided for tests, CLI tools, and lightweight use cases.

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

**Expand:**
Expansion requires the caller to supply the full objects. The library provides:
- `expand_field(path, value)` — replace a SAID string at `path` with the full object, verify the object's SAID matches
- `expand_all(sad_store)` — expand all compacted fields using a `SADStore` for lookup

**Invariant:** A credential's SAID is always computed over the fully compacted canonical form. From any disclosure state, `compact()` recovers the canonical form and its SAID. Expanding fields then re-compacting must produce the same SAID.

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
2. Inner `SelfAddressed` fields (`claims`, `schema`, and if present, `edges` and `rules`) have their SAIDs derived
3. Credential is compacted to canonical form (all nested fields replaced by SAIDs), then the credential's SAID is computed over this compact form. All chunks (including the compacted credential itself) are stored in the `SADStore`
4. `create()` returns `(Credential<T>, String)` — the expanded credential with its SAID set, plus the SAID
5. Issuer creates an `ixn` event anchoring the credential SAID
6. Credential delivered to holder (out of band)

```rust
// Issuance
let (credential, said) = Credential::create(schema, issuer, subject, claims, edges, rules, irrevocable, &sad_store).await?;
builder.interact(&said)?;  // anchor in KEL
```

## Revocation

Anchor-only, no separate revocation registry. Credentials with `irrevocable: Some(true)` skip revocation checks entirely — the issuer committed to irrevocability at issuance time (it's covered by the credential's SAID).

**Revocation hash** = `Blake3(credential_said.as_bytes()).qb64()`

- **Issued:** credential SAID is anchored in issuer's KEL
- **Revoked:** revocation hash is also anchored in issuer's KEL (only checked when `irrevocable` is not `Some(true)`)

During KEL verification, `check_anchors` is called with the credential SAID and (unless irrevocable) its revocation hash. After verification:

```rust
let revocation_hash = Digest::blake3_256(credential_said.as_bytes()).qb64();
kel_verifier.check_anchors([credential_said.clone(), revocation_hash.clone()]);

// ... verify KEL ...

let verification = kel_verifier.into_verification()?;
let is_issued = verification.is_said_anchored(&credential_said);
let is_revoked = verification.is_said_anchored(&revocation_hash);
// credential is valid iff is_issued && !is_revoked
```

To revoke:
```rust
let revocation_hash = Digest::blake3_256(credential.said.as_bytes()).qb64();
builder.interact(&revocation_hash)?;  // anchor revocation hash in KEL
```

## Credential Verification

Verification combines structural checks with KEL-anchored trust. Anchoring in the issuer's KEL is the proof of issuance — no separate signature verification is needed since the anchor proves the issuer committed to the credential SAID.

### Batched KEL Verification

Before any structural checks, the verifier walks the entire credential graph (top-level credential + all edge credentials from the `SADStore`) to collect every `(issuer_prefix, credential_said, revocation_hash)` tuple. These are grouped by issuer prefix, and a single `verify_key_events` call is made per unique issuer with all that issuer's SAIDs and revocation hashes registered via `check_anchors`. This avoids redundant KEL walks when multiple credentials share an issuer.

### Steps

1. **Collect anchors** — Walk the credential tree, pulling `issuer`, `said`, and (unless irrevocable) `revocation_hash` from each credential. Look up edge credentials from `SADStore` by SAID. Group by issuer prefix.
2. **Batch KEL verification** — One `verify_key_events` per unique issuer on the `KelStore`, with all anchors for that issuer registered via `check_anchors`. Store the resulting `KelVerification` per issuer.
3. **Structure** — For each credential, compact to canonical form, verify `said` matches
4. **Schema** — If schema is expanded, validate `claims` conforms to schema fields
5. **Anchoring** — From the issuer's `KelVerification`: `is_said_anchored(&said)` = issued
6. **Revocation** — Unless `irrevocable == Some(true)`, check `!is_said_anchored(&revocation_hash)`
7. **Edges** — For each expanded edge, check schema/issuer/delegation constraints against the referenced credential's verification results

### API

```rust
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
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

Verification is fully self-contained — it looks up the credential from `SADStore` by SAID, verifies the issuer's KEL internally via `KelStore`, looks up edge credentials from `SADStore`, and recurses. The caller does not need to pre-verify any KELs or supply credential values directly.

### Credential Graph Structure

A credential with edges forms a DAG rooted at the top-level credential, with edges pointing to other credentials, ultimately tracing back to KEL inception events. All credential data lives in the `SADStore` — edge credentials are looked up by their SAID. Insertion order doesn't matter since the store is content-addressable.

## Edge / Chaining Verification

When an edge is expanded and includes a `credential` SAID:

1. Look up the referenced credential from `SADStore` by SAID
2. If the edge has a `schema`, verify the referenced credential's schema SAID matches
3. If the edge has an `issuer`, verify the referenced credential's issuer matches
4. If `delegated` is `true`, verify the referenced credential's issuer's `KelVerification.delegating_prefix()` matches `edge.issuer` — i.e., the edge's issuer is the delegating authority, and the actual credential issuer is one of its delegates
5. Recursively call `verify_credential` on the referenced credential (which re-verifies the issuer's KEL, checking anchoring and revocation freshness)

The `delegated` flag enables hierarchical authority chains: the edge names an authority (`issuer`) and requires that the referenced credential come from an identifier that authority delegated. The verifier confirms this via `KelVerification::delegating_prefix()` on the referenced credential's issuer (requires adding this accessor to `KelVerification` in the kels crate).

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
    ├── schema.rs           # CredentialSchema, SchemaField, validation
    ├── edge.rs             # Edge, Edges types
    ├── rule.rs             # Rule, Rules types
    ├── store.rs            # SADStore trait + InMemorySADStore
    ├── disclosure.rs       # DSL parser, AST, apply_disclosure
    ├── compaction.rs       # compact, expand, round-trip
    ├── verification.rs     # verify_credential, CredentialVerification
    ├── revocation.rs       # revocation_hash
    └── error.rs            # CredentialError
```

Dependencies: `kels` (core types, `KelVerification`), `cesr` (CESR encoding, `Digest`), `verifiable-storage` (`SelfAddressed` derive, `compact_value`), `serde`, `serde_json`, `async-trait`.

FFI bindings added to existing `lib/kels-ffi/src/lib.rs` — no separate FFI crate.
