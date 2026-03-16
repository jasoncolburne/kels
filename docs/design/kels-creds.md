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

Typed credential for issuance. `T` is the claims payload (must satisfy the `Claims` trait alias: `Serialize + DeserializeOwned + SelfAddressed + Clone + Sync`). Fields that are `SelfAddressed` may use `Compactable<T>` to represent either the expanded object or a compacted SAID string.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Claims", rename_all = "camelCase")]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: String,              // always a SAID reference to a Schema
    pub issuer: String,
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    pub nonce: Option<String>,
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

Disclosure operates on `serde_json::Value` directly — no wrapper type needed. Verification takes a typed `Credential<T>` since it needs structured access to fields like `issuer`, `schema`, and `claims`. The JSON API uses `Credential<serde_json::Value>` via the `SelfAddressed` impl on `Value`.

### Schema

Defines the expected shape of a credential. SelfAddressed so it can be referenced by SAID. Contains field definitions that describe types, structure, compactability, optionality, and value constraints.

```rust
#[derive(SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    #[said]
    pub said: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
}
```

`SchemaField` is a struct describing a single field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaField {
    pub field_type: SchemaFieldType,   // String, Integer, Float, Boolean, Object, Array, Said, Prefix, Datetime
    pub compactable: bool,             // only meaningful for Object — can be compacted to/expanded from a SAID
    pub optional: bool,                // if true, field may be absent
    pub constraint: Option<Value>,     // if set, field value must equal this exact value
    pub fields: Option<BTreeMap<String, SchemaField>>,  // child fields for Object type
    pub items: Option<Box<SchemaField>>,                // element type for Array type
}
```

Builder methods: `SchemaField::string()`, `::integer()`, `::float()`, `::boolean()`, `::said()`, `::prefix()`, `::datetime()`, `::object(fields, compactable)`, `::array(items)`. Chainable modifiers: `.opt()` (make optional), `.with_constraint(value)` (add value constraint).

`Object` fields have a `compactable` flag: when `true`, the object has a `said` field and can appear as a SAID string when compacted. When `false`, the object is always fully expanded and must not have a `said` field.

Implements `FromStr` for JSON deserialization.

#### Schema Validation

`validate_schema(schema)` is a public function that validates schema field definitions are well-formed:
- Rejects `said` as a field name anywhere (it's implicit for compactable objects)
- Validates constraint types match field types (e.g., integer constraint on integer field)
- Rejects constraints on Object/Array fields
- Enforces `MAX_RECURSION_DEPTH` on nesting depth
- Recurses into Object child fields and Array item schemas

`validate_credential_report(credential, schema)` is a `pub(crate)` function that validates a credential against a schema. It calls `validate_schema` first, then validates the credential's fields:
- All required fields present with correct types
- Compactable objects have a `said` field when expanded; accepted as SAID strings when compacted
- Closed schema: extra fields beyond the schema definition (plus `said` for compactable objects) are rejected
- Value constraints enforced
- Returns `SchemaValidationReport { valid: bool, errors: Vec<String> }` for graduated reporting

`Credential::issue()` calls `validate_credential_report` and requires `valid == true` via `require_valid()`. Verification also uses it, but accepts compacted fields (which skip type checking).

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
    pub nonce: Option<String>,         // anti-correlation nonce
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

## Schema-Aware Compaction and Expansion

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

All compaction and expansion is schema-aware — the schema determines which fields are compactable and guides the tree walk. Only fields marked `compactable: true` in the schema are compacted/expanded.

**Compact (bottom-up, depth-first, schema-guided):**
1. Walk the JSON tree alongside the schema, depth-first (post-order)
2. At each node that the schema marks as compactable and that has a `said` field:
   a. Recursively compact all compactable children first (guided by sub-field schemas)
   b. Compute the node's SAID via `compute_said_from_value` (over its current form — children are now SAIDs)
   c. Set the `said` field on the object, store the object in the accumulator keyed by SAID
   d. Replace the object with its SAID string
3. The credential's own top-level SAID is derived last, over the fully compacted body

Each SAID is a function of its compacted children — a leaf object's SAID is over its raw fields, a parent's SAID is over a mix of raw fields and child SAIDs. This makes every SAID in the tree independently verifiable.

All compaction is bounded by `MAX_RECURSION_DEPTH = 32` to prevent stack overflow from deeply nested or malicious inputs.

**Expand (two-pass batch fetch, schema-guided, bottom-up SAID recomputation):**

1. **Pass 1** — Collect all candidate SAID strings from compactable fields in the current object (guided by schema)
2. **Batch fetch** — Fetch all candidates in a single `get_chunks()` call
3. **Pass 2** — Replace fetched SAIDs with their expanded objects, recurse into children (guided by schema)
4. **SAID recomputation** — After all children are expanded, recompute the parent's `said` field via `compute_said_from_value`. This ensures expanded objects have SAIDs consistent with their expanded content.

Array fields are handled by iterating elements and applying the items schema to each element.

### API

Two levels of entry points:

**Schema-level** (convenience — takes `&Schema`, delegates to fields-level):
- `compact_with_schema(value, schema)` — compact using schema's field definitions
- `expand_with_schema(value, schema, sad_store)` — expand using schema's field definitions

**Fields-level** (takes `&BTreeMap<String, SchemaField>` directly — used for sub-tree operations):
- `compact_with_fields(value, fields)` — compact using field definitions directly
- `expand_with_fields(value, fields, sad_store)` — expand using field definitions directly

The fields-level functions exist for disclosure operations that operate on sub-trees of a credential, where only the relevant field definitions are available (not a full `Schema` object).

**Invariant:** A credential's SAID is always computed over the fully compacted canonical form. From any disclosure state, compacting recovers the canonical form and its SAID. Expanding fields then re-compacting must produce the same SAID.

### Composability

Because each SAID in the tree is independently verifiable, compacted chunks are self-contained and decoupled from their parent credential:

- **Independent storage** — Schemas, data objects, and edges can be stored as separate blobs, keyed by SAID. There is no requirement to store a credential as a single document. A holder might keep the compact credential in one place and the expanded chunks elsewhere.

- **Schema reuse** — A `Schema` with a given SAID can be shared across many credentials. Verifiers can cache validated schemas by SAID and skip re-validation when they encounter the same schema in a different credential.

- **Chunk caching** — Any verifier can cache a verified chunk by its SAID. If the same SAID appears in another credential (or another edge of the same credential), the cached verification result is reusable. SAID equality guarantees content equality.

- **Forward references** — An edge can reference a credential SAID that the holder doesn't possess yet. The edge is structurally valid (its own SAID is derivable), and the referenced credential can be supplied later for verification. This enables workflows where credential requirements are declared before the credentials are obtained.

- **Selective transmission** — A holder can send the compact credential first (small payload), then transmit individual expanded chunks on demand as the verifier requests them. Each chunk is independently verifiable against the SAID already present in the compact form.

- **Cross-credential composition** — The same expanded object (e.g., an address, a qualification) can appear in multiple credentials. Since its SAID is content-derived, identical content produces identical SAIDs regardless of which credential contains it. Verifiers can recognize and deduplicate across credentials without the issuers coordinating.

## Disclosure Path DSL

A string expression controlling which fields are expanded vs. compacted in a disclosed credential. Designed as a plain string for FFI friendliness (`*const c_char`). Requires a `Schema` for schema-aware expansion and compaction of sub-trees.

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
   - `.*` — expand all compactable fields at every level (schema-aware)
   - `path` — expand only the field at that path (children stay compacted)
   - `path.*` — expand the field at that path and all compactable fields within it (schema-aware)
   - `-.*` — compact all compactable fields at every level (schema-aware)
   - `-path` — compact the field at that path (schema-aware)
   - `-path.*` — compact the field at that path and all compactable fields within it (schema-aware)

`compact_at_path` returns an error if the target field is not a compactable object (missing `said` field). Already-compacted strings are allowed through.

Sub-tree operations use `compact_with_fields`/`expand_with_fields` with field definitions resolved from the schema at the target path. Path resolution handles both Object fields (via `field.fields`) and Array fields (via `field.items.fields`).

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
pub async fn apply_disclosure(
    said: &str,
    tokens: &[PathToken],
    sad_store: &dyn SADStore,
    schema: &Schema,
) -> Result<serde_json::Value, CredentialError>;
```

## Issuance Flow

`Credential::issue()` is the only public way to create a credential. It atomically constructs the credential from fully expanded inputs and anchors its compacted SAID in the issuer's KEL. This prevents issuance of credentials with compacted (uninspected) fields — a compacted SAID commits to content the issuer has not examined, allowing an attacker to hide malicious payloads behind opaque hashes.

1. `issue()` takes fully expanded inputs (claims, edges, rules) plus a schema and `KeyEventBuilder`
2. Validates all constraints via `validate_credential_report()` and derives all SAIDs using schema-aware compaction
3. Credential is compacted to canonical form (only schema-marked compactable fields replaced by SAIDs, bottom-up), then the credential's SAID is computed over this compact form
4. The credential is reconstructed by expanding from the compacted SAID using a temporary in-memory store — this ensures all inner SAIDs are correctly derived without requiring callers to pre-populate them
5. The compacted SAID is anchored in the issuer's KEL via `builder.interact()` (creates an `ixn` event)
6. `issue()` returns `(Credential<T>, String)` — the expanded credential with all SAIDs set, plus the compacted SAID that was anchored
7. Issuer stores the credential via `Credential::store(schema, &sad_store)` or `json_api::store()` if needed for later disclosure
8. Credential delivered to holder (out of band)

```rust
// Issuance (atomic: construct + validate + anchor)
let (credential, compacted_said) = Credential::issue(
    &schema, issuer, subject, claims, unique, edges, rules, can_revoke, expires_at, &mut builder,
).await?;
credential.store(&schema, &sad_store).await?;       // store for disclosure
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
- `MAX_RECURSION_DEPTH = 32` — maximum depth for compaction, expansion, schema validation, claims validation, and edge verification

### Steps

1. **Schema SAID match** — Verify the credential's `schema` field matches the provided schema's SAID.
2. **Expanded SAID integrity** — Recompute the credential's SAID from its current data via `compute_said_from_value`. If it doesn't match `credential.said`, the data has been tampered with.
3. **Compacted SAID integrity** — Compact the credential to canonical form using schema-aware compaction and derive the compacted SAID. This is the SAID that was anchored in the issuer's KEL at issuance time.
4. **Schema validation** — Validate the credential against the schema via `validate_credential_report`. Compacted fields are accepted (type checking is skipped for SAID strings in compactable fields).
5. **KEL verification** — Build a `KelVerifier` for the issuer's prefix with `check_anchors` for the compacted SAID and (unless irrevocable) the revocation hash. Run `verify_key_events` against the `PagedKelSource`. KEL errors are captured rather than failing the entire operation.
6. **Anchoring** — From the `KelVerification`: `is_said_anchored(&compacted_said)` = issued.
7. **Revocation** — Unless `irrevocable == Some(true)`, check `is_said_anchored(&revocation_hash)`.
8. **Expiration** — Check if `expires_at` is present and in the past.
9. **Edge verification** — If a `SADStore` and `edge_schemas` are provided and edges are expanded, recursively verify each edge that references a credential SAID. For each edge:
   - Look up the referenced credential by SAID in the SADStore
   - Verify the credential's schema matches the edge's schema reference
   - Expand using schema-aware expansion with the edge's schema
   - Parse as `Credential<Value>` and recursively verify
   - Enforce `edge.issuer` constraint (if declared, must match the actual credential's issuer)
   - Enforce `edge.delegated` constraint (if `true`, verify the issuer's KEL has a `dip` inception and the delegating prefix's KEL anchors the issuer's prefix)

### API

```rust
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub kel_error: Option<String>,
    pub delegating_prefix: Option<String>,   // from issuer's KEL inception, if dip
    pub schema_validation: SchemaValidationReport,
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

pub struct SchemaValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Verify a credential against the KEL, optionally with recursive edge verification.
pub async fn verify_credential<T: Claims>(
    credential: &Credential<T>,
    schema: &Schema,
    source: &dyn PagedKelSource,
    sad_store: Option<&dyn SADStore>,
    edge_schemas: &BTreeMap<String, Schema>,
) -> Result<CredentialVerification, CredentialError>;
```

`CredentialVerification::is_valid(require_valid_schema: bool)` provides a single "all good" check: issued, not revoked, not expired, no KEL errors, and all edge credentials also valid (recursively). When `require_valid_schema` is `true`, also requires schema validation to pass via `SchemaValidationReport::require_valid()`.

When a `SADStore` is provided, edges with a `credential` SAID reference are looked up, expanded using schema-aware expansion (with the schema from `edge_schemas`), parsed as `Credential<Value>`, and recursively verified against the KEL. Each edge label maps to the `CredentialVerification` of the referenced credential. Recursion is bounded by `MAX_RECURSION_DEPTH`. Edges without a `credential` field are skipped — there's nothing to verify.

`kel_error` surfaces why KEL verification failed for this credential's issuer, if applicable. When KEL verification fails, `is_issued` and `is_revoked` are `false` (fail-secure) but the caller can distinguish "issuer has no KEL" from "issuer's KEL is cryptographically invalid."

`delegating_prefix` is captured from the issuer's `KelVerification` after KEL verification. If the issuer's KEL inception was a `dip`, this contains the delegating prefix. Used by edge delegation verification.

`Credential::verify()` is a convenience method that delegates to `verify_credential(self, schema, source, sad_store, edge_schemas)`.

## JSON API

The `json_api` module provides JSON-boundary functions for consumers who work with raw JSON strings rather than typed Rust structs. All schema parameters are JSON strings, parsed internally.

- `store(json_credential, json_schema, sad_store)` — compact and store a credential, returns compacted SAID
- `verify(json_credential, json_schema, source, sad_store, json_edge_schemas)` — verify a credential, returns verification result JSON. `json_edge_schemas` is an optional JSON object mapping schema SAIDs to schema objects.
- `disclose(compacted_said, disclosure_statement, sad_store, json_schema)` — apply disclosure DSL to a stored credential, returns disclosed credential JSON
- `validate(json_credential, json_schema)` — validate a credential against a schema, returns `SchemaValidationReport`
- `parse_edges(json)` — parse edge JSON into `Edges` (for FFI use)
- `parse_rules(json)` — parse rule JSON into `Rules` (for FFI use)

Credential issuance is not in the JSON API — it requires a `KeyEventBuilder` which is a typed Rust generic. Issuance goes through the typed `Credential::issue()` API; the FFI layer will manage builder lifecycle.

These use `Credential<serde_json::Value>` internally via the `SelfAddressed` impl on `Value`, ensuring the same validation and verification logic as the typed API.

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
    ├── schema.rs           # Schema, SchemaField, SchemaFieldType, SchemaValidationReport, SchemaValidationResult, validation
    ├── edge.rs             # Edge, Edges types (with deserialization guards)
    ├── rule.rs             # Rule, Rules types (with deserialization guards)
    ├── store.rs            # SADStore trait + InMemorySADStore + store_credentials
    ├── disclosure.rs       # DSL parser, AST, apply_disclosure
    ├── compaction.rs       # compact/expand (schema-aware, depth-bounded, with _fields variants for sub-trees)
    ├── verification.rs     # verify_credential, CredentialVerification
    ├── revocation.rs       # revocation_hash (domain-separated)
    ├── json_api.rs         # JSON-boundary functions (store, verify, disclose, validate, parse helpers)
    └── error.rs            # CredentialError
```

Dependencies: `kels` (core types, `KelVerification`, `KelVerifier`, `KelsError`), `cesr` (CESR encoding, `Digest`), `verifiable-storage` (`SelfAddressed` derive, `compute_said_from_value`), `serde`, `serde_json` (with `preserve_order` for deterministic serialization), `tokio` (sync primitives), `async-trait`, `thiserror`.

FFI bindings added to existing `lib/kels-ffi/src/lib.rs` — no separate FFI crate.
