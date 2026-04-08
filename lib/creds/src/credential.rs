use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use cesr::Matter;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use kels_core::{PagedKelSource, generate_nonce};
use kels_policy::{Policy, PolicyResolver};
use verifiable_storage::{SelfAddressed, StorageDatetime};

use crate::{
    compaction::{compact_with_schema, expand_with_schema},
    edge::Edges,
    error::CredentialError,
    rule::Rules,
    schema::Schema,
    store::{InMemorySADStore, SADStore},
    verification::{CredentialVerification, verify_credential},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compactable<T> {
    Said(cesr::Digest),
    Expanded(T),
}

impl<T> Compactable<T> {
    pub fn as_said(&self) -> Option<cesr::Digest> {
        match self {
            Compactable::Said(s) => Some(*s),
            Compactable::Expanded(_) => None,
        }
    }

    pub fn as_expanded(&self) -> Option<&T> {
        match self {
            Compactable::Said(_) => None,
            Compactable::Expanded(t) => Some(t),
        }
    }
}

/// Trait alias for the bounds required on credential claims types.
pub trait Claims: Serialize + DeserializeOwned + SelfAddressed + Clone + Sync {}
impl<T: Serialize + DeserializeOwned + SelfAddressed + Clone + Sync> Claims for T {}

/// Typed credential. `T` is the claims payload.
/// Fields that are `SelfAddressed` use `Compactable<T>` to represent either
/// the expanded object or a compacted SAID string.
///
/// # Security: Atomic Issuance
///
/// The only public way to build a credential is [`Credential::build()`], which
/// takes fully expanded inputs and derives all inner SAIDs. The caller must then
/// anchor the canonical SAID in the issuer's KEL (e.g., via
/// `KeyEventBuilder::interact()`). This prevents signing credentials with
/// compacted (uninspected) fields — a compacted SAID commits to content the
/// issuer has not examined, allowing an attacker to hide malicious payloads
/// behind opaque hashes. `Credential` values can be constructed via
/// deserialization (for verification and disclosure of received credentials),
/// but issuance requires expanded types.
///
/// Disclosure and verification may operate on compacted or partially compacted
/// forms — the content commitment was already accepted at issuance time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Claims", rename_all = "camelCase")]
pub struct Credential<T: Claims> {
    pub said: cesr::Digest,
    pub schema: cesr::Digest,
    pub policy: cesr::Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<cesr::Digest>,
    pub issued_at: StorageDatetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub claims: Compactable<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<StorageDatetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Compactable<Edges>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Compactable<Rules>>,
}

impl<T: Claims> Credential<T> {
    /// Construct a credential from expanded inputs, validate against schema,
    /// and derive all inner SAIDs. Returns the expanded credential and its canonical SAID.
    ///
    /// The caller is responsible for anchoring the canonical SAID in endorser KELs
    /// per the policy (e.g., via `KeyEventBuilder::interact()`).
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        schema: &Schema,
        policy: &Policy,
        subject: Option<cesr::Digest>,
        claims: T,
        unique: bool,
        edges: Option<Edges>,
        rules: Option<Rules>,
        expires_at: Option<StorageDatetime>,
    ) -> Result<(Self, String), CredentialError> {
        let issued_at = StorageDatetime::now();

        let nonce = if unique {
            Some(generate_nonce().to_string())
        } else {
            None
        };

        let credential = Self {
            said: cesr::Digest::default(),
            schema: schema.said,
            policy: policy.said,
            subject,
            issued_at,
            nonce,
            claims: Compactable::Expanded(claims),
            expires_at,
            edges: edges.map(Compactable::Expanded),
            rules: rules.map(Compactable::Expanded),
        };

        let report = crate::schema::validate_credential_report(&credential, schema)?;
        report.require_valid()?;

        // Schema-aware compact to derive all inner SAIDs, then expand back.
        let mut value = serde_json::to_value(&credential)?;
        let chunks = compact_with_schema(&mut value, schema)?;

        let compacted_said = value
            .as_str()
            .ok_or_else(|| {
                CredentialError::CompactionError(
                    "compact did not produce a SAID string".to_string(),
                )
            })?
            .to_string();

        // Expand back using schema-aware expansion from the accumulator
        let temp_store = InMemorySADStore::new();
        temp_store.store_chunks(&chunks).await?;

        let said_str: &str = compacted_said.as_ref();
        let root_chunk = chunks.get(said_str).ok_or_else(|| {
            CredentialError::CompactionError(
                "compacted credential not found in accumulator".to_string(),
            )
        })?;
        let mut expanded_value = root_chunk.clone();
        expand_with_schema(&mut expanded_value, schema, &temp_store).await?;

        let credential: Self = serde_json::from_value(expanded_value)?;

        Ok((credential, compacted_said))
    }

    /// Store this credential's compacted chunks in a SAD store.
    /// Returns the compacted SAID (the canonical identifier for retrieval/disclosure).
    pub async fn store(
        &self,
        schema: &Schema,
        sad_store: &dyn SADStore,
    ) -> Result<cesr::Digest, CredentialError> {
        let (compacted_said, chunks) = self.compact(schema)?;
        sad_store.store_chunks(&chunks).await?;
        Ok(compacted_said)
    }

    /// Compact this credential into its canonical compacted form and a HashMap of all
    /// extracted chunks keyed by SAID. Uses schema-aware compaction — only fields
    /// the schema marks as `compactable: true` are compacted.
    pub fn compact(
        &self,
        schema: &Schema,
    ) -> Result<(cesr::Digest, HashMap<String, serde_json::Value>), CredentialError> {
        if self.schema != schema.said {
            return Err(CredentialError::InvalidSchema(format!(
                "schema SAID mismatch: credential references {}, provided schema has {}",
                self.schema, schema.said
            )));
        }
        let mut value = serde_json::to_value(self)?;
        let accumulator = compact_with_schema(&mut value, schema)?;
        let compacted_said = Self::said_from_value(value)?;
        Ok((compacted_said, accumulator))
    }

    /// Verify a typed credential against the KEL.
    /// If a SADStore is provided, recursively verifies edge-referenced credentials.
    /// Delegates to [`verify_credential`](crate::verification::verify_credential).
    pub async fn verify(
        &self,
        schema: &Schema,
        policy: &Policy,
        resolver: &dyn PolicyResolver,
        source: &(dyn PagedKelSource + Sync),
        sad_store: Option<&dyn SADStore>,
        edge_schemas: &BTreeMap<String, Schema>,
    ) -> Result<CredentialVerification, CredentialError> {
        verify_credential(
            self,
            schema,
            policy,
            resolver,
            source,
            sad_store,
            edge_schemas,
        )
        .await
    }

    fn said_from_value(value: serde_json::Value) -> Result<cesr::Digest, CredentialError> {
        let s = value.as_str().ok_or_else(|| {
            CredentialError::CompactionError(
                "compact_value did not produce a SAID string".to_string(),
            )
        })?;
        cesr::Digest::from_qb64(s).map_err(|e| {
            CredentialError::CompactionError(format!("invalid CESR SAID from compaction: {e}"))
        })
    }
}

impl<T: Claims> FromStr for Credential<T> {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;

    use cesr::Matter;

    use crate::schema::SchemaField;

    /// A simple claims type for testing.
    #[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
    struct TestClaims {
        #[said]
        said: cesr::Digest,
        name: String,
        age: u32,
    }

    fn test_schema() -> Schema {
        let claims_fields = BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            ("age".to_string(), SchemaField::integer()),
        ]);

        let mut fields = BTreeMap::new();
        fields.insert("schema".to_string(), SchemaField::said());
        fields.insert("policy".to_string(), SchemaField::said());
        fields.insert("issuedAt".to_string(), SchemaField::datetime());
        fields.insert("subject".to_string(), SchemaField::prefix().opt());
        fields.insert("nonce".to_string(), SchemaField::string().opt());
        fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
        fields.insert(
            "claims".to_string(),
            SchemaField::object(claims_fields, true),
        );
        fields.insert(
            "edges".to_string(),
            SchemaField::object(BTreeMap::new(), true).opt(),
        );
        fields.insert(
            "rules".to_string(),
            SchemaField::object(BTreeMap::new(), true).opt(),
        );

        Schema::create(
            "Test Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap()
    }

    fn test_policy(prefix: &str) -> Policy {
        Policy::build(&format!("endorse({prefix})"), None, false).unwrap()
    }

    fn test_claims() -> TestClaims {
        TestClaims::create("Alice".to_string(), 30u32).unwrap()
    }

    async fn test_credential() -> (Credential<TestClaims>, String) {
        let policy = test_policy("KIssuer123456789012345678901234567890abcde");
        Credential::build(
            &test_schema(),
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_credential_said_derivation() {
        let (cred, compacted_said) = test_credential().await;
        assert!(!compacted_said.is_empty());
        assert_eq!(compacted_said.len(), 44);
        // Expanded SAID differs from compacted SAID
        assert_ne!(cred.said.to_string(), compacted_said);
        assert_eq!(cred.said.as_ref().len(), 44);
    }

    #[tokio::test]
    async fn test_compact_credential_said_matches() {
        let (cred, _) = test_credential().await;
        let (compacted_said, chunks) = cred.compact(&test_schema()).unwrap();
        // Compacted credential is in the accumulator keyed by compacted SAID
        assert!(chunks.contains_key(compacted_said.as_ref()));
        let compacted_value = chunks.get(compacted_said.as_ref()).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        // schema is always a SAID string
        assert_eq!(compacted_cred.schema.as_ref().len(), 44);
        assert!(compacted_cred.claims.as_said().is_some());
    }

    #[tokio::test]
    async fn test_compact_credential_roundtrip() {
        let (cred, _) = test_credential().await;
        let (compacted1, _) = cred.compact(&test_schema()).unwrap();
        let (compacted2, _) = cred.compact(&test_schema()).unwrap();
        assert_eq!(compacted1, compacted2);
    }

    #[tokio::test]
    async fn test_unique_credential() {
        let policy = test_policy("KIssuer123456789012345678901234567890abcde");
        let (cred, _) = Credential::build(
            &test_schema(),
            &policy,
            None,
            test_claims(),
            true,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(cred.nonce.is_some());
    }

    #[tokio::test]
    async fn test_deterministic_credential() {
        let policy = test_policy("KIssuer123456789012345678901234567890abcde");
        let (cred, _) = Credential::build(
            &test_schema(),
            &policy,
            None,
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(cred.nonce.is_none());
    }

    #[tokio::test]
    async fn test_credential_with_edges() {
        use crate::edge::{Edge, Edges};

        let edge = Edge::create(test_digest("test-schema"), None, None, None).unwrap();

        let mut edges_map = BTreeMap::new();
        edges_map.insert("license".to_string(), edge);
        let edges = Edges::new_validated(edges_map).unwrap();

        let schema = {
            let claims_fields = BTreeMap::from([
                ("name".to_string(), SchemaField::string()),
                ("age".to_string(), SchemaField::integer()),
            ]);

            let edge_fields = BTreeMap::from([(
                "license".to_string(),
                SchemaField::object(
                    BTreeMap::from([
                        ("schema".to_string(), SchemaField::said()),
                        ("policy".to_string(), SchemaField::said().opt()),
                        ("credential".to_string(), SchemaField::said().opt()),
                        ("nonce".to_string(), SchemaField::string().opt()),
                    ]),
                    true,
                ),
            )]);

            let mut fields = BTreeMap::new();
            fields.insert("schema".to_string(), SchemaField::said());
            fields.insert("policy".to_string(), SchemaField::said());
            fields.insert("issuedAt".to_string(), SchemaField::datetime());
            fields.insert("subject".to_string(), SchemaField::prefix().opt());
            fields.insert("nonce".to_string(), SchemaField::string().opt());
            fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
            fields.insert(
                "claims".to_string(),
                SchemaField::object(claims_fields, true),
            );
            fields.insert(
                "edges".to_string(),
                SchemaField::object(edge_fields, true).opt(),
            );
            fields.insert(
                "rules".to_string(),
                SchemaField::object(BTreeMap::new(), true).opt(),
            );

            Schema::create(
                "Test Schema".to_string(),
                "A test".to_string(),
                "1.0".to_string(),
                fields,
            )
            .unwrap()
        };

        let policy = test_policy("KIssuer123456789012345678901234567890abcde");
        let (cred, _) = Credential::build(
            &schema,
            &policy,
            None,
            test_claims(),
            false,
            Some(edges),
            None,
            None,
        )
        .await
        .unwrap();

        let (compacted_said, chunks) = cred.compact(&schema).unwrap();
        assert!(chunks.contains_key(compacted_said.as_ref()));
        let compacted_value = chunks.get(compacted_said.as_ref()).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        assert!(compacted_cred.edges.is_some());
        let edges_said = compacted_cred.edges.as_ref().unwrap().as_said().unwrap();
        assert!(chunks.contains_key(edges_said.as_ref()));
    }

    #[tokio::test]
    async fn test_credential_with_rules() {
        use crate::rule::{Rule, Rules};

        let rule = Rule::create("For verification only".to_string()).unwrap();
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), rule);
        let rules = Rules::new_validated(rules_map).unwrap();

        let schema = {
            let claims_fields = BTreeMap::from([
                ("name".to_string(), SchemaField::string()),
                ("age".to_string(), SchemaField::integer()),
            ]);

            let rule_fields = BTreeMap::from([(
                "terms".to_string(),
                SchemaField::object(
                    BTreeMap::from([("condition".to_string(), SchemaField::string())]),
                    true,
                ),
            )]);

            let mut fields = BTreeMap::new();
            fields.insert("schema".to_string(), SchemaField::said());
            fields.insert("policy".to_string(), SchemaField::said());
            fields.insert("issuedAt".to_string(), SchemaField::datetime());
            fields.insert("subject".to_string(), SchemaField::prefix().opt());
            fields.insert("nonce".to_string(), SchemaField::string().opt());
            fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
            fields.insert(
                "claims".to_string(),
                SchemaField::object(claims_fields, true),
            );
            fields.insert(
                "edges".to_string(),
                SchemaField::object(BTreeMap::new(), true).opt(),
            );
            fields.insert(
                "rules".to_string(),
                SchemaField::object(rule_fields, true).opt(),
            );

            Schema::create(
                "Test Schema".to_string(),
                "A test".to_string(),
                "1.0".to_string(),
                fields,
            )
            .unwrap()
        };

        let policy = test_policy("KIssuer123456789012345678901234567890abcde");
        let (cred, _) = Credential::build(
            &schema,
            &policy,
            None,
            test_claims(),
            false,
            None,
            Some(rules),
            None,
        )
        .await
        .unwrap();

        let (compacted_said, chunks) = cred.compact(&schema).unwrap();
        assert!(chunks.contains_key(compacted_said.as_ref()));
        let compacted_value = chunks.get(compacted_said.as_ref()).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        assert!(compacted_cred.rules.is_some());
        let rules_said = compacted_cred.rules.as_ref().unwrap().as_said().unwrap();
        assert!(chunks.contains_key(rules_said.as_ref()));
    }

    #[tokio::test]
    async fn test_credential_serialization_roundtrip() {
        let (cred, _) = test_credential().await;
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential<TestClaims> = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.said, deserialized.said);
    }

    // ==================== Integration tests — verify with real KEL ====================

    use std::sync::Arc;

    use kels_core::{
        FileKelStore, KeyEventBuilder, SoftwareKeyProvider, StoreKelSource, VerificationKeyCode,
    };
    use kels_policy::InMemoryPolicyResolver;

    async fn setup_kel() -> (
        KeyEventBuilder<SoftwareKeyProvider>,
        cesr::Digest,
        Arc<FileKelStore>,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let kel_store = Arc::new(FileKelStore::new(temp_dir.path()).unwrap());
        let mut builder = KeyEventBuilder::with_dependencies(
            SoftwareKeyProvider::new(
                VerificationKeyCode::Secp256r1,
                VerificationKeyCode::Secp256r1,
            ),
            None,
            Some(kel_store.clone() as Arc<dyn kels_core::KelStore>),
            None,
        )
        .await
        .unwrap();
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix;
        (builder, prefix, kel_store, temp_dir)
    }

    async fn credential_for_prefix(
        prefix: &cesr::Digest,
    ) -> (Credential<TestClaims>, String, Policy) {
        let policy = test_policy(prefix.as_ref());
        let (cred, said) = Credential::build(
            &test_schema(),
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        (cred, said, policy)
    }

    #[tokio::test]
    async fn test_verify_issued_credential() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = test_policy(prefix.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        result.is_valid(true).unwrap();
        assert_eq!(result.credential, cred.said);
        assert_eq!(result.policy, policy.said);
    }

    #[tokio::test]
    async fn test_verify_unissued_credential() {
        let (_builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let (cred, _, policy) = credential_for_prefix(&prefix).await;
        let resolver = InMemoryPolicyResolver::empty();

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(result.is_valid(true).is_err());
    }

    #[tokio::test]
    async fn test_verify_poisoned_credential() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = test_policy(prefix.as_ref());
        let resolver = InMemoryPolicyResolver::empty();

        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        // Anchor poison hash
        let p_hash = kels_policy::poison_hash(&compacted_said);
        builder.interact(&p_hash).await.unwrap();

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(result.is_valid(true).is_err());
        assert!(!result.policy_verification.is_satisfied);
    }

    #[tokio::test]
    async fn test_verify_immune_ignores_poison_hash() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = Policy::build(&format!("endorse({prefix})"), None, true).unwrap();
        let resolver = InMemoryPolicyResolver::empty();

        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            None,
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        // Anchor the poison hash — should be ignored for immune policy
        let p_hash = kels_policy::poison_hash(&compacted_said);
        builder.interact(&p_hash).await.unwrap();

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        result.is_valid(true).unwrap();
    }

    #[tokio::test]
    async fn test_verify_not_expired() {
        use std::time::Duration;

        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = test_policy(prefix.as_ref());
        let resolver = InMemoryPolicyResolver::empty();

        let far_future = StorageDatetime::now() + Duration::from_secs(3600);
        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            None,
            test_claims(),
            false,
            None,
            None,
            Some(far_future),
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        result.is_valid(true).unwrap();
    }

    #[tokio::test]
    async fn test_verify_schema_validation_expanded() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = test_policy(prefix.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        let result = cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(result.schema_validation.valid);
    }

    #[tokio::test]
    async fn test_verify_schema_validation_compacted() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let schema = test_schema();
        let policy = test_policy(prefix.as_ref());
        let resolver = InMemoryPolicyResolver::empty();

        // Build via the expanded API — Credential::build() takes expanded types
        // by value, so compacted credentials cannot be built. This test verifies
        // that schema validation works on the compacted *form* of a legitimately
        // issued credential during verification.
        let (cred, compacted_said) = Credential::build(
            &schema,
            &policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder
                .interact(&cesr::Digest::from_qb64(&compacted_said).unwrap())
                .await
                .unwrap();
        }

        // Get the compacted form and verify schema validation works on it
        let (_, chunks) = cred.compact(&schema).unwrap();
        let compacted_value = chunks
            .values()
            .find(|v| {
                v.get("policy")
                    .and_then(|p| p.as_str())
                    .is_some_and(|p| p == policy.said.as_ref())
            })
            .unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();

        let result = compacted_cred
            .verify(
                &schema,
                &policy,
                &resolver,
                &StoreKelSource::new(kel_store.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(result.schema_validation.valid);
        assert!(result.schema_validation.errors.is_empty());
    }

    #[tokio::test]
    async fn test_verify_chained_credentials() {
        use kels_core::forward_key_events;

        use crate::edge::{Edge, Edges};

        // Set up two issuers with separate KELs
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_b, prefix_b, kel_store_b, _dir_b) = setup_kel().await;

        let schema_a = test_schema();
        let policy_a = test_policy(prefix_a.as_ref());

        // Issuer A issues a base credential
        let (cred_a, compacted_said_a) = Credential::build(
            &schema_a,
            &policy_a,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder_a
                .interact(&cesr::Digest::from_qb64(&compacted_said_a).unwrap())
                .await
                .unwrap();
        }

        // Store credential A in a shared SADStore
        let sad_store = InMemorySADStore::new();
        cred_a.store(&schema_a, &sad_store).await.unwrap();

        // Issuer B issues a credential with an edge referencing A's credential
        let edge = Edge::create(
            cred_a.schema,
            Some(policy_a.said),
            Some(cesr::Digest::from_qb64(&compacted_said_a).unwrap()),
            None,
        )
        .unwrap();

        let mut edges_map = BTreeMap::new();
        edges_map.insert("license".to_string(), edge);
        let edges = Edges::new_validated(edges_map).unwrap();

        // Schema with edge fields described
        let edge_fields = BTreeMap::from([(
            "license".to_string(),
            SchemaField::object(
                BTreeMap::from([
                    ("schema".to_string(), SchemaField::said()),
                    ("policy".to_string(), SchemaField::said().opt()),
                    ("credential".to_string(), SchemaField::said().opt()),
                    ("nonce".to_string(), SchemaField::string().opt()),
                ]),
                true,
            ),
        )]);

        let claims_fields = BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            ("age".to_string(), SchemaField::integer()),
        ]);

        let mut fields = BTreeMap::new();
        fields.insert("schema".to_string(), SchemaField::said());
        fields.insert("policy".to_string(), SchemaField::said());
        fields.insert("issuedAt".to_string(), SchemaField::datetime());
        fields.insert("subject".to_string(), SchemaField::prefix().opt());
        fields.insert("nonce".to_string(), SchemaField::string().opt());
        fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
        fields.insert(
            "claims".to_string(),
            SchemaField::object(claims_fields, true),
        );
        fields.insert(
            "edges".to_string(),
            SchemaField::object(edge_fields, true).opt(),
        );
        fields.insert(
            "rules".to_string(),
            SchemaField::object(BTreeMap::new(), true).opt(),
        );

        let schema_b = Schema::create(
            "Test Schema B".to_string(),
            "Schema with edges".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let policy_b = test_policy(prefix_b.as_ref());
        let (cred_b, compacted_said_b) = Credential::build(
            &schema_b,
            &policy_b,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            Some(edges),
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder_b
                .interact(&cesr::Digest::from_qb64(&compacted_said_b).unwrap())
                .await
                .unwrap();
        }

        cred_b.store(&schema_b, &sad_store).await.unwrap();

        // Edge schemas map for recursive verification
        let edge_schemas = BTreeMap::from([(schema_a.said.to_string(), schema_a.clone())]);

        // Verify A alone works:
        let resolver_a = InMemoryPolicyResolver::empty();
        let result_a = cred_a
            .verify(
                &schema_a,
                &policy_a,
                &resolver_a,
                &StoreKelSource::new(kel_store_a.as_ref()),
                None,
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(result_a.policy_verification.is_satisfied);
        result_a.is_valid(true).unwrap();

        // Merge KEL stores so B's store has A's KEL too
        let source_a = StoreKelSource::new(kel_store_a.as_ref());
        let sink_b = kels_core::KelStoreSink(kel_store_b.as_ref());
        forward_key_events(
            &prefix_a,
            &source_a,
            &sink_b,
            kels_core::page_size(),
            kels_core::max_pages(),
            None,
        )
        .await
        .unwrap();

        // Verify B without SADStore — edges not checked
        let resolver_b = InMemoryPolicyResolver::new(vec![policy_a.clone()]);
        let result_b_no_edges = cred_b
            .verify(
                &schema_b,
                &policy_b,
                &resolver_b,
                &StoreKelSource::new(kel_store_b.as_ref()),
                None,
                &edge_schemas,
            )
            .await
            .unwrap();
        assert!(result_b_no_edges.policy_verification.is_satisfied);
        assert!(result_b_no_edges.edge_verifications.is_empty());

        // Verify B with SADStore — edge credential A is verified recursively
        let result_b = cred_b
            .verify(
                &schema_b,
                &policy_b,
                &resolver_b,
                &StoreKelSource::new(kel_store_b.as_ref()),
                Some(&sad_store),
                &edge_schemas,
            )
            .await
            .unwrap();
        assert!(result_b.policy_verification.is_satisfied);
        assert!(result_b.edge_verifications.contains_key("license"));
        let edge_v = result_b.edge_verifications.get("license").unwrap();
        assert!(edge_v.policy_verification.is_satisfied);
        assert_eq!(edge_v.policy, policy_a.said);
    }

    #[tokio::test]
    async fn test_verify_three_level_chain() {
        use kels_core::forward_key_events;

        use crate::edge::{Edge, Edges};

        // Three issuers: root -> intermediate -> leaf
        let (mut builder_root, prefix_root, kel_store_root, _dir_root) = setup_kel().await;
        let (mut builder_mid, prefix_mid, kel_store_mid, _dir_mid) = setup_kel().await;
        let (mut builder_leaf, prefix_leaf, kel_store_leaf, _dir_leaf) = setup_kel().await;

        let sad_store = InMemorySADStore::new();
        let root_schema = test_schema();
        let root_policy = test_policy(prefix_root.as_ref());

        // Root credential (no edges)
        let (cred_root, compacted_root) = Credential::build(
            &root_schema,
            &root_policy,
            Some(test_digest("test-subject")),
            test_claims(),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder_root
                .interact(&cesr::Digest::from_qb64(&compacted_root).unwrap())
                .await
                .unwrap();
        }
        cred_root.store(&root_schema, &sad_store).await.unwrap();

        // Helper to build a schema with edge fields
        let make_edge_schema = |edge_label: &str| {
            let edge_fields = BTreeMap::from([(
                edge_label.to_string(),
                SchemaField::object(
                    BTreeMap::from([
                        ("schema".to_string(), SchemaField::said()),
                        ("policy".to_string(), SchemaField::said().opt()),
                        ("credential".to_string(), SchemaField::said().opt()),
                        ("nonce".to_string(), SchemaField::string().opt()),
                    ]),
                    true,
                ),
            )]);

            let claims_fields = BTreeMap::from([
                ("name".to_string(), SchemaField::string()),
                ("age".to_string(), SchemaField::integer()),
            ]);

            let mut fields = BTreeMap::new();
            fields.insert("schema".to_string(), SchemaField::said());
            fields.insert("policy".to_string(), SchemaField::said());
            fields.insert("issuedAt".to_string(), SchemaField::datetime());
            fields.insert("subject".to_string(), SchemaField::prefix().opt());
            fields.insert("nonce".to_string(), SchemaField::string().opt());
            fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
            fields.insert(
                "claims".to_string(),
                SchemaField::object(claims_fields, true),
            );
            fields.insert(
                "edges".to_string(),
                SchemaField::object(edge_fields, true).opt(),
            );
            fields.insert(
                "rules".to_string(),
                SchemaField::object(BTreeMap::new(), true).opt(),
            );

            Schema::create(
                "Edge Schema".to_string(),
                "Schema with edge".to_string(),
                "1.0".to_string(),
                fields,
            )
            .unwrap()
        };

        // Intermediate credential with edge to root
        let edge_to_root = Edge::create(
            cred_root.schema,
            Some(root_policy.said),
            Some(cesr::Digest::from_qb64(&compacted_root).unwrap()),
            None,
        )
        .unwrap();
        let mut mid_edges = BTreeMap::new();
        mid_edges.insert("root".to_string(), edge_to_root);

        let mid_schema = make_edge_schema("root");
        let mid_policy = test_policy(prefix_mid.as_ref());
        let (cred_mid, compacted_mid) = Credential::build(
            &mid_schema,
            &mid_policy,
            None,
            test_claims(),
            false,
            Some(Edges::new_validated(mid_edges).unwrap()),
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder_mid
                .interact(&cesr::Digest::from_qb64(&compacted_mid).unwrap())
                .await
                .unwrap();
        }
        cred_mid.store(&mid_schema, &sad_store).await.unwrap();

        // Leaf credential with edge to intermediate
        let edge_to_mid = Edge::create(
            cred_mid.schema,
            Some(mid_policy.said),
            Some(cesr::Digest::from_qb64(&compacted_mid).unwrap()),
            None,
        )
        .unwrap();
        let mut leaf_edges = BTreeMap::new();
        leaf_edges.insert("authority".to_string(), edge_to_mid);

        let leaf_schema = make_edge_schema("authority");
        let leaf_policy = test_policy(prefix_leaf.as_ref());
        let (cred_leaf, compacted_leaf) = Credential::build(
            &leaf_schema,
            &leaf_policy,
            None,
            test_claims(),
            false,
            Some(Edges::new_validated(leaf_edges).unwrap()),
            None,
            None,
        )
        .await
        .unwrap();
        {
            use cesr::Matter;
            builder_leaf
                .interact(&cesr::Digest::from_qb64(&compacted_leaf).unwrap())
                .await
                .unwrap();
        }
        cred_leaf.store(&leaf_schema, &sad_store).await.unwrap();

        // All edge schemas for recursive verification
        let edge_schemas = BTreeMap::from([
            (root_schema.said.to_string(), root_schema),
            (mid_schema.said.to_string(), mid_schema),
        ]);

        // Merge all KEL stores into the leaf store
        {
            let source = StoreKelSource::new(kel_store_root.as_ref());
            let sink = kels_core::KelStoreSink(kel_store_leaf.as_ref());
            forward_key_events(
                &prefix_root,
                &source,
                &sink,
                kels_core::page_size(),
                kels_core::max_pages(),
                None,
            )
            .await
            .unwrap();
        }
        {
            let source = StoreKelSource::new(kel_store_mid.as_ref());
            let sink = kels_core::KelStoreSink(kel_store_leaf.as_ref());
            forward_key_events(
                &prefix_mid,
                &source,
                &sink,
                kels_core::page_size(),
                kels_core::max_pages(),
                None,
            )
            .await
            .unwrap();
        }

        // Resolver knows all policies for edge verification
        let resolver = InMemoryPolicyResolver::new(vec![root_policy.clone(), mid_policy.clone()]);

        // Verify leaf — should recursively verify intermediate and root
        let result = cred_leaf
            .verify(
                &leaf_schema,
                &leaf_policy,
                &resolver,
                &StoreKelSource::new(kel_store_leaf.as_ref()),
                Some(&sad_store),
                &edge_schemas,
            )
            .await
            .unwrap();

        assert!(result.policy_verification.is_satisfied);
        assert!(result.edge_verifications.contains_key("authority"));

        let mid_v = result.edge_verifications.get("authority").unwrap();
        assert_eq!(mid_v.policy, mid_policy.said);
        assert!(mid_v.edge_verifications.contains_key("root"));

        let root_v = mid_v.edge_verifications.get("root").unwrap();
        assert_eq!(root_v.policy, root_policy.said);
        assert!(root_v.edge_verifications.is_empty());
    }
}
