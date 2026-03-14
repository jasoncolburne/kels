use std::collections::HashMap;
use std::str::FromStr;

use kels::{
    KelStore, KelVerifier, KeyEventBuilder, KeyProvider, MAX_EVENTS_PER_KEL_QUERY, StoreKelSource,
    verify_key_events,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use verifiable_storage::{
    SelfAddressed, StorageDatetime, compact_value_bounded, compute_said_from_value,
};

use crate::edge::Edges;
use crate::error::CredentialError;
use crate::revocation::revocation_hash;
use crate::rule::Rules;
use crate::schema::{CredentialSchema, validate_claims};
use crate::store::{InMemorySADStore, SADStore};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compactable<T> {
    Said(String),
    Expanded(T),
}

impl<T> Compactable<T> {
    pub fn as_said(&self) -> Option<&str> {
        match self {
            Compactable::Said(s) => Some(s),
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

/// Result of schema validation during credential verification.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaValidationResult {
    Valid,
    Invalid,
    NotValidated,
}

/// The result of verifying a single credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub kel_error: Option<String>,
    pub schema_validation: SchemaValidationResult,
}

/// Trait alias for the bounds required on credential claims types.
pub trait Claims: Serialize + DeserializeOwned + SelfAddressed + Clone {}
impl<T: Serialize + DeserializeOwned + SelfAddressed + Clone> Claims for T {}

/// Typed credential for issuance. `T` is the claims payload.
/// Fields that are `SelfAddressed` use `Compactable<T>` to represent either
/// the expanded object or a compacted SAID string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Claims", rename_all = "camelCase")]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: Compactable<CredentialSchema>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    pub claims: Compactable<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<StorageDatetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irrevocable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Compactable<Edges>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Compactable<Rules>>,
}

impl<T: Claims> Credential<T> {
    /// Create a new credential with all inner SAIDs derived.
    /// `issued_at` is auto-populated with the current timestamp.
    /// Does NOT store the credential — call `store()` separately.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        schema: CredentialSchema,
        issuer: String,
        subject: Option<String>,
        claims: T,
        edges: Option<Edges>,
        rules: Option<Rules>,
        irrevocable: Option<bool>,
        expires_at: Option<StorageDatetime>,
    ) -> Result<(Self, String), CredentialError> {
        crate::schema::validate_schema(&schema)?;
        crate::schema::validate_claims(&schema, &serde_json::to_value(&claims)?)?;
        crate::schema::validate_edges(&schema, edges.as_ref())?;
        crate::schema::validate_rules(&schema, rules.as_ref())?;

        let issued_at = StorageDatetime::now();

        // Validate expires_at against schema.expires
        if schema.expires {
            let exp = expires_at.as_ref().ok_or_else(|| {
                CredentialError::SchemaValidationError(
                    "schema requires expires_at but none provided".to_string(),
                )
            })?;
            if exp <= &issued_at {
                return Err(CredentialError::SchemaValidationError(
                    "expires_at must be after issued_at".to_string(),
                ));
            }
        } else if expires_at.is_some() {
            return Err(CredentialError::SchemaValidationError(
                "schema does not allow expires_at".to_string(),
            ));
        }

        let credential = Self {
            said: String::new(),
            schema: Compactable::Expanded(schema),
            issuer,
            subject,
            issued_at,
            claims: Compactable::Expanded(claims),
            expires_at,
            irrevocable,
            edges: edges.map(Compactable::Expanded),
            rules: rules.map(Compactable::Expanded),
        };

        // Compact/expand cycle to derive all SAIDs
        let (compacted_said, chunks) = credential.compact()?;
        let temp_store = InMemorySADStore::new();
        temp_store.store_chunks(&chunks).await?;

        let mut expanded = serde_json::to_value(&compacted_said)?;
        crate::compaction::expand_all(&mut expanded, &temp_store).await?;
        let credential: Self = serde_json::from_value(expanded)?;

        Ok((credential, compacted_said))
    }

    /// Issue this credential by anchoring its compacted SAID in the issuer's KEL.
    /// Returns the compacted SAID.
    pub async fn issue<K: KeyProvider + Clone>(
        &self,
        builder: &mut KeyEventBuilder<K>,
    ) -> Result<String, CredentialError> {
        let (compacted_said, _) = self.compact()?;
        builder.interact(&compacted_said).await?;
        Ok(compacted_said)
    }

    /// Store this credential's compacted chunks in a SAD store.
    /// Returns the compacted SAID (the canonical identifier for retrieval/disclosure).
    pub async fn store(&self, sad_store: &dyn SADStore) -> Result<String, CredentialError> {
        let (compacted_said, chunks) = self.compact()?;
        sad_store.store_chunks(&chunks).await?;
        Ok(compacted_said)
    }

    /// Compact this credential into its canonical compacted form and a HashMap of all
    /// extracted chunks keyed by SAID.
    pub fn compact(&self) -> Result<(String, HashMap<String, serde_json::Value>), CredentialError> {
        let mut value = serde_json::to_value(self)?;
        let mut accumulator: HashMap<String, serde_json::Value> = HashMap::new();
        compact_value_bounded(
            &mut value,
            &mut accumulator,
            crate::compaction::MAX_EXPANSION_DEPTH,
        )?;

        // value is now a SAID string — the compacted credential is in the accumulator
        let compacted_said = Self::string_from_value(value)?;
        Ok((compacted_said, accumulator))
    }

    /// Verify a typed credential against the KEL.
    ///
    /// Checks:
    /// 1. Expanded SAID integrity — recompute SAID from credential data
    /// 2. Compacted SAID integrity — compact to canonical form, verify consistency
    /// 3. KEL anchoring — issuer's KEL contains the compacted credential SAID
    /// 4. Revocation — issuer's KEL contains the revocation hash (unless irrevocable)
    /// 5. Expiration — `expiresAt` vs current time
    /// 6. Schema validation — if both schema and claims are expanded
    pub async fn verify(
        &self,
        kel_store: &dyn KelStore,
    ) -> Result<CredentialVerification, CredentialError> {
        // Expanded SAID integrity — verify the credential's own SAID is consistent with data
        let value = serde_json::to_value(self)?;
        let computed_said = compute_said_from_value(&value)?;
        if computed_said != self.said {
            return Err(CredentialError::VerificationError(format!(
                "SAID mismatch: credential has {}, data produces {}",
                self.said, computed_said
            )));
        }

        // Compacted SAID integrity — compact and derive the anchored SAID
        let (compacted_said, _) = self.compact()?;

        // Schema validation (if both schema and claims are expanded)
        let schema_validation = match (&self.schema, &self.claims) {
            (Compactable::Expanded(schema), Compactable::Expanded(claims)) => {
                if validate_claims(schema, &serde_json::to_value(claims)?).is_ok() {
                    SchemaValidationResult::Valid
                } else {
                    SchemaValidationResult::Invalid
                }
            }
            _ => SchemaValidationResult::NotValidated,
        };

        // KEL verification — check anchoring (compacted SAID) and revocation
        let irrevocable = self.irrevocable.unwrap_or(false);
        let rev_hash = if irrevocable {
            None
        } else {
            Some(revocation_hash(&compacted_said))
        };

        let mut saids_to_check = vec![compacted_said.clone()];
        if let Some(ref rh) = rev_hash {
            saids_to_check.push(rh.clone());
        }

        let mut verifier = KelVerifier::new(&self.issuer);
        verifier.check_anchors(saids_to_check);

        let source = StoreKelSource::new(kel_store);
        let (is_issued, is_revoked, kel_error) = match verify_key_events(
            &self.issuer,
            &source,
            verifier,
            MAX_EVENTS_PER_KEL_QUERY,
            1024,
        )
        .await
        {
            Ok(kel_v) => {
                let issued = kel_v.is_said_anchored(&compacted_said);
                let revoked = rev_hash
                    .as_ref()
                    .is_some_and(|rh| kel_v.is_said_anchored(rh));
                (issued, revoked, None)
            }
            Err(e) => (false, false, Some(e)),
        };

        // Check expiration
        let is_expired = self
            .expires_at
            .as_ref()
            .is_some_and(|exp| exp <= &StorageDatetime::now());

        Ok(CredentialVerification {
            credential_said: self.said.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            is_issued,
            is_revoked,
            is_expired,
            kel_error: kel_error.map(|e| e.to_string()),
            schema_validation,
        })
    }

    fn string_from_value(value: serde_json::Value) -> Result<String, CredentialError> {
        Ok(value
            .as_str()
            .ok_or_else(|| {
                CredentialError::CompactionError(
                    "compact_value did not produce a SAID string".to_string(),
                )
            })?
            .to_string())
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
    use super::*;
    use std::collections::BTreeMap;

    use crate::schema::SchemaField;

    /// A simple claims type for testing.
    #[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
    struct TestClaims {
        #[said]
        said: String,
        name: String,
        age: u32,
    }

    fn test_schema() -> CredentialSchema {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::String);
        fields.insert("age".to_string(), SchemaField::Integer);

        CredentialSchema::create(
            "Test Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
            false,
            None,
            None,
        )
        .unwrap()
    }

    fn test_claims() -> TestClaims {
        TestClaims::create("Alice".to_string(), 30u32).unwrap()
    }

    async fn test_credential() -> (Credential<TestClaims>, String) {
        Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            Some("ESubject23456789012345678901234567890abcde".to_string()),
            test_claims(),
            None,
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
        assert_ne!(cred.said, compacted_said);
        assert_eq!(cred.said.len(), 44);
    }

    #[tokio::test]
    async fn test_compact_credential_said_matches() {
        let (cred, _) = test_credential().await;
        let (compacted_said, chunks) = cred.compact().unwrap();
        // Compacted credential is in the accumulator keyed by compacted SAID
        assert!(chunks.contains_key(&compacted_said));
        let compacted_value = chunks.get(&compacted_said).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        assert!(compacted_cred.schema.as_said().is_some());
        assert!(compacted_cred.claims.as_said().is_some());
    }

    #[tokio::test]
    async fn test_compact_credential_roundtrip() {
        let (cred, _) = test_credential().await;
        let (compacted1, _) = cred.compact().unwrap();
        let (compacted2, _) = cred.compact().unwrap();
        assert_eq!(compacted1, compacted2);
    }

    #[tokio::test]
    async fn test_credential_with_edges() {
        use crate::edge::{Edge, Edges};

        let edge = Edge::create(
            "EAbc1234567890123456789012345678901234567890".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let mut edges_map = BTreeMap::new();
        edges_map.insert("license".to_string(), edge);
        let edges = Edges::new_validated(edges_map).unwrap();

        let (cred, _) = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            test_claims(),
            Some(edges),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let (compacted_said, chunks) = cred.compact().unwrap();
        assert!(chunks.contains_key(&compacted_said));
        let compacted_value = chunks.get(&compacted_said).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        assert!(compacted_cred.edges.is_some());
        let edges_said = compacted_cred.edges.as_ref().unwrap().as_said().unwrap();
        assert!(chunks.contains_key(edges_said));
    }

    #[tokio::test]
    async fn test_credential_with_rules() {
        use crate::rule::{Rule, Rules};

        let rule = Rule::create("For verification only".to_string()).unwrap();
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), rule);
        let rules = Rules::new_validated(rules_map).unwrap();

        let (cred, _) = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            test_claims(),
            None,
            Some(rules),
            None,
            None,
        )
        .await
        .unwrap();

        let (compacted_said, chunks) = cred.compact().unwrap();
        assert!(chunks.contains_key(&compacted_said));
        let compacted_value = chunks.get(&compacted_said).unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();
        assert!(compacted_cred.rules.is_some());
        let rules_said = compacted_cred.rules.as_ref().unwrap().as_said().unwrap();
        assert!(chunks.contains_key(rules_said));
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

    use kels::{FileKelStore, SoftwareKeyProvider};

    async fn setup_kel() -> (
        KeyEventBuilder<SoftwareKeyProvider>,
        String,
        Arc<FileKelStore>,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let kel_store = Arc::new(FileKelStore::new(temp_dir.path()).unwrap());
        let mut builder = KeyEventBuilder::with_dependencies(
            SoftwareKeyProvider::new(),
            None,
            Some(kel_store.clone() as Arc<dyn kels::KelStore>),
            None,
        )
        .await
        .unwrap();
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        (builder, prefix, kel_store, temp_dir)
    }

    async fn credential_for_issuer(issuer: &str) -> (Credential<TestClaims>, String) {
        Credential::create(
            test_schema(),
            issuer.to_string(),
            Some("ESubject23456789012345678901234567890abcde".to_string()),
            test_claims(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_verify_issued_credential() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let (cred, _) = credential_for_issuer(&prefix).await;

        cred.issue(&mut builder).await.unwrap();

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(result.is_issued);
        assert!(!result.is_revoked);
        assert!(!result.is_expired);
        assert_eq!(result.credential_said, cred.said);
        assert_eq!(result.issuer, prefix);
    }

    #[tokio::test]
    async fn test_verify_unissued_credential() {
        let (_builder, prefix, kel_store, _dir) = setup_kel().await;
        let (cred, _) = credential_for_issuer(&prefix).await;

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(!result.is_issued);
        assert!(!result.is_revoked);
    }

    #[tokio::test]
    async fn test_verify_revoked_credential() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let (cred, _) = credential_for_issuer(&prefix).await;

        // Issue
        let compacted_said = cred.issue(&mut builder).await.unwrap();

        // Anchor revocation (hash of compacted SAID)
        let rev_hash = crate::revocation::revocation_hash(&compacted_said);
        builder.interact(&rev_hash).await.unwrap();

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(result.is_issued);
        assert!(result.is_revoked);
    }

    #[tokio::test]
    async fn test_verify_irrevocable_ignores_revocation_hash() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;

        let (cred, _) = Credential::create(
            test_schema(),
            prefix.clone(),
            None,
            test_claims(),
            None,
            None,
            Some(true),
            None,
        )
        .await
        .unwrap();

        // Issue
        let compacted_said = cred.issue(&mut builder).await.unwrap();

        // Anchor the revocation hash — should be ignored
        let rev_hash = crate::revocation::revocation_hash(&compacted_said);
        builder.interact(&rev_hash).await.unwrap();

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(result.is_issued);
        assert!(!result.is_revoked);
    }

    #[tokio::test]
    async fn test_verify_not_expired() {
        use std::time::Duration;

        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;

        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::String);
        fields.insert("age".to_string(), SchemaField::Integer);
        let schema = CredentialSchema::create(
            "Expiring Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
            true,
            None,
            None,
        )
        .unwrap();

        let far_future = StorageDatetime::now() + Duration::from_secs(3600);
        let (cred, _) = Credential::create(
            schema,
            prefix.clone(),
            None,
            test_claims(),
            None,
            None,
            None,
            Some(far_future),
        )
        .await
        .unwrap();

        cred.issue(&mut builder).await.unwrap();

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(result.is_issued);
        assert!(!result.is_expired);
    }

    #[tokio::test]
    async fn test_verify_schema_validation_expanded() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let (cred, _) = credential_for_issuer(&prefix).await;

        cred.issue(&mut builder).await.unwrap();

        let result = cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(matches!(
            result.schema_validation,
            SchemaValidationResult::Valid
        ));
    }

    #[tokio::test]
    async fn test_verify_schema_validation_compacted() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let (cred, _) = credential_for_issuer(&prefix).await;

        // Get the compacted credential (schema and claims are SAIDs)
        let (_, chunks) = cred.compact().unwrap();
        let compacted_value = chunks
            .values()
            .find(|v| {
                v.get("issuer")
                    .and_then(|i| i.as_str())
                    .is_some_and(|i| i == prefix)
            })
            .unwrap();
        let compacted_cred: Credential<TestClaims> =
            serde_json::from_value(compacted_value.clone()).unwrap();

        compacted_cred.issue(&mut builder).await.unwrap();

        let result = compacted_cred.verify(kel_store.as_ref()).await.unwrap();
        assert!(matches!(
            result.schema_validation,
            SchemaValidationResult::NotValidated
        ));
    }
}
