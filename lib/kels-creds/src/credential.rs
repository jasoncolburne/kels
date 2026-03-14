use std::collections::HashMap;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use verifiable_storage::{SelfAddressed, StorageDatetime, compact_value_bounded};

use crate::edge::Edges;
use crate::error::CredentialError;
use crate::rule::Rules;
use crate::schema::CredentialSchema;
use crate::store::SADStore;

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
        store: &dyn SADStore,
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

        let (compacted_said, chunks) = credential.compact()?;
        store.store_chunks(&chunks).await?;

        // Reconstruct from store — all SAIDs are now correctly derived
        let mut expanded = serde_json::to_value(&compacted_said)?;
        crate::compaction::expand_all(&mut expanded, store).await?;
        let credential: Self = serde_json::from_value(expanded)?;

        Ok((credential, compacted_said))
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
    use crate::store::InMemorySADStore;

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
        let store = InMemorySADStore::new();
        Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            Some("ESubject23456789012345678901234567890abcde".to_string()),
            test_claims(),
            None,
            None,
            None,
            None,
            &store,
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

        let store = InMemorySADStore::new();
        let (cred, _) = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            test_claims(),
            Some(edges),
            None,
            None,
            None,
            &store,
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

        let store = InMemorySADStore::new();
        let (cred, _) = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            test_claims(),
            None,
            Some(rules),
            None,
            None,
            &store,
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
}
