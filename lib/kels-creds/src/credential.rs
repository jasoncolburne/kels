use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use verifiable_storage::{SelfAddressed, StorageDatetime, compact_value};

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
#[serde(bound = "T: Claims")]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: Compactable<CredentialSchema>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub issued_at: StorageDatetime,
    pub claims: Compactable<T>,
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
        mut schema: CredentialSchema,
        issuer: String,
        subject: Option<String>,
        mut claims: T,
        edges: Option<Edges>,
        rules: Option<Rules>,
        irrevocable: Option<bool>,
        store: &dyn SADStore,
    ) -> Result<(Self, String), CredentialError> {
        schema.derive_said()?;
        claims.derive_said()?;

        let mut credential = Self {
            said: String::new(),
            schema: Compactable::Expanded(schema),
            issuer,
            subject,
            issued_at: StorageDatetime::now(),
            claims: Compactable::Expanded(claims),
            irrevocable,
            edges: edges.map(Compactable::Expanded),
            rules: rules.map(Compactable::Expanded),
        };

        let (compacted, chunks) = credential.compact()?;
        credential.said = compacted.said.clone();
        store.store_chunks(&chunks).await?;

        Ok((credential, compacted.said))
    }

    /// Compact this credential into its canonical compacted form and a HashMap of all
    /// extracted chunks keyed by SAID.
    pub fn compact(
        &self,
    ) -> Result<(Credential<T>, HashMap<String, serde_json::Value>), CredentialError> {
        let mut value = serde_json::to_value(self)?;
        let mut accumulator: HashMap<String, serde_json::Value> = HashMap::new();
        compact_value(&mut value, &mut accumulator)?;

        // value is now a SAID string — the compacted credential is in the accumulator
        let compacted_said = Self::string_from_value(value)?;
        let compacted_value = accumulator.get(&compacted_said).ok_or_else(|| {
            CredentialError::CompactionError("Couldn't find root chunk in accumulator".to_string())
        })?;

        let compacted: Credential<T> = serde_json::from_value(compacted_value.clone())?;

        Ok((compacted, accumulator))
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
            &store,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_credential_said_derivation() {
        let (cred, said) = test_credential().await;
        assert!(!said.is_empty());
        assert_eq!(said.len(), 44);
        assert_eq!(cred.said, said);
    }

    #[tokio::test]
    async fn test_compact_credential_said_matches() {
        let (cred, _) = test_credential().await;
        let (compact, chunks) = cred.compact().unwrap();
        assert_eq!(compact.said, cred.said);
        // All chunks should be in the accumulator
        assert!(chunks.contains_key(&compact.said));
        assert!(chunks.contains_key(compact.schema.as_said().unwrap()));
        assert!(chunks.contains_key(compact.claims.as_said().unwrap()));
    }

    #[tokio::test]
    async fn test_compact_credential_roundtrip() {
        let (cred, _) = test_credential().await;
        let (compact1, _) = cred.compact().unwrap();
        let (compact2, _) = cred.compact().unwrap();
        assert_eq!(compact1.said, compact2.said);
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
            &store,
        )
        .await
        .unwrap();

        let (compact, chunks) = cred.compact().unwrap();
        assert_eq!(compact.said, cred.said);
        assert!(compact.edges.is_some());
        let edges_said = compact.edges.as_ref().unwrap().as_said().unwrap();
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
            &store,
        )
        .await
        .unwrap();

        let (compact, chunks) = cred.compact().unwrap();
        assert_eq!(compact.said, cred.said);
        assert!(compact.rules.is_some());
        let rules_said = compact.rules.as_ref().unwrap().as_said().unwrap();
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
