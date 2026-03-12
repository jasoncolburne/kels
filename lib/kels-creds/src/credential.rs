use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::compaction::{compact, compute_said_from_value};
use crate::edge::Edges;
use crate::error::CredentialError;
use crate::rule::Rules;
use crate::schema::CredentialSchema;

/// Trait alias for the bounds required on credential claims types.
pub trait Claims: Serialize + DeserializeOwned + SelfAddressed + Clone {}
impl<T: Serialize + DeserializeOwned + SelfAddressed + Clone> Claims for T {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: DeserializeOwned"))]
pub struct Credential<T: Claims> {
    pub said: String,
    pub schema: CredentialSchema,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub issued_at: String,
    pub claims: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irrevocable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Edges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
}

impl<T: Claims> Clone for Credential<T> {
    fn clone(&self) -> Self {
        Self {
            said: self.said.clone(),
            schema: self.schema.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            issued_at: self.issued_at.clone(),
            claims: self.claims.clone(),
            irrevocable: self.irrevocable,
            edges: self.edges.clone(),
            rules: self.rules.clone(),
        }
    }
}

impl<T: Claims> SelfAddressed for Credential<T> {
    fn derive_said(&mut self) -> Result<(), verifiable_storage::StorageError> {
        // Serialize to Value, compact (replaces inner SelfAddressed fields with SAIDs),
        // then compute the top-level SAID over the compacted form.
        self.said = "#".repeat(44);
        let mut value = serde_json::to_value(&*self)?;
        compact(&mut value)
            .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;
        let said = compute_said_from_value(&value)
            .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;
        self.said = said;
        Ok(())
    }

    fn verify_said(&self) -> Result<(), verifiable_storage::StorageError> {
        let mut clone = self.clone();
        clone.derive_said()?;
        if clone.said == self.said {
            Ok(())
        } else {
            Err(verifiable_storage::StorageError::InvalidSaid(format!(
                "expected {}, got {}",
                self.said, clone.said
            )))
        }
    }

    fn get_said(&self) -> String {
        self.said.clone()
    }
}

impl<T: Claims> Credential<T> {
    /// Create a new credential with all inner SAIDs derived and the top-level SAID computed.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        mut schema: CredentialSchema,
        issuer: String,
        subject: Option<String>,
        issued_at: String,
        mut claims: T,
        edges: Option<Edges>,
        rules: Option<Rules>,
        irrevocable: Option<bool>,
    ) -> Result<Self, CredentialError> {
        schema.derive_said()?;
        claims.derive_said()?;

        let mut credential = Self {
            said: String::new(),
            schema,
            issuer,
            subject,
            issued_at,
            claims,
            irrevocable,
            edges,
            rules,
        };

        credential.derive_said()?;
        Ok(credential)
    }
}

/// Runtime representation of a credential using `serde_json::Value`.
/// Used for disclosure and verification when the concrete type `T` is not available.
#[derive(Debug, Clone)]
pub struct CredentialValue {
    inner: serde_json::Value,
}

impl CredentialValue {
    /// Wrap a JSON value as a CredentialValue.
    pub fn from_value(value: serde_json::Value) -> Result<Self, CredentialError> {
        if !value.is_object() {
            return Err(CredentialError::InvalidCredential(
                "credential must be a JSON object".to_string(),
            ));
        }
        if value.get("said").is_none() {
            return Err(CredentialError::InvalidCredential(
                "credential must have a 'said' field".to_string(),
            ));
        }
        Ok(Self { inner: value })
    }

    /// Create from a typed Credential by serializing to Value.
    pub fn from_credential<T: Claims>(credential: &Credential<T>) -> Result<Self, CredentialError> {
        let value = serde_json::to_value(credential)?;
        Self::from_value(value)
    }

    /// Get the credential's SAID.
    pub fn said(&self) -> Option<&str> {
        self.inner.get("said").and_then(|v| v.as_str())
    }

    /// Get the credential's issuer prefix.
    pub fn issuer(&self) -> Option<&str> {
        self.inner.get("issuer").and_then(|v| v.as_str())
    }

    /// Get the credential's subject prefix.
    pub fn subject(&self) -> Option<&str> {
        self.inner.get("subject").and_then(|v| v.as_str())
    }

    /// Check if this credential is marked irrevocable.
    pub fn is_irrevocable(&self) -> bool {
        self.inner
            .get("irrevocable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Get a reference to the inner Value.
    pub fn inner(&self) -> &serde_json::Value {
        &self.inner
    }

    /// Get a mutable reference to the inner Value.
    pub fn inner_mut(&mut self) -> &mut serde_json::Value {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use serde_json::json;

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
        )
        .unwrap()
    }

    fn test_claims() -> TestClaims {
        TestClaims::create("Alice".to_string(), 30u32).unwrap()
    }

    fn test_credential() -> Credential<TestClaims> {
        Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            Some("ESubject23456789012345678901234567890abcde".to_string()),
            "2025-01-01T00:00:00Z".to_string(),
            test_claims(),
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_credential_said_derivation() {
        let cred = test_credential();
        assert!(!cred.said.is_empty());
        assert_eq!(cred.said.len(), 44);
    }

    #[test]
    fn test_credential_said_verify() {
        let cred = test_credential();
        assert!(cred.verify_said().is_ok());
    }

    #[test]
    fn test_credential_said_deterministic() {
        let c1 = test_credential();
        let c2 = test_credential();
        assert_eq!(c1.said, c2.said);
    }

    #[test]
    fn test_credential_value_from_credential() {
        let cred = test_credential();
        let cv = CredentialValue::from_credential(&cred).unwrap();

        assert_eq!(cv.said(), Some(cred.said.as_str()));
        assert_eq!(
            cv.issuer(),
            Some("EIssuer123456789012345678901234567890abcde")
        );
        assert_eq!(
            cv.subject(),
            Some("ESubject23456789012345678901234567890abcde")
        );
    }

    #[test]
    fn test_credential_value_said_matches_typed() {
        let cred = test_credential();
        let cv = CredentialValue::from_credential(&cred).unwrap();
        assert_eq!(cv.said().unwrap(), cred.said.as_str());

        // Compact the CredentialValue and check SAID matches
        let mut inner = cv.inner().clone();
        compact(&mut inner).unwrap();
        let compacted_said = inner.get("said").unwrap().as_str().unwrap();
        assert_eq!(compacted_said, cred.said.as_str());
    }

    #[test]
    fn test_credential_value_from_invalid() {
        assert!(CredentialValue::from_value(json!("string")).is_err());
        assert!(CredentialValue::from_value(json!({"no_said": true})).is_err());
    }

    #[test]
    fn test_credential_value_irrevocable() {
        let cred = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            "2025-01-01T00:00:00Z".to_string(),
            test_claims(),
            None,
            None,
            Some(true),
        )
        .unwrap();

        let cv = CredentialValue::from_credential(&cred).unwrap();
        assert!(cv.is_irrevocable());
    }

    #[test]
    fn test_credential_value_not_irrevocable() {
        let cred = test_credential();
        let cv = CredentialValue::from_credential(&cred).unwrap();
        assert!(!cv.is_irrevocable());
    }

    #[test]
    fn test_credential_with_edges() {
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

        let cred = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            "2025-01-01T00:00:00Z".to_string(),
            test_claims(),
            Some(edges),
            None,
            None,
        )
        .unwrap();

        assert!(cred.verify_said().is_ok());
    }

    #[test]
    fn test_credential_with_rules() {
        use crate::rule::{Rule, Rules};

        let rule = Rule::create("For verification only".to_string()).unwrap();
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), rule);
        let rules = Rules::new_validated(rules_map).unwrap();

        let cred = Credential::create(
            test_schema(),
            "EIssuer123456789012345678901234567890abcde".to_string(),
            None,
            "2025-01-01T00:00:00Z".to_string(),
            test_claims(),
            None,
            Some(rules),
            None,
        )
        .unwrap();

        assert!(cred.verify_said().is_ok());
    }

    #[test]
    fn test_credential_serialization_roundtrip() {
        let cred = test_credential();
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential<TestClaims> = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.said, deserialized.said);
        assert!(deserialized.verify_said().is_ok());
    }
}
