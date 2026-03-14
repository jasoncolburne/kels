use std::{collections::BTreeMap, str::FromStr};

use serde::Deserialize;

use kels::PagedKelSource;
use verifiable_storage::StorageDatetime;

use crate::{
    compaction::compact,
    credential::Credential,
    disclosure::{apply_disclosure, parse_disclosure},
    edge::{Edge, Edges},
    error::CredentialError,
    rule::{Rule, Rules},
    schema::{CredentialSchema, SchemaValidationReport, validate_credential_report},
    store::SADStore,
};

/// Edge input without SAID (SAIDs are derived during creation).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EdgeInput {
    schema: String,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    delegated: Option<bool>,
}

/// Rule input without SAID (SAIDs are derived during creation).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleInput {
    condition: String,
}

/// Create a credential from JSON inputs.
///
/// Returns the fully-expanded credential as a JSON string with all SAIDs derived.
/// Does NOT store the credential — call `store()` separately.
///
/// - `json_schema`: A `CredentialSchema` JSON with SAID already derived
/// - `json_claims`: Claims JSON object (without `said` field — it will be added and derived)
/// - `json_edges`: Optional map of label → edge data (without SAIDs)
/// - `json_rules`: Optional map of label → rule data (without SAIDs)
#[allow(clippy::too_many_arguments)]
pub async fn create(
    json_schema: &str,
    json_claims: &str,
    json_edges: Option<&str>,
    json_rules: Option<&str>,
    issuer: &str,
    subject: Option<&str>,
    unique: bool,
    can_revoke: bool,
    expires_at: Option<&str>,
) -> Result<String, CredentialError> {
    let schema: CredentialSchema = serde_json::from_str(json_schema)?;

    // Parse claims — add said field, sort keys for deterministic SAID
    let claims_raw: serde_json::Value = serde_json::from_str(json_claims)?;
    let claims_obj = claims_raw.as_object().ok_or_else(|| {
        CredentialError::SchemaValidationError("claims must be a JSON object".to_string())
    })?;

    let mut sorted_claims = serde_json::Map::new();
    sorted_claims.insert("said".to_string(), serde_json::Value::String(String::new()));
    let mut keys: Vec<&String> = claims_obj.keys().collect();
    keys.sort();
    for key in keys {
        if let Some(value) = claims_obj.get(key) {
            sorted_claims.insert(key.clone(), value.clone());
        }
    }
    let claims_value = serde_json::Value::Object(sorted_claims);

    let edges = if let Some(json) = json_edges {
        Some(parse_edges(json)?)
    } else {
        None
    };

    let rules = if let Some(json) = json_rules {
        Some(parse_rules(json)?)
    } else {
        None
    };

    let exp = if let Some(exp_str) = expires_at {
        Some(
            serde_json::from_value::<StorageDatetime>(serde_json::Value::String(
                exp_str.to_string(),
            ))
            .map_err(|e| {
                CredentialError::SchemaValidationError(format!("invalid expires_at: {}", e))
            })?,
        )
    } else {
        None
    };

    let (credential, _) = Credential::create(
        schema,
        issuer.to_string(),
        subject.map(|s| s.to_string()),
        claims_value,
        unique,
        edges,
        rules,
        can_revoke,
        exp,
    )
    .await?;

    serde_json::to_string(&credential).map_err(CredentialError::from)
}

/// Store a JSON credential in the SAD store.
///
/// Compacts the credential and stores all chunks. Returns the compacted SAID
/// (the canonical identifier for retrieval and disclosure).
pub async fn store(
    json_credential: &str,
    sad_store: &dyn SADStore,
) -> Result<String, CredentialError> {
    let mut value: serde_json::Value = serde_json::from_str(json_credential)?;
    let chunks = compact(&mut value)?;
    sad_store.store_chunks(&chunks).await?;

    let compacted_said = value
        .as_str()
        .ok_or_else(|| {
            CredentialError::CompactionError("compact did not produce a SAID string".to_string())
        })?
        .to_string();

    Ok(compacted_said)
}

/// Verify a JSON credential against the KEL.
///
/// Takes the credential at whatever disclosure level the caller has and verifies
/// what's visible: SAID integrity, KEL anchoring, revocation, expiration, and
/// schema validation (if schema and claims are both expanded).
/// If a SADStore is provided, recursively verifies edge-referenced credentials.
///
/// Returns verification result as a JSON string.
pub async fn verify(
    json_credential: &str,
    source: &dyn PagedKelSource,
    sad_store: Option<&dyn SADStore>,
) -> Result<String, CredentialError> {
    let credential: Credential<serde_json::Value> = Credential::from_str(json_credential)?;
    let verification = credential.verify(source, sad_store).await?;
    serde_json::to_string(&verification).map_err(CredentialError::from)
}

/// Apply a disclosure statement to a stored credential.
///
/// Retrieves the credential from the SAD store by its compacted SAID, applies
/// the disclosure statement, and returns the resulting credential view as JSON.
pub async fn disclose(
    compacted_said: &str,
    disclosure_statement: &str,
    sad_store: &dyn SADStore,
) -> Result<String, CredentialError> {
    let tokens = parse_disclosure(disclosure_statement)?;
    let value = apply_disclosure(compacted_said, &tokens, sad_store).await?;
    serde_json::to_string(&value).map_err(CredentialError::from)
}

/// Validate a credential against a schema, reporting per-field results.
/// Schema structure and expiration are always checked (errors on failure).
/// Claims, edges, and rules each report Valid/Invalid/NotValidated depending
/// on whether the field is expanded or compacted.
pub fn validate(
    json_credential: &str,
    json_schema: &str,
) -> Result<SchemaValidationReport, CredentialError> {
    let credential: Credential<serde_json::Value> = Credential::from_str(json_credential)?;
    let schema: CredentialSchema = serde_json::from_str(json_schema)?;

    let schema_said = if let Some(schema) = credential.schema.as_expanded() {
        &schema.said
    } else {
        credential
            .schema
            .as_said()
            .ok_or(CredentialError::InvalidSaid(
                "Invalid schema said".to_string(),
            ))?
    };

    if *schema_said != schema.said {
        return Err(CredentialError::InvalidSaid(
            "Schema said mismatch".to_string(),
        ));
    }

    validate_credential_report(&credential, &schema)
}

fn parse_edges(json: &str) -> Result<Edges, CredentialError> {
    let inputs: BTreeMap<String, EdgeInput> = serde_json::from_str(json)?;
    let mut edges = BTreeMap::new();

    for (label, input) in inputs {
        let edge = Edge::create(
            input.schema,
            input.issuer,
            input.credential,
            input.nonce,
            input.delegated,
        )?;
        edges.insert(label, edge);
    }

    Edges::new_validated(edges)
}

fn parse_rules(json: &str) -> Result<Rules, CredentialError> {
    let inputs: BTreeMap<String, RuleInput> = serde_json::from_str(json)?;
    let mut rules = BTreeMap::new();

    for (label, input) in inputs {
        let rule = Rule::create(input.condition)?;
        rules.insert(label, rule);
    }

    Rules::new_validated(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::{
        schema::{CredentialSchema, SchemaField},
        store::InMemorySADStore,
    };

    fn test_schema_json() -> String {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::String);
        fields.insert("age".to_string(), SchemaField::Integer);

        let schema = CredentialSchema::create(
            "Test Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
            false,
            false,
            false,
            false,
            None,
            None,
        )
        .unwrap();

        serde_json::to_string(&schema).unwrap()
    }

    #[tokio::test]
    async fn test_create_basic() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice", "age": 30}"#;

        let result = create(
            &schema_json,
            claims_json,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            Some("ESubject23456789012345678901234567890abcde"),
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let credential: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(credential.get("said").is_some());
        assert_eq!(credential.get("said").unwrap().as_str().unwrap().len(), 44);
        assert!(credential.get("schema").unwrap().is_object());
        assert!(credential.get("claims").unwrap().is_object());
        assert_eq!(
            credential.get("issuer").unwrap().as_str().unwrap(),
            "EIssuer123456789012345678901234567890abcde"
        );
    }

    #[tokio::test]
    async fn test_create_deterministic() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice", "age": 30}"#;

        let r1 = create(
            &schema_json,
            claims_json,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let r2 = create(
            &schema_json,
            claims_json,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        // SAIDs should differ due to different issued_at timestamps,
        // but the structure should be identical
        let v1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(
            v1.get("claims").unwrap().get("name"),
            v2.get("claims").unwrap().get("name")
        );
    }

    #[tokio::test]
    async fn test_create_with_edges() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice", "age": 30}"#;
        let edges_json =
            r#"{"license": {"schema": "EAbc1234567890123456789012345678901234567890"}}"#;

        let result = create(
            &schema_json,
            claims_json,
            Some(edges_json),
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let credential: serde_json::Value = serde_json::from_str(&result).unwrap();
        let edges = credential.get("edges").unwrap();
        assert!(edges.is_object());
        assert!(edges.get("license").is_some());
    }

    #[tokio::test]
    async fn test_create_with_rules() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice", "age": 30}"#;
        let rules_json = r#"{"terms": {"condition": "For verification only"}}"#;

        let result = create(
            &schema_json,
            claims_json,
            None,
            Some(rules_json),
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let credential: serde_json::Value = serde_json::from_str(&result).unwrap();
        let rules = credential.get("rules").unwrap();
        assert!(rules.is_object());
        assert!(rules.get("terms").is_some());
    }

    #[tokio::test]
    async fn test_create_invalid_claims() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice"}"#; // missing "age"

        let result = create(
            &schema_json,
            claims_json,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_claims_field_order_independent() {
        let schema_json = test_schema_json();

        // Different JSON field orders should produce the same SAID
        // (because we sort claims keys)
        let claims1 = r#"{"name": "Alice", "age": 30}"#;
        let claims2 = r#"{"age": 30, "name": "Alice"}"#;

        let r1 = create(
            &schema_json,
            claims1,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let r2 = create(
            &schema_json,
            claims2,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let v1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        // Claims SAIDs should match since keys are sorted
        assert_eq!(
            v1.get("claims").unwrap().get("said"),
            v2.get("claims").unwrap().get("said")
        );
    }

    #[tokio::test]
    async fn test_store_and_disclose() {
        let schema_json = test_schema_json();
        let claims_json = r#"{"name": "Alice", "age": 30}"#;

        let credential_json = create(
            &schema_json,
            claims_json,
            None,
            None,
            "EIssuer123456789012345678901234567890abcde",
            None,
            false,
            true,
            None,
        )
        .await
        .unwrap();

        let sad_store = InMemorySADStore::new();
        let compacted_said = store(&credential_json, &sad_store).await.unwrap();
        assert_eq!(compacted_said.len(), 44);

        // Disclose everything
        let disclosed = disclose(&compacted_said, ".*", &sad_store).await.unwrap();
        let disclosed_value: serde_json::Value = serde_json::from_str(&disclosed).unwrap();
        assert!(disclosed_value.get("claims").unwrap().is_object());
        assert!(disclosed_value.get("schema").unwrap().is_object());

        // Disclose only schema
        let partial = disclose(&compacted_said, "schema", &sad_store)
            .await
            .unwrap();
        let partial_value: serde_json::Value = serde_json::from_str(&partial).unwrap();
        assert!(partial_value.get("schema").unwrap().is_object());
        assert!(partial_value.get("claims").unwrap().is_string());
    }

    #[tokio::test]
    async fn test_parse_edges() {
        let json = r#"{
            "license": {
                "schema": "EAbc1234567890123456789012345678901234567890",
                "issuer": "EIssuer123456789012345678901234567890abcde",
                "credential": "ECred12345678901234567890123456789012abcdef"
            }
        }"#;

        let edges = super::parse_edges(json).unwrap();
        assert_eq!(edges.edges.len(), 1);
        assert!(edges.edges.contains_key("license"));
        let edge = edges.edges.get("license").unwrap();
        assert_eq!(edge.said.len(), 44);
    }

    #[tokio::test]
    async fn test_parse_rules() {
        let json = r#"{"terms": {"condition": "For verification only"}}"#;

        let rules = super::parse_rules(json).unwrap();
        assert_eq!(rules.rules.len(), 1);
        assert!(rules.rules.contains_key("terms"));
        let rule = rules.rules.get("terms").unwrap();
        assert_eq!(rule.said.len(), 44);
    }
}
