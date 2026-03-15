use std::{collections::BTreeMap, str::FromStr};

use serde::Deserialize;

use kels::PagedKelSource;
use verifiable_storage::StorageDatetime;

use crate::{
    compaction::compact_with_schema,
    credential::Credential,
    disclosure::{apply_disclosure, parse_disclosure},
    edge::{Edge, Edges},
    error::CredentialError,
    rule::{Rule, Rules},
    schema::{Schema, SchemaValidationReport, validate_credential_report},
    store::SADStore,
    verification::verify_credential,
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
/// - `json_schema`: A `Schema` JSON with SAID already derived
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
    let schema: Schema = serde_json::from_str(json_schema)?;

    // Parse claims — add said field for SelfAddressed derivation
    let mut claims_value: serde_json::Value = serde_json::from_str(json_claims)?;
    let claims_obj = claims_value.as_object_mut().ok_or_else(|| {
        CredentialError::SchemaValidationError("claims must be a JSON object".to_string())
    })?;
    claims_obj.insert("said".to_string(), serde_json::Value::String(String::new()));

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
        &schema,
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
/// Compacts the credential using schema-aware compaction and stores all chunks.
/// Returns the compacted SAID (the canonical identifier for retrieval and disclosure).
pub async fn store(
    json_credential: &str,
    json_schema: &str,
    sad_store: &dyn SADStore,
) -> Result<String, CredentialError> {
    let schema: Schema = serde_json::from_str(json_schema)?;
    let mut value: serde_json::Value = serde_json::from_str(json_credential)?;
    let cred_schema = value
        .get("schema")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            CredentialError::InvalidCredential("credential has no schema field".to_string())
        })?;
    if cred_schema != schema.said {
        return Err(CredentialError::InvalidSchema(format!(
            "schema SAID mismatch: credential references {cred_schema}, provided schema has {}",
            schema.said
        )));
    }
    let chunks = compact_with_schema(&mut value, &schema)?;
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
/// schema validation.
/// If a SADStore is provided, recursively verifies edge-referenced credentials.
///
/// - `json_edge_schemas`: JSON object mapping schema SAIDs to schema objects
///
/// Returns verification result as a JSON string.
pub async fn verify(
    json_credential: &str,
    json_schema: &str,
    source: &dyn PagedKelSource,
    sad_store: Option<&dyn SADStore>,
    json_edge_schemas: Option<&str>,
) -> Result<String, CredentialError> {
    let schema: Schema = serde_json::from_str(json_schema)?;
    let edge_schemas: BTreeMap<String, Schema> = if let Some(json) = json_edge_schemas {
        serde_json::from_str(json)?
    } else {
        BTreeMap::new()
    };
    let credential: Credential<serde_json::Value> = Credential::from_str(json_credential)?;
    let verification =
        verify_credential(&credential, &schema, source, sad_store, &edge_schemas).await?;
    serde_json::to_string(&verification).map_err(CredentialError::from)
}

/// Apply a disclosure statement to a stored credential.
///
/// Retrieves the credential from the SAD store by its compacted SAID, applies
/// the disclosure statement, and returns the resulting credential view as JSON.
/// Requires the schema for schema-aware expansion.
pub async fn disclose(
    compacted_said: &str,
    disclosure_statement: &str,
    sad_store: &dyn SADStore,
    json_schema: &str,
) -> Result<String, CredentialError> {
    let schema: Schema = serde_json::from_str(json_schema)?;
    let tokens = parse_disclosure(disclosure_statement)?;
    let value = apply_disclosure(compacted_said, &tokens, sad_store, &schema).await?;
    serde_json::to_string(&value).map_err(CredentialError::from)
}

/// Validate a credential against a schema, reporting validation results.
pub fn validate(
    json_credential: &str,
    json_schema: &str,
) -> Result<SchemaValidationReport, CredentialError> {
    let credential: Credential<serde_json::Value> = Credential::from_str(json_credential)?;
    let schema: Schema = serde_json::from_str(json_schema)?;

    if credential.schema != schema.said {
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
        schema::{Schema, SchemaField},
        store::InMemorySADStore,
    };

    fn test_schema() -> Schema {
        let claims_fields = BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            ("age".to_string(), SchemaField::integer()),
        ]);

        let mut fields = BTreeMap::new();
        fields.insert("schema".to_string(), SchemaField::said());
        fields.insert("issuer".to_string(), SchemaField::prefix());
        fields.insert("issuedAt".to_string(), SchemaField::datetime());
        fields.insert("subject".to_string(), SchemaField::prefix().opt());
        fields.insert("nonce".to_string(), SchemaField::string().opt());
        fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
        fields.insert("irrevocable".to_string(), SchemaField::boolean().opt());
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

    fn test_schema_json() -> String {
        serde_json::to_string(&test_schema()).unwrap()
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
        assert!(credential.get("schema").unwrap().is_string());
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
        let claims_fields = BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            ("age".to_string(), SchemaField::integer()),
        ]);
        let edge_fields = BTreeMap::from([(
            "license".to_string(),
            SchemaField::object(
                BTreeMap::from([
                    ("schema".to_string(), SchemaField::said()),
                    ("issuer".to_string(), SchemaField::prefix().opt()),
                    ("credential".to_string(), SchemaField::said().opt()),
                    ("nonce".to_string(), SchemaField::string().opt()),
                    ("delegated".to_string(), SchemaField::boolean().opt()),
                ]),
                true,
            ),
        )]);
        let mut fields = BTreeMap::new();
        fields.insert("schema".to_string(), SchemaField::said());
        fields.insert("issuer".to_string(), SchemaField::prefix());
        fields.insert("issuedAt".to_string(), SchemaField::datetime());
        fields.insert("subject".to_string(), SchemaField::prefix().opt());
        fields.insert("nonce".to_string(), SchemaField::string().opt());
        fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
        fields.insert("irrevocable".to_string(), SchemaField::boolean().opt());
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
        let schema = Schema::create(
            "Edge Test Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();
        let schema_json = serde_json::to_string(&schema).unwrap();

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
        fields.insert("issuer".to_string(), SchemaField::prefix());
        fields.insert("issuedAt".to_string(), SchemaField::datetime());
        fields.insert("subject".to_string(), SchemaField::prefix().opt());
        fields.insert("nonce".to_string(), SchemaField::string().opt());
        fields.insert("expiresAt".to_string(), SchemaField::datetime().opt());
        fields.insert("irrevocable".to_string(), SchemaField::boolean().opt());
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
        let schema = Schema::create(
            "Rule Test Schema".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();
        let schema_json = serde_json::to_string(&schema).unwrap();

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
        let compacted_said = store(&credential_json, &schema_json, &sad_store)
            .await
            .unwrap();
        assert_eq!(compacted_said.len(), 44);

        // Disclose everything
        let disclosed = disclose(&compacted_said, ".*", &sad_store, &schema_json)
            .await
            .unwrap();
        let disclosed_value: serde_json::Value = serde_json::from_str(&disclosed).unwrap();
        assert!(disclosed_value.get("claims").unwrap().is_object());
        // schema is always a SAID string, not compactable
        assert!(disclosed_value.get("schema").unwrap().is_string());

        // Disclose only claims
        let partial = disclose(&compacted_said, "claims", &sad_store, &schema_json)
            .await
            .unwrap();
        let partial_value: serde_json::Value = serde_json::from_str(&partial).unwrap();
        assert!(partial_value.get("claims").unwrap().is_object());
        // schema is always a SAID string
        assert!(partial_value.get("schema").unwrap().is_string());
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
