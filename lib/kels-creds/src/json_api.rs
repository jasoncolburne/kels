use std::{collections::BTreeMap, str::FromStr};

use serde::Deserialize;

use kels::PagedKelSource;
use kels_policy::{InMemoryPolicyResolver, Policy, PolicyResolver};
use verifiable_storage::{SelfAddressed, StorageDatetime};

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
pub struct EdgeInput {
    pub schema: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Rule input without SAID (SAIDs are derived during creation).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInput {
    pub condition: String,
}

/// Build a credential from JSON inputs. Validates against schema, derives all SAIDs,
/// and returns the expanded credential JSON and canonical SAID.
///
/// The caller is responsible for anchoring the canonical SAID in endorser KELs.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    json_claims: &str,
    json_schema: &str,
    json_policy: &str,
    subject: Option<&str>,
    unique: bool,
    json_edges: Option<&str>,
    json_rules: Option<&str>,
    json_expires_at: Option<&str>,
) -> Result<(String, String), CredentialError> {
    let schema: Schema = serde_json::from_str(json_schema)?;
    let policy: kels_policy::Policy = serde_json::from_str(json_policy)?;
    let mut claims: serde_json::Value = serde_json::from_str(json_claims)?;
    claims.derive_said()?;

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
    let expires_at: Option<StorageDatetime> = if let Some(json) = json_expires_at {
        Some(serde_json::from_str(json)?)
    } else {
        None
    };

    let (credential, canonical_said) = Credential::build(
        &schema,
        &policy,
        subject.map(String::from),
        claims,
        unique,
        edges,
        rules,
        expires_at,
    )
    .await?;

    let credential_json = serde_json::to_string(&credential)?;
    Ok((credential_json, canonical_said))
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
/// what's visible: SAID integrity, policy evaluation, expiration, and
/// schema validation.
/// If a SADStore is provided, recursively verifies edge-referenced credentials.
///
/// - `json_policy`: JSON policy document
/// - `json_policies`: optional JSON array of policy documents for nested policy resolution
/// - `json_edge_schemas`: JSON object mapping schema SAIDs to schema objects
///
/// Returns verification result as a JSON string.
pub async fn verify(
    json_credential: &str,
    json_schema: &str,
    json_policy: &str,
    json_policies: Option<&str>,
    source: &(dyn PagedKelSource + Sync),
    sad_store: Option<&dyn SADStore>,
    json_edge_schemas: Option<&str>,
) -> Result<String, CredentialError> {
    let schema: Schema = serde_json::from_str(json_schema)?;
    let policy: Policy = serde_json::from_str(json_policy)?;
    let resolver: Box<dyn PolicyResolver> = if let Some(json) = json_policies {
        let policies: Vec<Policy> = serde_json::from_str(json)?;
        Box::new(InMemoryPolicyResolver::new(policies))
    } else {
        Box::new(InMemoryPolicyResolver::empty())
    };
    let edge_schemas: BTreeMap<String, Schema> = if let Some(json) = json_edge_schemas {
        serde_json::from_str(json)?
    } else {
        BTreeMap::new()
    };
    let credential: Credential<serde_json::Value> = Credential::from_str(json_credential)?;
    let verification = verify_credential(
        &credential,
        &schema,
        &policy,
        resolver.as_ref(),
        source,
        sad_store,
        &edge_schemas,
    )
    .await?;
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

pub fn parse_edges(json: &str) -> Result<Edges, CredentialError> {
    let inputs: BTreeMap<String, EdgeInput> = serde_json::from_str(json)?;
    let mut edges = BTreeMap::new();

    for (label, input) in inputs {
        let edge = Edge::create(input.schema, input.policy, input.credential, input.nonce)?;
        edges.insert(label, edge);
    }

    Edges::new_validated(edges)
}

pub fn parse_rules(json: &str) -> Result<Rules, CredentialError> {
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

    use kels_policy::Policy;
    use verifiable_storage::SelfAddressed;

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

    fn test_schema_json() -> String {
        serde_json::to_string(&test_schema()).unwrap()
    }

    #[tokio::test]
    async fn test_store_and_disclose() {
        let schema = test_schema();
        let schema_json = test_schema_json();
        let policy = Policy::build(
            "endorse(KIssuer123456789012345678901234567890abcde)",
            None,
            false,
        )
        .unwrap();

        // Build a credential via the typed API
        let mut claims = serde_json::json!({"said": "", "name": "Alice", "age": 30});
        claims.derive_said().unwrap();
        let (cred, _) = crate::credential::Credential::build(
            &schema, &policy, None, claims, false, None, None, None,
        )
        .await
        .unwrap();
        let credential_json = serde_json::to_string(&cred).unwrap();

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
                "schema": "KAbc1234567890123456789012345678901234567890",
                "policy": "KPolicy23456789012345678901234567890abcdefg",
                "credential": "KCred12345678901234567890123456789012abcdef"
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
