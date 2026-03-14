use std::{collections::BTreeMap, str::FromStr};

use serde::{Deserialize, Serialize};

use verifiable_storage::{SelfAddressed, StorageDatetime};

use crate::{
    compaction::MAX_RECURSION_DEPTH, credential::Credential, edge::Edges, error::CredentialError,
    rule::Rules,
};

/// Result of schema validation during credential verification.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaValidationResult {
    Valid,
    Invalid,
    NotValidated,
}

/// Per-field validation report for graduated disclosure scenarios.
/// Schema structure and expiration are always checked (errors on failure).
/// Claims, edges, and rules report `NotValidated` when compacted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidationReport {
    pub claims: SchemaValidationResult,
    pub edges: SchemaValidationResult,
    pub rules: SchemaValidationResult,
}

impl SchemaValidationReport {
    /// Require all fields to be Valid. Returns an error if any field is Invalid.
    /// NotValidated fields are accepted (compacted fields can't be validated).
    pub fn require_all_valid(&self) -> Result<(), CredentialError> {
        if matches!(self.claims, SchemaValidationResult::Invalid) {
            return Err(CredentialError::SchemaValidationError(
                "claims validation failed".to_string(),
            ));
        }
        if matches!(self.edges, SchemaValidationResult::Invalid) {
            return Err(CredentialError::SchemaValidationError(
                "edges validation failed".to_string(),
            ));
        }
        if matches!(self.rules, SchemaValidationResult::Invalid) {
            return Err(CredentialError::SchemaValidationError(
                "rules validation failed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Schema-level constraint on an edge field. `true` in JSON means "must be present",
/// a string means "must equal this specific value".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SchemaConstraint {
    Required(bool),
    Value(String),
}

/// Schema-level constraint for an edge. All fields mirror Edge fields.
/// `schema` is required (same as Edge). Other fields, if present, constrain the edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaEdge {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<SchemaConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<SchemaConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,
}

/// Schema-level constraint for a rule. If `condition` is set, the rule must match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SchemaField {
    String,
    Integer,
    Float,
    Boolean,
    /// A nested object. If `compactable` is true, the object has a `said` field and
    /// can appear as a SAID string when compacted.
    Object {
        fields: BTreeMap<String, SchemaField>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        compactable: bool,
    },
    Array(Box<SchemaField>),
    Said,
    Prefix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    #[said]
    pub said: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
    #[serde(default)]
    pub expires: bool,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub subject: bool,
    #[serde(default)]
    pub revocable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<BTreeMap<String, SchemaEdge>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<BTreeMap<String, SchemaRule>>,
}

impl FromStr for CredentialSchema {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Validate that a schema's field definitions are well-formed.
/// Rejects `said` as a field name anywhere (it's implicit for compactable objects).
/// Also rejects `said` as an edge or rule label.
pub(crate) fn validate_schema(schema: &CredentialSchema) -> Result<(), CredentialError> {
    validate_schema_fields("fields", &schema.fields, MAX_RECURSION_DEPTH)?;

    if let Some(edges) = &schema.edges {
        for label in edges.keys() {
            if label == "said" {
                return Err(CredentialError::SchemaValidationError(
                    "'said' is a reserved label and cannot be used as an edge label in schema"
                        .to_string(),
                ));
            }
        }
    }

    if let Some(rules) = &schema.rules {
        for label in rules.keys() {
            if label == "said" {
                return Err(CredentialError::SchemaValidationError(
                    "'said' is a reserved label and cannot be used as a rule label in schema"
                        .to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_schema_fields(
    path: &str,
    fields: &BTreeMap<String, SchemaField>,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    if remaining_depth == 0 {
        return Err(CredentialError::SchemaValidationError(format!(
            "maximum schema nesting depth exceeded at {path}"
        )));
    }
    for (name, field_type) in fields {
        if name == "said" {
            return Err(CredentialError::SchemaValidationError(format!(
                "'said' is a reserved field name and cannot appear in schema definition at {path}.{name}"
            )));
        }
        if let SchemaField::Object { fields: sub, .. } = field_type {
            validate_schema_fields(&format!("{path}.{name}"), sub, remaining_depth - 1)?;
        }
        if let SchemaField::Array(element_type) = field_type {
            validate_schema_array_fields(
                &format!("{path}.{name}[]"),
                element_type,
                remaining_depth - 1,
            )?;
        }
    }
    Ok(())
}

fn validate_schema_array_fields(
    path: &str,
    field_type: &SchemaField,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    if remaining_depth == 0 {
        return Err(CredentialError::SchemaValidationError(format!(
            "maximum schema nesting depth exceeded at {path}"
        )));
    }
    if let SchemaField::Object { fields, .. } = field_type {
        validate_schema_fields(path, fields, remaining_depth - 1)?;
    }
    if let SchemaField::Array(element_type) = field_type {
        validate_schema_array_fields(&format!("{path}[]"), element_type, remaining_depth - 1)?;
    }
    Ok(())
}

/// Validate a credential against a schema with graduated disclosure support.
/// Schema structure and expiration are always checked (errors on failure).
/// Claims, edges, and rules each report Valid/Invalid/NotValidated depending
/// on whether the field is expanded or compacted.
pub(crate) fn validate_credential_report<T: crate::credential::Claims>(
    credential: &Credential<T>,
    schema: &CredentialSchema,
) -> Result<SchemaValidationReport, CredentialError> {
    validate_schema(schema)?;
    validate_expiration(
        schema,
        &credential.issued_at,
        credential.expires_at.as_ref(),
    )?;

    if schema.unique && credential.nonce.is_none() {
        return Err(CredentialError::SchemaValidationError(
            "schema requires a nonce (unique) but none provided".to_string(),
        ));
    }

    if schema.subject && credential.subject.is_none() {
        return Err(CredentialError::SchemaValidationError(
            "schema requires a subject but none provided".to_string(),
        ));
    }

    if schema.revocable && credential.irrevocable == Some(true) {
        return Err(CredentialError::SchemaValidationError(
            "schema requires credential to be revocable but it is irrevocable".to_string(),
        ));
    }

    let claims = match credential.claims.as_expanded() {
        Some(claims) => match validate_claims(schema, &serde_json::to_value(claims)?) {
            Ok(()) => SchemaValidationResult::Valid,
            Err(_) => SchemaValidationResult::Invalid,
        },
        None => SchemaValidationResult::NotValidated,
    };

    let edges = match credential.edges.as_ref().and_then(|e| e.as_expanded()) {
        Some(edges) => match validate_edges(schema, Some(edges)) {
            Ok(()) => SchemaValidationResult::Valid,
            Err(_) => SchemaValidationResult::Invalid,
        },
        None if credential.edges.is_some() => SchemaValidationResult::NotValidated,
        None => match validate_edges(schema, None) {
            Ok(()) => SchemaValidationResult::Valid,
            Err(_) => SchemaValidationResult::Invalid,
        },
    };

    let rules = match credential.rules.as_ref().and_then(|r| r.as_expanded()) {
        Some(rules) => match validate_rules(schema, Some(rules)) {
            Ok(()) => SchemaValidationResult::Valid,
            Err(_) => SchemaValidationResult::Invalid,
        },
        None if credential.rules.is_some() => SchemaValidationResult::NotValidated,
        None => match validate_rules(schema, None) {
            Ok(()) => SchemaValidationResult::Valid,
            Err(_) => SchemaValidationResult::Invalid,
        },
    };

    Ok(SchemaValidationReport {
        claims,
        edges,
        rules,
    })
}

/// Validate expiration constraints: if schema requires expiration, it must be
/// present and after issued_at. If schema forbids expiration, it must be absent.
pub(crate) fn validate_expiration(
    schema: &CredentialSchema,
    issued_at: &StorageDatetime,
    expires_at: Option<&StorageDatetime>,
) -> Result<(), CredentialError> {
    if schema.expires {
        let exp = expires_at.ok_or_else(|| {
            CredentialError::SchemaValidationError(
                "schema requires expires_at but none provided".to_string(),
            )
        })?;
        if exp <= issued_at {
            return Err(CredentialError::SchemaValidationError(
                "expires_at must be after issued_at".to_string(),
            ));
        }
    } else if expires_at.is_some() {
        return Err(CredentialError::SchemaValidationError(
            "schema does not allow expires_at".to_string(),
        ));
    }

    Ok(())
}

/// Validate that a claims value conforms to a schema's field definitions.
/// Closed schema: extra fields not in the schema are rejected; `said` is
/// implicitly required on compactable objects and disallowed on non-compactable ones.
/// If claims is a string (compacted to SAID), validation is skipped.
pub(crate) fn validate_claims(
    schema: &CredentialSchema,
    claims: &serde_json::Value,
) -> Result<(), CredentialError> {
    // Compacted claims (SAID string) — skip validation
    if claims.is_string() {
        return Ok(());
    }

    let obj = claims.as_object().ok_or_else(|| {
        CredentialError::SchemaValidationError(
            "claims must be an object or a compacted SAID string".to_string(),
        )
    })?;

    // Claims is always compactable (has a `said` field)
    validate_object_fields("claims", &schema.fields, obj, true, MAX_RECURSION_DEPTH)
}

/// Validate that credential edges conform to the schema's edge definitions.
/// If the schema defines edges, the credential must provide exactly those labels,
/// and each edge must match the schema constraints.
/// If the schema has no edge definitions, any edges are accepted.
pub(crate) fn validate_edges(
    schema: &CredentialSchema,
    edges: Option<&Edges>,
) -> Result<(), CredentialError> {
    let Some(schema_edges) = &schema.edges else {
        return Ok(());
    };

    let edges = edges.ok_or_else(|| {
        CredentialError::SchemaValidationError(
            "schema defines edges but credential has none".to_string(),
        )
    })?;

    // Check all schema-defined edges are present and match constraints
    for (label, schema_edge) in schema_edges {
        let edge = edges.edges.get(label).ok_or_else(|| {
            CredentialError::SchemaValidationError(format!("missing required edge: {label}"))
        })?;

        if edge.schema != schema_edge.schema {
            return Err(CredentialError::SchemaValidationError(format!(
                "edge '{label}' schema mismatch: expected {}, got {}",
                schema_edge.schema, edge.schema
            )));
        }

        match &schema_edge.issuer {
            Some(SchemaConstraint::Required(true)) if edge.issuer.is_none() => {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' requires an issuer"
                )));
            }
            Some(SchemaConstraint::Value(expected)) if edge.issuer.as_ref() != Some(expected) => {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' issuer mismatch: expected {expected}"
                )));
            }
            _ => {}
        }

        match &schema_edge.credential {
            Some(SchemaConstraint::Required(true)) if edge.credential.is_none() => {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' requires a credential"
                )));
            }
            Some(SchemaConstraint::Value(expected))
                if edge.credential.as_ref() != Some(expected) =>
            {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' credential mismatch: expected {expected}"
                )));
            }
            _ => {}
        }

        if schema_edge.nonce == Some(true) && edge.nonce.is_none() {
            return Err(CredentialError::SchemaValidationError(format!(
                "edge '{label}' requires a nonce"
            )));
        }

        if let Some(expected_delegated) = schema_edge.delegated
            && edge.delegated != Some(expected_delegated)
        {
            return Err(CredentialError::SchemaValidationError(format!(
                "edge '{label}' delegated mismatch: expected {expected_delegated}"
            )));
        }
    }

    // Reject extra edges not in schema
    for label in edges.edges.keys() {
        if !schema_edges.contains_key(label) {
            return Err(CredentialError::SchemaValidationError(format!(
                "unexpected edge: {label}"
            )));
        }
    }

    Ok(())
}

/// Validate that credential rules conform to the schema's rule definitions.
/// If the schema defines rules, the credential must provide exactly those labels,
/// and each rule must match the schema constraints.
/// If the schema has no rule definitions, any rules are accepted.
pub(crate) fn validate_rules(
    schema: &CredentialSchema,
    rules: Option<&Rules>,
) -> Result<(), CredentialError> {
    let Some(schema_rules) = &schema.rules else {
        return Ok(());
    };

    let rules = rules.ok_or_else(|| {
        CredentialError::SchemaValidationError(
            "schema defines rules but credential has none".to_string(),
        )
    })?;

    // Check all schema-defined rules are present and match constraints
    for (label, schema_rule) in schema_rules {
        let rule = rules.rules.get(label).ok_or_else(|| {
            CredentialError::SchemaValidationError(format!("missing required rule: {label}"))
        })?;

        if let Some(ref expected_condition) = schema_rule.condition
            && &rule.condition != expected_condition
        {
            return Err(CredentialError::SchemaValidationError(format!(
                "rule '{label}' condition mismatch: expected '{expected_condition}', got '{}'",
                rule.condition
            )));
        }
    }

    // Reject extra rules not in schema
    for label in rules.rules.keys() {
        if !schema_rules.contains_key(label) {
            return Err(CredentialError::SchemaValidationError(format!(
                "unexpected rule: {label}"
            )));
        }
    }

    Ok(())
}

fn validate_object_fields(
    name: &str,
    schema_fields: &BTreeMap<String, SchemaField>,
    obj: &serde_json::Map<String, serde_json::Value>,
    compactable: bool,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    if remaining_depth == 0 {
        return Err(CredentialError::SchemaValidationError(format!(
            "maximum nesting depth exceeded at {name}"
        )));
    }

    // Check all schema-defined fields are present and valid
    for (field_name, field_type) in schema_fields {
        if let Some(value) = obj.get(field_name) {
            validate_field(
                &format!("{name}.{field_name}"),
                field_type,
                value,
                remaining_depth - 1,
            )?;
        } else {
            return Err(CredentialError::SchemaValidationError(format!(
                "missing required field: {name}.{field_name}"
            )));
        }
    }

    // Compactable objects must have a `said` field when expanded
    if compactable && !obj.contains_key("said") {
        return Err(CredentialError::SchemaValidationError(format!(
            "missing required field: {name}.said (compactable objects must have a said field)"
        )));
    }

    // Closed schema: reject extra fields (allow `said` on compactable objects)
    for key in obj.keys() {
        if compactable && key == "said" {
            continue;
        }
        if !schema_fields.contains_key(key) {
            return Err(CredentialError::SchemaValidationError(format!(
                "unexpected field: {name}.{key}"
            )));
        }
    }

    Ok(())
}

fn validate_field(
    name: &str,
    field_type: &SchemaField,
    value: &serde_json::Value,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    match field_type {
        SchemaField::String | SchemaField::Said | SchemaField::Prefix => {
            if !value.is_string() {
                return Err(CredentialError::SchemaValidationError(format!(
                    "field '{name}' must be a string"
                )));
            }
        }
        SchemaField::Integer => {
            if !value.is_i64() && !value.is_u64() {
                return Err(CredentialError::SchemaValidationError(format!(
                    "field '{name}' must be an integer"
                )));
            }
        }
        SchemaField::Float => {
            if !value.is_f64() && !value.is_i64() && !value.is_u64() {
                return Err(CredentialError::SchemaValidationError(format!(
                    "field '{name}' must be a number"
                )));
            }
        }
        SchemaField::Boolean => {
            if !value.is_boolean() {
                return Err(CredentialError::SchemaValidationError(format!(
                    "field '{name}' must be a boolean"
                )));
            }
        }
        SchemaField::Object {
            fields,
            compactable,
        } => {
            if *compactable && value.is_string() {
                // Compacted to SAID string — valid for compactable objects
                return Ok(());
            }
            let obj = value.as_object().ok_or_else(|| {
                if *compactable {
                    CredentialError::SchemaValidationError(format!(
                        "field '{name}' must be an object or a compacted SAID string"
                    ))
                } else {
                    CredentialError::SchemaValidationError(format!(
                        "field '{name}' must be an object"
                    ))
                }
            })?;
            validate_object_fields(name, fields, obj, *compactable, remaining_depth)?;
        }
        SchemaField::Array(element_type) => {
            let arr = value.as_array().ok_or_else(|| {
                CredentialError::SchemaValidationError(format!("field '{name}' must be an array"))
            })?;
            for (i, elem) in arr.iter().enumerate() {
                validate_field(&format!("{name}[{i}]"), element_type, elem, remaining_depth)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use verifiable_storage::SelfAddressed;

    fn test_schema() -> CredentialSchema {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::String);
        fields.insert("age".to_string(), SchemaField::Integer);
        fields.insert("active".to_string(), SchemaField::Boolean);

        CredentialSchema::create(
            "Test Schema".to_string(),
            "A test schema".to_string(),
            "1.0".to_string(),
            fields,
            false,
            false,
            false,
            false,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_schema_said_derivation() {
        let schema = test_schema();
        assert!(!schema.said.is_empty());
        assert_eq!(schema.said.len(), 44);
    }

    #[test]
    fn test_schema_said_verify() {
        let schema = test_schema();
        assert!(schema.verify_said().is_ok());
    }

    #[test]
    fn test_schema_said_deterministic() {
        let s1 = test_schema();
        let s2 = test_schema();
        assert_eq!(s1.said, s2.said);
    }

    #[test]
    fn test_schema_serialization_roundtrip() {
        let schema = test_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let deserialized: CredentialSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema.said, deserialized.said);
        assert_eq!(schema.name, deserialized.name);
    }

    #[test]
    fn test_validate_claims_valid() {
        let schema = test_schema();
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "name": "Alice",
            "age": 30,
            "active": true
        });
        assert!(validate_claims(&schema, &claims).is_ok());
    }

    #[test]
    fn test_validate_claims_missing_field() {
        let schema = test_schema();
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "name": "Alice",
            "age": 30
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(matches!(err, CredentialError::SchemaValidationError(_)));
        assert!(err.to_string().contains("active"));
    }

    #[test]
    fn test_validate_claims_wrong_type() {
        let schema = test_schema();
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "name": "Alice",
            "age": 1.23,
            "active": true
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(err.to_string().contains("age"));
    }

    #[test]
    fn test_validate_claims_compacted_skips() {
        let schema = test_schema();
        let compacted = json!("EAbc1234567890123456789012345678901234567890");
        assert!(validate_claims(&schema, &compacted).is_ok());
    }

    #[test]
    fn test_validate_claims_nested_object() {
        let mut address_fields = BTreeMap::new();
        address_fields.insert("city".to_string(), SchemaField::String);
        address_fields.insert("zip".to_string(), SchemaField::String);

        let mut fields = BTreeMap::new();
        fields.insert(
            "address".to_string(),
            SchemaField::Object {
                fields: address_fields,
                compactable: false,
            },
        );

        let schema = CredentialSchema::create(
            "Address Schema".to_string(),
            "Schema with nested object".to_string(),
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

        let valid = json!({ "said": "EAbc1234567890123456789012345678901234567890", "address": { "city": "Toronto", "zip": "M5V" } });
        assert!(validate_claims(&schema, &valid).is_ok());

        let missing_sub = json!({ "said": "EAbc1234567890123456789012345678901234567890", "address": { "city": "Toronto" } });
        assert!(validate_claims(&schema, &missing_sub).is_err());
    }

    #[test]
    fn test_validate_claims_array() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "tags".to_string(),
            SchemaField::Array(Box::new(SchemaField::String)),
        );

        let schema = CredentialSchema::create(
            "Tags Schema".to_string(),
            "Schema with array".to_string(),
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

        let valid = json!({ "said": "EAbc1234567890123456789012345678901234567890", "tags": ["a", "b", "c"] });
        assert!(validate_claims(&schema, &valid).is_ok());

        let invalid =
            json!({ "said": "EAbc1234567890123456789012345678901234567890", "tags": [1, 2, 3] });
        assert!(validate_claims(&schema, &invalid).is_err());
    }

    #[test]
    fn test_schema_field_said_and_prefix() {
        let mut fields = BTreeMap::new();
        fields.insert("ref".to_string(), SchemaField::Said);
        fields.insert("id".to_string(), SchemaField::Prefix);

        let schema = CredentialSchema::create(
            "Ref Schema".to_string(),
            "Schema with SAID/prefix fields".to_string(),
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

        let valid = json!({ "said": "EAbc1234567890123456789012345678901234567890", "ref": "EAbc...", "id": "EAbc..." });
        assert!(validate_claims(&schema, &valid).is_ok());

        let invalid = json!({ "said": "EAbc1234567890123456789012345678901234567890", "ref": 123, "id": "EAbc..." });
        assert!(validate_claims(&schema, &invalid).is_err());
    }

    #[test]
    fn test_validate_claims_float() {
        let mut fields = BTreeMap::new();
        fields.insert("score".to_string(), SchemaField::Float);

        let schema = CredentialSchema::create(
            "Score Schema".to_string(),
            "Schema with float".to_string(),
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

        let valid =
            json!({ "said": "EAbc1234567890123456789012345678901234567890", "score": 9.81 });
        assert!(validate_claims(&schema, &valid).is_ok());
    }

    #[test]
    fn test_validate_claims_not_object() {
        let schema = test_schema();
        let claims = json!(42);
        assert!(validate_claims(&schema, &claims).is_err());
    }

    #[test]
    fn test_validate_claims_extra_field_rejected() {
        let schema = test_schema();
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "name": "Alice",
            "age": 30,
            "active": true,
            "extra": "not allowed"
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(err.to_string().contains("unexpected field"));
    }

    #[test]
    fn test_validate_claims_missing_said_on_compactable() {
        let schema = test_schema();
        let claims = json!({
            "name": "Alice",
            "age": 30,
            "active": true
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(err.to_string().contains("said"));
    }

    #[test]
    fn test_validate_claims_said_rejected_on_non_compactable() {
        let mut inner = BTreeMap::new();
        inner.insert("x".to_string(), SchemaField::String);

        let mut fields = BTreeMap::new();
        fields.insert(
            "obj".to_string(),
            SchemaField::Object {
                fields: inner,
                compactable: false,
            },
        );

        let schema = CredentialSchema::create(
            "NonCompact".to_string(),
            "Non-compactable object".to_string(),
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

        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "obj": { "said": "EBad1234567890123456789012345678901234567890", "x": "val" }
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(err.to_string().contains("unexpected field"));
    }

    #[test]
    fn test_validate_compactable_object_accepts_said_string() {
        let mut inner = BTreeMap::new();
        inner.insert("x".to_string(), SchemaField::String);

        let mut fields = BTreeMap::new();
        fields.insert(
            "sub".to_string(),
            SchemaField::Object {
                fields: inner,
                compactable: true,
            },
        );

        let schema = CredentialSchema::create(
            "Compact".to_string(),
            "Compactable sub-object".to_string(),
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

        // Compacted form (SAID string) should be accepted
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "sub": "ESub1234567890123456789012345678901234567890"
        });
        assert!(validate_claims(&schema, &claims).is_ok());

        // Expanded form with said should be accepted
        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "sub": { "said": "ESub1234567890123456789012345678901234567890", "x": "val" }
        });
        assert!(validate_claims(&schema, &claims).is_ok());
    }

    #[test]
    fn test_validate_non_compactable_rejects_string() {
        let mut inner = BTreeMap::new();
        inner.insert("x".to_string(), SchemaField::String);

        let mut fields = BTreeMap::new();
        fields.insert(
            "obj".to_string(),
            SchemaField::Object {
                fields: inner,
                compactable: false,
            },
        );

        let schema = CredentialSchema::create(
            "NonCompact".to_string(),
            "Non-compactable object".to_string(),
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

        let claims = json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "obj": "ESome123456789012345678901234567890123456789"
        });
        let err = validate_claims(&schema, &claims).unwrap_err();
        assert!(err.to_string().contains("must be an object"));
    }

    #[test]
    fn test_validate_schema_rejects_said_field_name() {
        let mut fields = BTreeMap::new();
        fields.insert("said".to_string(), SchemaField::String);
        fields.insert("name".to_string(), SchemaField::String);

        let schema = CredentialSchema::create(
            "Bad".to_string(),
            "Schema with said field".to_string(),
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

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("reserved field name"));
    }

    #[test]
    fn test_validate_schema_rejects_nested_said_field_name() {
        let mut inner = BTreeMap::new();
        inner.insert("said".to_string(), SchemaField::String);

        let mut fields = BTreeMap::new();
        fields.insert(
            "nested".to_string(),
            SchemaField::Object {
                fields: inner,
                compactable: true,
            },
        );

        let schema = CredentialSchema::create(
            "Bad".to_string(),
            "Schema with nested said field".to_string(),
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

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("reserved field name"));
    }

    #[test]
    fn test_validate_schema_rejects_excessive_nesting() {
        // Build a schema nested deeper than MAX_RECURSION_DEPTH
        let mut fields = BTreeMap::new();
        fields.insert("leaf".to_string(), SchemaField::String);

        for _ in 0..MAX_RECURSION_DEPTH + 1 {
            let mut outer = BTreeMap::new();
            outer.insert(
                "inner".to_string(),
                SchemaField::Object {
                    fields,
                    compactable: false,
                },
            );
            fields = outer;
        }

        let schema = CredentialSchema::create(
            "Deep".to_string(),
            "Excessively nested schema".to_string(),
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

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("maximum schema nesting depth"));
    }

    #[test]
    fn test_validate_claims_rejects_excessive_nesting() {
        // Build a schema nested deeper than MAX_RECURSION_DEPTH
        let mut fields = BTreeMap::new();
        fields.insert("leaf".to_string(), SchemaField::String);

        let mut claims_inner = json!({"leaf": "value"});

        for _ in 0..MAX_RECURSION_DEPTH + 1 {
            let mut outer = BTreeMap::new();
            outer.insert(
                "inner".to_string(),
                SchemaField::Object {
                    fields,
                    compactable: false,
                },
            );
            fields = outer;

            claims_inner = json!({"inner": claims_inner});
        }

        let schema = CredentialSchema::create(
            "Deep".to_string(),
            "Excessively nested schema".to_string(),
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

        claims_inner.as_object_mut().unwrap().insert(
            "said".to_string(),
            json!("EAbc1234567890123456789012345678901234567890"),
        );

        let err = validate_claims(&schema, &claims_inner).unwrap_err();
        assert!(err.to_string().contains("maximum nesting depth"));
    }
}
