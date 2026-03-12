use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::error::CredentialError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SchemaField {
    String,
    Integer,
    Float,
    Boolean,
    Object(BTreeMap<String, SchemaField>),
    Array(Box<SchemaField>),
    Said,
    Prefix,
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct CredentialSchema {
    #[said]
    pub said: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
}

/// Validate that a claims value conforms to a schema's field definitions.
/// If claims is a string (compacted to SAID), validation is skipped.
pub fn validate_claims(
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

    for (field_name, field_type) in &schema.fields {
        if let Some(value) = obj.get(field_name) {
            validate_field(field_name, field_type, value)?;
        } else {
            return Err(CredentialError::SchemaValidationError(format!(
                "missing required field: {field_name}"
            )));
        }
    }

    Ok(())
}

fn validate_field(
    name: &str,
    field_type: &SchemaField,
    value: &serde_json::Value,
) -> Result<(), CredentialError> {
    // Compacted (SAID string) — any string is acceptable for a compactable field
    if value.is_string() {
        return Ok(());
    }

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
            if !value.is_f64() {
                return Err(CredentialError::SchemaValidationError(format!(
                    "field '{name}' must be a float"
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
        SchemaField::Object(fields) => {
            let obj = value.as_object().ok_or_else(|| {
                CredentialError::SchemaValidationError(format!("field '{name}' must be an object"))
            })?;
            for (sub_name, sub_type) in fields {
                if let Some(sub_value) = obj.get(sub_name) {
                    validate_field(&format!("{name}.{sub_name}"), sub_type, sub_value)?;
                } else {
                    return Err(CredentialError::SchemaValidationError(format!(
                        "missing required field: {name}.{sub_name}"
                    )));
                }
            }
        }
        SchemaField::Array(element_type) => {
            let arr = value.as_array().ok_or_else(|| {
                CredentialError::SchemaValidationError(format!("field '{name}' must be an array"))
            })?;
            for (i, elem) in arr.iter().enumerate() {
                validate_field(&format!("{name}[{i}]"), element_type, elem)?;
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
        fields.insert("address".to_string(), SchemaField::Object(address_fields));

        let schema = CredentialSchema::create(
            "Address Schema".to_string(),
            "Schema with nested object".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let valid = json!({ "address": { "city": "Toronto", "zip": "M5V" } });
        assert!(validate_claims(&schema, &valid).is_ok());

        let missing_sub = json!({ "address": { "city": "Toronto" } });
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
        )
        .unwrap();

        let valid = json!({ "tags": ["a", "b", "c"] });
        assert!(validate_claims(&schema, &valid).is_ok());

        let invalid = json!({ "tags": [1, 2, 3] });
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
        )
        .unwrap();

        let valid = json!({ "ref": "EAbc...", "id": "EAbc..." });
        assert!(validate_claims(&schema, &valid).is_ok());

        let invalid = json!({ "ref": 123, "id": "EAbc..." });
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
        )
        .unwrap();

        let valid = json!({ "score": 9.81 });
        assert!(validate_claims(&schema, &valid).is_ok());
    }

    #[test]
    fn test_validate_claims_not_object() {
        let schema = test_schema();
        let claims = json!(42);
        assert!(validate_claims(&schema, &claims).is_err());
    }
}
