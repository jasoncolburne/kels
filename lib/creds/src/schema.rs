use std::{collections::BTreeMap, str::FromStr};

use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::{compaction::MAX_RECURSION_DEPTH, credential::Credential, error::CredentialError};

/// Result of schema validation during credential verification.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaValidationResult {
    Valid,
    Invalid,
    NotValidated,
}

/// Per-field validation report for graduated disclosure scenarios.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl SchemaValidationReport {
    pub fn require_valid(&self) -> Result<(), CredentialError> {
        if !self.valid {
            return Err(CredentialError::SchemaValidationError(
                self.errors.join("; "),
            ));
        }
        Ok(())
    }
}

/// The type of a schema field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SchemaFieldType {
    String,
    Integer,
    Float,
    Boolean,
    Object,
    Array,
    Said,
    Prefix,
    Datetime,
}

/// A field descriptor in a schema. Describes the type, structure, compactability,
/// optionality, and value constraints of a single field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaField {
    #[serde(rename = "type")]
    pub field_type: SchemaFieldType,

    /// If true, this object can be compacted to/expanded from a SAID string.
    /// Only meaningful when `field_type` is `Object`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compactable: bool,

    /// If true, this field may be absent from the object.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,

    /// If set, the field's value must equal this exact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<serde_json::Value>,

    /// Child fields for `Object` type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, SchemaField>>,

    /// Element type for `Array` type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaField>>,
}

impl SchemaField {
    pub fn string() -> Self {
        Self {
            field_type: SchemaFieldType::String,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn integer() -> Self {
        Self {
            field_type: SchemaFieldType::Integer,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn float() -> Self {
        Self {
            field_type: SchemaFieldType::Float,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn boolean() -> Self {
        Self {
            field_type: SchemaFieldType::Boolean,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn said() -> Self {
        Self {
            field_type: SchemaFieldType::Said,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn prefix() -> Self {
        Self {
            field_type: SchemaFieldType::Prefix,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn datetime() -> Self {
        Self {
            field_type: SchemaFieldType::Datetime,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: None,
        }
    }

    pub fn object(fields: BTreeMap<String, SchemaField>, compactable: bool) -> Self {
        Self {
            field_type: SchemaFieldType::Object,
            compactable,
            optional: false,
            constraint: None,
            fields: Some(fields),
            items: None,
        }
    }

    pub fn array(items: SchemaField) -> Self {
        Self {
            field_type: SchemaFieldType::Array,
            compactable: false,
            optional: false,
            constraint: None,
            fields: None,
            items: Some(Box::new(items)),
        }
    }

    /// Make this field optional.
    pub fn opt(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Add a value constraint.
    pub fn with_constraint(mut self, value: serde_json::Value) -> Self {
        self.constraint = Some(value);
        self
    }
}

/// A generic, self-addressed schema. Describes the structure, types, compactability,
/// and constraints of any self-addressed document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    #[said]
    pub said: cesr::Digest256,
    pub name: String,
    pub description: String,
    pub version: String,
    pub fields: BTreeMap<String, SchemaField>,
}

impl Schema {
    /// Store this schema in a SAD store as a single chunk keyed by its SAID.
    pub async fn store(
        &self,
        sad_store: &dyn crate::store::SADStore,
    ) -> Result<(), CredentialError> {
        let value = serde_json::to_value(self)?;
        sad_store.store_chunk(self.said.as_ref(), &value).await
    }

    /// Fetch a schema from a SAD store by its SAID.
    pub async fn fetch(
        said: &cesr::Digest256,
        sad_store: &dyn crate::store::SADStore,
    ) -> Result<Self, CredentialError> {
        let chunk = sad_store.get_chunk(said.as_ref()).await?.ok_or_else(|| {
            CredentialError::ExpansionError(format!("schema {} not found in store", said))
        })?;
        Ok(serde_json::from_value(chunk)?)
    }
}

impl FromStr for Schema {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Validate that a schema is well-formed and compliant with kels-creds.
/// Combines structural validation and credential envelope compliance.
pub fn validate_schema(schema: &Schema) -> Result<(), CredentialError> {
    validate_schema_structure(schema)?;
    validate_schema_compliance(schema)
}

/// Validate that a schema's field definitions are well-formed.
/// Rejects `said` as a field name anywhere (it's implicit for compactable objects).
pub fn validate_schema_structure(schema: &Schema) -> Result<(), CredentialError> {
    validate_schema_fields("fields", &schema.fields, MAX_RECURSION_DEPTH)
}

/// Validate that a schema includes the required credential envelope fields
/// with correct types. These fields are required by the `Credential` struct.
pub fn validate_schema_compliance(schema: &Schema) -> Result<(), CredentialError> {
    fn require_field(
        fields: &BTreeMap<String, SchemaField>,
        name: &str,
        expected_type: SchemaFieldType,
        optional: bool,
    ) -> Result<(), CredentialError> {
        let field = fields.get(name).ok_or_else(|| {
            CredentialError::SchemaValidationError(format!(
                "schema missing required credential field '{name}'"
            ))
        })?;
        if field.field_type != expected_type {
            return Err(CredentialError::SchemaValidationError(format!(
                "credential field '{name}' must be type {expected_type:?}, got {:?}",
                field.field_type
            )));
        }
        if field.optional != optional {
            let expectation = if optional { "optional" } else { "required" };
            return Err(CredentialError::SchemaValidationError(format!(
                "credential field '{name}' must be {expectation}"
            )));
        }
        Ok(())
    }

    fn require_compactable_object(
        fields: &BTreeMap<String, SchemaField>,
        name: &str,
        optional: bool,
    ) -> Result<(), CredentialError> {
        let field = fields.get(name).ok_or_else(|| {
            CredentialError::SchemaValidationError(format!(
                "schema missing required credential field '{name}'"
            ))
        })?;
        if field.field_type != SchemaFieldType::Object {
            return Err(CredentialError::SchemaValidationError(format!(
                "credential field '{name}' must be type Object, got {:?}",
                field.field_type
            )));
        }
        if !field.compactable {
            return Err(CredentialError::SchemaValidationError(format!(
                "credential field '{name}' must be compactable"
            )));
        }
        if field.optional != optional {
            let expectation = if optional { "optional" } else { "required" };
            return Err(CredentialError::SchemaValidationError(format!(
                "credential field '{name}' must be {expectation}"
            )));
        }
        Ok(())
    }

    let fields = &schema.fields;

    // Required fields
    require_field(fields, "schema", SchemaFieldType::Said, false)?;
    require_field(fields, "policy", SchemaFieldType::Said, false)?;
    require_field(fields, "issuedAt", SchemaFieldType::Datetime, false)?;
    require_compactable_object(fields, "claims", false)?;

    // Optional fields with required types
    require_field(fields, "subject", SchemaFieldType::Prefix, true)?;
    require_field(fields, "nonce", SchemaFieldType::String, true)?;
    require_field(fields, "expiresAt", SchemaFieldType::Datetime, true)?;
    require_compactable_object(fields, "edges", true)?;
    require_compactable_object(fields, "rules", true)?;

    // Validate edge entry structure
    if let Some(ref edge_fields) = fields["edges"].fields {
        for (label, entry) in edge_fields {
            if entry.field_type != SchemaFieldType::Object {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' must be type Object, got {:?}",
                    entry.field_type
                )));
            }
            if !entry.compactable {
                return Err(CredentialError::SchemaValidationError(format!(
                    "edge '{label}' must be compactable"
                )));
            }
            if let Some(ref entry_fields) = entry.fields {
                const ALLOWED_EDGE_FIELDS: &[&str] = &["schema", "policy", "credential", "nonce"];

                // schema is required
                require_field(entry_fields, "schema", SchemaFieldType::Said, false).map_err(
                    |_| {
                        CredentialError::SchemaValidationError(format!(
                            "edge '{label}' must have required field 'schema' of type Said"
                        ))
                    },
                )?;

                // Optional edge fields with required types
                if let Some(f) = entry_fields.get("policy")
                    && (f.field_type != SchemaFieldType::Said || !f.optional)
                {
                    return Err(CredentialError::SchemaValidationError(format!(
                        "edge '{label}' field 'policy' must be optional Said"
                    )));
                }
                if let Some(f) = entry_fields.get("credential")
                    && (f.field_type != SchemaFieldType::Said || !f.optional)
                {
                    return Err(CredentialError::SchemaValidationError(format!(
                        "edge '{label}' field 'credential' must be optional Said"
                    )));
                }
                if let Some(f) = entry_fields.get("nonce")
                    && (f.field_type != SchemaFieldType::String || !f.optional)
                {
                    return Err(CredentialError::SchemaValidationError(format!(
                        "edge '{label}' field 'nonce' must be optional String"
                    )));
                }

                for name in entry_fields.keys() {
                    if !ALLOWED_EDGE_FIELDS.contains(&name.as_str()) {
                        return Err(CredentialError::SchemaValidationError(format!(
                            "edge '{label}' has unknown field '{name}'"
                        )));
                    }
                }
            }
        }
    }

    // Validate rule entry structure
    if let Some(ref rule_fields) = fields["rules"].fields {
        for (label, entry) in rule_fields {
            if entry.field_type != SchemaFieldType::Object {
                return Err(CredentialError::SchemaValidationError(format!(
                    "rule '{label}' must be type Object, got {:?}",
                    entry.field_type
                )));
            }
            if !entry.compactable {
                return Err(CredentialError::SchemaValidationError(format!(
                    "rule '{label}' must be compactable"
                )));
            }
            if let Some(ref entry_fields) = entry.fields {
                const ALLOWED_RULE_FIELDS: &[&str] = &["condition"];

                require_field(entry_fields, "condition", SchemaFieldType::String, false).map_err(
                    |_| {
                        CredentialError::SchemaValidationError(format!(
                            "rule '{label}' must have required field 'condition' of type String"
                        ))
                    },
                )?;

                for name in entry_fields.keys() {
                    if !ALLOWED_RULE_FIELDS.contains(&name.as_str()) {
                        return Err(CredentialError::SchemaValidationError(format!(
                            "rule '{label}' has unknown field '{name}'"
                        )));
                    }
                }
            }
        }
    }

    // Reject unknown top-level fields
    const ALLOWED_FIELDS: &[&str] = &[
        "schema",
        "policy",
        "issuedAt",
        "claims",
        "subject",
        "nonce",
        "expiresAt",
        "edges",
        "rules",
    ];
    for name in fields.keys() {
        if !ALLOWED_FIELDS.contains(&name.as_str()) {
            return Err(CredentialError::SchemaValidationError(format!(
                "unknown top-level credential field '{name}'"
            )));
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
    for (name, field) in fields {
        if name == "said" {
            return Err(CredentialError::SchemaValidationError(format!(
                "'said' is a reserved field name and cannot appear in schema definition at {path}.{name}"
            )));
        }
        validate_schema_field(&format!("{path}.{name}"), field, remaining_depth - 1)?;
    }
    Ok(())
}

fn validate_schema_field(
    path: &str,
    field: &SchemaField,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    if remaining_depth == 0 {
        return Err(CredentialError::SchemaValidationError(format!(
            "maximum schema nesting depth exceeded at {path}"
        )));
    }

    match field.field_type {
        SchemaFieldType::Object => {
            if let Some(ref fields) = field.fields {
                validate_schema_fields(path, fields, remaining_depth)?;
            }
        }
        SchemaFieldType::Array => {
            if let Some(ref items) = field.items {
                validate_schema_field(&format!("{path}[]"), items, remaining_depth)?;
            }
        }
        _ => {}
    }

    // Validate constraint type matches field type
    if let Some(ref constraint) = field.constraint {
        validate_constraint_type(path, &field.field_type, constraint)?;
    }

    Ok(())
}

fn validate_constraint_type(
    path: &str,
    field_type: &SchemaFieldType,
    constraint: &serde_json::Value,
) -> Result<(), CredentialError> {
    let valid = match field_type {
        SchemaFieldType::String
        | SchemaFieldType::Said
        | SchemaFieldType::Prefix
        | SchemaFieldType::Datetime => constraint.is_string(),
        SchemaFieldType::Integer => constraint.is_i64() || constraint.is_u64(),
        SchemaFieldType::Float => constraint.is_f64() || constraint.is_i64() || constraint.is_u64(),
        SchemaFieldType::Boolean => constraint.is_boolean(),
        SchemaFieldType::Object | SchemaFieldType::Array => {
            return Err(CredentialError::SchemaValidationError(format!(
                "constraints are not supported on object/array fields at {path}"
            )));
        }
    };

    if !valid {
        return Err(CredentialError::SchemaValidationError(format!(
            "constraint type mismatch at {path}"
        )));
    }

    Ok(())
}

/// Validate a credential against a schema. Returns a report with errors.
pub(crate) fn validate_credential_report<T: crate::credential::Claims>(
    credential: &Credential<T>,
    schema: &Schema,
) -> Result<SchemaValidationReport, CredentialError> {
    validate_schema(schema)?;

    let value = serde_json::to_value(credential)?;
    let obj = value.as_object().ok_or_else(|| {
        CredentialError::SchemaValidationError("credential must be an object".to_string())
    })?;

    let mut errors = Vec::new();
    validate_object_fields(
        "credential",
        &schema.fields,
        obj,
        true,
        MAX_RECURSION_DEPTH,
        &mut errors,
    );

    Ok(SchemaValidationReport {
        valid: errors.is_empty(),
        errors,
    })
}

fn validate_object_fields(
    name: &str,
    schema_fields: &BTreeMap<String, SchemaField>,
    obj: &serde_json::Map<String, serde_json::Value>,
    compactable: bool,
    remaining_depth: usize,
    errors: &mut Vec<String>,
) {
    if remaining_depth == 0 {
        errors.push(format!("maximum nesting depth exceeded at {name}"));
        return;
    }

    // Check all schema-defined fields
    for (field_name, field) in schema_fields {
        if let Some(value) = obj.get(field_name) {
            validate_field(
                &format!("{name}.{field_name}"),
                field,
                value,
                remaining_depth - 1,
                errors,
            );
        } else if !field.optional {
            errors.push(format!("missing required field: {name}.{field_name}"));
        }
    }

    // Compactable objects must have a `said` field when expanded
    if compactable && !obj.contains_key("said") {
        errors.push(format!(
            "missing required field: {name}.said (compactable objects must have a said field)"
        ));
    }

    // Closed schema: reject extra fields (allow `said` on compactable objects)
    for key in obj.keys() {
        if compactable && key == "said" {
            continue;
        }
        if !schema_fields.contains_key(key) {
            errors.push(format!("unexpected field: {name}.{key}"));
        }
    }
}

fn validate_field(
    name: &str,
    field: &SchemaField,
    value: &serde_json::Value,
    remaining_depth: usize,
    errors: &mut Vec<String>,
) {
    match field.field_type {
        SchemaFieldType::String
        | SchemaFieldType::Said
        | SchemaFieldType::Prefix
        | SchemaFieldType::Datetime => {
            if !value.is_string() {
                errors.push(format!("field '{name}' must be a string"));
                return;
            }
        }
        SchemaFieldType::Integer => {
            if !value.is_i64() && !value.is_u64() {
                errors.push(format!("field '{name}' must be an integer"));
                return;
            }
        }
        SchemaFieldType::Float => {
            if !value.is_f64() && !value.is_i64() && !value.is_u64() {
                errors.push(format!("field '{name}' must be a number"));
                return;
            }
        }
        SchemaFieldType::Boolean => {
            if !value.is_boolean() {
                errors.push(format!("field '{name}' must be a boolean"));
                return;
            }
        }
        SchemaFieldType::Object => {
            if field.compactable && value.is_string() {
                // Compacted to SAID string — valid, skip further validation
                return;
            }
            let Some(obj) = value.as_object() else {
                if field.compactable {
                    errors.push(format!(
                        "field '{name}' must be an object or a compacted SAID string"
                    ));
                } else {
                    errors.push(format!("field '{name}' must be an object"));
                }
                return;
            };
            if let Some(ref sub_fields) = field.fields {
                validate_object_fields(
                    name,
                    sub_fields,
                    obj,
                    field.compactable,
                    remaining_depth,
                    errors,
                );
            }
        }
        SchemaFieldType::Array => {
            let Some(arr) = value.as_array() else {
                errors.push(format!("field '{name}' must be an array"));
                return;
            };
            if let Some(ref element_type) = field.items {
                for (i, elem) in arr.iter().enumerate() {
                    validate_field(
                        &format!("{name}[{i}]"),
                        element_type,
                        elem,
                        remaining_depth,
                        errors,
                    );
                }
            }
        }
    }

    // Check value constraint
    if let Some(ref constraint) = field.constraint
        && value != constraint
    {
        errors.push(format!(
            "field '{name}' value mismatch: expected {constraint}, got {value}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use verifiable_storage::SelfAddressed;

    fn test_schema() -> Schema {
        let claims_fields = BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            ("age".to_string(), SchemaField::integer()),
            ("active".to_string(), SchemaField::boolean()),
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
            "A test schema".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap()
    }

    #[test]
    fn test_schema_said_derivation() {
        let schema = test_schema();
        assert!(!schema.said.to_string().is_empty());
        assert_eq!(schema.said.to_string().len(), 44);
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
        let deserialized: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema.said, deserialized.said);
        assert_eq!(schema.name, deserialized.name);
    }

    #[test]
    fn test_schema_field_builders() {
        let f = SchemaField::string().opt().with_constraint(json!("hello"));
        assert_eq!(f.field_type, SchemaFieldType::String);
        assert!(f.optional);
        assert_eq!(f.constraint, Some(json!("hello")));
    }

    #[test]
    fn test_validate_schema_rejects_said_field_name() {
        let mut fields = BTreeMap::new();
        fields.insert("said".to_string(), SchemaField::string());

        let schema = Schema::create(
            "Bad".to_string(),
            "Schema with said field".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("reserved field name"));
    }

    #[test]
    fn test_validate_schema_rejects_nested_said_field_name() {
        let inner = BTreeMap::from([("said".to_string(), SchemaField::string())]);
        let mut fields = BTreeMap::new();
        fields.insert("nested".to_string(), SchemaField::object(inner, true));

        let schema = Schema::create(
            "Bad".to_string(),
            "Schema with nested said field".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("reserved field name"));
    }

    #[test]
    fn test_validate_schema_rejects_excessive_nesting() {
        let mut fields = BTreeMap::from([("leaf".to_string(), SchemaField::string())]);

        for _ in 0..MAX_RECURSION_DEPTH + 1 {
            let mut outer = BTreeMap::new();
            outer.insert("inner".to_string(), SchemaField::object(fields, false));
            fields = outer;
        }

        let schema = Schema::create(
            "Deep".to_string(),
            "Excessively nested schema".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("maximum schema nesting depth"));
    }

    #[test]
    fn test_validate_constraint_type_mismatch() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "age".to_string(),
            SchemaField::integer().with_constraint(json!("not a number")),
        );

        let schema = Schema::create(
            "Bad".to_string(),
            "Bad constraint".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let err = validate_schema(&schema).unwrap_err();
        assert!(err.to_string().contains("constraint type mismatch"));
    }

    #[test]
    fn test_schema_field_serde_roundtrip() {
        let field = SchemaField::object(
            BTreeMap::from([
                ("name".to_string(), SchemaField::string()),
                ("score".to_string(), SchemaField::float().opt()),
            ]),
            true,
        );

        let json = serde_json::to_value(&field).unwrap();
        let deserialized: SchemaField = serde_json::from_value(json).unwrap();
        assert_eq!(field, deserialized);
    }
}
