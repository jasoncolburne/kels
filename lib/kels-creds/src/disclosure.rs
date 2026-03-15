use std::collections::HashMap;

use verifiable_storage::compact_value_bounded;

use crate::{
    compaction::{MAX_RECURSION_DEPTH, expand_with_schema},
    error::CredentialError,
    schema::Schema,
    store::SADStore,
};

/// AST node for the disclosure path DSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathToken {
    /// Expand the field at this path (children stay as-is).
    Expand(Vec<String>),
    /// Expand the field at this path and all compactable children recursively.
    /// Empty vec means expand everything from root.
    ExpandRecursive(Vec<String>),
    /// Compact the field at this path (children stay as-is).
    Compact(Vec<String>),
    /// Compact the field at this path and all compactable children recursively.
    /// Empty vec means compact everything from root.
    CompactRecursive(Vec<String>),
}

/// Parse a disclosure DSL expression into a sequence of path tokens.
///
/// Grammar:
/// ```text
/// expression = token (SPACE token)*
/// token      = ["-"] path
/// path       = segment ("." segment)* [".*"]
/// segment    = identifier
/// ```
///
/// Normalization: bare `*` → `.*`, bare `-*` → `-.*`
pub fn parse_disclosure(expr: &str) -> Result<Vec<PathToken>, CredentialError> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let mut tokens = Vec::new();
    for raw_token in trimmed.split_whitespace() {
        tokens.push(parse_token(raw_token)?);
    }
    Ok(tokens)
}

fn parse_token(raw: &str) -> Result<PathToken, CredentialError> {
    let (negate, path_str) = if let Some(rest) = raw.strip_prefix('-') {
        (true, rest)
    } else {
        (false, raw)
    };

    // Normalize: bare "*" → ".*"
    let normalized = if path_str == "*" { ".*" } else { path_str };

    if normalized.is_empty() {
        return Err(CredentialError::InvalidDisclosure(
            "empty path in disclosure expression".to_string(),
        ));
    }

    let (recursive, segment_str) = if let Some(prefix) = normalized.strip_suffix(".*") {
        (true, prefix)
    } else {
        (false, normalized)
    };

    let segments: Vec<String> = if segment_str.is_empty() {
        // This is ".*" or "-.*" — root-level recursive
        vec![]
    } else {
        segment_str
            .split('.')
            .map(|s| {
                if s.is_empty() || s == "*" {
                    return Err(CredentialError::InvalidDisclosure(format!(
                        "invalid segment in path: '{}'",
                        normalized
                    )));
                }
                Ok(s.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok(match (negate, recursive) {
        (false, false) => PathToken::Expand(segments),
        (false, true) => PathToken::ExpandRecursive(segments),
        (true, false) => PathToken::Compact(segments),
        (true, true) => PathToken::CompactRecursive(segments),
    })
}

/// Apply disclosure tokens to a credential value.
///
/// 1. Starts by fetching the credential's root chunk from the store
/// 2. Applies tokens left-to-right:
///    - Expand: look up SAID in SAD store, replace with full object
///    - ExpandRecursive: expand and recursively expand all children (schema-aware)
///    - Compact: replace object at path with its SAID
///    - CompactRecursive: compact object and all children
pub async fn apply_disclosure(
    said: &str,
    tokens: &[PathToken],
    sad_store: &dyn SADStore,
    schema: &Schema,
) -> Result<serde_json::Value, CredentialError> {
    // Start fully compacted
    let chunk = sad_store.get_chunk(said).await?;
    let Some(mut value) = chunk else {
        return Err(CredentialError::ExpansionError(
            "Couldn't find value in SAD store".to_string(),
        ));
    };

    for token in tokens {
        match token {
            PathToken::ExpandRecursive(path) if path.is_empty() => {
                expand_with_schema(&mut value, schema, sad_store).await?;
            }
            PathToken::CompactRecursive(path) if path.is_empty() => {
                compact_children(&mut value)?;
            }
            PathToken::Expand(path) => {
                expand_at_path(&mut value, path, sad_store).await?;
            }
            PathToken::ExpandRecursive(path) => {
                expand_at_path(&mut value, path, sad_store).await?;
                // After expanding the field, recursively expand its children
                // using schema-aware expansion
                let (parent, last) = navigate_to_field(&mut value, path)?;
                if let Some(child) = parent.get_mut(last) {
                    // Find the schema field for this path to get sub-fields
                    if let Some(sub_schema_fields) =
                        resolve_schema_fields_at_path(&schema.fields, path)
                    {
                        let sub_schema = Schema {
                            said: String::new(),
                            name: String::new(),
                            description: String::new(),
                            version: String::new(),
                            fields: sub_schema_fields,
                        };
                        expand_with_schema(child, &sub_schema, sad_store).await?;
                    }
                }
            }
            PathToken::Compact(path) | PathToken::CompactRecursive(path) => {
                compact_at_path(&mut value, path)?;
            }
        }
    }

    Ok(value)
}

/// Resolve the schema fields at a given path. Returns the fields map for the
/// object at that path, if it exists in the schema.
fn resolve_schema_fields_at_path(
    fields: &std::collections::BTreeMap<String, crate::schema::SchemaField>,
    path: &[String],
) -> Option<std::collections::BTreeMap<String, crate::schema::SchemaField>> {
    if path.is_empty() {
        return Some(fields.clone());
    }

    let field = fields.get(&path[0])?;
    if let Some(ref sub_fields) = field.fields {
        if path.len() == 1 {
            Some(sub_fields.clone())
        } else {
            resolve_schema_fields_at_path(sub_fields, &path[1..])
        }
    } else {
        None
    }
}

/// Expand a field at the given path (single level, not recursive).
async fn expand_at_path(
    value: &mut serde_json::Value,
    path: &[String],
    sad_store: &dyn SADStore,
) -> Result<(), CredentialError> {
    let (parent, last) = navigate_to_field(value, path)?;

    let current = parent
        .get(last)
        .ok_or_else(|| CredentialError::InvalidDisclosure(format!("field '{}' not found", last)))?;

    if let Some(said) = current.as_str() {
        // Field is compacted (SAID string) — look it up
        let expanded = sad_store.get_chunk(said).await?.ok_or_else(|| {
            CredentialError::ExpansionError(format!("chunk not found in store for SAID: {}", said))
        })?;
        parent.insert(last.to_string(), expanded);
    }

    Ok(())
}

/// Compact a field at the given path to its canonical SAID string.
/// Children are always compacted first to ensure the correct canonical SAID.
fn compact_at_path(value: &mut serde_json::Value, path: &[String]) -> Result<(), CredentialError> {
    let (parent, last) = navigate_to_field(value, path)?;

    let child = parent
        .get_mut(last)
        .ok_or_else(|| CredentialError::InvalidDisclosure(format!("field '{}' not found", last)))?;

    if child.is_string() {
        // Already compacted
        return Ok(());
    }

    if !child.is_object() || child.get("said").is_none() {
        return Err(CredentialError::InvalidDisclosure(format!(
            "field '{}' is not a compactable object (missing 'said' field)",
            last
        )));
    }

    // Always compact children first to derive the canonical SAID.
    compact_value_bounded(child, &mut HashMap::new(), MAX_RECURSION_DEPTH)?;

    Ok(())
}

/// Compact all children to SAIDs while keeping the root expanded.
/// Works by fully compacting (root becomes a SAID string), then restoring the
/// root object from the accumulator — its children remain as SAID strings.
fn compact_children(value: &mut serde_json::Value) -> Result<(), CredentialError> {
    let mut accumulator = HashMap::new();
    compact_value_bounded(value, &mut accumulator, MAX_RECURSION_DEPTH)?;
    let said = value.as_str().ok_or(CredentialError::CompactionError(
        "Could not compact children".to_string(),
    ))?;
    *value = accumulator
        .get(said)
        .ok_or(CredentialError::CompactionError(
            "Could not find value in accumulator".to_string(),
        ))?
        .clone();
    Ok(())
}

/// Navigate to the parent of the field at the given path and return the parent map + last key.
fn navigate_to_field<'a>(
    value: &'a mut serde_json::Value,
    path: &'a [String],
) -> Result<(&'a mut serde_json::Map<String, serde_json::Value>, &'a str), CredentialError> {
    if path.is_empty() {
        return Err(CredentialError::InvalidDisclosure("empty path".to_string()));
    }

    let mut current = value;
    for segment in &path[..path.len() - 1] {
        current = current.get_mut(segment.as_str()).ok_or_else(|| {
            CredentialError::InvalidDisclosure(format!("path segment '{}' not found", segment))
        })?;
    }

    let parent = current
        .as_object_mut()
        .ok_or_else(|| CredentialError::InvalidDisclosure("parent is not an object".to_string()))?;

    let last = &path[path.len() - 1];

    Ok((parent, last.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::compaction::compact;
    use crate::schema::{Schema, SchemaField};
    use crate::store::InMemorySADStore;

    // -- parse_disclosure tests --

    #[test]
    fn test_parse_empty() {
        let tokens = parse_disclosure("").unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_parse_expand_all() {
        let tokens = parse_disclosure(".*").unwrap();
        assert_eq!(tokens, vec![PathToken::ExpandRecursive(vec![])]);
    }

    #[test]
    fn test_parse_bare_star() {
        // * normalizes to .*
        let tokens = parse_disclosure("*").unwrap();
        assert_eq!(tokens, vec![PathToken::ExpandRecursive(vec![])]);
    }

    #[test]
    fn test_parse_compact_all() {
        let tokens = parse_disclosure("-.*").unwrap();
        assert_eq!(tokens, vec![PathToken::CompactRecursive(vec![])]);
    }

    #[test]
    fn test_parse_bare_minus_star() {
        let tokens = parse_disclosure("-*").unwrap();
        assert_eq!(tokens, vec![PathToken::CompactRecursive(vec![])]);
    }

    #[test]
    fn test_parse_simple_expand() {
        let tokens = parse_disclosure("claims").unwrap();
        assert_eq!(tokens, vec![PathToken::Expand(vec!["claims".to_string()])]);
    }

    #[test]
    fn test_parse_nested_expand() {
        let tokens = parse_disclosure("claims.address").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::Expand(vec![
                "claims".to_string(),
                "address".to_string()
            ])]
        );
    }

    #[test]
    fn test_parse_recursive_expand() {
        let tokens = parse_disclosure("claims.*").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::ExpandRecursive(vec!["claims".to_string()])]
        );
    }

    #[test]
    fn test_parse_simple_compact() {
        let tokens = parse_disclosure("-claims").unwrap();
        assert_eq!(tokens, vec![PathToken::Compact(vec!["claims".to_string()])]);
    }

    #[test]
    fn test_parse_recursive_compact() {
        let tokens = parse_disclosure("-claims.*").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::CompactRecursive(vec!["claims".to_string()])]
        );
    }

    #[test]
    fn test_parse_multiple_tokens() {
        let tokens = parse_disclosure(".* -claims.address").unwrap();
        assert_eq!(
            tokens,
            vec![
                PathToken::ExpandRecursive(vec![]),
                PathToken::Compact(vec!["claims".to_string(), "address".to_string()]),
            ]
        );
    }

    #[test]
    fn test_parse_complex_expression() {
        let tokens = parse_disclosure("schema edges.license.*").unwrap();
        assert_eq!(
            tokens,
            vec![
                PathToken::Expand(vec!["schema".to_string()]),
                PathToken::ExpandRecursive(vec!["edges".to_string(), "license".to_string()]),
            ]
        );
    }

    #[test]
    fn test_parse_invalid_empty_segment() {
        assert!(parse_disclosure("claims..address").is_err());
    }

    #[test]
    fn test_parse_invalid_bare_dash() {
        assert!(parse_disclosure("-").is_err());
    }

    // -- apply_disclosure tests --

    /// Compact a value and return (root_said, chunks). The compacted root object
    /// is in the chunks keyed by root_said.
    fn compact_and_collect(
        value: &mut serde_json::Value,
    ) -> (String, std::collections::HashMap<String, serde_json::Value>) {
        let chunks: HashMap<String, serde_json::Value> = compact(value).unwrap();
        let said = value.as_str().unwrap().to_string();
        (said, chunks)
    }

    /// Build a store from all chunks in the accumulator.
    async fn store_from_chunks(
        chunks: &std::collections::HashMap<String, serde_json::Value>,
    ) -> InMemorySADStore {
        let store = InMemorySADStore::new();
        store.store_chunks(chunks).await.unwrap();
        store
    }

    fn make_test_credential() -> serde_json::Value {
        json!({
            "said": "ECredentail",
            "schema": {
                "said": "ESchema",
                "name": "TestSchema",
                "version": "1.0"
            },
            "issuer": "EIssuer",
            "issued_at": "2025-01-01T00:00:00Z",
            "claims": {
                "said": "EClaim",
                "name": "Alice",
                "age": 30
            },
        })
    }

    fn test_disclosure_schema() -> Schema {
        let mut fields = BTreeMap::new();
        fields.insert(
            "schema".to_string(),
            SchemaField::object(
                BTreeMap::from([
                    ("name".to_string(), SchemaField::string()),
                    ("version".to_string(), SchemaField::string()),
                ]),
                true,
            ),
        );
        fields.insert("issuer".to_string(), SchemaField::string());
        fields.insert("issued_at".to_string(), SchemaField::string());
        fields.insert(
            "claims".to_string(),
            SchemaField::object(
                BTreeMap::from([
                    ("name".to_string(), SchemaField::string()),
                    ("age".to_string(), SchemaField::integer()),
                ]),
                true,
            ),
        );

        Schema::create(
            "Disclosure Test".to_string(),
            "For disclosure tests".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_apply_disclosure_expand_all() {
        let mut credential = make_test_credential();
        let (root_said, chunks) = compact_and_collect(&mut credential);
        let store = store_from_chunks(&chunks).await;
        let schema = test_disclosure_schema();

        let tokens = parse_disclosure(".*").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();

        assert!(value.get("schema").unwrap().is_object());
        assert!(value.get("claims").unwrap().is_object());
    }

    #[tokio::test]
    async fn test_apply_disclosure_selective() {
        let mut credential = make_test_credential();
        let (root_said, chunks) = compact_and_collect(&mut credential);
        let store = store_from_chunks(&chunks).await;
        let schema = test_disclosure_schema();

        let tokens = parse_disclosure("schema").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();

        assert!(value.get("schema").unwrap().is_object());
        assert!(value.get("claims").unwrap().is_string());
    }

    #[tokio::test]
    async fn test_apply_disclosure_expand_then_compact() {
        let mut credential = make_test_credential();
        let (root_said, chunks) = compact_and_collect(&mut credential);
        let store = store_from_chunks(&chunks).await;
        let schema = test_disclosure_schema();

        let tokens = parse_disclosure(".* -.*").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();

        assert_eq!(value.get("said").unwrap().as_str().unwrap(), root_said);
    }

    #[tokio::test]
    async fn test_apply_disclosure_empty_expression() {
        let mut credential = make_test_credential();
        let (root_said, chunks) = compact_and_collect(&mut credential);
        let store = store_from_chunks(&chunks).await;
        let schema = test_disclosure_schema();

        let tokens = parse_disclosure("").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();

        assert_eq!(value.get("said").unwrap().as_str().unwrap(), root_said);
    }

    #[tokio::test]
    async fn test_apply_disclosure_nested_recursive() {
        let mut credential = json!({
            "said": "ECredential",
            "schema": "ESchemaPlaceholder123456789012345678901234",
            "issuer": "EIssuer",
            "issued_at": "2025-01-01T00:00:00Z",
            "claims": {
                "said": "EClaims",
                "name": "Alice",
                "address": {
                    "said": "EAddress",
                    "deep": "data",
                    "skipped": {
                        "data": "more",
                        "included": {
                            "said": "EIncluded",
                            "deepest": "foo"
                        }
                    }
                }
            },
        });

        let schema = Schema::create(
            "Nested Test".to_string(),
            "For nested tests".to_string(),
            "1.0".to_string(),
            BTreeMap::from([
                ("schema".to_string(), SchemaField::string()),
                ("issuer".to_string(), SchemaField::string()),
                ("issued_at".to_string(), SchemaField::string()),
                (
                    "claims".to_string(),
                    SchemaField::object(
                        BTreeMap::from([
                            ("name".to_string(), SchemaField::string()),
                            (
                                "address".to_string(),
                                SchemaField::object(
                                    BTreeMap::from([
                                        ("deep".to_string(), SchemaField::string()),
                                        (
                                            "skipped".to_string(),
                                            SchemaField::object(
                                                BTreeMap::from([
                                                    ("data".to_string(), SchemaField::string()),
                                                    (
                                                        "included".to_string(),
                                                        SchemaField::object(
                                                            BTreeMap::from([(
                                                                "deepest".to_string(),
                                                                SchemaField::string(),
                                                            )]),
                                                            true,
                                                        ),
                                                    ),
                                                ]),
                                                false,
                                            ),
                                        ),
                                    ]),
                                    true,
                                ),
                            ),
                        ]),
                        true,
                    ),
                ),
            ]),
        )
        .unwrap();

        let (root_said, chunks) = compact_and_collect(&mut credential);
        let store = store_from_chunks(&chunks).await;

        let tokens = parse_disclosure("claims.*").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();

        let claims_val = value.get("claims").unwrap();
        assert!(claims_val.is_object());
        let address = claims_val.get("address").unwrap();
        assert!(address.is_object());
        assert_eq!(address.get("deep").unwrap().as_str().unwrap(), "data");
        let skipped = address.get("skipped").unwrap();
        assert!(skipped.is_object());
        let included = skipped.get("included").unwrap();
        assert!(included.is_object());
        assert_eq!(included.get("deepest").unwrap().as_str().unwrap(), "foo");

        let tokens = parse_disclosure("claims claims.address").unwrap();
        let value = apply_disclosure(&root_said, &tokens, &store, &schema)
            .await
            .unwrap();
        let claims_val = value.get("claims").unwrap();
        assert!(claims_val.is_object());
        let address = claims_val.get("address").unwrap();
        assert!(address.is_object());
        let skipped = address.get("skipped").unwrap();
        assert!(skipped.is_object());
        let included = skipped.get("included").unwrap();
        assert!(included.is_string());
    }
}
