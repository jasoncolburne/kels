use crate::compaction::{compact_inner, expand_all};
use crate::credential::CredentialValue;
use crate::error::CredentialError;
use crate::store::ChunkStore;

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
/// 1. Starts by compacting the credential to canonical form
/// 2. Applies tokens left-to-right:
///    - Expand: look up SAID in chunk_store, replace with full object
///    - ExpandRecursive: expand and recursively expand all children
///    - Compact: replace object at path with its SAID
///    - CompactRecursive: compact object and all children
pub async fn apply_disclosure(
    credential: &mut CredentialValue,
    tokens: &[PathToken],
    chunk_store: &dyn ChunkStore,
) -> Result<(), CredentialError> {
    // Start fully compacted
    compact_inner(credential.inner_mut(), true)?;

    for token in tokens {
        match token {
            PathToken::ExpandRecursive(path) if path.is_empty() => {
                expand_all(credential.inner_mut(), chunk_store).await?;
            }
            PathToken::CompactRecursive(path) if path.is_empty() => {
                compact_inner(credential.inner_mut(), true)?;
            }
            PathToken::Expand(path) => {
                expand_at_path(credential.inner_mut(), path, chunk_store, false).await?;
            }
            PathToken::ExpandRecursive(path) => {
                expand_at_path(credential.inner_mut(), path, chunk_store, true).await?;
            }
            PathToken::Compact(path) => {
                compact_at_path(credential.inner_mut(), path, false)?;
            }
            PathToken::CompactRecursive(path) => {
                compact_at_path(credential.inner_mut(), path, true)?;
            }
        }
    }

    Ok(())
}

/// Expand a field at the given path. If `recursive`, also expand all children.
async fn expand_at_path(
    value: &mut serde_json::Value,
    path: &[String],
    chunk_store: &dyn ChunkStore,
    recursive: bool,
) -> Result<(), CredentialError> {
    let (parent, last) = navigate_to_field(value, path)?;

    let current = parent
        .get(last)
        .ok_or_else(|| CredentialError::InvalidDisclosure(format!("field '{}' not found", last)))?;

    if let Some(said) = current.as_str() {
        // Field is compacted (SAID string) — look it up
        let expanded = chunk_store.get_chunk(said).await?.ok_or_else(|| {
            CredentialError::ExpansionError(format!("chunk not found in store for SAID: {}", said))
        })?;
        parent.insert(last.to_string(), expanded);

        if recursive && let Some(child) = parent.get_mut(last) {
            expand_all(child, chunk_store).await?;
        }
    } else if recursive {
        // Field is already expanded — recursively expand its children
        if let Some(child) = parent.get_mut(last) {
            expand_all(child, chunk_store).await?;
        }
    }

    Ok(())
}

/// Compact a field at the given path. If `recursive`, compact all children first.
fn compact_at_path(
    value: &mut serde_json::Value,
    path: &[String],
    recursive: bool,
) -> Result<(), CredentialError> {
    let (parent, last) = navigate_to_field(value, path)?;

    let child = parent
        .get_mut(last)
        .ok_or_else(|| CredentialError::InvalidDisclosure(format!("field '{}' not found", last)))?;

    // Only compact if the field is an object with a "said" field
    if child.is_object() && child.get("said").is_some() {
        if recursive {
            compact_inner(child, false)?;
        } else {
            // Compact just this field — compute its SAID and replace with string
            // But don't recurse into children first
            let said = crate::compaction::compute_said_from_value(child)?;
            *child = serde_json::Value::String(said);
        }
    }
    // If it's already a string (compacted) or doesn't have "said", nothing to do

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

    // Safety: path is non-empty, so last() always succeeds
    let last = path
        .last()
        .ok_or_else(|| CredentialError::InvalidDisclosure("empty path".to_string()))?;

    Ok((parent, last.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::compaction::compact;
    use crate::store::InMemoryChunkStore;

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

    async fn setup_store_with_chunks(chunks: Vec<(&str, serde_json::Value)>) -> InMemoryChunkStore {
        let store = InMemoryChunkStore::new();
        for (said, value) in chunks {
            store.store_chunk(said, &value).await.unwrap();
        }
        store
    }

    fn make_test_credential() -> (serde_json::Value, serde_json::Value, serde_json::Value) {
        let schema = json!({
            "said": "",
            "name": "TestSchema",
            "version": "1.0"
        });

        let claims = json!({
            "said": "",
            "name": "Alice",
            "age": 30
        });

        let credential = json!({
            "said": "",
            "schema": schema,
            "issuer": "EIssuer",
            "issued_at": "2025-01-01T00:00:00Z",
            "claims": claims,
        });

        (credential, schema, claims)
    }

    #[tokio::test]
    async fn test_apply_disclosure_expand_all() {
        let (mut credential, schema, claims) = make_test_credential();

        // Compact to get SAIDs
        let mut schema_copy = schema.clone();
        compact(&mut schema_copy).unwrap();
        let schema_said = schema_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let mut claims_copy = claims.clone();
        compact(&mut claims_copy).unwrap();
        let claims_said = claims_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        compact(&mut credential).unwrap();

        // Store the expanded chunks
        let store = setup_store_with_chunks(vec![
            (&schema_said, schema_copy),
            (&claims_said, claims_copy),
        ])
        .await;

        let mut cv = CredentialValue::from_value(credential).unwrap();
        let tokens = parse_disclosure(".*").unwrap();
        apply_disclosure(&mut cv, &tokens, &store).await.unwrap();

        // Schema and claims should be expanded (objects, not strings)
        assert!(cv.inner().get("schema").unwrap().is_object());
        assert!(cv.inner().get("claims").unwrap().is_object());
    }

    #[tokio::test]
    async fn test_apply_disclosure_selective() {
        let (mut credential, schema, claims) = make_test_credential();

        let mut schema_copy = schema.clone();
        compact(&mut schema_copy).unwrap();
        let schema_said = schema_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let mut claims_copy = claims.clone();
        compact(&mut claims_copy).unwrap();
        let claims_said = claims_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        compact(&mut credential).unwrap();

        let store = setup_store_with_chunks(vec![
            (&schema_said, schema_copy),
            (&claims_said, claims_copy),
        ])
        .await;

        let mut cv = CredentialValue::from_value(credential).unwrap();
        let tokens = parse_disclosure("schema").unwrap();
        apply_disclosure(&mut cv, &tokens, &store).await.unwrap();

        // Schema should be expanded
        assert!(cv.inner().get("schema").unwrap().is_object());
        // Claims should still be compacted (string)
        assert!(cv.inner().get("claims").unwrap().is_string());
    }

    #[tokio::test]
    async fn test_apply_disclosure_expand_then_compact() {
        let (mut credential, schema, claims) = make_test_credential();

        let mut schema_copy = schema.clone();
        compact(&mut schema_copy).unwrap();
        let schema_said = schema_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let mut claims_copy = claims.clone();
        compact(&mut claims_copy).unwrap();
        let claims_said = claims_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        compact(&mut credential).unwrap();
        let original_said = credential
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let store = setup_store_with_chunks(vec![
            (&schema_said, schema_copy),
            (&claims_said, claims_copy),
        ])
        .await;

        let mut cv = CredentialValue::from_value(credential).unwrap();

        // Expand all, then compact all — SAID should be preserved
        let tokens = parse_disclosure(".* -.*").unwrap();
        apply_disclosure(&mut cv, &tokens, &store).await.unwrap();

        assert_eq!(
            cv.inner().get("said").unwrap().as_str().unwrap(),
            original_said
        );
    }

    #[tokio::test]
    async fn test_apply_disclosure_empty_expression() {
        let (mut credential, _, _) = make_test_credential();
        compact(&mut credential).unwrap();

        let store = InMemoryChunkStore::new();
        let mut cv = CredentialValue::from_value(credential.clone()).unwrap();
        let tokens = parse_disclosure("").unwrap();
        apply_disclosure(&mut cv, &tokens, &store).await.unwrap();

        // Should still be compacted (no tokens to apply)
        assert_eq!(
            cv.inner().get("said").unwrap().as_str().unwrap(),
            credential.get("said").unwrap().as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn test_apply_disclosure_nested_recursive() {
        // Build a credential with nested compactable objects
        let inner = json!({
            "said": "",
            "deep": "data"
        });
        let claims = json!({
            "said": "",
            "name": "Alice",
            "address": inner
        });
        let mut credential = json!({
            "said": "",
            "schema": "ESchemaPlaceholder123456789012345678901234",
            "issuer": "EIssuer",
            "issued_at": "2025-01-01T00:00:00Z",
            "claims": claims.clone(),
        });

        // Compact to get all SAIDs
        let mut inner_copy = inner.clone();
        compact(&mut inner_copy).unwrap();
        let inner_said = inner_copy
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let mut claims_with_compacted_inner = claims.clone();
        compact(&mut claims_with_compacted_inner).unwrap();
        let claims_said = claims_with_compacted_inner
            .get("said")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        compact(&mut credential).unwrap();

        // Store chunks: claims (with inner compacted) and inner
        let store = setup_store_with_chunks(vec![
            (&claims_said, claims_with_compacted_inner),
            (&inner_said, inner_copy),
        ])
        .await;

        let mut cv = CredentialValue::from_value(credential).unwrap();

        // claims.* should expand claims AND its nested address
        let tokens = parse_disclosure("claims.*").unwrap();
        apply_disclosure(&mut cv, &tokens, &store).await.unwrap();

        let claims_val = cv.inner().get("claims").unwrap();
        assert!(claims_val.is_object());
        let address = claims_val.get("address").unwrap();
        assert!(address.is_object());
        assert_eq!(address.get("deep").unwrap().as_str().unwrap(), "data");
    }
}
