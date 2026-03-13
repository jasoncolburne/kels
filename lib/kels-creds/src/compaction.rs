use std::collections::HashMap;

use verifiable_storage::compact_value;

use crate::error::CredentialError;
use crate::store::SADStore;

/// Compact a JSON value bottom-up, depth-first. Delegates to `compact_value` from
/// verifiable-storage. Returns extracted chunks keyed by SAID. After this call,
/// `value` is a SAID string (all nodes including root are replaced).
pub fn compact(
    value: &mut serde_json::Value,
) -> Result<HashMap<String, serde_json::Value>, CredentialError> {
    let mut accumulator = HashMap::new();
    compact_value(value, &mut accumulator)?;
    Ok(accumulator)
}

/// Compact a slice of credential values and store all resulting chunks in a single batch.
pub async fn store_credentials(
    values: &[serde_json::Value],
    sad_store: &dyn SADStore,
) -> Result<(), CredentialError> {
    let mut all_chunks = HashMap::new();
    for value in values {
        let mut value = value.clone();
        let chunks = compact(&mut value)?;
        all_chunks.extend(chunks);
    }
    sad_store.store_chunks(&all_chunks).await
}

/// Replace a compacted SAID string at a path with a full object, verifying the SAID matches.
pub fn expand_field(
    value: &mut serde_json::Value,
    path: &[&str],
    expanded: serde_json::Value,
) -> Result<(), CredentialError> {
    if path.is_empty() {
        return Err(CredentialError::ExpansionError("empty path".to_string()));
    }

    let target = navigate_to_parent(value, path)?;
    let last = path[path.len() - 1];

    let current = target
        .get(last)
        .ok_or_else(|| CredentialError::ExpansionError(format!("field '{}' not found", last)))?;

    // The current value should be a SAID string
    let current_said = current.as_str().ok_or_else(|| {
        CredentialError::ExpansionError(format!("field '{}' is not a compacted SAID", last))
    })?;

    // Verify the expanded object's SAID matches
    if expanded.get("said").and_then(|s| s.as_str()).is_none() {
        return Err(CredentialError::ExpansionError(format!(
            "expanded value has no 'said' field for '{}'",
            last
        )));
    }

    let mut compacted_copy = expanded.clone();
    compact_value(&mut compacted_copy, &mut HashMap::new())?;
    let computed = compacted_copy.as_str().ok_or_else(|| {
        CredentialError::ExpansionError("compaction did not produce a SAID string".to_string())
    })?;
    if computed != current_said {
        return Err(CredentialError::ExpansionError(format!(
            "SAID mismatch for '{}': expected {}, got {}",
            last, current_said, computed
        )));
    }

    target.insert(last.to_string(), expanded);
    Ok(())
}

/// Expand all compacted SAID strings in a value by looking them up in the SAD store.
/// Walks the tree and replaces any string value that resolves in the SAD store
/// with the full object. Recurses into expanded objects to expand nested SAIDs.
pub fn expand_all<'a>(
    value: &'a mut serde_json::Value,
    sad_store: &'a dyn SADStore,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    Box::pin(async move {
        if let Some(obj) = value.as_object_mut() {
            let keys: Vec<String> = obj.keys().cloned().collect();
            for key in keys {
                if key == "said" {
                    continue;
                }
                if let Some(child) = obj.get(&key)
                    && let Some(said) = child.as_str()
                    && let Some(expanded) = sad_store.get_chunk(said).await?
                {
                    obj.insert(key.clone(), expanded);
                    if let Some(child) = obj.get_mut(&key) {
                        expand_all(child, sad_store).await?;
                    }
                    continue;
                }
                if let Some(child) = obj.get_mut(&key) {
                    expand_all(child, sad_store).await?;
                }
            }
        } else if let Some(arr) = value.as_array_mut() {
            for elem in arr.iter_mut() {
                if let Some(said) = elem.as_str().map(|s| s.to_string())
                    && let Some(expanded) = sad_store.get_chunk(&said).await?
                {
                    *elem = expanded;
                    expand_all(elem, sad_store).await?;
                    continue;
                }
                expand_all(elem, sad_store).await?;
            }
        }

        Ok(())
    })
}

fn navigate_to_parent<'a>(
    value: &'a mut serde_json::Value,
    path: &[&str],
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>, CredentialError> {
    let mut current = value;
    for &segment in &path[..path.len() - 1] {
        current = current.get_mut(segment).ok_or_else(|| {
            CredentialError::ExpansionError(format!("path segment '{}' not found", segment))
        })?;
    }
    current
        .as_object_mut()
        .ok_or_else(|| CredentialError::ExpansionError("parent is not an object".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use verifiable_storage::compute_said_from_value;

    #[test]
    fn test_compute_said_from_value() {
        let value = json!({
            "said": "",
            "name": "test"
        });
        let said = compute_said_from_value(&value).unwrap();
        assert_eq!(said.len(), 44);
    }

    #[test]
    fn test_compute_said_deterministic() {
        let v1 = json!({"said": "", "name": "test"});
        let v2 = json!({"said": "different", "name": "test"});
        assert_eq!(
            compute_said_from_value(&v1).unwrap(),
            compute_said_from_value(&v2).unwrap()
        );
    }

    #[test]
    fn test_compute_said_not_object() {
        let value = json!("string");
        assert!(compute_said_from_value(&value).is_err());
    }

    #[test]
    fn test_compact_replaces_with_said() {
        let mut value = json!({
            "said": "",
            "name": "root",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        let chunks = compact(&mut value).unwrap();

        // Root is replaced with a SAID string
        assert!(value.is_string());
        assert_eq!(value.as_str().unwrap().len(), 44);

        // Both root and child are in the accumulator
        assert_eq!(chunks.len(), 2);
        let root = chunks.get(value.as_str().unwrap()).unwrap();
        assert!(root.is_object());
        assert!(root.get("child").unwrap().is_string());
    }

    #[test]
    fn test_compact_no_said_field() {
        let mut value = json!({
            "name": "no said field"
        });

        let chunks = compact(&mut value).unwrap();
        assert!(value.is_object());
        assert!(value.get("said").is_none());
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_compact_nested() {
        let mut value = json!({
            "said": "",
            "level1": {
                "said": "",
                "level2": {
                    "said": "",
                    "data": "deep"
                }
            }
        });

        let chunks = compact(&mut value).unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(value.is_string());
    }

    #[test]
    fn test_compact_idempotent() {
        let mut value = json!({
            "said": "",
            "name": "test",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        let chunks1 = compact(&mut value).unwrap();
        let said1 = value.as_str().unwrap().to_string();

        let chunks2 = compact(&mut value).unwrap();
        let said2 = value.as_str().unwrap().to_string();

        assert_eq!(said1, said2);
        assert!(chunks2.is_empty());
        assert_eq!(chunks1.len(), 2);
    }

    #[test]
    fn test_compact_then_expand_roundtrip() {
        let child_obj = json!({
            "said": "",
            "data": "leaf"
        });

        let mut value = json!({
            "said": "",
            "name": "root",
            "child": child_obj.clone()
        });

        let chunks = compact(&mut value).unwrap();
        let root_said = value.as_str().unwrap().to_string();

        let mut root = chunks.get(&root_said).unwrap().clone();
        expand_field(&mut root, &["child"], child_obj).unwrap();

        let chunks2 = compact(&mut root).unwrap();
        let root_said2 = root.as_str().unwrap().to_string();

        assert_eq!(root_said, root_said2);
        assert_eq!(chunks.len(), chunks2.len());
    }

    #[test]
    fn test_expand_field_said_mismatch() {
        let mut value = json!({
            "said": "",
            "child": {
                "said": "",
                "data": "original"
            }
        });

        let chunks = compact(&mut value).unwrap();
        let mut root = chunks.get(value.as_str().unwrap()).unwrap().clone();

        let wrong_expanded = json!({
            "said": "",
            "data": "wrong content"
        });

        assert!(expand_field(&mut root, &["child"], wrong_expanded).is_err());
    }

    #[test]
    fn test_expand_field_not_compacted() {
        let mut value = json!({
            "said": "",
            "child": {"already": "expanded"}
        });

        let expanded = json!({
            "said": "",
            "data": "something"
        });

        assert!(expand_field(&mut value, &["child"], expanded).is_err());
    }

    #[test]
    fn test_expand_field_empty_path() {
        let mut value = json!({"said": ""});
        assert!(expand_field(&mut value, &[], json!({})).is_err());
    }

    #[test]
    fn test_said_agreement_with_typed() {
        use std::collections::BTreeMap;

        use crate::schema::{CredentialSchema, SchemaField};

        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::String);

        let schema = CredentialSchema::create(
            "Test".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap();

        let value = serde_json::to_value(&schema).unwrap();
        let value_said = compute_said_from_value(&value).unwrap();
        assert_eq!(schema.said, value_said);
    }

    #[test]
    fn test_compact_with_array_children() {
        let mut value = json!({
            "said": "",
            "items": [
                {"said": "", "data": "first"},
                {"said": "", "data": "second"}
            ]
        });

        let chunks = compact(&mut value).unwrap();

        assert_eq!(chunks.len(), 3);
        assert!(value.is_string());

        let root = chunks.get(value.as_str().unwrap()).unwrap();
        let items = root.get("items").unwrap().as_array().unwrap();
        assert!(items[0].is_string());
        assert!(items[1].is_string());
        assert_ne!(items[0].as_str().unwrap(), items[1].as_str().unwrap());
    }
}
