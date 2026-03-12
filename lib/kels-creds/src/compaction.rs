use cesr::{Digest, Matter};

use crate::error::CredentialError;
use crate::store::ChunkStore;

const SAID_PLACEHOLDER: &str = "############################################";

/// Compute a SAID from a serde_json::Value.
/// Sets the "said" field to placeholder, serializes, blake3 hashes, CESR encodes.
pub fn compute_said_from_value(value: &serde_json::Value) -> Result<String, CredentialError> {
    let mut work = value.clone();
    let obj = work.as_object_mut().ok_or_else(|| {
        CredentialError::CompactionError("value must be an object to compute SAID".to_string())
    })?;

    obj.insert(
        "said".to_string(),
        serde_json::Value::String(SAID_PLACEHOLDER.to_string()),
    );

    let bytes = serde_json::to_vec(&work)?;
    Ok(Digest::blake3_256(&bytes).qb64())
}

/// Compact a JSON value bottom-up, depth-first.
///
/// Walks the tree in post-order. At each object node with a "said" field:
/// 1. Recursively compact all children first
/// 2. Derive the node's SAID over its current form (children are now SAIDs)
/// 3. Replace the object with its SAID string in the parent
///
/// The root object keeps its structure with a computed "said" field —
/// it is not itself replaced by a SAID string.
pub fn compact(value: &mut serde_json::Value) -> Result<(), CredentialError> {
    compact_inner(value, /* is_root */ true)
}

pub(crate) fn compact_inner(
    value: &mut serde_json::Value,
    is_root: bool,
) -> Result<(), CredentialError> {
    if let Some(obj) = value.as_object_mut() {
        // Collect keys that need recursive compaction
        let keys: Vec<String> = obj.keys().cloned().collect();
        for key in &keys {
            if key == "said" {
                continue;
            }
            if let Some(child) = obj.get_mut(key) {
                compact_inner(child, false)?;
            }
        }

        // If this object has a "said" field, compute its SAID
        if obj.contains_key("said") {
            let said = compute_said_from_value(value)?;
            if is_root {
                // Root: keep structure, set said field
                let obj = value
                    .as_object_mut()
                    .ok_or_else(|| CredentialError::CompactionError("lost root".to_string()))?;
                obj.insert("said".to_string(), serde_json::Value::String(said));
            } else {
                // Non-root: replace entire object with SAID string
                *value = serde_json::Value::String(said);
            }
        }
    } else if let Some(arr) = value.as_array_mut() {
        for elem in arr.iter_mut() {
            compact_inner(elem, false)?;
        }
    }

    Ok(())
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
    let expanded_said = if let Some(said) = expanded.get("said").and_then(|s| s.as_str()) {
        // If the object has a said field, verify by computing SAID of the compacted form
        let mut compacted_copy = expanded.clone();
        compact_inner(&mut compacted_copy, false)?;
        let computed = compacted_copy.as_str().ok_or_else(|| {
            CredentialError::ExpansionError("compaction did not produce a SAID string".to_string())
        })?;
        if computed != current_said {
            return Err(CredentialError::ExpansionError(format!(
                "SAID mismatch: expected {}, got {} (from said field {})",
                current_said, computed, said
            )));
        }
        computed.to_string()
    } else {
        return Err(CredentialError::ExpansionError(format!(
            "expanded value has no 'said' field for '{}'",
            last
        )));
    };

    // Verify match
    if expanded_said != current_said {
        return Err(CredentialError::ExpansionError(format!(
            "SAID mismatch for '{}': expected {}, got {}",
            last, current_said, expanded_said
        )));
    }

    target.insert(last.to_string(), expanded);
    Ok(())
}

/// Expand all compacted SAID strings in a value by looking them up in the chunk store.
/// Walks the tree and replaces any string value that resolves in the chunk store
/// with the full object. Recurses into expanded objects to expand nested SAIDs.
pub fn expand_all<'a>(
    value: &'a mut serde_json::Value,
    chunk_store: &'a dyn ChunkStore,
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
                    && let Some(expanded) = chunk_store.get_chunk(said).await?
                {
                    obj.insert(key.clone(), expanded);
                    if let Some(child) = obj.get_mut(&key) {
                        expand_all(child, chunk_store).await?;
                    }
                    continue;
                }
                if let Some(child) = obj.get_mut(&key) {
                    expand_all(child, chunk_store).await?;
                }
            }
        } else if let Some(arr) = value.as_array_mut() {
            for elem in arr.iter_mut() {
                if let Some(said) = elem.as_str().map(|s| s.to_string())
                    && let Some(expanded) = chunk_store.get_chunk(&said).await?
                {
                    *elem = expanded;
                    expand_all(elem, chunk_store).await?;
                    continue;
                }
                expand_all(elem, chunk_store).await?;
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
        // Both should produce the same SAID since the said field is replaced with placeholder
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
    fn test_compact_flat_object() {
        let mut value = json!({
            "said": "",
            "name": "root",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        compact(&mut value).unwrap();

        // Root should still be an object with computed said
        assert!(value.is_object());
        let said = value.get("said").unwrap().as_str().unwrap();
        assert_eq!(said.len(), 44);

        // Child should be replaced by its SAID string
        let child = value.get("child").unwrap();
        assert!(child.is_string());
        assert_eq!(child.as_str().unwrap().len(), 44);
    }

    #[test]
    fn test_compact_no_said_field() {
        let mut value = json!({
            "name": "no said field"
        });

        // Should succeed without modification (no said field to derive)
        compact(&mut value).unwrap();
        assert!(value.is_object());
        assert!(value.get("said").is_none());
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

        compact(&mut value).unwrap();

        // Root should be an object
        assert!(value.is_object());
        // level1 should be a SAID string (since it's not root)
        let level1 = value.get("level1").unwrap();
        assert!(level1.is_string());
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

        compact(&mut value).unwrap();
        let said1 = value.get("said").unwrap().as_str().unwrap().to_string();

        // Compacting again should produce the same result
        compact(&mut value).unwrap();
        let said2 = value.get("said").unwrap().as_str().unwrap().to_string();

        assert_eq!(said1, said2);
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

        // First compact to get child's SAID
        let mut child_for_said = child_obj.clone();
        compact(&mut child_for_said).unwrap();

        compact(&mut value).unwrap();
        let said_after_compact = value.get("said").unwrap().as_str().unwrap().to_string();

        // Expand child back
        expand_field(&mut value, &["child"], child_obj).unwrap();

        // Re-compact should produce the same SAID
        compact(&mut value).unwrap();
        let said_after_roundtrip = value.get("said").unwrap().as_str().unwrap().to_string();

        assert_eq!(said_after_compact, said_after_roundtrip);
    }

    #[test]
    fn test_expand_field_said_mismatch() {
        let mut value = json!({
            "said": "",
            "child": "EAbc1234567890123456789012345678901234567890"
        });

        let wrong_expanded = json!({
            "said": "",
            "data": "wrong content"
        });

        // Should fail because the expanded object's SAID won't match
        assert!(expand_field(&mut value, &["child"], wrong_expanded).is_err());
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

        // Should fail because the field is not a SAID string
        assert!(expand_field(&mut value, &["child"], expanded).is_err());
    }

    #[test]
    fn test_expand_field_empty_path() {
        let mut value = json!({"said": ""});
        assert!(expand_field(&mut value, &[], json!({})).is_err());
    }

    #[test]
    fn test_said_agreement_with_typed() {
        // Verify that compute_said_from_value agrees with the typed SelfAddressed derive
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

        // Serialize the typed schema to a Value and compute SAID
        let value = serde_json::to_value(&schema).unwrap();
        let value_said = compute_said_from_value(&value).unwrap();

        // Should match the typed SAID
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

        compact(&mut value).unwrap();

        // Array items with said fields should be compacted to SAID strings
        let items = value.get("items").unwrap().as_array().unwrap();
        assert!(items[0].is_string());
        assert!(items[1].is_string());
        // Different data should produce different SAIDs
        assert_ne!(items[0].as_str().unwrap(), items[1].as_str().unwrap());
    }
}
