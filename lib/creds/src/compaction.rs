use std::collections::{HashMap, HashSet};

use verifiable_storage::compute_said_from_value;

use crate::{
    error::CredentialError,
    schema::{Schema, SchemaField, SchemaFieldType},
    store::SADStore,
};

/// Maximum recursion depth for compaction, expansion, and schema validation.
/// Bounds stack usage for deeply nested credential structures or malicious inputs.
pub const MAX_RECURSION_DEPTH: usize = 32;

/// Schema-aware compaction. Only compacts fields that the schema marks as
/// `compactable: true`. Walks the schema alongside the value, compacting
/// bottom-up (children first, then parent).
pub fn compact_with_schema(
    value: &mut serde_json::Value,
    schema: &Schema,
) -> Result<HashMap<String, serde_json::Value>, CredentialError> {
    compact_with_fields(value, &schema.fields)
}

/// Schema-aware compaction using a fields map directly.
/// Use this when operating on a sub-tree where only the field definitions
/// are available (e.g., disclosure operations on a nested object).
pub fn compact_with_fields(
    value: &mut serde_json::Value,
    fields: &std::collections::BTreeMap<String, SchemaField>,
) -> Result<HashMap<String, serde_json::Value>, CredentialError> {
    let mut accumulator = HashMap::new();
    compact_object_with_schema(value, fields, true, &mut accumulator, MAX_RECURSION_DEPTH)?;
    Ok(accumulator)
}

/// Compact a single self-addressed node: compute its SAID, store the object
/// (with SAID populated) in the accumulator, and replace `value` with the
/// SAID string. Does NOT recurse into children — the caller is responsible
/// for compacting children first via the schema-aware walk.
fn compact_single_node(
    value: &mut serde_json::Value,
    accumulator: &mut HashMap<String, serde_json::Value>,
) -> Result<(), CredentialError> {
    let said = compute_said_from_value(value)?;

    // Set the said field on the object before storing
    if let Some(obj) = value.as_object_mut() {
        obj.insert("said".to_string(), serde_json::Value::String(said.clone()));
    }

    accumulator.insert(said.clone(), value.clone());
    *value = serde_json::Value::String(said);

    Ok(())
}

fn compact_object_with_schema(
    value: &mut serde_json::Value,
    schema_fields: &std::collections::BTreeMap<String, SchemaField>,
    compactable: bool,
    accumulator: &mut HashMap<String, serde_json::Value>,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    if remaining_depth == 0 {
        return Err(CredentialError::CompactionError(
            "maximum compaction depth exceeded".to_string(),
        ));
    }

    let Some(obj) = value.as_object_mut() else {
        // Already compacted (SAID string) or not an object — nothing to do
        return Ok(());
    };

    // Compact children first (bottom-up)
    let keys: Vec<String> = obj.keys().cloned().collect();
    for key in &keys {
        if key == "said" {
            continue;
        }
        let Some(field_schema) = schema_fields.get(key) else {
            continue;
        };
        if let Some(child) = obj.get_mut(key) {
            compact_field_with_schema(child, field_schema, accumulator, remaining_depth - 1)?;
        }
    }

    // Now compact this object if it's compactable
    if compactable && obj.contains_key("said") {
        compact_single_node(value, accumulator)?;
    }

    Ok(())
}

fn compact_field_with_schema(
    value: &mut serde_json::Value,
    field: &SchemaField,
    accumulator: &mut HashMap<String, serde_json::Value>,
    remaining_depth: usize,
) -> Result<(), CredentialError> {
    match field.field_type {
        SchemaFieldType::Object => {
            if let Some(ref sub_fields) = field.fields {
                compact_object_with_schema(
                    value,
                    sub_fields,
                    field.compactable,
                    accumulator,
                    remaining_depth,
                )?;
            } else if field.compactable {
                // No inner field descriptions but compactable — compact just this node
                compact_single_node(value, accumulator)?;
            }
        }
        SchemaFieldType::Array => {
            if let Some(ref items) = field.items
                && let Some(arr) = value.as_array_mut()
            {
                for elem in arr.iter_mut() {
                    compact_field_with_schema(elem, items, accumulator, remaining_depth)?;
                }
            }
        }
        _ => {
            // Scalar types — nothing to compact
        }
    }
    Ok(())
}

/// Schema-aware expansion. Only expands fields that the schema marks as
/// `compactable: true`. Walks the schema alongside the value, expanding
/// SAID strings into full objects from the SAD store.
pub fn expand_with_schema<'a>(
    value: &'a mut serde_json::Value,
    schema: &'a Schema,
    sad_store: &'a dyn SADStore,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    expand_with_fields(value, &schema.fields, sad_store)
}

/// Schema-aware expansion using a fields map directly.
/// Use this when operating on a sub-tree where only the field definitions
/// are available (e.g., disclosure operations on a nested object).
pub fn expand_with_fields<'a>(
    value: &'a mut serde_json::Value,
    fields: &'a std::collections::BTreeMap<String, SchemaField>,
    sad_store: &'a dyn SADStore,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    Box::pin(async move {
        expand_object_with_schema(value, fields, sad_store, MAX_RECURSION_DEPTH).await
    })
}

fn expand_object_with_schema<'a>(
    value: &'a mut serde_json::Value,
    schema_fields: &'a std::collections::BTreeMap<String, SchemaField>,
    sad_store: &'a dyn SADStore,
    remaining_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(CredentialError::ExpansionError(
                "maximum expansion depth exceeded".to_string(),
            ));
        }

        let Some(obj) = value.as_object_mut() else {
            return Ok(());
        };

        // Collect all compactable fields that are currently SAID strings — batch fetch
        let mut candidate_saids = HashSet::new();
        for (key, field) in schema_fields {
            if field.compactable
                && let Some(child) = obj.get(key.as_str())
                && let Some(said) = child.as_str()
            {
                candidate_saids.insert(said.to_string());
            }
        }

        let fetched = if candidate_saids.is_empty() {
            HashMap::new()
        } else {
            sad_store.get_chunks(&candidate_saids).await?
        };

        // Expand compactable fields and recurse into all object/array children
        let keys: Vec<String> = schema_fields.keys().cloned().collect();
        for key in keys {
            let Some(field) = schema_fields.get(&key) else {
                continue;
            };

            // Expand if compactable and currently a SAID string
            if field.compactable
                && let Some(child) = obj.get(&key)
                && let Some(said) = child.as_str()
                && let Some(expanded) = fetched.get(said)
            {
                obj.insert(key.clone(), expanded.clone());
            }

            // Recurse into child
            if let Some(child) = obj.get_mut(&key) {
                expand_field_with_schema(child, field, sad_store, remaining_depth - 1).await?;
            }
        }

        // Recompute SAID after expansion — children changed so the parent's SAID must update
        if obj.contains_key("said") {
            let recomputed = compute_said_from_value(value)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("said".to_string(), serde_json::Value::String(recomputed));
            }
        }

        Ok(())
    })
}

fn expand_field_with_schema<'a>(
    value: &'a mut serde_json::Value,
    field: &'a SchemaField,
    sad_store: &'a dyn SADStore,
    remaining_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    Box::pin(async move {
        match field.field_type {
            SchemaFieldType::Object => {
                if let Some(ref sub_fields) = field.fields {
                    expand_object_with_schema(value, sub_fields, sad_store, remaining_depth)
                        .await?;
                }
            }
            SchemaFieldType::Array => {
                if let Some(ref items) = field.items {
                    if items.compactable {
                        // Batch fetch array element SAIDs
                        let mut candidate_saids = HashSet::new();
                        if let Some(arr) = value.as_array() {
                            for elem in arr {
                                if let Some(said) = elem.as_str() {
                                    candidate_saids.insert(said.to_string());
                                }
                            }
                        }
                        let fetched = if candidate_saids.is_empty() {
                            HashMap::new()
                        } else {
                            sad_store.get_chunks(&candidate_saids).await?
                        };

                        if let Some(arr) = value.as_array_mut() {
                            for elem in arr.iter_mut() {
                                if let Some(said) = elem.as_str().map(|s| s.to_string())
                                    && let Some(expanded) = fetched.get(&said)
                                {
                                    *elem = expanded.clone();
                                }
                            }
                        }
                    }

                    // Recurse into array elements
                    if let Some(arr) = value.as_array_mut() {
                        for elem in arr.iter_mut() {
                            expand_field_with_schema(elem, items, sad_store, remaining_depth)
                                .await?;
                        }
                    }
                }
            }
            _ => {
                // Scalar types — nothing to expand
            }
        }
        Ok(())
    })
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

    use std::collections::BTreeMap;

    use crate::schema::{Schema, SchemaField};

    fn make_schema(fields: BTreeMap<String, SchemaField>) -> Schema {
        Schema::create(
            "Test".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            fields,
        )
        .unwrap()
    }

    #[test]
    fn test_compact_replaces_with_said() {
        let schema = make_schema(BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            (
                "child".to_string(),
                SchemaField::object(
                    BTreeMap::from([("data".to_string(), SchemaField::string())]),
                    true,
                ),
            ),
        ]));

        let mut value = json!({
            "said": "",
            "name": "root",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        let chunks = compact_with_schema(&mut value, &schema).unwrap();

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
    fn test_compact_non_compactable_not_compacted() {
        // Schema marks "child" as NOT compactable
        let schema = make_schema(BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            (
                "child".to_string(),
                SchemaField::object(
                    BTreeMap::from([("data".to_string(), SchemaField::string())]),
                    false,
                ),
            ),
        ]));

        let mut value = json!({
            "said": "",
            "name": "root",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        let chunks = compact_with_schema(&mut value, &schema).unwrap();

        // Root is compacted
        assert!(value.is_string());
        // Only root in accumulator — child was NOT compacted
        assert_eq!(chunks.len(), 1);
        let root = chunks.get(value.as_str().unwrap()).unwrap();
        // child remains as an object (not a SAID string)
        assert!(root.get("child").unwrap().is_object());
    }

    #[test]
    fn test_compact_nested() {
        let schema = make_schema(BTreeMap::from([(
            "level1".to_string(),
            SchemaField::object(
                BTreeMap::from([(
                    "level2".to_string(),
                    SchemaField::object(
                        BTreeMap::from([("data".to_string(), SchemaField::string())]),
                        true,
                    ),
                )]),
                true,
            ),
        )]));

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

        let chunks = compact_with_schema(&mut value, &schema).unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(value.is_string());

        for (said, chunk) in chunks {
            let chunk_said = chunk.get("said").unwrap().as_str().unwrap();
            assert_eq!(chunk_said, said);
        }
    }

    #[test]
    fn test_compact_idempotent() {
        let schema = make_schema(BTreeMap::from([
            ("name".to_string(), SchemaField::string()),
            (
                "child".to_string(),
                SchemaField::object(
                    BTreeMap::from([("data".to_string(), SchemaField::string())]),
                    true,
                ),
            ),
        ]));

        let mut value = json!({
            "said": "",
            "name": "test",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        let chunks1 = compact_with_schema(&mut value, &schema).unwrap();
        let said1 = value.as_str().unwrap().to_string();

        let chunks2 = compact_with_schema(&mut value, &schema).unwrap();
        let said2 = value.as_str().unwrap().to_string();

        assert_eq!(said1, said2);
        assert!(chunks2.is_empty());
        assert_eq!(chunks1.len(), 2);
    }

    #[test]
    fn test_said_agreement_with_typed() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), SchemaField::string());

        let schema = make_schema(fields);

        let value = serde_json::to_value(&schema).unwrap();
        let value_said = compute_said_from_value(&value).unwrap();
        assert_eq!(schema.said, value_said);
    }

    #[test]
    fn test_compact_with_array_children() {
        let schema = make_schema(BTreeMap::from([(
            "items".to_string(),
            SchemaField::array(SchemaField::object(
                BTreeMap::from([("data".to_string(), SchemaField::string())]),
                true,
            )),
        )]));

        let mut value = json!({
            "said": "",
            "items": [
                {"said": "", "data": "first"},
                {"said": "", "data": "second"}
            ]
        });

        let chunks = compact_with_schema(&mut value, &schema).unwrap();

        assert_eq!(chunks.len(), 3);
        assert!(value.is_string());

        let root = chunks.get(value.as_str().unwrap()).unwrap();
        let items = root.get("items").unwrap().as_array().unwrap();
        assert!(items[0].is_string());
        assert!(items[1].is_string());
        assert_ne!(items[0].as_str().unwrap(), items[1].as_str().unwrap());
    }

    #[tokio::test]
    async fn test_schema_aware_compact_expand_roundtrip() {
        use crate::store::InMemorySADStore;

        let schema = crate::schema::Schema::create(
            "Test".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            std::collections::BTreeMap::from([
                ("name".to_string(), SchemaField::string()),
                (
                    "child".to_string(),
                    SchemaField::object(
                        std::collections::BTreeMap::from([(
                            "data".to_string(),
                            SchemaField::string(),
                        )]),
                        true,
                    ),
                ),
            ]),
        )
        .unwrap();

        let mut value = json!({
            "said": "",
            "name": "root",
            "child": {
                "said": "",
                "data": "leaf"
            }
        });

        // Compact with schema
        let chunks = compact_with_schema(&mut value, &schema).unwrap();

        // Root should be compacted to a SAID string
        assert!(value.is_string());

        // Store chunks
        let store = InMemorySADStore::new();
        store.store_chunks(&chunks).await.unwrap();

        // Get root object back
        let root_said = value.as_str().unwrap();
        let mut root = store.get_chunk(root_said).await.unwrap().unwrap();

        // Child should be a SAID string (compacted)
        assert!(root.get("child").unwrap().is_string());

        // Expand with schema
        expand_with_schema(&mut root, &schema, &store)
            .await
            .unwrap();

        // Child should now be expanded
        assert!(root.get("child").unwrap().is_object());
        assert_eq!(
            root.get("child")
                .unwrap()
                .get("data")
                .unwrap()
                .as_str()
                .unwrap(),
            "leaf"
        );
    }

    #[tokio::test]
    async fn test_schema_aware_expand_skips_non_compactable() {
        use crate::store::InMemorySADStore;

        // Schema where "ref_said" is a Said type (not compactable)
        let schema = crate::schema::Schema::create(
            "Test".to_string(),
            "A test".to_string(),
            "1.0".to_string(),
            std::collections::BTreeMap::from([
                ("ref_said".to_string(), SchemaField::said()),
                (
                    "child".to_string(),
                    SchemaField::object(
                        std::collections::BTreeMap::from([(
                            "data".to_string(),
                            SchemaField::string(),
                        )]),
                        true,
                    ),
                ),
            ]),
        )
        .unwrap();

        let store = InMemorySADStore::new();

        // Store a chunk that matches the ref_said value
        let ref_value =
            json!({"said": "KRef_1234567890123456789012345678901234567", "extra": "data"});
        store
            .store_chunk("KRef_1234567890123456789012345678901234567", &ref_value)
            .await
            .unwrap();

        let child_value =
            json!({"said": "KChild234567890123456789012345678901234567", "data": "leaf"});
        store
            .store_chunk("KChild234567890123456789012345678901234567", &child_value)
            .await
            .unwrap();

        let mut value = json!({
            "said": "",
            "ref_said": "KRef_1234567890123456789012345678901234567",
            "child": "KChild234567890123456789012345678901234567"
        });

        expand_with_schema(&mut value, &schema, &store)
            .await
            .unwrap();

        // ref_said should NOT be expanded (it's a Said type, not compactable)
        assert!(value.get("ref_said").unwrap().is_string());
        assert_eq!(
            value.get("ref_said").unwrap().as_str().unwrap(),
            "KRef_1234567890123456789012345678901234567"
        );

        // child SHOULD be expanded (it's compactable)
        assert!(value.get("child").unwrap().is_object());
    }
}
