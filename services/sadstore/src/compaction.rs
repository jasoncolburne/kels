//! Schema-free SAD compaction for SADStore.
//!
//! Recursively walks a submitted SAD, stores every nested object that has a
//! `said` field independently in MinIO, and replaces it with its SAID string.
//! The canonical SAID of the parent is always derived from the fully compacted form.
//! Clients can submit expanded or pre-compacted — SADStore normalizes either way.

use std::pin::Pin;

use verifiable_storage::compute_said_from_value;

use crate::object_store::{ObjectStore, ObjectStoreError};

/// Maximum recursion depth for compaction. Bounds stack usage for deeply
/// nested structures or malicious inputs.
const MAX_COMPACTION_DEPTH: usize = 32;

/// Compact all nested SADs inside `value`. Each nested object with a `said`
/// field is stored independently in MinIO and replaced with its SAID string.
/// Does NOT compact `value` itself — only its descendants.
///
/// After compaction, the caller should derive the canonical SAID on `value`
/// (the fully compacted form) before storing.
pub async fn compact_sad(
    value: &mut serde_json::Value,
    object_store: &ObjectStore,
) -> Result<(), ObjectStoreError> {
    compact_children(value, object_store, MAX_COMPACTION_DEPTH).await
}

/// Process all children of `value`, compacting any nested SADs found.
fn compact_children<'a>(
    value: &'a mut serde_json::Value,
    object_store: &'a ObjectStore,
    remaining_depth: usize,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), ObjectStoreError>> + Send + 'a>> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(ObjectStoreError::S3(
                "maximum compaction depth exceeded".into(),
            ));
        }

        match value {
            serde_json::Value::Object(_) => {
                // Collect keys to avoid borrow issues during mutation
                #[allow(clippy::expect_used)]
                let keys: Vec<String> = value
                    .as_object()
                    .expect("matched Object variant")
                    .keys()
                    .cloned()
                    .collect();

                for key in keys {
                    if key == "said" {
                        continue;
                    }

                    // Remove the child, compact it, re-insert
                    #[allow(clippy::expect_used)]
                    let mut child = value
                        .as_object_mut()
                        .expect("matched Object variant")
                        .remove(&key)
                        .unwrap_or(serde_json::Value::Null);

                    compact_value(&mut child, object_store, remaining_depth - 1).await?;

                    #[allow(clippy::expect_used)]
                    value
                        .as_object_mut()
                        .expect("matched Object variant")
                        .insert(key, child);
                }
            }
            serde_json::Value::Array(arr) => {
                for elem in arr.iter_mut() {
                    compact_value(elem, object_store, remaining_depth - 1).await?;
                }
            }
            _ => {}
        }

        Ok(())
    })
}

/// Compact a single value. If it's a nested SAD (object with `said` field),
/// compact its children first, store it in MinIO, and replace with its SAID
/// string. Otherwise just recurse into children.
fn compact_value<'a>(
    value: &'a mut serde_json::Value,
    object_store: &'a ObjectStore,
    remaining_depth: usize,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), ObjectStoreError>> + Send + 'a>> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(ObjectStoreError::S3(
                "maximum compaction depth exceeded".into(),
            ));
        }

        let is_sad = value.as_object().is_some_and(|o| o.contains_key("said"));

        if is_sad {
            // Depth-first: compact this object's children before storing it
            compact_children(value, object_store, remaining_depth).await?;

            // Derive canonical SAID on the compacted form
            let said = compute_said_from_value(value)
                .map_err(|e| ObjectStoreError::S3(format!("SAID computation failed: {}", e)))?;

            // Set the said field to the canonical value
            #[allow(clippy::expect_used)]
            value
                .as_object_mut()
                .expect("is_sad check guarantees object")
                .insert(
                    "said".to_string(),
                    serde_json::Value::String(said.to_string()),
                );

            // Store in MinIO (idempotent — same content = same SAID)
            let data = serde_json::to_vec(value)
                .map_err(|e| ObjectStoreError::S3(format!("serialization failed: {}", e)))?;
            object_store.put(&said, &data).await?;

            // Replace the inline object with its SAID string
            *value = serde_json::Value::String(said.to_string());
        } else {
            // Not a SAD — recurse into children
            compact_children(value, object_store, remaining_depth).await?;
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sad_detection() {
        let sad = serde_json::json!({"said": "", "data": "hello"});
        assert!(sad.as_object().unwrap().contains_key("said"));

        let not_sad = serde_json::json!({"data": "hello"});
        assert!(!not_sad.as_object().unwrap().contains_key("said"));

        let string = serde_json::json!("already-compacted-said");
        assert!(string.as_object().is_none());
    }

    #[test]
    fn test_compute_said_from_value_deterministic() {
        let v1 = serde_json::json!({"said": "", "name": "test"});
        let v2 = serde_json::json!({"said": "different", "name": "test"});
        assert_eq!(
            compute_said_from_value(&v1).unwrap(),
            compute_said_from_value(&v2).unwrap()
        );
    }
}
