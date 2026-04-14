//! Schema-free SAD compaction for SADStore.
//!
//! Recursively walks a submitted SAD, computes canonical SAIDs for every nested
//! object that has a `said` field, and replaces each with its SAID string.
//!
//! Two-phase design to prevent resource amplification:
//! 1. **Dry run** (`compact_sad`): compute SAIDs and build compacted JSON in memory,
//!    collecting the `(SAID, bytes)` pairs for each nested SAD. No MinIO writes.
//! 2. **Commit** (`commit_compacted`): write the collected nested SADs to MinIO.
//!
//! The caller HEAD-checks the canonical SAID between phases — if the parent already
//! exists, the commit is skipped entirely. This prevents attackers from filling
//! MinIO with arbitrary objects via repeated expanded SAD submissions.

use std::collections::HashMap;

use verifiable_storage::compute_said_from_value;

use crate::object_store::{ObjectStore, ObjectStoreError};

/// Maximum recursion depth for compaction. Bounds stack usage for deeply
/// nested structures or malicious inputs.
const MAX_COMPACTION_DEPTH: usize = 32;

/// Compact all nested SADs inside `value` in memory. Each nested object with
/// a `said` field has its canonical SAID computed, its bytes serialized, and
/// is replaced with its SAID string. The nested SADs are NOT written to MinIO —
/// they are collected in the returned map for a later `commit_compacted` call.
///
/// After this returns, `value` is fully compacted and the caller should derive
/// the canonical SAID before deciding whether to commit.
pub fn compact_sad(
    value: &mut serde_json::Value,
) -> Result<HashMap<cesr::Digest256, Vec<u8>>, ObjectStoreError> {
    let mut collected = HashMap::new();
    compact_children(value, &mut collected, MAX_COMPACTION_DEPTH)?;
    Ok(collected)
}

/// Write previously collected nested SADs to MinIO. Call this only after
/// confirming the parent SAD doesn't already exist (HEAD check).
pub async fn commit_compacted(
    collected: &HashMap<cesr::Digest256, Vec<u8>>,
    object_store: &ObjectStore,
) -> Result<(), ObjectStoreError> {
    for (said, data) in collected {
        object_store.put(said, data).await?;
    }
    Ok(())
}

/// Process all children of `value`, compacting any nested SADs found.
fn compact_children(
    value: &mut serde_json::Value,
    collected: &mut HashMap<cesr::Digest256, Vec<u8>>,
    remaining_depth: usize,
) -> Result<(), ObjectStoreError> {
    if remaining_depth == 0 {
        return Err(ObjectStoreError::S3(
            "maximum compaction depth exceeded".into(),
        ));
    }

    match value {
        serde_json::Value::Object(_) => {
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

                #[allow(clippy::expect_used)]
                let mut child = value
                    .as_object_mut()
                    .expect("matched Object variant")
                    .remove(&key)
                    .unwrap_or(serde_json::Value::Null);

                compact_value(&mut child, collected, remaining_depth - 1)?;

                #[allow(clippy::expect_used)]
                value
                    .as_object_mut()
                    .expect("matched Object variant")
                    .insert(key, child);
            }
        }
        serde_json::Value::Array(arr) => {
            for elem in arr.iter_mut() {
                compact_value(elem, collected, remaining_depth - 1)?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Compact a single value. If it's a nested SAD (object with `said` field),
/// compact its children first, compute its SAID, serialize it, collect
/// the `(SAID, bytes)` pair, and replace with its SAID string.
fn compact_value(
    value: &mut serde_json::Value,
    collected: &mut HashMap<cesr::Digest256, Vec<u8>>,
    remaining_depth: usize,
) -> Result<(), ObjectStoreError> {
    if remaining_depth == 0 {
        return Err(ObjectStoreError::S3(
            "maximum compaction depth exceeded".into(),
        ));
    }

    let is_sad = value.as_object().is_some_and(|o| o.contains_key("said"));

    if is_sad {
        // Depth-first: compact this object's children before computing its SAID
        compact_children(value, collected, remaining_depth)?;

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

        // Serialize and collect (don't write to MinIO yet)
        let data = serde_json::to_vec(value)
            .map_err(|e| ObjectStoreError::S3(format!("serialization failed: {}", e)))?;
        collected.insert(said, data);

        // Replace the inline object with its SAID string
        *value = serde_json::Value::String(said.to_string());
    } else {
        // Not a SAD — recurse into children
        compact_children(value, collected, remaining_depth)?;
    }

    Ok(())
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

    #[test]
    fn test_compact_collects_nested_sads() {
        let mut value = serde_json::json!({
            "said": "",
            "data": "parent",
            "child": {
                "said": "",
                "info": "nested"
            }
        });

        let collected = compact_sad(&mut value).unwrap();

        // Child should be compacted to a SAID string
        assert!(value.get("child").unwrap().is_string());
        // One nested SAD collected
        assert_eq!(collected.len(), 1);
        // Parent value is still an object (not compacted itself)
        assert!(value.is_object());
    }

    #[test]
    fn test_compact_idempotent_for_pre_compacted() {
        let mut value = serde_json::json!({
            "said": "",
            "data": "parent",
            "child": "Kalready_a_said_string_________________________"
        });

        let collected = compact_sad(&mut value).unwrap();

        // No nested SADs to compact
        assert!(collected.is_empty());
        // Child unchanged
        assert_eq!(
            value.get("child").unwrap().as_str().unwrap(),
            "Kalready_a_said_string_________________________"
        );
    }
}
