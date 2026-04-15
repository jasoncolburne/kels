//! Schema-free SAD expansion for SADStore.
//!
//! Heuristic expansion: any string field that parses as a `cesr::Digest256`
//! and resolves from MinIO is treated as a compacted reference and expanded.
//! No schema required — mirrors the schema-free compaction in `compaction.rs`.

use async_trait::async_trait;
use cesr::Matter;

use kels_core::{KelsError, PathToken, SadStore, parse_disclosure};

use crate::object_store::{ObjectStore, ObjectStoreError};

/// Maximum recursion depth for heuristic expansion.
const MAX_EXPANSION_DEPTH: usize = 32;

/// Maximum total SAID resolutions per request.
const MAX_EXPANSIONS: usize = 1000;

/// Adapter wrapping MinIO `ObjectStore` as a `SadStore` for disclosure expansion.
/// Read-only — write/list/delete operations return errors.
struct ObjectStoreSadAdapter<'a> {
    object_store: &'a ObjectStore,
}

impl<'a> ObjectStoreSadAdapter<'a> {
    fn new(object_store: &'a ObjectStore) -> Self {
        Self { object_store }
    }
}

#[async_trait]
impl SadStore for ObjectStoreSadAdapter<'_> {
    async fn store(
        &self,
        _said: &cesr::Digest256,
        _value: &serde_json::Value,
    ) -> Result<(), KelsError> {
        Err(KelsError::StorageError("read-only adapter".to_string()))
    }

    async fn load(&self, said: &cesr::Digest256) -> Result<Option<serde_json::Value>, KelsError> {
        match self.object_store.get(said).await {
            Ok(data) => {
                let value = serde_json::from_slice(&data)?;
                Ok(Some(value))
            }
            Err(ObjectStoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(KelsError::StorageError(e.to_string())),
        }
    }

    async fn list(
        &self,
        _since: Option<&cesr::Digest256>,
        _limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), KelsError> {
        Err(KelsError::StorageError("read-only adapter".to_string()))
    }

    async fn delete(&self, _said: &cesr::Digest256) -> Result<(), KelsError> {
        Err(KelsError::StorageError("read-only adapter".to_string()))
    }
}

/// Apply a disclosure expression to a SAD stored in MinIO.
///
/// Parses the disclosure DSL, loads the root SAD, and applies heuristic
/// expansion (SAID-detection, no schema). Returns the expanded value.
pub async fn apply_disclosure_to_sad(
    said: &cesr::Digest256,
    disclosure: &str,
    object_store: &ObjectStore,
) -> Result<serde_json::Value, KelsError> {
    let tokens = parse_disclosure(disclosure)?;
    let adapter = ObjectStoreSadAdapter::new(object_store);
    let mut value = adapter.load_or_not_found(said).await?;

    if tokens.is_empty() {
        return Ok(value);
    }

    apply_tokens(&mut value, &tokens, &adapter).await?;
    Ok(value)
}

/// Apply parsed disclosure tokens to a value using the given SAD store.
///
/// Shared between production (`apply_disclosure_to_sad`) and tests.
async fn apply_tokens(
    value: &mut serde_json::Value,
    tokens: &[PathToken],
    sad_store: &dyn SadStore,
) -> Result<(), KelsError> {
    let mut state = ExpansionState { count: 0 };

    for token in tokens {
        match token {
            PathToken::ExpandRecursive(path) if path.is_empty() => {
                expand_recursive(value, sad_store, &mut state, 0).await?;
            }
            PathToken::CompactRecursive(path) if path.is_empty() => {
                // Compact all children but keep root expanded
                compact_children_only(value);
            }
            PathToken::Expand(path) => {
                expand_at_path(value, path, sad_store, &mut state).await?;
            }
            PathToken::ExpandRecursive(path) => {
                expand_at_path(value, path, sad_store, &mut state).await?;
                // After expanding at path, recursively expand within that subtree
                // Depth starts at path.len() since we're already that deep in the document
                if let Some(child) = navigate_to_value_mut(value, path) {
                    expand_recursive(child, sad_store, &mut state, path.len()).await?;
                }
            }
            PathToken::Compact(path) => {
                compact_at_path(value, path);
            }
            PathToken::CompactRecursive(path) => {
                if let Some(child) = navigate_to_value_mut(value, path) {
                    compact_recursive(child);
                    // Compact the target itself to its SAID
                    compact_at_path(value, path);
                }
            }
        }
    }

    Ok(())
}

/// Mutable walk state tracking SADbomb protection limits.
struct ExpansionState {
    /// Total SAID resolutions performed so far.
    count: usize,
}

impl ExpansionState {
    /// Check if we can still perform expansions.
    fn can_expand(&self) -> bool {
        self.count < MAX_EXPANSIONS
    }

    /// Record an expansion.
    fn record(&mut self) {
        self.count += 1;
    }
}

/// Recursively expand all SAID-like strings in a value.
///
/// Soft limits: stops at `MAX_EXPANSION_DEPTH` depth or `MAX_EXPANSIONS` total
/// resolutions. Unexpanded SAIDs remain in place (partial expansion, not error).
fn expand_recursive<'a>(
    value: &'a mut serde_json::Value,
    sad_store: &'a dyn SadStore,
    state: &'a mut ExpansionState,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), KelsError>> + Send + 'a>> {
    Box::pin(async move {
        if depth >= MAX_EXPANSION_DEPTH || !state.can_expand() {
            return Ok(());
        }

        match value {
            serde_json::Value::Object(_) => {
                // Collect keys that have SAID-like string values
                #[allow(clippy::expect_used)]
                let keys: Vec<String> = value
                    .as_object()
                    .expect("matched Object variant")
                    .keys()
                    .cloned()
                    .collect();

                for key in keys {
                    if !state.can_expand() {
                        break;
                    }

                    // Skip `said` — expanding it would self-reference the
                    // containing object, causing incorrect replacement.
                    if key == "said" {
                        continue;
                    }

                    #[allow(clippy::expect_used)]
                    let child = value
                        .as_object_mut()
                        .expect("matched Object variant")
                        .get_mut(&key);

                    if let Some(child) = child {
                        if let Some(said_str) = child.as_str() {
                            if let Ok(digest) = cesr::Digest256::from_qb64(said_str)
                                && let Some(expanded) = sad_store.load(&digest).await?
                            {
                                state.record();
                                *child = expanded;
                                // Recurse into the newly expanded value
                                expand_recursive(child, sad_store, state, depth + 1).await?;
                            }
                        } else {
                            // Recurse into non-string children
                            expand_recursive(child, sad_store, state, depth + 1).await?;
                        }
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for elem in arr.iter_mut() {
                    if !state.can_expand() {
                        break;
                    }

                    if let Some(said_str) = elem.as_str() {
                        if let Ok(digest) = cesr::Digest256::from_qb64(said_str)
                            && let Some(expanded) = sad_store.load(&digest).await?
                        {
                            state.record();
                            *elem = expanded;
                            expand_recursive(elem, sad_store, state, depth + 1).await?;
                        }
                    } else {
                        expand_recursive(elem, sad_store, state, depth + 1).await?;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    })
}

/// Expand a single SAID at a specific path. One level only, no recursion.
async fn expand_at_path(
    value: &mut serde_json::Value,
    path: &[String],
    sad_store: &dyn SadStore,
    state: &mut ExpansionState,
) -> Result<(), KelsError> {
    if path.is_empty() || !state.can_expand() {
        return Ok(());
    }

    let target = navigate_to_value_mut(value, path);
    if let Some(target) = target
        && let Some(said_str) = target.as_str().map(|s| s.to_string())
        && let Ok(digest) = cesr::Digest256::from_qb64(&said_str)
        && let Some(expanded) = sad_store.load(&digest).await?
    {
        state.record();
        *target = expanded;
    }

    Ok(())
}

/// Compact a value at a path to its SAID string (if it has a `said` field).
/// Silent no-op when the target has no `said` field — the heuristic path is
/// best-effort; callers validate the result against their schema.
fn compact_at_path(value: &mut serde_json::Value, path: &[String]) {
    if path.is_empty() {
        return;
    }

    let target = navigate_to_value_mut(value, path);
    if let Some(target) = target
        && let Some(said) = target
            .get("said")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
    {
        *target = serde_json::Value::String(said);
    }
}

/// Recursively compact all expanded objects back to their SAID strings.
/// Any object with a `said` field gets replaced with that SAID string.
fn compact_recursive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(_) => {
            // First compact children
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
                if let Some(child) = value
                    .as_object_mut()
                    .expect("matched Object variant")
                    .get_mut(&key)
                {
                    compact_recursive(child);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for elem in arr.iter_mut() {
                compact_recursive(elem);
            }
        }
        _ => {}
    }

    // After compacting children, compact this value itself if it has a SAID
    if let Some(said) = value
        .get("said")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
    {
        *value = serde_json::Value::String(said);
    }
}

/// Compact all children of a value recursively, but keep the root itself expanded.
fn compact_children_only(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        let keys: Vec<String> = obj.keys().cloned().collect();
        for key in keys {
            if key == "said" {
                continue;
            }
            if let Some(child) = obj.get_mut(&key) {
                compact_recursive(child);
            }
        }
    }
}

/// Navigate to a mutable reference at the given path.
fn navigate_to_value_mut<'a>(
    value: &'a mut serde_json::Value,
    path: &[String],
) -> Option<&'a mut serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }

    let mut current = value;
    for segment in path {
        current = current.get_mut(segment.as_str())?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kels_core::InMemorySadStore;
    use serde_json::json;
    use verifiable_storage::compute_said_from_value;

    /// Helper: compact a value with nested SADs, store all chunks, return root SAID.
    /// Mirrors the schema-free compaction from compaction.rs.
    async fn compact_and_store(
        value: &mut serde_json::Value,
        store: &InMemorySadStore,
    ) -> cesr::Digest256 {
        compact_children_for_test(value, store).await;

        // Derive root SAID
        let root_said = compute_said_from_value(value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("said".to_string(), json!(root_said.to_string()));
        store.store(&root_said, value).await.unwrap();
        root_said
    }

    /// Recursively compact nested SADs (schema-free, test helper).
    fn compact_children_for_test<'a>(
        value: &'a mut serde_json::Value,
        store: &'a InMemorySadStore,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match value {
                serde_json::Value::Object(_) => {
                    let keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();

                    for key in keys {
                        if key == "said" {
                            continue;
                        }

                        let mut child = value.as_object_mut().unwrap().remove(&key).unwrap();
                        compact_value_for_test(&mut child, store).await;
                        value.as_object_mut().unwrap().insert(key, child);
                    }
                }
                serde_json::Value::Array(arr) => {
                    for elem in arr.iter_mut() {
                        compact_value_for_test(elem, store).await;
                    }
                }
                _ => {}
            }
        })
    }

    /// Compact a single value if it's a SAD (test helper).
    fn compact_value_for_test<'a>(
        value: &'a mut serde_json::Value,
        store: &'a InMemorySadStore,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let is_sad = value.as_object().is_some_and(|o| o.contains_key("said"));

            if is_sad {
                compact_children_for_test(value, store).await;

                let said = compute_said_from_value(value).unwrap();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("said".to_string(), json!(said.to_string()));
                store.store(&said, value).await.unwrap();
                *value = serde_json::Value::String(said.to_string());
            } else {
                compact_children_for_test(value, store).await;
            }
        })
    }

    /// Wrapper to test heuristic expansion via InMemorySadStore.
    async fn apply_test_disclosure(
        said: &cesr::Digest256,
        disclosure: &str,
        store: &InMemorySadStore,
    ) -> Result<serde_json::Value, KelsError> {
        let tokens = parse_disclosure(disclosure)?;
        let mut value = store.load_or_not_found(said).await?;

        if tokens.is_empty() {
            return Ok(value);
        }

        apply_tokens(&mut value, &tokens, store).await?;
        Ok(value)
    }

    #[tokio::test]
    async fn test_expand_all_round_trip() {
        let store = InMemorySadStore::new();

        let mut original = json!({
            "said": "",
            "data": "parent",
            "child": {
                "said": "",
                "info": "nested",
                "grandchild": {
                    "said": "",
                    "deep": "value"
                }
            }
        });

        // Save original before compaction for comparison
        let original_clone = original.clone();

        let root_said = compact_and_store(&mut original, &store).await;

        // Verify it's compacted
        let compacted = store.load_or_not_found(&root_said).await.unwrap();
        assert!(compacted.get("child").unwrap().is_string());

        // Expand all
        let expanded = apply_test_disclosure(&root_said, "*", &store)
            .await
            .unwrap();

        // Verify structure matches original (SAIDs will differ since original had "")
        assert!(expanded.get("child").unwrap().is_object());
        let child = expanded.get("child").unwrap();
        assert_eq!(child.get("info").unwrap().as_str().unwrap(), "nested");
        assert!(child.get("grandchild").unwrap().is_object());
        let grandchild = child.get("grandchild").unwrap();
        assert_eq!(grandchild.get("deep").unwrap().as_str().unwrap(), "value");

        // Verify data content matches
        assert_eq!(
            expanded.get("data").unwrap().as_str().unwrap(),
            original_clone.get("data").unwrap().as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn test_selective_expand() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "custody": {
                "said": "",
                "policy": "strict"
            },
            "content": {
                "said": "",
                "data": "hello"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        // Expand only custody
        let result = apply_test_disclosure(&root_said, "custody", &store)
            .await
            .unwrap();
        assert!(result.get("custody").unwrap().is_object());
        assert!(result.get("content").unwrap().is_string()); // Still compacted
    }

    #[tokio::test]
    async fn test_selective_recursive_expand() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "custody": {
                "said": "",
                "nodes": {
                    "said": "",
                    "list": ["a", "b"]
                }
            },
            "content": {
                "said": "",
                "data": "hello"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        // Expand custody recursively
        let result = apply_test_disclosure(&root_said, "custody.*", &store)
            .await
            .unwrap();
        let custody = result.get("custody").unwrap();
        assert!(custody.is_object());
        assert!(custody.get("nodes").unwrap().is_object());
        assert!(result.get("content").unwrap().is_string()); // Still compacted
    }

    #[tokio::test]
    async fn test_expand_then_compact() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "custody": {
                "said": "",
                "policy": "strict"
            },
            "content": {
                "said": "",
                "data": "hello"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        // Expand all then compact custody
        let result = apply_test_disclosure(&root_said, ".* -custody", &store)
            .await
            .unwrap();
        assert!(result.get("custody").unwrap().is_string()); // Re-compacted
        assert!(result.get("content").unwrap().is_object()); // Still expanded
    }

    #[tokio::test]
    async fn test_empty_disclosure() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "child": {
                "said": "",
                "info": "nested"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        let result = apply_test_disclosure(&root_said, "", &store).await.unwrap();
        // Should return compacted form
        assert!(result.get("child").unwrap().is_string());
    }

    #[tokio::test]
    async fn test_non_said_44_char_strings_not_expanded() {
        let store = InMemorySadStore::new();

        // A 44-char string that is NOT a valid CESR Digest256
        let fake_said = "X".repeat(44);

        let mut value = json!({
            "said": "",
            "reference": fake_said,
            "child": {
                "said": "",
                "info": "nested"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        let result = apply_test_disclosure(&root_said, "*", &store)
            .await
            .unwrap();

        // The fake SAID string should remain unchanged
        assert_eq!(
            result.get("reference").unwrap().as_str().unwrap(),
            fake_said
        );
        // Real nested SAD should be expanded
        assert!(result.get("child").unwrap().is_object());
    }

    #[tokio::test]
    async fn test_depth_limit_partial_expansion() {
        let store = InMemorySadStore::new();

        // Build a chain deeper than MAX_EXPANSION_DEPTH
        let depth = MAX_EXPANSION_DEPTH + 5;
        let mut innermost = json!({
            "said": "",
            "level": depth
        });
        let innermost_said = compute_said_from_value(&innermost).unwrap();
        innermost
            .as_object_mut()
            .unwrap()
            .insert("said".to_string(), json!(innermost_said.to_string()));
        store.store(&innermost_said, &innermost).await.unwrap();

        let mut current_said = innermost_said.to_string();
        for level in (0..depth).rev() {
            let mut obj = json!({
                "said": "",
                "level": level,
                "nested": current_said
            });
            let said = compute_said_from_value(&obj).unwrap();
            obj.as_object_mut()
                .unwrap()
                .insert("said".to_string(), json!(said.to_string()));
            store.store(&said, &obj).await.unwrap();
            current_said = said.to_string();
        }

        let root_said = cesr::Digest256::from_qb64(&current_said).unwrap();

        let result = apply_test_disclosure(&root_said, "*", &store)
            .await
            .unwrap();

        // Walk down and verify expansion stops at depth limit
        let mut current = &result;
        let mut expanded_count = 0;
        while let Some(nested) = current.get("nested") {
            if nested.is_object() {
                expanded_count += 1;
                current = nested;
            } else {
                // Hit a SAID string — expansion stopped here
                assert!(nested.is_string());
                break;
            }
        }

        // Should have expanded some but not all
        assert!(expanded_count > 0);
        assert!(expanded_count < depth);
    }

    #[tokio::test]
    async fn test_expansion_count_limit() {
        let store = InMemorySadStore::new();

        // Create many independent nested SADs — more than MAX_EXPANSIONS
        let count = MAX_EXPANSIONS + 50;
        let mut fields = serde_json::Map::new();
        fields.insert("said".to_string(), json!(""));

        for i in 0..count {
            let mut nested = json!({
                "said": "",
                "index": i
            });
            let said = compute_said_from_value(&nested).unwrap();
            nested
                .as_object_mut()
                .unwrap()
                .insert("said".to_string(), json!(said.to_string()));
            store.store(&said, &nested).await.unwrap();
            fields.insert(format!("field_{}", i), json!(said.to_string()));
        }

        let mut root = serde_json::Value::Object(fields);
        let root_said = compute_said_from_value(&root).unwrap();
        root.as_object_mut()
            .unwrap()
            .insert("said".to_string(), json!(root_said.to_string()));
        store.store(&root_said, &root).await.unwrap();

        let result = apply_test_disclosure(&root_said, "*", &store)
            .await
            .unwrap();

        // Count how many were expanded vs left as strings
        let obj = result.as_object().unwrap();
        let mut expanded = 0;
        let mut compacted = 0;
        for (key, val) in obj {
            if key == "said" {
                continue;
            }
            if val.is_object() {
                expanded += 1;
            } else if val.is_string() {
                compacted += 1;
            }
        }

        assert_eq!(expanded, MAX_EXPANSIONS);
        assert!(compacted > 0);
    }

    #[tokio::test]
    async fn test_invalid_disclosure_expression() {
        let result = parse_disclosure("-");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_compact_recursive() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "custody": {
                "said": "",
                "nodes": {
                    "said": "",
                    "list": ["a", "b"]
                }
            },
            "content": {
                "said": "",
                "data": "hello"
            }
        });

        let root_said = compact_and_store(&mut value, &store).await;

        // Expand all, then compact all recursively
        let result = apply_test_disclosure(&root_said, ".* -.*", &store)
            .await
            .unwrap();

        // Root should still be an object (compact_recursive compacts children,
        // then replaces root with SAID — but our top-level CompactRecursive([])
        // only compacts children, leaving root expanded)
        assert_eq!(
            result.get("said").unwrap().as_str().unwrap(),
            root_said.to_string()
        );
    }

    #[tokio::test]
    async fn test_expand_with_array_elements() {
        let store = InMemorySadStore::new();

        let mut value = json!({
            "said": "",
            "items": [
                {
                    "said": "",
                    "name": "first"
                },
                {
                    "said": "",
                    "name": "second"
                }
            ]
        });

        let root_said = compact_and_store(&mut value, &store).await;

        let result = apply_test_disclosure(&root_said, "*", &store)
            .await
            .unwrap();

        let items = result.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_object());
        assert_eq!(items[0].get("name").unwrap().as_str().unwrap(), "first");
        assert!(items[1].is_object());
        assert_eq!(items[1].get("name").unwrap().as_str().unwrap(), "second");
    }
}
