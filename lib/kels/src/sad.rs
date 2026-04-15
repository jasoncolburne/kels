//! Shared SAD tree manipulation primitives.
//!
//! Pure path-directed and recursive operations on JSON values containing
//! self-addressed data (objects with a `said` field). Used by both schema-aware
//! (lib/creds) and heuristic (services/sadstore) disclosure paths.
//!
//! These primitives make no decisions about *which* fields to expand or compact —
//! that policy lives in the caller (schema-guided or heuristic SAID detection).

use cesr::Matter;

use crate::{KelsError, SadStore};

/// Maximum recursion depth for expansion operations.
pub const MAX_EXPANSION_DEPTH: usize = 32;

/// Maximum total SAID resolutions per disclosure request.
pub const MAX_EXPANSIONS: usize = 1000;

/// Mutable walk state tracking SADbomb protection limits.
pub struct ExpansionState {
    /// Total SAID resolutions performed so far.
    count: usize,
}

impl ExpansionState {
    /// Create a new expansion state with zero resolutions.
    pub fn new() -> Self {
        Self { count: 0 }
    }

    /// Check if we can still perform expansions.
    pub fn can_expand(&self) -> bool {
        self.count < MAX_EXPANSIONS
    }

    /// Record an expansion.
    pub fn record(&mut self) {
        self.count += 1;
    }
}

impl Default for ExpansionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Navigate to a mutable reference at the given path.
///
/// Returns `None` if any segment along the path doesn't exist.
pub fn navigate_to_value_mut<'a>(
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

/// Expand a single SAID at a specific path. One level only, no recursion.
///
/// Returns `Ok(true)` if the value was expanded, `Ok(false)` if there was
/// nothing to expand (path not found, value isn't a SAID string, or SAID
/// not in store). Propagates store errors as `Err`.
pub async fn expand_at_path(
    value: &mut serde_json::Value,
    path: &[String],
    sad_store: &dyn SadStore,
) -> Result<bool, KelsError> {
    if path.is_empty() {
        return Ok(false);
    }

    let target = navigate_to_value_mut(value, path);
    if let Some(target) = target
        && let Some(said_str) = target.as_str().map(|s| s.to_string())
        && let Ok(digest) = cesr::Digest256::from_qb64(&said_str)
        && let Some(expanded) = sad_store.load(&digest).await?
    {
        *target = expanded;
        return Ok(true);
    }

    Ok(false)
}

/// Compact a value at a path to its SAID string (if it has a `said` field).
///
/// Returns `Ok(true)` if the value was compacted, `Ok(false)` if the target
/// has no `said` field or the path doesn't exist.
pub fn compact_at_path(value: &mut serde_json::Value, path: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }

    let target = navigate_to_value_mut(value, path);
    if let Some(target) = target
        && let Some(said) = target
            .get("said")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
    {
        *target = serde_json::Value::String(said);
        return true;
    }

    false
}

/// Recursively compact all expanded objects back to their SAID strings.
/// Any object with a `said` field gets replaced with that SAID string.
/// Bottom-up: children are compacted before parents.
pub fn compact_recursive(value: &mut serde_json::Value) {
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
pub fn compact_children_only(value: &mut serde_json::Value) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemorySadStore;
    use serde_json::json;

    #[test]
    fn test_navigate_to_value_mut_empty_path() {
        let mut value = json!({"a": 1});
        let result = navigate_to_value_mut(&mut value, &[]);
        assert!(result.is_some());
    }

    #[test]
    fn test_navigate_to_value_mut_nested() {
        let mut value = json!({"a": {"b": {"c": 42}}});
        let path = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = navigate_to_value_mut(&mut value, &path);
        assert_eq!(result.unwrap(), &json!(42));
    }

    #[test]
    fn test_navigate_to_value_mut_missing() {
        let mut value = json!({"a": 1});
        let path = vec!["b".to_string()];
        assert!(navigate_to_value_mut(&mut value, &path).is_none());
    }

    #[tokio::test]
    async fn test_expand_at_path_success() {
        let store = InMemorySadStore::new();
        let child = json!({"said": "Kchild_said_placeholder_____________________", "data": "leaf"});
        let digest = cesr::Digest256::from_qb64("Kchild_said_placeholder_____________________");
        if let Ok(d) = digest {
            store.store(&d, &child).await.unwrap();

            let mut value = json!({
                "said": "",
                "child": d.to_string()
            });

            let result = expand_at_path(&mut value, &["child".to_string()], &store)
                .await
                .unwrap();
            assert!(result);
            assert!(value.get("child").unwrap().is_object());
        }
    }

    #[tokio::test]
    async fn test_expand_at_path_not_a_said() {
        let store = InMemorySadStore::new();
        let mut value = json!({"field": "not-a-said"});
        let result = expand_at_path(&mut value, &["field".to_string()], &store)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_expand_at_path_empty_path() {
        let store = InMemorySadStore::new();
        let mut value = json!({"field": "value"});
        let result = expand_at_path(&mut value, &[], &store).await.unwrap();
        assert!(!result);
    }

    #[test]
    fn test_compact_at_path_with_said() {
        let mut value = json!({
            "child": {
                "said": "Ksome_said__________________________________",
                "data": "leaf"
            }
        });
        let result = compact_at_path(&mut value, &["child".to_string()]);
        assert!(result);
        assert!(value.get("child").unwrap().is_string());
        assert_eq!(
            value.get("child").unwrap().as_str().unwrap(),
            "Ksome_said__________________________________"
        );
    }

    #[test]
    fn test_compact_at_path_no_said() {
        let mut value = json!({"child": {"data": "no said field"}});
        let result = compact_at_path(&mut value, &["child".to_string()]);
        assert!(!result);
        assert!(value.get("child").unwrap().is_object());
    }

    #[test]
    fn test_compact_at_path_empty_path() {
        let mut value = json!({"data": "value"});
        assert!(!compact_at_path(&mut value, &[]));
    }

    #[test]
    fn test_compact_recursive() {
        let mut value = json!({
            "said": "Kroot_______________________________________",
            "child": {
                "said": "Kchild______________________________________",
                "grandchild": {
                    "said": "Kgrand______________________________________",
                    "data": "deep"
                }
            }
        });

        compact_recursive(&mut value);
        assert!(value.is_string());
        assert_eq!(
            value.as_str().unwrap(),
            "Kroot_______________________________________"
        );
    }

    #[test]
    fn test_compact_children_only() {
        let mut value = json!({
            "said": "Kroot_______________________________________",
            "child": {
                "said": "Kchild______________________________________",
                "data": "leaf"
            },
            "other": "plain"
        });

        compact_children_only(&mut value);
        assert!(value.is_object());
        assert_eq!(
            value.get("said").unwrap().as_str().unwrap(),
            "Kroot_______________________________________"
        );
        assert!(value.get("child").unwrap().is_string());
        assert_eq!(value.get("other").unwrap().as_str().unwrap(), "plain");
    }

    #[test]
    fn test_expansion_state() {
        let mut state = ExpansionState::new();
        assert!(state.can_expand());
        for _ in 0..MAX_EXPANSIONS {
            state.record();
        }
        assert!(!state.can_expand());
    }
}
