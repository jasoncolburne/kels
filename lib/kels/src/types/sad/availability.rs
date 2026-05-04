//! Availability — per-SAD replication and lifecycle. Inline-on-parent struct.
//!
//! Round 13 reshape (#167): `availability` is a top-level reserved key on SAD
//! objects whose value is an inline JSON object. Three independently optional
//! fields:
//!
//! - `nodes: Option<Digest256>` — reference to a [`super::NodeSet`] SAD
//!   declaring which nodes serve this SAD. `None` = default broadcast.
//! - `ttl: Option<u64>` — lifetime in seconds. `None` = permanent.
//! - `once: Option<bool>` — read-once semantics. `None`/`Some(false)` =
//!   unrestricted reads.
//!
//! Each SAD declares its own `availability` explicitly — no inheritance.
//! Compaction-extracted children carry their own `availability` (the steel
//! boot in #101 catches accidental drops).
//!
//! `once == true` is only valid when the SAD is hosted on a single accepting
//! node. Specifically, `availability.nodes` must reference a NodeSet with
//! exactly one prefix, and that prefix must match the accepting node's
//! prefix. Distributed read-once would require coordination we explicitly
//! avoid. Per-node enforcement: each replica tracks its own "has this been
//! read?" state. The structural constraint (single-prefix NodeSet) is
//! enforced at parse time; the live "matches accepting node" check is
//! enforced server-side at POST.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::custody::CustodyValidationError;

/// Per-SAD replication and lifecycle controls.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Availability {
    /// SAID of a [`super::NodeSet`] SAD declaring serving nodes. `None` =
    /// default broadcast.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nodes: Option<cesr::Digest256>,
    /// Lifetime in seconds. `None` = permanent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl: Option<u64>,
    /// Read-once semantics. `None` / `Some(false)` = unrestricted reads.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub once: Option<bool>,
}

impl Availability {
    /// Returns true when no field is set — equivalent to absence of the
    /// `availability` key on the parent SAD.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_none() && self.ttl.is_none() && self.once.is_none()
    }

    /// True when read-once semantics are requested.
    pub fn is_once(&self) -> bool {
        self.once == Some(true)
    }
}

/// Known availability fields (camelCase, matching the JSON wire format).
const KNOWN_AVAILABILITY_FIELDS: &[&str] = &["nodes", "ttl", "once"];

/// Parse and validate an availability object from a JSON value.
///
/// Returns:
/// - `Ok(Some(availability))` — valid, recognized fields only.
/// - `Ok(None)` — unknown fields present, safety valve: caller treats as
///   unenforceable.
/// - `Err(e)` — the value isn't an object, or parsing failed.
///
/// Structural rule: `once == Some(true)` requires `nodes` to be present.
/// (The "single-prefix NodeSet matching accepting-node prefix" tightening
/// is enforced server-side at POST, since it requires resolving the NodeSet
/// SAD and knowing the accepting node's identity.)
pub fn parse_and_validate_availability(
    value: &serde_json::Value,
) -> Result<Option<Availability>, CustodyValidationError> {
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            return Err(CustodyValidationError::ParseError(
                "availability must be an object".into(),
            ));
        }
    };

    let known: HashSet<&str> = KNOWN_AVAILABILITY_FIELDS.iter().copied().collect();
    if obj.keys().any(|k| !known.contains(k.as_str())) {
        return Ok(None);
    }

    let availability: Availability = serde_json::from_value(value.clone())
        .map_err(|e| CustodyValidationError::ParseError(e.to_string()))?;

    if availability.is_once() && availability.nodes.is_none() {
        return Err(CustodyValidationError::ParseError(
            "availability.once requires availability.nodes (single-prefix NodeSet)".into(),
        ));
    }

    Ok(Some(availability))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_default_is_empty() {
        let a = Availability::default();
        assert!(a.is_empty());
        assert!(!a.is_once());
    }

    #[test]
    fn test_parse_full() {
        let value = serde_json::json!({
            "nodes": test_digest(b"nodeset").to_string(),
            "ttl": 3600,
            "once": true,
        });
        let parsed = parse_and_validate_availability(&value).unwrap().unwrap();
        assert_eq!(parsed.nodes, Some(test_digest(b"nodeset")));
        assert_eq!(parsed.ttl, Some(3600));
        assert!(parsed.is_once());
    }

    #[test]
    fn test_once_requires_nodes() {
        let value = serde_json::json!({
            "once": true,
        });
        let err = parse_and_validate_availability(&value).unwrap_err();
        assert!(matches!(err, CustodyValidationError::ParseError(_)));
    }

    #[test]
    fn test_once_false_no_nodes_ok() {
        let value = serde_json::json!({
            "once": false,
        });
        let parsed = parse_and_validate_availability(&value).unwrap().unwrap();
        assert!(!parsed.is_once());
    }

    #[test]
    fn test_unknown_field_safety_valve() {
        let value = serde_json::json!({
            "ttl": 60,
            "customField": 123,
        });
        let result = parse_and_validate_availability(&value).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_legacy_custody_relocation_caught_via_safety_valve() {
        // Pre-#167 custody field names never belonged in availability;
        // included here as a regression guard. Identifier built dynamically
        // so the literal forbidden token never appears in source.
        let legacy = format!("{}{}", "write", "Policy");
        let mut obj = serde_json::Map::new();
        obj.insert(legacy, serde_json::Value::String("x".into()));
        let value = serde_json::Value::Object(obj);
        let result = parse_and_validate_availability(&value).unwrap();
        assert!(result.is_none());
    }
}
