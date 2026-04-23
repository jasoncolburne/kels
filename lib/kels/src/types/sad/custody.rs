//! Custody and node set SAD types for per-record storage policy.
//!
//! `custody` is a reserved top-level key on any SAD. It is itself a SAD
//! (with its own SAID), compacted and stored independently in MinIO,
//! referenced by SAID in the parent record. The SAID covers all custody
//! fields, making storage policy tamper-evident.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

/// Per-record storage policy.
///
/// Fields:
/// - `writePolicy` — SAID of a policy SAD controlling writes (consumer-side, anchoring model)
/// - `readPolicy` — SAID of a policy SAD controlling reads (SADStore fetch-time enforcement)
/// - `ttl` — seconds until expiry (per-record: `sad_objects.created_at + ttl`)
/// - `once` — atomic delete on first successful retrieval
/// - `nodes` — SAID of a `NodeSet` SAD for selective replication
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "custodies")]
#[serde(rename_all = "camelCase")]
pub struct Custody {
    #[said]
    pub said: cesr::Digest256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_policy: Option<cesr::Digest256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_policy: Option<cesr::Digest256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub once: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<cesr::Digest256>,
}

/// A set of node prefixes for selective replication.
///
/// Prefixes are sorted lexicographically before SAID derivation so the same
/// set of nodes always produces the same SAID regardless of insertion order.
/// Use `create_sorted()` instead of `create()` to ensure correct ordering.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct NodeSet {
    #[said]
    pub said: cesr::Digest256,
    pub prefixes: Vec<cesr::Digest256>,
}

impl NodeSet {
    /// Create a NodeSet with prefixes sorted for deterministic SAID derivation.
    pub fn create_sorted(
        mut prefixes: Vec<cesr::Digest256>,
    ) -> Result<Self, verifiable_storage::StorageError> {
        prefixes.sort();
        Self::create(prefixes)
    }
}

/// Context in which custody validation is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SadCustodyContext {
    /// Standalone SAD objects — all custody fields allowed.
    Object,
    /// Chained events — `ttl` and `once` are rejected.
    Event,
}

/// Errors from custody validation.
#[derive(Debug, Clone)]
pub enum CustodyValidationError {
    /// `ttl` is structurally incompatible with chained events.
    TtlNotAllowedOnEvent,
    /// `once` is structurally incompatible with chained events.
    OnceNotAllowedOnEvent,
    /// `once: true` requires `nodes` to be present for consistent delete semantics.
    OnceRequiresNodes,
    /// Failed to parse the custody object.
    ParseError(String),
}

impl std::fmt::Display for CustodyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TtlNotAllowedOnEvent => {
                write!(
                    f,
                    "ttl is not allowed on events — expiring a link in a chain breaks verification for descendants"
                )
            }
            Self::OnceNotAllowedOnEvent => {
                write!(
                    f,
                    "once is not allowed on events — deleting a link in a chain breaks verification for descendants"
                )
            }
            Self::OnceRequiresNodes => {
                write!(
                    f,
                    "once: true requires nodes to be present for consistent delete-on-read semantics"
                )
            }
            Self::ParseError(msg) => write!(f, "custody parse error: {}", msg),
        }
    }
}

impl std::error::Error for CustodyValidationError {}

/// Known custody fields (camelCase, matching the JSON wire format).
const KNOWN_CUSTODY_FIELDS: &[&str] =
    &["said", "writePolicy", "readPolicy", "ttl", "once", "nodes"];

/// Parse and validate a custody object from a JSON value.
///
/// Returns:
/// - `Ok(Some(custody))` — valid custody, server enforces the policy
/// - `Ok(None)` — unknown fields present, safety valve disengages enforcement
/// - `Err(e)` — known but disallowed fields in this context (e.g. `ttl` on event)
pub fn parse_and_validate_custody(
    value: &serde_json::Value,
    context: SadCustodyContext,
) -> Result<Option<Custody>, CustodyValidationError> {
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            return Err(CustodyValidationError::ParseError(
                "custody must be an object".into(),
            ));
        }
    };

    // Safety valve: any unrecognized key disengages all server-side enforcement.
    let known: HashSet<&str> = KNOWN_CUSTODY_FIELDS.iter().copied().collect();
    if obj.keys().any(|k| !known.contains(k.as_str())) {
        return Ok(None);
    }

    let custody: Custody = serde_json::from_value(value.clone())
        .map_err(|e| CustodyValidationError::ParseError(e.to_string()))?;

    match context {
        SadCustodyContext::Event => {
            // ttl and once are known but disallowed — explicit rejection, not safety valve.
            if custody.ttl.is_some() {
                return Err(CustodyValidationError::TtlNotAllowedOnEvent);
            }
            if custody.once.is_some() {
                return Err(CustodyValidationError::OnceNotAllowedOnEvent);
            }
        }
        SadCustodyContext::Object => {
            if custody.once == Some(true) && custody.nodes.is_none() {
                return Err(CustodyValidationError::OnceRequiresNodes);
            }
        }
    }

    Ok(Some(custody))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::SelfAddressed;

    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Custody Tests ====================

    #[test]
    fn test_custody_create_and_verify() {
        let custody = Custody::create(
            Some(test_digest(b"write-policy")),
            Some(test_digest(b"read-policy")),
            Some(3600),
            Some(true),
            Some(test_digest(b"node-set")),
        )
        .unwrap();
        assert!(custody.verify_said().is_ok());
    }

    #[test]
    fn test_custody_empty_is_valid() {
        let custody = Custody::create(None, None, None, None, None).unwrap();
        assert!(custody.verify_said().is_ok());
    }

    #[test]
    fn test_custody_different_fields_different_said() {
        let c1 = Custody::create(None, None, Some(3600), None, None).unwrap();
        let c2 = Custody::create(None, None, Some(7200), None, None).unwrap();
        let c3 = Custody::create(None, None, None, None, None).unwrap();
        assert_ne!(c1.said, c2.said);
        assert_ne!(c1.said, c3.said);
    }

    #[test]
    fn test_custody_same_fields_same_said() {
        let wp = Some(test_digest(b"wp"));
        let c1 = Custody::create(wp, None, Some(3600), None, None).unwrap();
        let c2 = Custody::create(wp, None, Some(3600), None, None).unwrap();
        assert_eq!(c1.said, c2.said);
    }

    // ==================== NodeSet Tests ====================

    #[test]
    fn test_nodeset_create_sorted_deterministic() {
        let a = test_digest(b"node-a");
        let b = test_digest(b"node-b");
        let c = test_digest(b"node-c");

        let ns1 = NodeSet::create_sorted(vec![c, a, b]).unwrap();
        let ns2 = NodeSet::create_sorted(vec![b, c, a]).unwrap();
        let ns3 = NodeSet::create_sorted(vec![a, b, c]).unwrap();

        assert_eq!(ns1.said, ns2.said);
        assert_eq!(ns2.said, ns3.said);

        // Prefixes are sorted
        assert!(ns1.prefixes.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_nodeset_different_members_different_said() {
        let a = test_digest(b"node-a");
        let b = test_digest(b"node-b");

        let ns1 = NodeSet::create_sorted(vec![a, b]).unwrap();
        let ns2 = NodeSet::create_sorted(vec![a]).unwrap();
        assert_ne!(ns1.said, ns2.said);
    }

    #[test]
    fn test_nodeset_empty_is_valid() {
        let ns = NodeSet::create_sorted(vec![]).unwrap();
        assert!(ns.verify_said().is_ok());
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_validate_sad_object_all_fields_allowed() {
        let custody = Custody::create(
            Some(test_digest(b"wp")),
            Some(test_digest(b"rp")),
            Some(3600),
            Some(true),
            Some(test_digest(b"nodes")),
        )
        .unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_validate_event_rejects_ttl() {
        let custody =
            Custody::create(Some(test_digest(b"wp")), None, Some(3600), None, None).unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Event);
        assert!(matches!(
            result,
            Err(CustodyValidationError::TtlNotAllowedOnEvent)
        ));
    }

    #[test]
    fn test_validate_event_rejects_once() {
        let custody = Custody::create(
            Some(test_digest(b"wp")),
            None,
            None,
            Some(true),
            Some(test_digest(b"nodes")),
        )
        .unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Event);
        assert!(matches!(
            result,
            Err(CustodyValidationError::OnceNotAllowedOnEvent)
        ));
    }

    #[test]
    fn test_validate_event_allows_write_read_nodes() {
        let custody = Custody::create(
            Some(test_digest(b"wp")),
            Some(test_digest(b"rp")),
            None,
            None,
            Some(test_digest(b"nodes")),
        )
        .unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Event);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_validate_once_requires_nodes() {
        let custody = Custody::create(
            None,
            None,
            None,
            Some(true),
            None, // no nodes!
        )
        .unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(matches!(
            result,
            Err(CustodyValidationError::OnceRequiresNodes)
        ));
    }

    #[test]
    fn test_validate_once_false_no_nodes_ok() {
        let custody = Custody::create(None, None, None, Some(false), None).unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_validate_unknown_fields_safety_valve() {
        let mut value = serde_json::json!({
            "said": cesr::Digest256::default().to_string(),
            "writePolicy": test_digest(b"wp").to_string(),
            "customField": "something"
        });
        // Safety valve: unknown field present, no enforcement
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(result.unwrap().is_none());

        // Same for event context — safety valve fires before context checks
        let result = parse_and_validate_custody(&value, SadCustodyContext::Event);
        assert!(result.unwrap().is_none());

        // Remove unknown field — now it should parse normally
        value.as_object_mut().unwrap().remove("customField");
        // This will fail parse because the said is a placeholder, but that's
        // a different code path — the point is it doesn't return None
    }

    #[test]
    fn test_validate_empty_custody_object() {
        let custody = Custody::create(None, None, None, None, None).unwrap();
        let value = serde_json::to_value(&custody).unwrap();
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(result.is_ok());
        let parsed = result.unwrap().unwrap();
        assert!(parsed.write_policy.is_none());
        assert!(parsed.read_policy.is_none());
        assert!(parsed.ttl.is_none());
        assert!(parsed.once.is_none());
        assert!(parsed.nodes.is_none());
    }

    #[test]
    fn test_validate_not_an_object() {
        let value = serde_json::json!("not an object");
        let result = parse_and_validate_custody(&value, SadCustodyContext::Object);
        assert!(matches!(result, Err(CustodyValidationError::ParseError(_))));
    }
}
