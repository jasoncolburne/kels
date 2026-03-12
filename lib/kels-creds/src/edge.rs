use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::error::CredentialError;

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct Edge {
    #[said]
    pub said: String,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct Edges {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub edges: BTreeMap<String, Edge>,
}

/// Validate that no edge labels use the reserved name "said".
fn validate_labels(labels: &BTreeMap<String, Edge>) -> Result<(), CredentialError> {
    for label in labels.keys() {
        if label == "said" {
            return Err(CredentialError::ReservedLabel(
                "'said' cannot be used as an edge label".to_string(),
            ));
        }
    }
    Ok(())
}

impl Edges {
    /// Create a new Edges container with label validation and SAID derivation.
    pub fn new_validated(edges: BTreeMap<String, Edge>) -> Result<Self, CredentialError> {
        validate_labels(&edges)?;
        let mut instance = Self {
            said: String::new(),
            edges,
        };
        instance.derive_said()?;
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use verifiable_storage::SelfAddressed;

    fn test_edge() -> Edge {
        Edge::create(
            "EAbc1234567890123456789012345678901234567890".to_string(),
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_edge_said_derivation() {
        let edge = test_edge();
        assert!(!edge.said.is_empty());
        assert_eq!(edge.said.len(), 44);
    }

    #[test]
    fn test_edge_said_verify() {
        let edge = test_edge();
        assert!(edge.verify_said().is_ok());
    }

    #[test]
    fn test_edge_with_optional_fields() {
        let edge = Edge::create(
            "EAbc1234567890123456789012345678901234567890".to_string(),
            Some("EIssuer123456789012345678901234567890abcde".to_string()),
            Some("ECred12345678901234567890123456789012abcdef".to_string()),
            Some(true),
        )
        .unwrap();

        assert!(edge.verify_said().is_ok());

        let json = serde_json::to_value(&edge).unwrap();
        assert!(json.get("issuer").is_some());
        assert!(json.get("credential").is_some());
        assert!(json.get("delegated").is_some());
    }

    #[test]
    fn test_edge_optional_fields_omitted() {
        let edge = test_edge();
        let json = serde_json::to_value(&edge).unwrap();
        assert!(json.get("issuer").is_none());
        assert!(json.get("credential").is_none());
        assert!(json.get("delegated").is_none());
    }

    #[test]
    fn test_edges_said_derivation() {
        let mut edges_map = BTreeMap::new();
        edges_map.insert("license".to_string(), test_edge());

        let edges = Edges::new_validated(edges_map).unwrap();
        assert!(!edges.said.is_empty());
        assert_eq!(edges.said.len(), 44);
        assert!(edges.verify_said().is_ok());
    }

    #[test]
    fn test_edges_flatten_serialization() {
        let mut edges_map = BTreeMap::new();
        edges_map.insert("license".to_string(), test_edge());

        let edges = Edges::new_validated(edges_map).unwrap();
        let json = serde_json::to_value(&edges).unwrap();

        // Flattened: "license" should be a top-level key alongside "said"
        assert!(json.get("said").is_some());
        assert!(json.get("license").is_some());
        // No "edges" wrapper key
        assert!(json.get("edges").is_none());
    }

    #[test]
    fn test_edges_reserved_label_rejected() {
        let mut edges_map = BTreeMap::new();
        edges_map.insert("said".to_string(), test_edge());

        let err = Edges::new_validated(edges_map).unwrap_err();
        assert!(matches!(err, CredentialError::ReservedLabel(_)));
    }

    #[test]
    fn test_edges_deterministic_said() {
        let mut m1 = BTreeMap::new();
        m1.insert("a".to_string(), test_edge());
        let e1 = Edges::new_validated(m1).unwrap();

        let mut m2 = BTreeMap::new();
        m2.insert("a".to_string(), test_edge());
        let e2 = Edges::new_validated(m2).unwrap();

        assert_eq!(e1.said, e2.said);
    }

    #[test]
    fn test_edge_serialization_roundtrip() {
        let edge = test_edge();
        let json = serde_json::to_string(&edge).unwrap();
        let deserialized: Edge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge.said, deserialized.said);
    }
}
