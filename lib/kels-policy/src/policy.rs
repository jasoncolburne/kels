use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use crate::{
    PolicyNode,
    error::PolicyError,
    parser::{canonicalize, parse},
};

const VALID_KINDS: &[&str] = &["immune", "poisonable"];

/// An immutable, self-addressed policy document.
///
/// Contains a DSL expression defining trust conditions and an optional `kind`
/// that controls poisoning behavior:
/// - Absent (default): poison hashes checked, poisoned endorsements don't count toward threshold
/// - `"immune"`: no poison checks, endorsements are permanent
/// - `"poisonable"`: any single poisoned endorsement unsatisfies the entire policy
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[crate_new]
pub struct Policy {
    #[said]
    pub said: String,
    pub expression: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl Policy {
    /// Build a new policy from a DSL expression and optional kind.
    ///
    /// Parses and canonicalizes the expression, validates the kind, and derives the SAID.
    pub fn build(expression: &str, kind: Option<&str>) -> Result<Self, PolicyError> {
        let canonical = canonicalize(expression)?;

        if let Some(k) = kind
            && !VALID_KINDS.contains(&k)
        {
            return Err(PolicyError::InvalidPolicy(format!(
                "unknown kind '{k}', valid kinds are: {VALID_KINDS:?}"
            )));
        }

        let mut policy = Self {
            said: String::new(),
            expression: canonical,
            kind: kind.map(String::from),
        };
        policy.derive_said()?;
        Ok(policy)
    }

    /// Parse this policy's expression into an AST.
    pub fn parse(&self) -> Result<PolicyNode, PolicyError> {
        parse(&self.expression)
    }

    /// Whether this policy is immune to poisoning.
    pub fn is_immune(&self) -> bool {
        self.kind.as_deref() == Some("immune")
    }

    /// Whether this policy is poisonable (any single poison kills it).
    pub fn is_poisonable(&self) -> bool {
        self.kind.as_deref() == Some("poisonable")
    }

    /// Collect all endorser prefixes referenced in the expression.
    /// Includes both `endorse(PREFIX)` prefixes and `delegate(_, DELEGATE)` prefixes.
    pub fn endorser_prefixes(&self) -> Result<BTreeSet<String>, PolicyError> {
        let ast = self.parse()?;
        let mut prefixes = BTreeSet::new();
        collect_endorser_prefixes(&ast, &mut prefixes);
        Ok(prefixes)
    }

    /// Collect all nested policy SAIDs referenced in the expression.
    pub fn referenced_policy_saids(&self) -> Result<BTreeSet<String>, PolicyError> {
        let ast = self.parse()?;
        let mut saids = BTreeSet::new();
        collect_policy_saids(&ast, &mut saids);
        Ok(saids)
    }

    /// Compact this policy by stripping delegate specifics.
    /// Returns a new policy with the compacted expression and a new SAID.
    pub fn compact(&self) -> Result<Self, PolicyError> {
        let ast = self.parse()?;
        let compacted = ast.compact();
        let mut policy = Self {
            said: String::new(),
            expression: compacted.to_string(),
            kind: self.kind.clone(),
        };
        policy.derive_said()?;
        Ok(policy)
    }
}

fn collect_endorser_prefixes(node: &PolicyNode, prefixes: &mut BTreeSet<String>) {
    match node {
        PolicyNode::Endorse(prefix) => {
            prefixes.insert(prefix.clone());
        }
        PolicyNode::Delegate(delegator, delegate) => {
            prefixes.insert(delegator.clone());
            if !delegate.is_empty() {
                prefixes.insert(delegate.clone());
            }
        }
        PolicyNode::Threshold(_, children) => {
            for child in children {
                collect_endorser_prefixes(child, prefixes);
            }
        }
        PolicyNode::Weighted(_, pairs) => {
            for (node, _) in pairs {
                collect_endorser_prefixes(node, prefixes);
            }
        }
        PolicyNode::Policy(_) => {}
    }
}

fn collect_policy_saids(node: &PolicyNode, saids: &mut BTreeSet<String>) {
    match node {
        PolicyNode::Endorse(_) | PolicyNode::Delegate(_, _) => {}
        PolicyNode::Threshold(_, children) => {
            for child in children {
                collect_policy_saids(child, saids);
            }
        }
        PolicyNode::Weighted(_, pairs) => {
            for (node, _) in pairs {
                collect_policy_saids(node, saids);
            }
        }
        PolicyNode::Policy(said) => {
            saids.insert(said.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX_A: &str = "KBfd1234567890123456789012345678901234567890";
    const PREFIX_B: &str = "KAbc5678901234567890123456789012345678901234";
    const PREFIX_C: &str = "KCde9012345678901234567890123456789012345678";
    const SAID_A: &str = "KHij3456789012345678901234567890123456789012";

    #[test]
    fn test_create_simple() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        assert_eq!(policy.said.len(), 44);
        assert_eq!(policy.expression, format!("endorse({PREFIX_A})"));
        assert!(policy.kind.is_none());
    }

    #[test]
    fn test_create_immune() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), Some("immune")).unwrap();
        assert!(policy.is_immune());
        assert!(!policy.is_poisonable());
    }

    #[test]
    fn test_create_poisonable() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), Some("poisonable")).unwrap();
        assert!(policy.is_poisonable());
        assert!(!policy.is_immune());
    }

    #[test]
    fn test_create_invalid_kind() {
        let result = Policy::build(&format!("endorse({PREFIX_A})"), Some("bad"));
        assert!(result.is_err());
    }

    #[test]
    fn test_create_invalid_expression() {
        let result = Policy::build("invalid()", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_said_differs_by_kind() {
        let p1 = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), Some("immune")).unwrap();
        let p3 = Policy::build(&format!("endorse({PREFIX_A})"), Some("poisonable")).unwrap();
        assert_ne!(p1.said, p2.said);
        assert_ne!(p2.said, p3.said);
        assert_ne!(p1.said, p3.said);
    }

    #[test]
    fn test_said_deterministic() {
        let p1 = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_said_canonicalization() {
        let p1 = Policy::build(&format!("endorse( {PREFIX_A} )"), None).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_endorser_prefixes() {
        let policy = Policy::build(
            &format!(
                "threshold(2, [endorse({PREFIX_A}), delegate({PREFIX_B}, {PREFIX_C}), policy({SAID_A})])"
            ),
            None,
        )
        .unwrap();
        let prefixes = policy.endorser_prefixes().unwrap();
        assert_eq!(prefixes.len(), 3);
        assert!(prefixes.contains(PREFIX_A));
        assert!(prefixes.contains(PREFIX_B));
        assert!(prefixes.contains(PREFIX_C));
    }

    #[test]
    fn test_referenced_policy_saids() {
        let policy = Policy::build(
            &format!("threshold(1, [endorse({PREFIX_A}), policy({SAID_A})])"),
            None,
        )
        .unwrap();
        let saids = policy.referenced_policy_saids().unwrap();
        assert_eq!(saids.len(), 1);
        assert!(saids.contains(SAID_A));
    }

    #[test]
    fn test_compact() {
        let policy = Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_B})"), None).unwrap();
        let compacted = policy.compact().unwrap();
        assert_eq!(compacted.expression, format!("delegate({PREFIX_A})"));
        assert_ne!(compacted.said, policy.said);
    }

    #[test]
    fn test_compact_stable_said() {
        let p1 = Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_B})"), None).unwrap();
        let p2 = Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_C})"), None).unwrap();
        let c1 = p1.compact().unwrap();
        let c2 = p2.compact().unwrap();
        assert_eq!(c1.said, c2.said);
    }

    #[test]
    fn test_parse_roundtrip() {
        let policy = Policy::build(
            &format!(
                "threshold(2, [endorse({PREFIX_A}), weighted(3, [endorse({PREFIX_B}):2, endorse({PREFIX_C}):1])])"
            ),
            None,
        )
        .unwrap();
        let ast = policy.parse().unwrap();
        let reparsed = Policy::build(&ast.to_string(), None).unwrap();
        assert_eq!(policy.said, reparsed.said);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.said, deserialized.said);
        assert_eq!(policy.expression, deserialized.expression);
        assert_eq!(policy.kind, deserialized.kind);
    }

    #[test]
    fn test_serialization_omits_none_kind() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(!json.contains("kind"));
    }

    #[test]
    fn test_serialization_includes_kind() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), Some("poisonable")).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("poisonable"));
    }
}
