use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use crate::{
    PolicyNode,
    error::PolicyError,
    parser::{canonicalize, parse},
};

/// An immutable, self-addressed policy document.
///
/// Contains a DSL expression defining trust conditions. Poisoning behavior is
/// controlled by two mutually exclusive optional fields:
///
/// - Neither set (default): any endorser can poison by anchoring the poison hash;
///   poisoned endorsements don't count toward threshold (soft withdrawal)
/// - `poison`: DSL expression defining who can poison and under what conditions;
///   when the poison expression is satisfied, the entire policy is unsatisfied
/// - `immune`: if true, no poison checks at all; endorsements are permanent
///
/// `poison` and `immune` cannot both be set.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[crate_new]
pub struct Policy {
    #[said]
    pub said: String,
    pub expression: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poison: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_immune"
    )]
    pub immune: Option<bool>,
}

/// Deserialize `immune` field, normalizing `false` to `None`.
/// Only `true` is meaningful; `false` would produce a different SAID than `None`
/// while behaving identically at runtime.
fn deserialize_immune<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Option<bool> = Option::deserialize(deserializer)?;
    match value {
        Some(true) => Ok(Some(true)),
        _ => Ok(None),
    }
}

impl Policy {
    /// Build a new policy from a DSL expression with optional poison expression and immune flag.
    ///
    /// Parses and canonicalizes expressions, validates mutual exclusion, and derives the SAID.
    pub fn build(
        expression: &str,
        poison: Option<&str>,
        immune: bool,
    ) -> Result<Self, PolicyError> {
        let canonical = canonicalize(expression)?;

        let canonical_poison = poison.map(canonicalize).transpose()?;

        if immune && poison.is_some() {
            return Err(PolicyError::InvalidPolicy(
                "immune and poison are mutually exclusive".to_string(),
            ));
        }

        let immune_field = if immune { Some(true) } else { None };

        let mut policy = Self {
            said: String::new(),
            expression: canonical,
            poison: canonical_poison,
            immune: immune_field,
        };
        policy.derive_said()?;
        Ok(policy)
    }

    /// Parse this policy's expression into an AST.
    pub fn parse(&self) -> Result<PolicyNode, PolicyError> {
        parse(&self.expression)
    }

    /// Parse this policy's poison expression into an AST, if present.
    pub fn parse_poison(&self) -> Result<Option<PolicyNode>, PolicyError> {
        match &self.poison {
            Some(expr) => Ok(Some(parse(expr)?)),
            None => Ok(None),
        }
    }

    /// Whether this policy is immune to poisoning.
    pub fn is_immune(&self) -> bool {
        self.immune == Some(true)
    }

    /// Whether this policy has a poison expression (hard poisonable).
    pub fn is_poisonable(&self) -> bool {
        self.poison.is_some()
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
        let compacted_poison = self
            .parse_poison()?
            .map(|poison_ast| poison_ast.compact().to_string());
        let mut policy = Self {
            said: String::new(),
            expression: compacted.to_string(),
            poison: compacted_poison,
            immune: self.immune,
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
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        assert_eq!(policy.said.len(), 44);
        assert_eq!(policy.expression, format!("endorse({PREFIX_A})"));
        assert!(policy.immune.is_none());
        assert!(policy.poison.is_none());
    }

    #[test]
    fn test_create_immune() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None, true).unwrap();
        assert!(policy.is_immune());
        assert!(!policy.is_poisonable());
    }

    #[test]
    fn test_create_poisonable() {
        let policy = Policy::build(
            &format!("endorse({PREFIX_A})"),
            Some(&format!("endorse({PREFIX_B})")),
            false,
        )
        .unwrap();
        assert!(policy.is_poisonable());
        assert!(!policy.is_immune());
    }

    #[test]
    fn test_create_invalid_expression() {
        let result = Policy::build("invalid()", None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_immune_with_poison_rejected() {
        let result = Policy::build(
            &format!("endorse({PREFIX_A})"),
            Some(&format!("endorse({PREFIX_B})")),
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_with_poison() {
        let policy = Policy::build(
            &format!("endorse({PREFIX_A})"),
            Some(&format!("endorse({PREFIX_B})")),
            false,
        )
        .unwrap();
        assert!(policy.poison.is_some());
        assert_eq!(
            policy.poison.as_deref(),
            Some(format!("endorse({PREFIX_B})").as_str())
        );
    }

    #[test]
    fn test_said_differs_by_poison() {
        let p1 = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        let p2 = Policy::build(
            &format!("endorse({PREFIX_A})"),
            Some(&format!("endorse({PREFIX_B})")),
            false,
        )
        .unwrap();
        assert_ne!(p1.said, p2.said);
    }

    #[test]
    fn test_said_differs_by_immune() {
        let p1 = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), None, true).unwrap();
        assert_ne!(p1.said, p2.said);
    }

    #[test]
    fn test_said_deterministic() {
        let p1 = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_said_canonicalization() {
        let p1 = Policy::build(&format!("endorse( {PREFIX_A} )"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_endorser_prefixes() {
        let policy = Policy::build(
            &format!(
                "threshold(2, [endorse({PREFIX_A}), delegate({PREFIX_B}, {PREFIX_C}), policy({SAID_A})])"
            ),
            None,
            false,
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
            false,
        )
        .unwrap();
        let saids = policy.referenced_policy_saids().unwrap();
        assert_eq!(saids.len(), 1);
        assert!(saids.contains(SAID_A));
    }

    #[test]
    fn test_compact() {
        let policy =
            Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_B})"), None, false).unwrap();
        let compacted = policy.compact().unwrap();
        assert_eq!(compacted.expression, format!("delegate({PREFIX_A})"));
        assert_ne!(compacted.said, policy.said);
    }

    #[test]
    fn test_compact_stable_said() {
        let p1 = Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_B})"), None, false).unwrap();
        let p2 = Policy::build(&format!("delegate({PREFIX_A}, {PREFIX_C})"), None, false).unwrap();
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
            false,
        )
        .unwrap();
        let ast = policy.parse().unwrap();
        let reparsed = Policy::build(&ast.to_string(), None, false).unwrap();
        assert_eq!(policy.said, reparsed.said);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.said, deserialized.said);
        assert_eq!(policy.expression, deserialized.expression);
        assert_eq!(policy.immune, deserialized.immune);
    }

    #[test]
    fn test_serialization_omits_defaults() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None, false).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(!json.contains("immune"));
        assert!(!json.contains("poison"));
    }

    #[test]
    fn test_serialization_includes_immune() {
        let policy = Policy::build(&format!("endorse({PREFIX_A})"), None, true).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("immune"));
    }

    #[test]
    fn test_serialization_includes_poison() {
        let policy = Policy::build(
            &format!("endorse({PREFIX_A})"),
            Some(&format!("endorse({PREFIX_B})")),
            false,
        )
        .unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("poison"));
    }
}
