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
#[storable(table = "policies")]
#[serde(rename_all = "camelCase")]
#[crate_new]
pub struct Policy {
    #[said]
    pub said: cesr::Digest256,
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
            said: cesr::Digest256::default(),
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
        self.poison.as_ref().map(|expr| parse(expr)).transpose()
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
    pub fn endorser_prefixes(&self) -> Result<BTreeSet<cesr::Digest256>, PolicyError> {
        let ast = self.parse()?;
        let mut prefixes = BTreeSet::new();
        collect_endorser_prefixes(&ast, &mut prefixes);
        if let Some(poison_ast) = self.parse_poison()? {
            collect_endorser_prefixes(&poison_ast, &mut prefixes);
        }
        Ok(prefixes)
    }

    /// Collect all nested policy SAIDs referenced in the expression.
    pub fn referenced_policy_saids(&self) -> Result<BTreeSet<cesr::Digest256>, PolicyError> {
        let ast = self.parse()?;
        let mut saids = BTreeSet::new();
        collect_policy_saids(&ast, &mut saids);
        if let Some(poison_ast) = self.parse_poison()? {
            collect_policy_saids(&poison_ast, &mut saids);
        }
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
            said: cesr::Digest256::default(),
            expression: compacted.to_string(),
            poison: compacted_poison,
            immune: self.immune,
        };
        policy.derive_said()?;
        Ok(policy)
    }
}

fn collect_endorser_prefixes(node: &PolicyNode, prefixes: &mut BTreeSet<cesr::Digest256>) {
    match node {
        PolicyNode::Endorse(prefix) => {
            prefixes.insert(*prefix);
        }
        PolicyNode::Delegate(delegator, delegate) => {
            prefixes.insert(*delegator);
            if *delegate != cesr::Digest256::default() {
                prefixes.insert(*delegate);
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

fn collect_policy_saids(node: &PolicyNode, saids: &mut BTreeSet<cesr::Digest256>) {
    match node {
        PolicyNode::Endorse(_) | PolicyNode::Delegate(_, _) => {}
        PolicyNode::Weighted(_, pairs) => {
            for (node, _) in pairs {
                collect_policy_saids(node, saids);
            }
        }
        PolicyNode::Policy(said) => {
            saids.insert(*said);
        }
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;

    #[test]
    fn test_create_simple() {
        let a = test_digest("prefix-a");
        let policy = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        assert_eq!(policy.said.to_string().len(), 44);
        assert_eq!(policy.expression, format!("endorse({a})"));
        assert!(policy.immune.is_none());
        assert!(policy.poison.is_none());
    }

    #[test]
    fn test_create_immune() {
        let a = test_digest("prefix-a");
        let policy = Policy::build(&format!("endorse({a})"), None, true).unwrap();
        assert!(policy.is_immune());
        assert!(!policy.is_poisonable());
    }

    #[test]
    fn test_create_poisonable() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let policy = Policy::build(
            &format!("endorse({a})"),
            Some(&format!("endorse({b})")),
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
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let result = Policy::build(
            &format!("endorse({a})"),
            Some(&format!("endorse({b})")),
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_with_poison() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let policy = Policy::build(
            &format!("endorse({a})"),
            Some(&format!("endorse({b})")),
            false,
        )
        .unwrap();
        assert!(policy.poison.is_some());
        assert_eq!(
            policy.poison.as_deref(),
            Some(format!("endorse({b})").as_str())
        );
    }

    #[test]
    fn test_said_differs_by_poison() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let p1 = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        let p2 = Policy::build(
            &format!("endorse({a})"),
            Some(&format!("endorse({b})")),
            false,
        )
        .unwrap();
        assert_ne!(p1.said, p2.said);
    }

    #[test]
    fn test_said_differs_by_immune() {
        let a = test_digest("prefix-a");
        let p1 = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({a})"), None, true).unwrap();
        assert_ne!(p1.said, p2.said);
    }

    #[test]
    fn test_said_deterministic() {
        let a = test_digest("prefix-a");
        let p1 = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_said_canonicalization() {
        let a = test_digest("prefix-a");
        let p1 = Policy::build(&format!("endorse( {a} )"), None, false).unwrap();
        let p2 = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        assert_eq!(p1.said, p2.said);
    }

    #[test]
    fn test_endorser_prefixes() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let s = test_digest("said-a");
        let policy = Policy::build(
            &format!("threshold(2, [endorse({a}), delegate({b}, {c}), policy({s})])"),
            None,
            false,
        )
        .unwrap();
        let prefixes = policy.endorser_prefixes().unwrap();
        assert_eq!(prefixes.len(), 3);
        assert!(prefixes.contains(&a));
        assert!(prefixes.contains(&b));
        assert!(prefixes.contains(&c));
    }

    #[test]
    fn test_referenced_policy_saids() {
        let a = test_digest("prefix-a");
        let s = test_digest("said-a");
        let policy = Policy::build(
            &format!("threshold(1, [endorse({a}), policy({s})])"),
            None,
            false,
        )
        .unwrap();
        let saids = policy.referenced_policy_saids().unwrap();
        assert_eq!(saids.len(), 1);
        assert!(saids.contains(&s));
    }

    #[test]
    fn test_compact() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let policy = Policy::build(&format!("delegate({a}, {b})"), None, false).unwrap();
        let compacted = policy.compact().unwrap();
        assert_eq!(compacted.expression, format!("delegate({a})"));
        assert_ne!(compacted.said, policy.said);
    }

    #[test]
    fn test_compact_stable_said() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let p1 = Policy::build(&format!("delegate({a}, {b})"), None, false).unwrap();
        let p2 = Policy::build(&format!("delegate({a}, {c})"), None, false).unwrap();
        let c1 = p1.compact().unwrap();
        let c2 = p2.compact().unwrap();
        assert_eq!(c1.said, c2.said);
    }

    #[test]
    fn test_parse_roundtrip() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let policy = Policy::build(
            &format!("threshold(2, [endorse({a}), weighted(3, [endorse({b}):2, endorse({c}):1])])"),
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
        let a = test_digest("prefix-a");
        let policy = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.said, deserialized.said);
        assert_eq!(policy.expression, deserialized.expression);
        assert_eq!(policy.immune, deserialized.immune);
    }

    #[test]
    fn test_serialization_omits_defaults() {
        let a = test_digest("prefix-a");
        let policy = Policy::build(&format!("endorse({a})"), None, false).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(!json.contains("immune"));
        assert!(!json.contains("poison"));
    }

    #[test]
    fn test_serialization_includes_immune() {
        let a = test_digest("prefix-a");
        let policy = Policy::build(&format!("endorse({a})"), None, true).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("immune"));
    }

    #[test]
    fn test_serialization_includes_poison() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let policy = Policy::build(
            &format!("endorse({a})"),
            Some(&format!("endorse({b})")),
            false,
        )
        .unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("poison"));
    }
}
