use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::error::CredentialError;

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct Rule {
    #[said]
    pub said: String,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct Rules {
    #[said]
    pub said: String,
    #[serde(flatten)]
    pub rules: BTreeMap<String, Rule>,
}

/// Validate that no rule labels use the reserved name "said".
fn validate_labels(labels: &BTreeMap<String, Rule>) -> Result<(), CredentialError> {
    for label in labels.keys() {
        if label == "said" {
            return Err(CredentialError::ReservedLabel(
                "'said' cannot be used as a rule label".to_string(),
            ));
        }
    }
    Ok(())
}

impl Rules {
    /// Create a new Rules container with label validation and SAID derivation.
    pub fn new_validated(rules: BTreeMap<String, Rule>) -> Result<Self, CredentialError> {
        validate_labels(&rules)?;
        let mut instance = Self {
            said: String::new(),
            rules,
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

    fn test_rule() -> Rule {
        Rule::create("Must be used only for verification purposes".to_string()).unwrap()
    }

    #[test]
    fn test_rule_said_derivation() {
        let rule = test_rule();
        assert!(!rule.said.is_empty());
        assert_eq!(rule.said.len(), 44);
    }

    #[test]
    fn test_rule_said_verify() {
        let rule = test_rule();
        assert!(rule.verify_said().is_ok());
    }

    #[test]
    fn test_rule_said_deterministic() {
        let r1 = test_rule();
        let r2 = test_rule();
        assert_eq!(r1.said, r2.said);
    }

    #[test]
    fn test_rule_serialization_roundtrip() {
        let rule = test_rule();
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule.said, deserialized.said);
        assert_eq!(rule.condition, deserialized.condition);
    }

    #[test]
    fn test_rules_said_derivation() {
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), test_rule());

        let rules = Rules::new_validated(rules_map).unwrap();
        assert!(!rules.said.is_empty());
        assert_eq!(rules.said.len(), 44);
        assert!(rules.verify_said().is_ok());
    }

    #[test]
    fn test_rules_flatten_serialization() {
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), test_rule());

        let rules = Rules::new_validated(rules_map).unwrap();
        let json = serde_json::to_value(&rules).unwrap();

        // Flattened: "terms" should be a top-level key alongside "said"
        assert!(json.get("said").is_some());
        assert!(json.get("terms").is_some());
        // No "rules" wrapper key
        assert!(json.get("rules").is_none());
    }

    #[test]
    fn test_rules_reserved_label_rejected() {
        let mut rules_map = BTreeMap::new();
        rules_map.insert("said".to_string(), test_rule());

        let err = Rules::new_validated(rules_map).unwrap_err();
        assert!(matches!(err, CredentialError::ReservedLabel(_)));
    }

    #[test]
    fn test_rules_deterministic_said() {
        let mut m1 = BTreeMap::new();
        m1.insert("terms".to_string(), test_rule());
        let r1 = Rules::new_validated(m1).unwrap();

        let mut m2 = BTreeMap::new();
        m2.insert("terms".to_string(), test_rule());
        let r2 = Rules::new_validated(m2).unwrap();

        assert_eq!(r1.said, r2.said);
    }
}
