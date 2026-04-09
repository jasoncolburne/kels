use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use verifiable_storage::SelfAddressed;

use crate::error::CredentialError;

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[said]
    pub said: cesr::Digest256,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct Rules {
    #[said]
    pub said: cesr::Digest256,
    #[serde(flatten)]
    pub rules: BTreeMap<String, Rule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRules {
    said: cesr::Digest256,
    #[serde(flatten)]
    rules: BTreeMap<String, Rule>,
}

impl TryFrom<RawRules> for Rules {
    type Error = CredentialError;

    fn try_from(raw: RawRules) -> Result<Self, Self::Error> {
        validate_labels(&raw.rules)?;
        Ok(Self {
            said: raw.said,
            rules: raw.rules,
        })
    }
}

impl<'de> Deserialize<'de> for Rules {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRules::deserialize(deserializer)?;
        Rules::try_from(raw).map_err(serde::de::Error::custom)
    }
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
    pub fn new_validated(mut rules: BTreeMap<String, Rule>) -> Result<Self, CredentialError> {
        validate_labels(&rules)?;
        for rule in rules.values_mut() {
            rule.derive_said()?;
        }
        let mut instance = Self {
            said: cesr::Digest256::default(),
            rules,
        };
        instance.derive_said()?;
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;

    use verifiable_storage::SelfAddressed;

    fn test_rule() -> Rule {
        Rule::create("Must be used only for verification purposes".to_string()).unwrap()
    }

    #[test]
    fn test_rule_said_derivation() {
        let rule = test_rule();
        assert!(!rule.said.to_string().is_empty());
        assert_eq!(rule.said.to_string().len(), 44);
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
        assert!(!rules.said.to_string().is_empty());
        assert_eq!(rules.said.to_string().len(), 44);
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

    #[test]
    fn test_rules_deserialization_roundtrip() {
        let mut rules_map = BTreeMap::new();
        rules_map.insert("terms".to_string(), test_rule());
        let rules = Rules::new_validated(rules_map).unwrap();
        let json = serde_json::to_string(&rules).unwrap();
        let deserialized: Rules = serde_json::from_str(&json).unwrap();
        assert_eq!(rules.said, deserialized.said);
        assert_eq!(rules.rules.len(), deserialized.rules.len());
    }

    #[test]
    fn test_rules_try_from_rejects_reserved_label() {
        let raw = super::RawRules {
            said: test_digest("reserved-label-test"),
            rules: {
                let mut m = BTreeMap::new();
                m.insert("said".to_string(), test_rule());
                m
            },
        };
        let err = Rules::try_from(raw).unwrap_err();
        assert!(matches!(err, CredentialError::ReservedLabel(_)));
    }
}
