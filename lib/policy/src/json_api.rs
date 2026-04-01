use crate::{Policy, error::PolicyError};

/// Build a policy from a DSL expression string.
///
/// Returns the policy as a JSON string and the canonical SAID.
pub fn build(
    expression: &str,
    poison: Option<&str>,
    immune: bool,
) -> Result<(String, String), PolicyError> {
    let policy = Policy::build(expression, poison, immune)?;
    let said = policy.said.clone();
    let json = serde_json::to_string(&policy)?;
    Ok((json, said))
}

/// Compact a policy JSON string by stripping delegate specifics.
///
/// Returns the compacted policy as a JSON string and the canonical SAID.
pub fn compact(json_policy: &str) -> Result<(String, String), PolicyError> {
    let policy: Policy = serde_json::from_str(json_policy)?;
    let compacted = policy.compact()?;
    let said = compacted.said.clone();
    let json = serde_json::to_string(&compacted)?;
    Ok((json, said))
}

/// Compute the poison hash for a credential SAID.
pub fn poison_hash(credential_said: &str) -> String {
    crate::evaluator::poison_hash(credential_said)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        let (json, said) = build(
            "endorse(KBfd1234567890123456789012345678901234567890)",
            None,
            false,
        )
        .unwrap();
        assert_eq!(said.len(), 44);
        assert!(json.contains("endorse"));
        assert!(!json.contains("immune"));
        assert!(!json.contains("poison"));
    }

    #[test]
    fn test_build_immune() {
        let (json, _) = build(
            "endorse(KBfd1234567890123456789012345678901234567890)",
            None,
            true,
        )
        .unwrap();
        assert!(json.contains("immune"));
    }

    #[test]
    fn test_build_with_poison() {
        let (json, _) = build(
            "endorse(KBfd1234567890123456789012345678901234567890)",
            Some("endorse(KAbc5678901234567890123456789012345678901234)"),
            false,
        )
        .unwrap();
        assert!(json.contains("poison"));
    }

    #[test]
    fn test_compact() {
        let (full_json, full_said) = build(
            "delegate(KBfd1234567890123456789012345678901234567890, KAbc5678901234567890123456789012345678901234)",
            None,
            false,
        )
        .unwrap();
        let (compacted_json, compacted_said) = compact(&full_json).unwrap();
        assert_ne!(full_said, compacted_said);
        assert!(!compacted_json.contains("KAbc"));
    }

    #[test]
    fn test_poison_hash_deterministic() {
        let h1 = poison_hash("KCred12345678901234567890123456789012abcdef");
        let h2 = poison_hash("KCred12345678901234567890123456789012abcdef");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 44);
    }
}
