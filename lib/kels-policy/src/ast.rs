use std::fmt;

/// AST node representing a policy expression.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyNode {
    /// A specific prefix must anchor the credential SAID.
    Endorse(String),
    /// A delegated endorsement: the delegate must be delegated by the delegator,
    /// and the delegate must anchor the credential SAID.
    Delegate(String, String),
    /// At least `min` of the children must be satisfied.
    Threshold(usize, Vec<PolicyNode>),
    /// Sum of weights of satisfied children must be >= min_weight.
    Weighted(u64, Vec<(PolicyNode, u64)>),
    /// Resolve and evaluate another policy by SAID.
    Policy(String),
}

impl PolicyNode {
    /// Compact this node by stripping delegate specifics.
    /// `delegate(DELEGATOR, DELEGATE)` becomes `delegate(DELEGATOR)` —
    /// represented as `Delegate(delegator, "")` with an empty delegate.
    pub fn compact(&self) -> Self {
        match self {
            PolicyNode::Endorse(prefix) => PolicyNode::Endorse(prefix.clone()),
            PolicyNode::Delegate(delegator, _) => {
                PolicyNode::Delegate(delegator.clone(), String::new())
            }
            PolicyNode::Threshold(min, children) => {
                PolicyNode::Threshold(*min, children.iter().map(|c| c.compact()).collect())
            }
            PolicyNode::Weighted(min_weight, pairs) => PolicyNode::Weighted(
                *min_weight,
                pairs
                    .iter()
                    .map(|(node, weight)| (node.compact(), *weight))
                    .collect(),
            ),
            PolicyNode::Policy(said) => PolicyNode::Policy(said.clone()),
        }
    }
}

impl fmt::Display for PolicyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyNode::Endorse(prefix) => write!(f, "endorse({prefix})"),
            PolicyNode::Delegate(delegator, delegate) => {
                if delegate.is_empty() {
                    write!(f, "delegate({delegator})")
                } else {
                    write!(f, "delegate({delegator}, {delegate})")
                }
            }
            PolicyNode::Threshold(min, children) => {
                write!(f, "threshold({min}, [")?;
                for (i, child) in children.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{child}")?;
                }
                write!(f, "])")
            }
            PolicyNode::Weighted(min_weight, pairs) => {
                write!(f, "weighted({min_weight}, [")?;
                for (i, (node, weight)) in pairs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{node}:{weight}")?;
                }
                write!(f, "])")
            }
            PolicyNode::Policy(said) => write!(f, "policy({said})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_endorse() {
        let node = PolicyNode::Endorse("KBfd1234567890123456789012345678901234567890".to_string());
        assert_eq!(
            node.to_string(),
            "endorse(KBfd1234567890123456789012345678901234567890)"
        );
    }

    #[test]
    fn test_display_delegate() {
        let node = PolicyNode::Delegate(
            "KBfd1234567890123456789012345678901234567890".to_string(),
            "KAbc5678901234567890123456789012345678901234".to_string(),
        );
        assert_eq!(
            node.to_string(),
            "delegate(KBfd1234567890123456789012345678901234567890, KAbc5678901234567890123456789012345678901234)"
        );
    }

    #[test]
    fn test_display_delegate_compacted() {
        let node = PolicyNode::Delegate(
            "KBfd1234567890123456789012345678901234567890".to_string(),
            String::new(),
        );
        assert_eq!(
            node.to_string(),
            "delegate(KBfd1234567890123456789012345678901234567890)"
        );
    }

    #[test]
    fn test_display_threshold() {
        let node = PolicyNode::Threshold(
            2,
            vec![
                PolicyNode::Endorse("KBfd1234567890123456789012345678901234567890".to_string()),
                PolicyNode::Endorse("KAbc5678901234567890123456789012345678901234".to_string()),
                PolicyNode::Endorse("KCde9012345678901234567890123456789012345678".to_string()),
            ],
        );
        assert_eq!(
            node.to_string(),
            "threshold(2, [endorse(KBfd1234567890123456789012345678901234567890), endorse(KAbc5678901234567890123456789012345678901234), endorse(KCde9012345678901234567890123456789012345678)])"
        );
    }

    #[test]
    fn test_display_weighted() {
        let node = PolicyNode::Weighted(
            5,
            vec![
                (
                    PolicyNode::Endorse("KBfd1234567890123456789012345678901234567890".to_string()),
                    3,
                ),
                (
                    PolicyNode::Endorse("KAbc5678901234567890123456789012345678901234".to_string()),
                    2,
                ),
            ],
        );
        assert_eq!(
            node.to_string(),
            "weighted(5, [endorse(KBfd1234567890123456789012345678901234567890):3, endorse(KAbc5678901234567890123456789012345678901234):2])"
        );
    }

    #[test]
    fn test_display_policy() {
        let node = PolicyNode::Policy("KHij3456789012345678901234567890123456789012".to_string());
        assert_eq!(
            node.to_string(),
            "policy(KHij3456789012345678901234567890123456789012)"
        );
    }

    #[test]
    fn test_compact_strips_delegate() {
        let node = PolicyNode::Delegate(
            "KBfd1234567890123456789012345678901234567890".to_string(),
            "KAbc5678901234567890123456789012345678901234".to_string(),
        );
        let compacted = node.compact();
        assert_eq!(
            compacted,
            PolicyNode::Delegate(
                "KBfd1234567890123456789012345678901234567890".to_string(),
                String::new()
            )
        );
    }

    #[test]
    fn test_compact_preserves_endorse() {
        let node = PolicyNode::Endorse("KBfd1234567890123456789012345678901234567890".to_string());
        assert_eq!(node.compact(), node);
    }

    #[test]
    fn test_compact_recursive() {
        let node = PolicyNode::Threshold(
            1,
            vec![
                PolicyNode::Delegate(
                    "KBfd1234567890123456789012345678901234567890".to_string(),
                    "KAbc5678901234567890123456789012345678901234".to_string(),
                ),
                PolicyNode::Endorse("KCde9012345678901234567890123456789012345678".to_string()),
            ],
        );
        let compacted = node.compact();
        assert_eq!(
            compacted,
            PolicyNode::Threshold(
                1,
                vec![
                    PolicyNode::Delegate(
                        "KBfd1234567890123456789012345678901234567890".to_string(),
                        String::new()
                    ),
                    PolicyNode::Endorse("KCde9012345678901234567890123456789012345678".to_string()),
                ]
            )
        );
    }
}
