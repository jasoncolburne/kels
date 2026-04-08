use std::fmt;

/// AST node representing a policy expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyNode {
    /// A specific prefix must anchor the credential SAID.
    Endorse(cesr::Digest),
    /// A delegated endorsement: the delegate must be delegated by the delegator,
    /// and the delegate must anchor the credential SAID.
    Delegate(cesr::Digest, cesr::Digest),
    /// Sum of weights of satisfied children must be >= min_weight.
    /// `threshold(M, [A, B, C])` in the DSL parses to `Weighted(M, [(A, 1), (B, 1), (C, 1)])`.
    Weighted(u64, Vec<(PolicyNode, u64)>),
    /// Resolve and evaluate another policy by SAID.
    Policy(cesr::Digest),
}

impl PolicyNode {
    /// Compact this node by stripping delegate specifics.
    /// `delegate(DELEGATOR, DELEGATE)` becomes `delegate(DELEGATOR)` —
    /// represented as `Delegate(delegator, default)` with a default digest.
    pub fn compact(&self) -> Self {
        match self {
            PolicyNode::Endorse(prefix) => PolicyNode::Endorse(*prefix),
            PolicyNode::Delegate(delegator, _) => {
                PolicyNode::Delegate(*delegator, cesr::Digest::default())
            }
            PolicyNode::Weighted(min_weight, pairs) => PolicyNode::Weighted(
                *min_weight,
                pairs
                    .iter()
                    .map(|(node, weight)| (node.compact(), *weight))
                    .collect(),
            ),
            PolicyNode::Policy(said) => PolicyNode::Policy(*said),
        }
    }
}

impl fmt::Display for PolicyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyNode::Endorse(prefix) => write!(f, "endorse({prefix})"),
            PolicyNode::Delegate(delegator, delegate) => {
                if *delegate == cesr::Digest::default() {
                    write!(f, "delegate({delegator})")
                } else {
                    write!(f, "delegate({delegator}, {delegate})")
                }
            }
            PolicyNode::Weighted(min_weight, pairs) => {
                // Output as threshold() when all weights are 1 (syntactic sugar round-trip)
                let all_unit_weight = pairs.iter().all(|(_, w)| *w == 1);
                if all_unit_weight {
                    write!(f, "threshold({min_weight}, [")?;
                    for (i, (node, _)) in pairs.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{node}")?;
                    }
                    write!(f, "])")
                } else {
                    write!(f, "weighted({min_weight}, [")?;
                    for (i, (node, weight)) in pairs.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{node}:{weight}")?;
                    }
                    write!(f, "])")
                }
            }
            PolicyNode::Policy(said) => write!(f, "policy({said})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use cesr::Matter;

    use super::*;

    fn digest(s: &str) -> cesr::Digest {
        cesr::Digest::from_qb64(s).unwrap()
    }

    #[test]
    fn test_display_endorse() {
        let node = PolicyNode::Endorse(digest("KBfd1234567890123456789012345678901234567890"));
        assert_eq!(
            node.to_string(),
            "endorse(KBfd1234567890123456789012345678901234567890)"
        );
    }

    #[test]
    fn test_display_delegate() {
        let node = PolicyNode::Delegate(
            digest("KBfd1234567890123456789012345678901234567890"),
            digest("KAbc5678901234567890123456789012345678901234"),
        );
        assert_eq!(
            node.to_string(),
            "delegate(KBfd1234567890123456789012345678901234567890, KAbc5678901234567890123456789012345678901234)"
        );
    }

    #[test]
    fn test_display_delegate_compacted() {
        let node = PolicyNode::Delegate(
            digest("KBfd1234567890123456789012345678901234567890"),
            cesr::Digest::default(),
        );
        assert_eq!(
            node.to_string(),
            "delegate(KBfd1234567890123456789012345678901234567890)"
        );
    }

    #[test]
    fn test_display_threshold() {
        let node = PolicyNode::Weighted(
            2,
            vec![
                (
                    PolicyNode::Endorse(digest("KBfd1234567890123456789012345678901234567890")),
                    1,
                ),
                (
                    PolicyNode::Endorse(digest("KAbc5678901234567890123456789012345678901234")),
                    1,
                ),
                (
                    PolicyNode::Endorse(digest("KCde9012345678901234567890123456789012345678")),
                    1,
                ),
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
                    PolicyNode::Endorse(digest("KBfd1234567890123456789012345678901234567890")),
                    3,
                ),
                (
                    PolicyNode::Endorse(digest("KAbc5678901234567890123456789012345678901234")),
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
        let node = PolicyNode::Policy(digest("KHij3456789012345678901234567890123456789012"));
        assert_eq!(
            node.to_string(),
            "policy(KHij3456789012345678901234567890123456789012)"
        );
    }

    #[test]
    fn test_compact_strips_delegate() {
        let node = PolicyNode::Delegate(
            digest("KBfd1234567890123456789012345678901234567890"),
            digest("KAbc5678901234567890123456789012345678901234"),
        );
        let compacted = node.compact();
        assert_eq!(
            compacted,
            PolicyNode::Delegate(
                digest("KBfd1234567890123456789012345678901234567890"),
                cesr::Digest::default()
            )
        );
    }

    #[test]
    fn test_compact_preserves_endorse() {
        let node = PolicyNode::Endorse(digest("KBfd1234567890123456789012345678901234567890"));
        assert_eq!(node.compact(), node);
    }

    #[test]
    fn test_compact_recursive() {
        let node = PolicyNode::Weighted(
            1,
            vec![
                (
                    PolicyNode::Delegate(
                        digest("KBfd1234567890123456789012345678901234567890"),
                        digest("KAbc5678901234567890123456789012345678901234"),
                    ),
                    1,
                ),
                (
                    PolicyNode::Endorse(digest("KCde9012345678901234567890123456789012345678")),
                    1,
                ),
            ],
        );
        let compacted = node.compact();
        assert_eq!(
            compacted,
            PolicyNode::Weighted(
                1,
                vec![
                    (
                        PolicyNode::Delegate(
                            digest("KBfd1234567890123456789012345678901234567890"),
                            cesr::Digest::default()
                        ),
                        1
                    ),
                    (
                        PolicyNode::Endorse(digest("KCde9012345678901234567890123456789012345678")),
                        1
                    ),
                ]
            )
        );
    }
}
