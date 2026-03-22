use crate::{PolicyNode, error::PolicyError};

/// Parse a policy DSL expression into an AST.
pub fn parse(input: &str) -> Result<PolicyNode, PolicyError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(PolicyError::ParseError("empty expression".to_string()));
    }
    let mut pos = 0;
    let node = parse_node(input, &mut pos)?;
    skip_whitespace(input, &mut pos);
    if pos != input.len() {
        return Err(PolicyError::ParseError(format!(
            "unexpected trailing content at position {pos}: '{}'",
            &input[pos..]
        )));
    }
    Ok(node)
}

/// Parse a policy DSL expression and return it in canonical form.
pub fn canonicalize(input: &str) -> Result<String, PolicyError> {
    let node = parse(input)?;
    Ok(node.to_string())
}

fn skip_whitespace(input: &str, pos: &mut usize) {
    while *pos < input.len() && input.as_bytes()[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn expect_char(input: &str, pos: &mut usize, expected: u8) -> Result<(), PolicyError> {
    skip_whitespace(input, pos);
    if *pos >= input.len() || input.as_bytes()[*pos] != expected {
        let found = if *pos >= input.len() {
            "end of input".to_string()
        } else {
            format!("'{}'", input.as_bytes()[*pos] as char)
        };
        return Err(PolicyError::ParseError(format!(
            "expected '{}' at position {}, found {found}",
            expected as char, *pos
        )));
    }
    *pos += 1;
    Ok(())
}

fn parse_identifier(input: &str, pos: &mut usize) -> Result<String, PolicyError> {
    skip_whitespace(input, pos);
    let start = *pos;
    while *pos < input.len() {
        let c = input.as_bytes()[*pos];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            *pos += 1;
        } else {
            break;
        }
    }
    if *pos == start {
        return Err(PolicyError::ParseError(format!(
            "expected identifier at position {start}"
        )));
    }
    Ok(input[start..*pos].to_string())
}

fn parse_number<T: std::str::FromStr>(input: &str, pos: &mut usize) -> Result<T, PolicyError> {
    skip_whitespace(input, pos);
    let start = *pos;
    while *pos < input.len() && input.as_bytes()[*pos].is_ascii_digit() {
        *pos += 1;
    }
    if *pos == start {
        return Err(PolicyError::ParseError(format!(
            "expected number at position {start}"
        )));
    }
    input[start..*pos].parse::<T>().map_err(|_| {
        PolicyError::ParseError(format!(
            "invalid number '{}' at position {start}",
            &input[start..*pos]
        ))
    })
}

fn peek_keyword(input: &str, pos: &mut usize) -> Option<String> {
    skip_whitespace(input, pos);
    let start = *pos;
    let mut end = start;
    while end < input.len() && input.as_bytes()[end].is_ascii_alphabetic() {
        end += 1;
    }
    if end == start {
        return None;
    }
    Some(input[start..end].to_string())
}

fn parse_node(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    let keyword = peek_keyword(input, pos)
        .ok_or_else(|| PolicyError::ParseError(format!("expected keyword at position {pos}")))?;

    match keyword.as_str() {
        "endorse" => parse_endorse(input, pos),
        "delegate" => parse_delegate(input, pos),
        "threshold" => parse_threshold(input, pos),
        "weighted" => parse_weighted(input, pos),
        "policy" => parse_policy(input, pos),
        _ => Err(PolicyError::ParseError(format!(
            "unknown keyword '{keyword}' at position {pos}"
        ))),
    }
}

fn consume_keyword(input: &str, pos: &mut usize, keyword: &str) -> Result<(), PolicyError> {
    skip_whitespace(input, pos);
    let end = *pos + keyword.len();
    if end > input.len() || &input[*pos..end] != keyword {
        return Err(PolicyError::ParseError(format!(
            "expected '{keyword}' at position {pos}"
        )));
    }
    *pos = end;
    Ok(())
}

fn parse_endorse(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "endorse")?;
    expect_char(input, pos, b'(')?;
    let prefix = parse_identifier(input, pos)?;
    expect_char(input, pos, b')')?;
    Ok(PolicyNode::Endorse(prefix))
}

fn parse_delegate(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "delegate")?;
    expect_char(input, pos, b'(')?;
    let delegator = parse_identifier(input, pos)?;

    // Support both full form `delegate(DELEGATOR, DELEGATE)` and
    // compacted form `delegate(DELEGATOR)` (empty delegate string).
    skip_whitespace(input, pos);
    let delegate = if *pos < input.len() && input.as_bytes()[*pos] == b',' {
        *pos += 1;
        parse_identifier(input, pos)?
    } else {
        String::new()
    };

    expect_char(input, pos, b')')?;
    Ok(PolicyNode::Delegate(delegator, delegate))
}

fn parse_threshold(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "threshold")?;
    expect_char(input, pos, b'(')?;
    let min: usize = parse_number(input, pos)?;
    expect_char(input, pos, b',')?;
    let children = parse_node_list(input, pos)?;
    expect_char(input, pos, b')')?;

    if children.is_empty() {
        return Err(PolicyError::ParseError(
            "threshold requires at least one child".to_string(),
        ));
    }
    if min == 0 {
        return Err(PolicyError::ParseError(
            "threshold minimum must be at least 1".to_string(),
        ));
    }
    if min > children.len() {
        return Err(PolicyError::ParseError(format!(
            "threshold minimum ({min}) exceeds child count ({})",
            children.len()
        )));
    }

    Ok(PolicyNode::Threshold(min, children))
}

fn parse_weighted(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "weighted")?;
    expect_char(input, pos, b'(')?;
    let min_weight: u64 = parse_number(input, pos)?;
    expect_char(input, pos, b',')?;
    let pairs = parse_weighted_list(input, pos)?;
    expect_char(input, pos, b')')?;

    if pairs.is_empty() {
        return Err(PolicyError::ParseError(
            "weighted requires at least one child".to_string(),
        ));
    }
    if min_weight == 0 {
        return Err(PolicyError::ParseError(
            "weighted minimum must be at least 1".to_string(),
        ));
    }

    let total_weight: u64 = pairs.iter().map(|(_, w)| w).sum();
    if min_weight > total_weight {
        return Err(PolicyError::ParseError(format!(
            "weighted minimum ({min_weight}) exceeds total weight ({total_weight})"
        )));
    }

    Ok(PolicyNode::Weighted(min_weight, pairs))
}

fn parse_policy(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "policy")?;
    expect_char(input, pos, b'(')?;
    let said = parse_identifier(input, pos)?;
    expect_char(input, pos, b')')?;
    Ok(PolicyNode::Policy(said))
}

fn parse_node_list(input: &str, pos: &mut usize) -> Result<Vec<PolicyNode>, PolicyError> {
    expect_char(input, pos, b'[')?;
    let mut nodes = Vec::new();

    skip_whitespace(input, pos);
    if *pos < input.len() && input.as_bytes()[*pos] == b']' {
        *pos += 1;
        return Ok(nodes);
    }

    nodes.push(parse_node(input, pos)?);
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input.as_bytes()[*pos] == b']' {
            *pos += 1;
            return Ok(nodes);
        }
        expect_char(input, pos, b',')?;
        nodes.push(parse_node(input, pos)?);
    }
}

fn parse_weighted_list(
    input: &str,
    pos: &mut usize,
) -> Result<Vec<(PolicyNode, u64)>, PolicyError> {
    expect_char(input, pos, b'[')?;
    let mut pairs = Vec::new();

    skip_whitespace(input, pos);
    if *pos < input.len() && input.as_bytes()[*pos] == b']' {
        *pos += 1;
        return Ok(pairs);
    }

    pairs.push(parse_weighted_item(input, pos)?);
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input.as_bytes()[*pos] == b']' {
            *pos += 1;
            return Ok(pairs);
        }
        expect_char(input, pos, b',')?;
        pairs.push(parse_weighted_item(input, pos)?);
    }
}

fn parse_weighted_item(input: &str, pos: &mut usize) -> Result<(PolicyNode, u64), PolicyError> {
    let node = parse_node(input, pos)?;
    expect_char(input, pos, b':')?;
    let weight: u64 = parse_number(input, pos)?;
    if weight == 0 {
        return Err(PolicyError::ParseError(
            "weight must be at least 1".to_string(),
        ));
    }
    Ok((node, weight))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX_A: &str = "KBfd1234567890123456789012345678901234567890";
    const PREFIX_B: &str = "KAbc5678901234567890123456789012345678901234";
    const PREFIX_C: &str = "KCde9012345678901234567890123456789012345678";
    const SAID_A: &str = "KHij3456789012345678901234567890123456789012";

    #[test]
    fn test_parse_endorse() {
        let node = parse(&format!("endorse({PREFIX_A})")).unwrap();
        assert_eq!(node, PolicyNode::Endorse(PREFIX_A.to_string()));
    }

    #[test]
    fn test_parse_delegate() {
        let node = parse(&format!("delegate({PREFIX_A}, {PREFIX_B})")).unwrap();
        assert_eq!(
            node,
            PolicyNode::Delegate(PREFIX_A.to_string(), PREFIX_B.to_string())
        );
    }

    #[test]
    fn test_parse_threshold() {
        let node = parse(&format!(
            "threshold(2, [endorse({PREFIX_A}), endorse({PREFIX_B}), endorse({PREFIX_C})])"
        ))
        .unwrap();
        assert_eq!(
            node,
            PolicyNode::Threshold(
                2,
                vec![
                    PolicyNode::Endorse(PREFIX_A.to_string()),
                    PolicyNode::Endorse(PREFIX_B.to_string()),
                    PolicyNode::Endorse(PREFIX_C.to_string()),
                ]
            )
        );
    }

    #[test]
    fn test_parse_weighted() {
        let node = parse(&format!(
            "weighted(5, [endorse({PREFIX_A}):3, endorse({PREFIX_B}):2])"
        ))
        .unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                5,
                vec![
                    (PolicyNode::Endorse(PREFIX_A.to_string()), 3),
                    (PolicyNode::Endorse(PREFIX_B.to_string()), 2),
                ]
            )
        );
    }

    #[test]
    fn test_parse_policy_ref() {
        let node = parse(&format!("policy({SAID_A})")).unwrap();
        assert_eq!(node, PolicyNode::Policy(SAID_A.to_string()));
    }

    #[test]
    fn test_parse_nested() {
        let expr = format!(
            "threshold(2, [endorse({PREFIX_A}), weighted(3, [endorse({PREFIX_B}):2, endorse({PREFIX_C}):1]), policy({SAID_A})])"
        );
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Threshold(
                2,
                vec![
                    PolicyNode::Endorse(PREFIX_A.to_string()),
                    PolicyNode::Weighted(
                        3,
                        vec![
                            (PolicyNode::Endorse(PREFIX_B.to_string()), 2),
                            (PolicyNode::Endorse(PREFIX_C.to_string()), 1),
                        ]
                    ),
                    PolicyNode::Policy(SAID_A.to_string()),
                ]
            )
        );
    }

    #[test]
    fn test_canonicalize_roundtrip() {
        let expr = format!(
            "threshold( 2 , [ endorse( {PREFIX_A} ) , endorse( {PREFIX_B} ) , endorse( {PREFIX_C} ) ] )"
        );
        let canonical = canonicalize(&expr).unwrap();
        let canonical2 = canonicalize(&canonical).unwrap();
        assert_eq!(canonical, canonical2);
    }

    #[test]
    fn test_parse_whitespace_tolerance() {
        let expr = format!(
            "  threshold(  2  ,  [  endorse( {PREFIX_A} )  ,  endorse( {PREFIX_B} )  ]  )  "
        );
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Threshold(
                2,
                vec![
                    PolicyNode::Endorse(PREFIX_A.to_string()),
                    PolicyNode::Endorse(PREFIX_B.to_string()),
                ]
            )
        );
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse("").is_err());
    }

    #[test]
    fn test_parse_unknown_keyword() {
        assert!(parse("unknown(foo)").is_err());
    }

    #[test]
    fn test_parse_trailing_content() {
        let expr = format!("endorse({PREFIX_A}) extra");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_threshold_min_zero() {
        let expr = format!("threshold(0, [endorse({PREFIX_A})])");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_threshold_min_exceeds_children() {
        let expr = format!("threshold(3, [endorse({PREFIX_A}), endorse({PREFIX_B})])");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_threshold_empty_list() {
        assert!(parse("threshold(1, [])").is_err());
    }

    #[test]
    fn test_parse_weighted_min_zero() {
        let expr = format!("weighted(0, [endorse({PREFIX_A}):1])");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_weighted_min_exceeds_total() {
        let expr = format!("weighted(10, [endorse({PREFIX_A}):3, endorse({PREFIX_B}):2])");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_weighted_zero_weight() {
        let expr = format!("weighted(1, [endorse({PREFIX_A}):0])");
        assert!(parse(&expr).is_err());
    }

    #[test]
    fn test_parse_weighted_empty_list() {
        assert!(parse("weighted(1, [])").is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        let node = PolicyNode::Threshold(
            2,
            vec![
                PolicyNode::Endorse(PREFIX_A.to_string()),
                PolicyNode::Weighted(
                    3,
                    vec![
                        (PolicyNode::Endorse(PREFIX_B.to_string()), 2),
                        (PolicyNode::Endorse(PREFIX_C.to_string()), 1),
                    ],
                ),
                PolicyNode::Policy(SAID_A.to_string()),
            ],
        );
        let display = node.to_string();
        let parsed = parse(&display).unwrap();
        assert_eq!(node, parsed);
    }

    #[test]
    fn test_parse_delegate_compacted() {
        let node = parse(&format!("delegate({PREFIX_A})")).unwrap();
        assert_eq!(
            node,
            PolicyNode::Delegate(PREFIX_A.to_string(), String::new())
        );
    }

    #[test]
    fn test_compact_delegate_roundtrip() {
        let node = PolicyNode::Delegate(PREFIX_A.to_string(), PREFIX_B.to_string());
        let compacted = node.compact();
        let display = compacted.to_string();
        let parsed = parse(&display).unwrap();
        assert_eq!(parsed, compacted);
    }

    #[test]
    fn test_parse_weighted_with_nested_nodes() {
        let expr = format!(
            "weighted(3, [threshold(1, [endorse({PREFIX_A}), endorse({PREFIX_B})]):2, endorse({PREFIX_C}):1])"
        );
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                3,
                vec![
                    (
                        PolicyNode::Threshold(
                            1,
                            vec![
                                PolicyNode::Endorse(PREFIX_A.to_string()),
                                PolicyNode::Endorse(PREFIX_B.to_string()),
                            ]
                        ),
                        2
                    ),
                    (PolicyNode::Endorse(PREFIX_C.to_string()), 1),
                ]
            )
        );
    }
}
