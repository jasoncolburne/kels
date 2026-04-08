use cesr::Matter;

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
    let len = *pos - start;
    if len < 2 {
        return Err(PolicyError::ParseError(format!(
            "identifier too short at position {start}: must be at least 2 characters"
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

fn parse_digest(input: &str, pos: &mut usize) -> Result<cesr::Digest, PolicyError> {
    let ident = parse_identifier(input, pos)?;
    cesr::Digest::from_qb64(&ident)
        .map_err(|e| PolicyError::ParseError(format!("invalid CESR digest '{}': {}", ident, e)))
}

fn parse_endorse(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "endorse")?;
    expect_char(input, pos, b'(')?;
    let prefix = parse_digest(input, pos)?;
    expect_char(input, pos, b')')?;
    Ok(PolicyNode::Endorse(prefix))
}

fn parse_delegate(input: &str, pos: &mut usize) -> Result<PolicyNode, PolicyError> {
    consume_keyword(input, pos, "delegate")?;
    expect_char(input, pos, b'(')?;
    let delegator = parse_digest(input, pos)?;

    // Support both full form `delegate(DELEGATOR, DELEGATE)` and
    // compacted form `delegate(DELEGATOR)` (default digest for delegate).
    skip_whitespace(input, pos);
    let delegate = if *pos < input.len() && input.as_bytes()[*pos] == b',' {
        *pos += 1;
        parse_digest(input, pos)?
    } else {
        cesr::Digest::default()
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

    let pairs = children.into_iter().map(|node| (node, 1u64)).collect();
    Ok(PolicyNode::Weighted(min as u64, pairs))
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

    let total_weight: u64 = pairs
        .iter()
        .map(|(_, w)| *w)
        .fold(0u64, u64::saturating_add);
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
    let said = parse_digest(input, pos)?;
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
    use cesr::test_digest;

    use super::*;

    #[test]
    fn test_parse_endorse() {
        let a = test_digest("prefix-a");
        let node = parse(&format!("endorse({a})")).unwrap();
        assert_eq!(node, PolicyNode::Endorse(a));
    }

    #[test]
    fn test_parse_delegate() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let node = parse(&format!("delegate({a}, {b})")).unwrap();
        assert_eq!(node, PolicyNode::Delegate(a, b));
    }

    #[test]
    fn test_parse_threshold() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let node = parse(&format!(
            "threshold(2, [endorse({a}), endorse({b}), endorse({c})])"
        ))
        .unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                2,
                vec![
                    (PolicyNode::Endorse(a), 1),
                    (PolicyNode::Endorse(b), 1),
                    (PolicyNode::Endorse(c), 1),
                ]
            )
        );
    }

    #[test]
    fn test_parse_weighted() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let node = parse(&format!("weighted(5, [endorse({a}):3, endorse({b}):2])")).unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                5,
                vec![(PolicyNode::Endorse(a), 3), (PolicyNode::Endorse(b), 2),]
            )
        );
    }

    #[test]
    fn test_parse_policy_ref() {
        let s = test_digest("said-a");
        let node = parse(&format!("policy({s})")).unwrap();
        assert_eq!(node, PolicyNode::Policy(s));
    }

    #[test]
    fn test_parse_nested() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let s = test_digest("said-a");
        let expr = format!(
            "threshold(2, [endorse({a}), weighted(3, [endorse({b}):2, endorse({c}):1]), policy({s})])"
        );
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                2,
                vec![
                    (PolicyNode::Endorse(a), 1),
                    (
                        PolicyNode::Weighted(
                            3,
                            vec![(PolicyNode::Endorse(b), 2), (PolicyNode::Endorse(c), 1),]
                        ),
                        1
                    ),
                    (PolicyNode::Policy(s), 1),
                ]
            )
        );
    }

    #[test]
    fn test_canonicalize_roundtrip() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let expr = format!("threshold( 2 , [ endorse( {a} ) , endorse( {b} ) , endorse( {c} ) ] )");
        let canonical = canonicalize(&expr).unwrap();
        let canonical2 = canonicalize(&canonical).unwrap();
        assert_eq!(canonical, canonical2);
    }

    #[test]
    fn test_parse_whitespace_tolerance() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let expr = format!("  threshold(  2  ,  [  endorse( {a} )  ,  endorse( {b} )  ]  )  ");
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                2,
                vec![(PolicyNode::Endorse(a), 1), (PolicyNode::Endorse(b), 1),]
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
        let a = test_digest("prefix-a");
        assert!(parse(&format!("endorse({a}) extra")).is_err());
    }

    #[test]
    fn test_parse_threshold_min_zero() {
        let a = test_digest("prefix-a");
        assert!(parse(&format!("threshold(0, [endorse({a})])")).is_err());
    }

    #[test]
    fn test_parse_threshold_min_exceeds_children() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        assert!(parse(&format!("threshold(3, [endorse({a}), endorse({b})])")).is_err());
    }

    #[test]
    fn test_parse_threshold_empty_list() {
        assert!(parse("threshold(1, [])").is_err());
    }

    #[test]
    fn test_parse_weighted_min_zero() {
        let a = test_digest("prefix-a");
        assert!(parse(&format!("weighted(0, [endorse({a}):1])")).is_err());
    }

    #[test]
    fn test_parse_weighted_min_exceeds_total() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        assert!(parse(&format!("weighted(10, [endorse({a}):3, endorse({b}):2])")).is_err());
    }

    #[test]
    fn test_parse_weighted_zero_weight() {
        let a = test_digest("prefix-a");
        assert!(parse(&format!("weighted(1, [endorse({a}):0])")).is_err());
    }

    #[test]
    fn test_parse_weighted_empty_list() {
        assert!(parse("weighted(1, [])").is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let s = test_digest("said-a");
        let node = PolicyNode::Weighted(
            2,
            vec![
                (PolicyNode::Endorse(a), 1),
                (
                    PolicyNode::Weighted(
                        3,
                        vec![(PolicyNode::Endorse(b), 2), (PolicyNode::Endorse(c), 1)],
                    ),
                    1,
                ),
                (PolicyNode::Policy(s), 1),
            ],
        );
        let display = node.to_string();
        let parsed = parse(&display).unwrap();
        assert_eq!(node, parsed);
    }

    #[test]
    fn test_parse_delegate_compacted() {
        let a = test_digest("prefix-a");
        let node = parse(&format!("delegate({a})")).unwrap();
        assert_eq!(node, PolicyNode::Delegate(a, cesr::Digest::default()));
    }

    #[test]
    fn test_compact_delegate_roundtrip() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let node = PolicyNode::Delegate(a, b);
        let compacted = node.compact();
        let display = compacted.to_string();
        let parsed = parse(&display).unwrap();
        assert_eq!(parsed, compacted);
    }

    #[test]
    fn test_parse_weighted_with_nested_nodes() {
        let a = test_digest("prefix-a");
        let b = test_digest("prefix-b");
        let c = test_digest("prefix-c");
        let expr =
            format!("weighted(3, [threshold(1, [endorse({a}), endorse({b})]):2, endorse({c}):1])");
        let node = parse(&expr).unwrap();
        assert_eq!(
            node,
            PolicyNode::Weighted(
                3,
                vec![
                    (
                        PolicyNode::Weighted(
                            1,
                            vec![(PolicyNode::Endorse(a), 1), (PolicyNode::Endorse(b), 1),]
                        ),
                        2
                    ),
                    (PolicyNode::Endorse(c), 1),
                ]
            )
        );
    }
}
