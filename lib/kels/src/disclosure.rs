//! Disclosure DSL parser.
//!
//! Parses disclosure expressions into a sequence of path tokens that describe
//! which fields to expand or compact. General-purpose — used by both the
//! credential framework (schema-aware) and SADStore (heuristic).

use crate::KelsError;

/// AST node for the disclosure path DSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathToken {
    /// Expand the field at this path (children stay as-is).
    Expand(Vec<String>),
    /// Expand the field at this path and all compactable children recursively.
    /// Empty vec means expand everything from root.
    ExpandRecursive(Vec<String>),
    /// Compact the field at this path (children stay as-is).
    Compact(Vec<String>),
    /// Compact the field at this path and all compactable children recursively.
    /// Empty vec means compact everything from root.
    CompactRecursive(Vec<String>),
}

/// Parse a disclosure DSL expression into a sequence of path tokens.
///
/// Grammar:
/// ```text
/// expression = token (SPACE token)*
/// token      = ["-"] path
/// path       = segment ("." segment)* [".*"]
/// segment    = identifier
/// ```
///
/// Normalization: bare `*` → `.*`, bare `-*` → `-.*`
pub fn parse_disclosure(expr: &str) -> Result<Vec<PathToken>, KelsError> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let mut tokens = Vec::new();
    for raw_token in trimmed.split_whitespace() {
        tokens.push(parse_token(raw_token)?);
    }
    Ok(tokens)
}

fn parse_token(raw: &str) -> Result<PathToken, KelsError> {
    let (negate, path_str) = if let Some(rest) = raw.strip_prefix('-') {
        (true, rest)
    } else {
        (false, raw)
    };

    // Normalize: bare "*" → ".*"
    let normalized = if path_str == "*" { ".*" } else { path_str };

    if normalized.is_empty() {
        return Err(KelsError::InvalidDisclosure(
            "empty path in disclosure expression".to_string(),
        ));
    }

    let (recursive, segment_str) = if let Some(prefix) = normalized.strip_suffix(".*") {
        (true, prefix)
    } else {
        (false, normalized)
    };

    let segments: Vec<String> = if segment_str.is_empty() {
        // This is ".*" or "-.*" — root-level recursive
        vec![]
    } else {
        segment_str
            .split('.')
            .map(|s| {
                if s.is_empty() || s == "*" {
                    return Err(KelsError::InvalidDisclosure(format!(
                        "invalid segment in path: '{}'",
                        normalized
                    )));
                }
                Ok(s.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok(match (negate, recursive) {
        (false, false) => PathToken::Expand(segments),
        (false, true) => PathToken::ExpandRecursive(segments),
        (true, false) => PathToken::Compact(segments),
        (true, true) => PathToken::CompactRecursive(segments),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let tokens = parse_disclosure("").unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_parse_expand_all() {
        let tokens = parse_disclosure(".*").unwrap();
        assert_eq!(tokens, vec![PathToken::ExpandRecursive(vec![])]);
    }

    #[test]
    fn test_parse_bare_star() {
        // * normalizes to .*
        let tokens = parse_disclosure("*").unwrap();
        assert_eq!(tokens, vec![PathToken::ExpandRecursive(vec![])]);
    }

    #[test]
    fn test_parse_compact_all() {
        let tokens = parse_disclosure("-.*").unwrap();
        assert_eq!(tokens, vec![PathToken::CompactRecursive(vec![])]);
    }

    #[test]
    fn test_parse_bare_minus_star() {
        let tokens = parse_disclosure("-*").unwrap();
        assert_eq!(tokens, vec![PathToken::CompactRecursive(vec![])]);
    }

    #[test]
    fn test_parse_simple_expand() {
        let tokens = parse_disclosure("claims").unwrap();
        assert_eq!(tokens, vec![PathToken::Expand(vec!["claims".to_string()])]);
    }

    #[test]
    fn test_parse_nested_expand() {
        let tokens = parse_disclosure("claims.address").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::Expand(vec![
                "claims".to_string(),
                "address".to_string()
            ])]
        );
    }

    #[test]
    fn test_parse_recursive_expand() {
        let tokens = parse_disclosure("claims.*").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::ExpandRecursive(vec!["claims".to_string()])]
        );
    }

    #[test]
    fn test_parse_simple_compact() {
        let tokens = parse_disclosure("-claims").unwrap();
        assert_eq!(tokens, vec![PathToken::Compact(vec!["claims".to_string()])]);
    }

    #[test]
    fn test_parse_recursive_compact() {
        let tokens = parse_disclosure("-claims.*").unwrap();
        assert_eq!(
            tokens,
            vec![PathToken::CompactRecursive(vec!["claims".to_string()])]
        );
    }

    #[test]
    fn test_parse_multiple_tokens() {
        let tokens = parse_disclosure(".* -claims.address").unwrap();
        assert_eq!(
            tokens,
            vec![
                PathToken::ExpandRecursive(vec![]),
                PathToken::Compact(vec!["claims".to_string(), "address".to_string()]),
            ]
        );
    }

    #[test]
    fn test_parse_complex_expression() {
        let tokens = parse_disclosure("schema edges.license.*").unwrap();
        assert_eq!(
            tokens,
            vec![
                PathToken::Expand(vec!["schema".to_string()]),
                PathToken::ExpandRecursive(vec!["edges".to_string(), "license".to_string()]),
            ]
        );
    }

    #[test]
    fn test_parse_invalid_empty_segment() {
        assert!(parse_disclosure("claims..address").is_err());
    }

    #[test]
    fn test_parse_invalid_bare_dash() {
        assert!(parse_disclosure("-").is_err());
    }
}
