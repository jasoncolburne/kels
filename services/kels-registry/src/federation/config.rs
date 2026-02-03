//! Federation configuration types.

use super::types::{FederationError, FederationNodeId};
use serde::{Deserialize, Serialize};

/// A federation member (registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMember {
    /// Registry identity prefix (KEL prefix).
    pub prefix: String,
    /// Registry HTTP URL.
    pub url: String,
}

/// Federation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// This registry's identity prefix.
    pub self_prefix: String,
    /// All federation members (including self).
    /// Order determines node ID (index = node_id).
    pub members: Vec<FederationMember>,
}

impl FederationConfig {
    /// Create a new federation configuration.
    pub fn new(self_prefix: String, members: Vec<FederationMember>) -> Self {
        Self {
            self_prefix,
            members,
        }
    }

    /// Load federation configuration from environment variables.
    ///
    /// Environment variables:
    /// - `FEDERATION_SELF_PREFIX`: This registry's prefix
    /// - `FEDERATION_MEMBERS`: Comma-separated list of "prefix=url" pairs
    pub fn from_env() -> Result<Option<Self>, FederationError> {
        let self_prefix = match std::env::var("FEDERATION_SELF_PREFIX") {
            Ok(p) if !p.is_empty() => p,
            _ => return Ok(None), // Federation not configured
        };

        let members_str = match std::env::var("FEDERATION_MEMBERS") {
            Ok(s) if !s.is_empty() => s,
            _ => return Ok(None), // Federation not configured
        };

        let members = parse_members(&members_str)?;

        if members.is_empty() {
            return Ok(None); // Federation not configured
        }

        // Verify self_prefix is in members
        if !members.iter().any(|m| m.prefix == self_prefix) {
            return Err(FederationError::ConfigError(format!(
                "FEDERATION_SELF_PREFIX '{}' not found in FEDERATION_MEMBERS",
                self_prefix
            )));
        }

        Ok(Some(Self::new(self_prefix, members)))
    }

    /// Get this node's Raft node ID.
    pub fn self_node_id(&self) -> Result<FederationNodeId, FederationError> {
        self.members
            .iter()
            .position(|m| m.prefix == self.self_prefix)
            .map(|i| i as FederationNodeId)
            .ok_or_else(|| {
                FederationError::ConfigError(format!(
                    "Self prefix '{}' not found in members",
                    self.self_prefix
                ))
            })
    }

    /// Get member by node ID.
    pub fn member_by_id(&self, node_id: FederationNodeId) -> Option<&FederationMember> {
        self.members.get(node_id as usize)
    }

    /// Get member by prefix.
    pub fn member_by_prefix(&self, prefix: &str) -> Option<&FederationMember> {
        self.members.iter().find(|m| m.prefix == prefix)
    }

    /// Check if a prefix is a federation member.
    pub fn is_member(&self, prefix: &str) -> bool {
        self.members.iter().any(|m| m.prefix == prefix)
    }
}

/// Parse members from environment variable format.
/// Format: "prefix1=url1,prefix2=url2,..."
fn parse_members(members_str: &str) -> Result<Vec<FederationMember>, FederationError> {
    let mut members = Vec::new();

    for part in members_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (prefix, url) = part.split_once('=').ok_or_else(|| {
            FederationError::ConfigError(format!(
                "Invalid member format '{}'. Expected 'prefix=url'",
                part
            ))
        })?;

        members.push(FederationMember {
            prefix: prefix.trim().to_string(),
            url: url.trim().to_string(),
        });
    }

    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_members() {
        let members =
            parse_members("ERegistryA=https://a.example.com,ERegistryB=https://b.example.com")
                .unwrap();

        assert_eq!(members.len(), 2);
        assert_eq!(members[0].prefix, "ERegistryA");
        assert_eq!(members[0].url, "https://a.example.com");
        assert_eq!(members[1].prefix, "ERegistryB");
        assert_eq!(members[1].url, "https://b.example.com");
    }

    #[test]
    fn test_parse_members_with_spaces() {
        let members = parse_members(
            " ERegistryA = https://a.example.com , ERegistryB = https://b.example.com ",
        )
        .unwrap();

        assert_eq!(members.len(), 2);
        assert_eq!(members[0].prefix, "ERegistryA");
        assert_eq!(members[1].prefix, "ERegistryB");
    }

    #[test]
    fn test_parse_members_invalid_format() {
        let result = parse_members("invalid_member_without_equals");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_self_node_id() {
        let config = FederationConfig::new(
            "ERegistryB".to_string(),
            vec![
                FederationMember {
                    prefix: "ERegistryA".to_string(),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    prefix: "ERegistryB".to_string(),
                    url: "https://b.example.com".to_string(),
                },
                FederationMember {
                    prefix: "ERegistryC".to_string(),
                    url: "https://c.example.com".to_string(),
                },
            ],
        );

        assert_eq!(config.self_node_id().unwrap(), 1);
    }

    #[test]
    fn test_config_member_by_id() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![
                FederationMember {
                    prefix: "ERegistryA".to_string(),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    prefix: "ERegistryB".to_string(),
                    url: "https://b.example.com".to_string(),
                },
            ],
        );

        let member = config.member_by_id(1).unwrap();
        assert_eq!(member.prefix, "ERegistryB");
    }

    #[test]
    fn test_config_is_member() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![FederationMember {
                prefix: "ERegistryA".to_string(),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.is_member("ERegistryA"));
        assert!(!config.is_member("ERegistryUnknown"));
    }

    #[test]
    fn test_parse_members_empty_string() {
        let members = parse_members("").unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn test_parse_members_whitespace_only() {
        let members = parse_members("   ,  , ").unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn test_config_member_by_id_out_of_bounds() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![FederationMember {
                prefix: "ERegistryA".to_string(),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.member_by_id(999).is_none());
    }

    #[test]
    fn test_config_member_by_prefix_not_found() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![FederationMember {
                prefix: "ERegistryA".to_string(),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.member_by_prefix("ERegistryUnknown").is_none());
    }

    #[test]
    fn test_config_member_by_prefix_found() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![
                FederationMember {
                    prefix: "ERegistryA".to_string(),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    prefix: "ERegistryB".to_string(),
                    url: "https://b.example.com".to_string(),
                },
            ],
        );

        let member = config.member_by_prefix("ERegistryB").unwrap();
        assert_eq!(member.url, "https://b.example.com");
    }

    #[test]
    fn test_config_self_node_id_not_found() {
        let config = FederationConfig::new(
            "ERegistryNotInList".to_string(),
            vec![FederationMember {
                prefix: "ERegistryA".to_string(),
                url: "https://a.example.com".to_string(),
            }],
        );

        let result = config.self_node_id();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_members_single_member() {
        let members = parse_members("ERegistryA=https://a.example.com").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].prefix, "ERegistryA");
        assert_eq!(members[0].url, "https://a.example.com");
    }

    #[test]
    fn test_federation_member_clone() {
        let member = FederationMember {
            prefix: "ERegistryA".to_string(),
            url: "https://a.example.com".to_string(),
        };
        let cloned = member.clone();
        assert_eq!(cloned.prefix, member.prefix);
        assert_eq!(cloned.url, member.url);
    }

    #[test]
    fn test_federation_config_clone() {
        let config = FederationConfig::new(
            "ERegistryA".to_string(),
            vec![FederationMember {
                prefix: "ERegistryA".to_string(),
                url: "https://a.example.com".to_string(),
            }],
        );
        let cloned = config.clone();
        assert_eq!(cloned.self_prefix, config.self_prefix);
        assert_eq!(cloned.members.len(), config.members.len());
    }
}
