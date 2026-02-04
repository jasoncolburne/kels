//! Federation configuration types.

use super::types::{FederationError, FederationNodeId};
use serde::{Deserialize, Serialize};

/// Trusted registry prefixes - MUST be set at compile time.
/// Format: "prefix1,prefix2,..." (comma-separated KELS prefixes)
/// Used for both federation membership and registry verification.
const TRUSTED_REGISTRY_PREFIXES: &str = env!("TRUSTED_REGISTRY_PREFIXES");

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

    /// Load federation configuration from environment and compile-time constants.
    ///
    /// Compile-time (security - who to trust):
    /// - `TRUSTED_FEDERATION_PREFIXES`: Comma-separated list of trusted registry prefixes
    ///
    /// Runtime (operational - connectivity):
    /// - `FEDERATION_SELF_PREFIX`: This registry's prefix
    /// - `FEDERATION_URLS`: Comma-separated list of "prefix=url" pairs
    pub fn from_env() -> Result<Option<Self>, FederationError> {
        // Parse compile-time trusted prefixes
        let trusted_prefixes: Vec<String> = TRUSTED_REGISTRY_PREFIXES
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // If no trusted prefixes compiled in, federation is not configured
        if trusted_prefixes.is_empty() {
            return Ok(None);
        }

        let self_prefix = match std::env::var("FEDERATION_SELF_PREFIX") {
            Ok(p) if !p.is_empty() => p,
            _ => return Ok(None), // Federation not configured
        };

        // Verify self_prefix is in the compiled-in trusted set
        if !trusted_prefixes.contains(&self_prefix) {
            return Err(FederationError::ConfigError(format!(
                "FEDERATION_SELF_PREFIX '{}' not in compiled TRUSTED_FEDERATION_PREFIXES",
                self_prefix
            )));
        }

        // Parse runtime URLs
        let urls_str = match std::env::var("FEDERATION_URLS") {
            Ok(s) if !s.is_empty() => s,
            _ => return Ok(None), // Federation not configured
        };

        let url_map = parse_urls(&urls_str)?;

        // Build members list from trusted prefixes + runtime URLs
        let mut members = Vec::new();
        for prefix in &trusted_prefixes {
            let url = url_map.get(prefix).ok_or_else(|| {
                FederationError::ConfigError(format!(
                    "No URL provided for trusted prefix '{}' in FEDERATION_URLS",
                    prefix
                ))
            })?;
            members.push(FederationMember {
                prefix: prefix.clone(),
                url: url.clone(),
            });
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

/// Parse URLs from environment variable format.
/// Format: "prefix1=url1,prefix2=url2,..."
fn parse_urls(
    urls_str: &str,
) -> Result<std::collections::HashMap<String, String>, FederationError> {
    let mut urls = std::collections::HashMap::new();

    for part in urls_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (prefix, url) = part.split_once('=').ok_or_else(|| {
            FederationError::ConfigError(format!(
                "Invalid URL format '{}'. Expected 'prefix=url'",
                part
            ))
        })?;

        urls.insert(prefix.trim().to_string(), url.trim().to_string());
    }

    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_urls() {
        let urls = parse_urls("ERegistryA=https://a.example.com,ERegistryB=https://b.example.com")
            .unwrap();

        assert_eq!(urls.len(), 2);
        assert_eq!(urls.get("ERegistryA").unwrap(), "https://a.example.com");
        assert_eq!(urls.get("ERegistryB").unwrap(), "https://b.example.com");
    }

    #[test]
    fn test_parse_urls_with_spaces() {
        let urls =
            parse_urls(" ERegistryA = https://a.example.com , ERegistryB = https://b.example.com ")
                .unwrap();

        assert_eq!(urls.len(), 2);
        assert!(urls.contains_key("ERegistryA"));
        assert!(urls.contains_key("ERegistryB"));
    }

    #[test]
    fn test_parse_urls_invalid_format() {
        let result = parse_urls("invalid_url_without_equals");
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
    fn test_parse_urls_empty_string() {
        let urls = parse_urls("").unwrap();
        assert!(urls.is_empty());
    }

    #[test]
    fn test_parse_urls_whitespace_only() {
        let urls = parse_urls("   ,  , ").unwrap();
        assert!(urls.is_empty());
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
    fn test_parse_urls_single_url() {
        let urls = parse_urls("ERegistryA=https://a.example.com").unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls.get("ERegistryA").unwrap(), "https://a.example.com");
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
