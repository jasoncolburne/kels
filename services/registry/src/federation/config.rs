//! Federation configuration types.

use std::collections::{HashMap, HashSet};

use cesr::Matter;
use serde::{Deserialize, Serialize};
use serde_json;

use super::types::{FederationError, FederationNodeId};

/// Trusted registry members - MUST be set at compile time.
/// Format: JSON array of objects with `id`, `prefix`, and `active` fields.
/// Used for federation membership with explicit Raft node IDs.
const TRUSTED_REGISTRY_MEMBERS: &str = env!("TRUSTED_REGISTRY_MEMBERS");

/// A trusted registry member parsed from compile-time JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustedMember {
    id: FederationNodeId,
    prefix: cesr::Digest,
    active: bool,
}

/// A federation member (registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMember {
    /// Explicit Raft node ID.
    pub id: FederationNodeId,
    /// Registry identity prefix (KEL prefix).
    pub prefix: cesr::Digest,
    /// Registry HTTP URL.
    pub url: String,
}

/// Federation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// This registry's identity prefix.
    pub self_prefix: cesr::Digest,
    /// Active federation members (including self).
    pub members: Vec<FederationMember>,
    /// All trusted prefixes (active + inactive), for historical verification.
    pub trusted_prefixes: Vec<cesr::Digest>,
}

impl FederationConfig {
    /// Create a new federation configuration.
    pub fn new(
        self_prefix: cesr::Digest,
        members: Vec<FederationMember>,
        trusted_prefixes: Vec<cesr::Digest>,
    ) -> Self {
        Self {
            self_prefix,
            members,
            trusted_prefixes,
        }
    }

    /// Load federation configuration from environment and compile-time constants.
    ///
    /// Compile-time (security - who to trust):
    /// - `TRUSTED_REGISTRY_MEMBERS`: JSON array of `{id, prefix}` objects
    ///
    /// Runtime (operational - connectivity):
    /// - `FEDERATION_SELF_PREFIX`: This registry's prefix
    /// - `FEDERATION_URLS`: Comma-separated list of "prefix=url" pairs
    pub fn from_env() -> Result<Option<Self>, FederationError> {
        // Parse compile-time trusted members (JSON)
        let trusted_members: Vec<TrustedMember> = serde_json::from_str(TRUSTED_REGISTRY_MEMBERS)
            .map_err(|e| {
                FederationError::ConfigError(format!(
                    "Failed to parse TRUSTED_REGISTRY_MEMBERS: {}",
                    e
                ))
            })?;

        // If no trusted members compiled in, federation is not configured
        if trusted_members.is_empty() {
            return Ok(None);
        }

        let self_prefix_str = match std::env::var("FEDERATION_SELF_PREFIX") {
            Ok(p) if !p.is_empty() => p,
            _ => return Ok(None), // Federation not configured
        };
        let self_prefix = cesr::Digest::from_qb64(&self_prefix_str).map_err(|e| {
            FederationError::ConfigError(format!(
                "Invalid CESR digest for FEDERATION_SELF_PREFIX '{}': {}",
                self_prefix_str, e
            ))
        })?;

        // Validate no duplicate IDs across all entries (active + inactive)
        let mut seen_ids = HashSet::new();
        for tm in &trusted_members {
            if !seen_ids.insert(tm.id) {
                return Err(FederationError::ConfigError(format!(
                    "Duplicate federation member ID: {}",
                    tm.id
                )));
            }
        }

        // If our prefix isn't in the trusted set, we're in standalone mode
        let self_member = trusted_members.iter().find(|m| m.prefix == self_prefix);
        match self_member {
            None => return Ok(None),
            Some(m) if !m.active => {
                return Err(FederationError::ConfigError(format!(
                    "Self prefix '{}' is marked inactive",
                    self_prefix
                )));
            }
            _ => {}
        }

        // Collect all trusted prefixes (active + inactive)
        let trusted_prefixes: Vec<cesr::Digest> =
            trusted_members.iter().map(|m| m.prefix.clone()).collect();

        // Parse runtime URLs
        let urls_str = match std::env::var("FEDERATION_URLS") {
            Ok(s) if !s.is_empty() => s,
            _ => return Ok(None), // Federation not configured
        };

        let url_map = parse_urls(&urls_str)?;

        // Build members list from active trusted members + runtime URLs
        let mut members = Vec::new();
        for tm in &trusted_members {
            if !tm.active {
                continue;
            }
            let prefix_str: &str = tm.prefix.as_ref();
            let url = url_map.get(prefix_str).ok_or_else(|| {
                FederationError::ConfigError(format!(
                    "No URL provided for trusted prefix '{}' in FEDERATION_URLS",
                    tm.prefix
                ))
            })?;
            members.push(FederationMember {
                id: tm.id,
                prefix: tm.prefix.clone(),
                url: url.clone(),
            });
        }

        Ok(Some(Self::new(self_prefix, members, trusted_prefixes)))
    }

    /// Get this node's Raft node ID.
    pub fn self_node_id(&self) -> Result<FederationNodeId, FederationError> {
        self.members
            .iter()
            .find(|m| m.prefix == self.self_prefix)
            .map(|m| m.id)
            .ok_or_else(|| {
                FederationError::ConfigError(format!(
                    "Self prefix '{}' not found in members",
                    self.self_prefix
                ))
            })
    }

    /// Get member by node ID.
    pub fn member_by_id(&self, node_id: FederationNodeId) -> Option<&FederationMember> {
        self.members.iter().find(|m| m.id == node_id)
    }

    /// Get member by prefix.
    pub fn member_by_prefix(&self, prefix: &str) -> Option<&FederationMember> {
        self.members.iter().find(|m| m.prefix.as_ref() == prefix)
    }

    /// Check if a prefix is an active federation member.
    pub fn is_member(&self, prefix: &str) -> bool {
        self.members.iter().any(|m| m.prefix.as_ref() == prefix)
    }

    /// Check if a prefix is a trusted prefix (active or inactive).
    pub fn is_trusted_prefix(&self, prefix: &str) -> bool {
        self.trusted_prefixes.iter().any(|p| p.as_ref() == prefix)
    }

    /// Calculate approval threshold for peer proposals.
    ///
    /// Inspired by KERI's immunity constraint (M = F+1, F = (N-1)/3), adapted
    /// with judgement to require unanimity in small federations and a smooth
    /// transition toward ceil(n/3) at scale. Minimum threshold is always 3
    /// to prevent trivial collusion.
    ///
    /// - n in [0,5]:  3
    /// - n in [6,9]:  4
    /// - n >= 10:     ceil(n/3)
    pub fn approval_threshold(&self) -> usize {
        Self::compute_approval_threshold(self.members.len())
    }

    /// Compute approval threshold from member count.
    /// Usable without a full config (e.g., from CLI with federation status).
    pub fn compute_approval_threshold(n: usize) -> usize {
        kels_core::compute_approval_threshold(n)
    }

    /// Get all member prefixes.
    pub fn member_prefixes(&self) -> Vec<cesr::Digest> {
        self.members.iter().map(|m| m.prefix.clone()).collect()
    }
}

/// Parse URLs from environment variable format.
/// Format: "prefix1=url1,prefix2=url2,..."
fn parse_urls(urls_str: &str) -> Result<HashMap<String, String>, FederationError> {
    let mut urls = HashMap::new();

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

    fn digest(name: &str) -> cesr::Digest {
        cesr::Digest::blake3_256(name.as_bytes())
    }

    /// Helper to build a config where all members are also trusted prefixes.
    fn make_config(self_prefix: &str, members: Vec<FederationMember>) -> FederationConfig {
        let trusted_prefixes = members.iter().map(|m| m.prefix.clone()).collect();
        FederationConfig::new(digest(self_prefix), members, trusted_prefixes)
    }

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
        let config = make_config(
            "ERegistryB",
            vec![
                FederationMember {
                    id: 0,
                    prefix: digest("ERegistryA"),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    id: 1,
                    prefix: digest("ERegistryB"),
                    url: "https://b.example.com".to_string(),
                },
                FederationMember {
                    id: 2,
                    prefix: digest("ERegistryC"),
                    url: "https://c.example.com".to_string(),
                },
            ],
        );

        assert_eq!(config.self_node_id().unwrap(), 1);
    }

    #[test]
    fn test_config_member_by_id() {
        let config = make_config(
            "ERegistryA",
            vec![
                FederationMember {
                    id: 0,
                    prefix: digest("ERegistryA"),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    id: 1,
                    prefix: digest("ERegistryB"),
                    url: "https://b.example.com".to_string(),
                },
            ],
        );

        let member = config.member_by_id(1).unwrap();
        assert_eq!(member.prefix, digest("ERegistryB"));
    }

    #[test]
    fn test_config_is_member() {
        let config = make_config(
            "ERegistryA",
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.is_member(digest("ERegistryA").as_ref()));
        assert!(!config.is_member(digest("ERegistryUnknown").as_ref()));
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
        let config = make_config(
            "ERegistryA",
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.member_by_id(999).is_none());
    }

    #[test]
    fn test_config_member_by_prefix_not_found() {
        let config = make_config(
            "ERegistryA",
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
        );

        assert!(config.member_by_prefix("ERegistryUnknown").is_none());
    }

    #[test]
    fn test_config_member_by_prefix_found() {
        let config = make_config(
            "ERegistryA",
            vec![
                FederationMember {
                    id: 0,
                    prefix: digest("ERegistryA"),
                    url: "https://a.example.com".to_string(),
                },
                FederationMember {
                    id: 1,
                    prefix: digest("ERegistryB"),
                    url: "https://b.example.com".to_string(),
                },
            ],
        );

        let member = config
            .member_by_prefix(digest("ERegistryB").as_ref())
            .unwrap();
        assert_eq!(member.url, "https://b.example.com");
    }

    #[test]
    fn test_config_self_node_id_not_found() {
        let config = make_config(
            "ERegistryNotInList",
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
        );

        // self_node_id() still errors — standalone detection happens in from_env()
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
            id: 0,
            prefix: digest("ERegistryA"),
            url: "https://a.example.com".to_string(),
        };
        let cloned = member.clone();
        assert_eq!(cloned.id, member.id);
        assert_eq!(cloned.prefix, member.prefix);
        assert_eq!(cloned.url, member.url);
    }

    #[test]
    fn test_federation_config_clone() {
        let config = make_config(
            "ERegistryA",
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
        );
        let cloned = config.clone();
        assert_eq!(cloned.self_prefix, config.self_prefix);
        assert_eq!(cloned.members.len(), config.members.len());
    }

    fn make_members(count: usize) -> Vec<FederationMember> {
        (0..count)
            .map(|i| FederationMember {
                id: i as u64,
                prefix: digest(&format!("ERegistry{}", i)),
                url: format!("https://registry{}.example.com", i),
            })
            .collect()
    }

    fn make_prefixes(count: usize) -> Vec<cesr::Digest> {
        (0..count)
            .map(|i| digest(&format!("ERegistry{}", i)))
            .collect()
    }

    #[test]
    fn test_approval_threshold_empty() {
        let config = FederationConfig::new(digest("ERegistry0"), vec![], vec![]);
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_1_member() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(1), make_prefixes(1));
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_2_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(2), make_prefixes(2));
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_3_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(3), make_prefixes(3));
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_4_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(4), make_prefixes(4));
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_5_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(5), make_prefixes(5));
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_approval_threshold_6_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(6), make_prefixes(6));
        assert_eq!(config.approval_threshold(), 4);
    }

    #[test]
    fn test_approval_threshold_7_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(7), make_prefixes(7));
        assert_eq!(config.approval_threshold(), 4);
    }

    #[test]
    fn test_approval_threshold_9_members() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(9), make_prefixes(9));
        assert_eq!(config.approval_threshold(), 4);
    }

    #[test]
    fn test_approval_threshold_10_members() {
        let config =
            FederationConfig::new(digest("ERegistry0"), make_members(10), make_prefixes(10));
        assert_eq!(config.approval_threshold(), 4);
    }

    #[test]
    fn test_approval_threshold_20_members() {
        let config =
            FederationConfig::new(digest("ERegistry0"), make_members(20), make_prefixes(20));
        assert_eq!(config.approval_threshold(), 7);
    }

    #[test]
    fn test_member_prefixes() {
        let config = FederationConfig::new(digest("ERegistry0"), make_members(3), make_prefixes(3));
        let prefixes = config.member_prefixes();
        assert_eq!(prefixes.len(), 3);
        assert!(prefixes.contains(&digest("ERegistry0")));
        assert!(prefixes.contains(&digest("ERegistry1")));
        assert!(prefixes.contains(&digest("ERegistry2")));
    }

    #[test]
    fn test_inactive_member_not_in_members() {
        // ERegistryB is inactive — only active members in `members`
        let config = FederationConfig::new(
            digest("ERegistryA"),
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
            vec![digest("ERegistryA"), digest("ERegistryB")],
        );

        assert_eq!(config.members.len(), 1);
        assert!(config.is_member(digest("ERegistryA").as_ref()));
        assert!(!config.is_member(digest("ERegistryB").as_ref()));
    }

    #[test]
    fn test_is_trusted_prefix_includes_inactive() {
        let config = FederationConfig::new(
            digest("ERegistryA"),
            vec![FederationMember {
                id: 0,
                prefix: digest("ERegistryA"),
                url: "https://a.example.com".to_string(),
            }],
            vec![digest("ERegistryA"), digest("ERegistryB")],
        );

        assert!(config.is_trusted_prefix(digest("ERegistryA").as_ref()));
        assert!(config.is_trusted_prefix(digest("ERegistryB").as_ref()));
        assert!(!config.is_trusted_prefix(digest("ERegistryUnknown").as_ref()));
    }

    #[test]
    fn test_approval_threshold_counts_active_only() {
        // 3 trusted prefixes but only 2 active members — threshold from active count
        let config = FederationConfig::new(
            digest("ERegistryA"),
            make_members(2),
            vec![
                digest("ERegistry0"),
                digest("ERegistry1"),
                digest("ERegistryInactive"),
            ],
        );

        // 2 active members → threshold 3 (from the 0..=5 bracket)
        assert_eq!(config.approval_threshold(), 3);
    }

    #[test]
    fn test_trusted_member_deserialization_missing_active_rejected() {
        let json = r#"[{"id": 0, "prefix": "KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]"#;
        let result: Result<Vec<TrustedMember>, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_trusted_member_deserialization_inactive() {
        let json = r#"[{"id": 0, "prefix": "KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "active": false}]"#;
        let members: Vec<TrustedMember> = serde_json::from_str(json).unwrap();
        assert!(!members[0].active);
    }

    #[test]
    fn test_trusted_member_deserialization_active() {
        let json = r#"[{"id": 0, "prefix": "KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "active": true}]"#;
        let members: Vec<TrustedMember> = serde_json::from_str(json).unwrap();
        assert!(members[0].active);
    }
}
