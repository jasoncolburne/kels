use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::{Policy, error::PolicyError};

/// Trait for resolving nested policy references by SAID.
#[async_trait]
pub trait PolicyResolver: Sync {
    async fn resolve_policy(&self, said: &str) -> Result<Policy, PolicyError>;
}

/// In-memory policy resolver backed by a BTreeMap.
pub struct InMemoryPolicyResolver {
    policies: BTreeMap<String, Policy>,
}

impl InMemoryPolicyResolver {
    pub fn new(policies: Vec<Policy>) -> Self {
        let map = policies
            .into_iter()
            .map(|p| (p.said.to_string(), p))
            .collect();
        Self { policies: map }
    }

    pub fn empty() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl PolicyResolver for InMemoryPolicyResolver {
    async fn resolve_policy(&self, said: &str) -> Result<Policy, PolicyError> {
        self.policies
            .get(said)
            .cloned()
            .ok_or_else(|| PolicyError::ResolutionError(format!("policy not found: {said}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_resolver() {
        let resolver = InMemoryPolicyResolver::empty();
        let result = resolver.resolve_policy("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_with_policy() {
        let policy = Policy::build(
            "endorse(KBfd1234567890123456789012345678901234567890)",
            None,
            false,
        )
        .unwrap();
        let said = policy.said.to_string();
        let resolver = InMemoryPolicyResolver::new(vec![policy]);
        let resolved = resolver.resolve_policy(&said).await.unwrap();
        assert_eq!(resolved.said.to_string(), said);
    }
}
