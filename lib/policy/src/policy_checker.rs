//! Canonical `PolicyChecker` implementation backed by KEL anchoring.
//!
//! Evaluates policy satisfaction by checking that the endorsers required by
//! the policy have anchored the queried SAID in their KELs.

use std::sync::Arc;

use kels_core::{KelsError, PagedKelSource, PolicyChecker};

use crate::{evaluate_anchored_policy, resolver::PolicyResolver};

/// `PolicyChecker` backed by `evaluate_anchored_policy`.
///
/// `is_anchored(said, policy)` resolves the policy via the configured resolver
/// and checks that the endorsers it names anchored `said` in their KELs. The
/// caller decides which `(said, policy)` pair to evaluate; for chain verifiers
/// that's typically `(event.said, branch_or_event_policy)`.
///
/// `is_immune(policy)` resolves the policy and reports its immunity flag.
///
/// Owns its dependencies via `Arc` so the checker is `'static` and can be
/// stashed in `Arc<dyn PolicyChecker + Send + Sync>` on `SadEventBuilder` or
/// any other type-erased holder. Cloning is cheap (Arc bumps a refcount).
#[derive(Clone)]
pub struct AnchoredPolicyChecker {
    kel_source: Arc<dyn PagedKelSource + Send + Sync>,
    resolver: Arc<dyn PolicyResolver + Send + Sync>,
}

impl AnchoredPolicyChecker {
    pub fn new(
        kel_source: Arc<dyn PagedKelSource + Send + Sync>,
        resolver: Arc<dyn PolicyResolver + Send + Sync>,
    ) -> Self {
        Self {
            kel_source,
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl PolicyChecker for AnchoredPolicyChecker {
    async fn is_anchored(
        &self,
        said: &cesr::Digest256,
        policy: &cesr::Digest256,
    ) -> Result<bool, KelsError> {
        let policy = self
            .resolver
            .resolve_policy(policy)
            .await
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))?;
        match evaluate_anchored_policy(&policy, said, &*self.kel_source, &*self.resolver).await {
            Ok(v) => Ok(v.is_satisfied),
            Err(e) => Err(KelsError::VerificationFailed(e.to_string())),
        }
    }

    async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError> {
        let resolved = self
            .resolver
            .resolve_policy(policy)
            .await
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))?;
        Ok(resolved.is_immune())
    }
}
