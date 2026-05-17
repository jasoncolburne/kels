//! Canonical `PolicyChecker` implementation backed by KEL anchoring.
//!
//! Evaluates policy satisfaction by checking that the endorsers required by
//! the policy have anchored the queried SAID in their KELs.

use std::sync::Arc;

use kels_core::{AnchorEvaluation, IelResolver, KelsError, PagedKelSource, PolicyChecker};

use crate::{evaluate_anchored_policy, resolver::PolicyResolver, verification::EndorsementStatus};

/// `PolicyChecker` backed by `evaluate_anchored_policy`.
///
/// `evaluate(said, policy)` resolves the policy via the configured resolver
/// and checks that the endorsers it names anchored `said` in their KELs. The
/// caller decides which `(said, policy)` pair to evaluate; for chain verifiers
/// that's typically `(event.said, branch_or_event_policy)`.
///
/// `is_immune(policy)` resolves the policy and reports its immunity flag.
///
/// Owns its dependencies via `Arc` so the checker is `'static` and can be
/// stashed in `Arc<dyn PolicyChecker + Send + Sync>` on `SadEventBuilder` or
/// any other type-erased holder. Cloning is cheap (Arc bumps a refcount).
///
/// `iel_resolver` resolves `iel(X)` DSL leaves to the current `authPolicy` of
/// the named IEL `X` (per `docs/design/features/policy.md §Identity Resolution`).
/// Must be a real implementation in production — the evaluator fails loudly
/// on any `iel(...)` leaf the resolver can't resolve.
#[derive(Clone)]
pub struct AnchoredPolicyChecker {
    kel_source: Arc<dyn PagedKelSource + Send + Sync>,
    resolver: Arc<dyn PolicyResolver + Send + Sync>,
    iel_resolver: Arc<dyn IelResolver + Send + Sync>,
}

impl AnchoredPolicyChecker {
    pub fn new(
        kel_source: Arc<dyn PagedKelSource + Send + Sync>,
        resolver: Arc<dyn PolicyResolver + Send + Sync>,
        iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    ) -> Self {
        Self {
            kel_source,
            resolver,
            iel_resolver,
        }
    }
}

#[async_trait::async_trait]
impl PolicyChecker for AnchoredPolicyChecker {
    async fn evaluate(
        &self,
        said: &cesr::Digest256,
        policy: &cesr::Digest256,
    ) -> Result<AnchorEvaluation, KelsError> {
        let policy = self
            .resolver
            .resolve_policy(policy)
            .await
            .map_err(map_policy_error)?;
        let verification = evaluate_anchored_policy(
            &policy,
            said,
            &*self.kel_source,
            &*self.resolver,
            &*self.iel_resolver,
        )
        .await
        .map_err(map_policy_error)?;
        // #156 contract: `missing_anchors` enumerates KEL prefixes whose
        // commitment could flip the policy outcome — i.e., chains where
        // an Ixn anchoring `said` could still land. `NotEndorsed`
        // (chain live, anchor pending) and `KelError` (chain not yet
        // locally known / transient access errors) qualify; `KelPermanentFail`
        // (contested / decommissioned chains, anchor cannot land) is
        // omitted per the AnchorEvaluation contract — including it would
        // cause threshold-multi-chain parks to re-park indefinitely on a
        // contesting chain (the I-N1 failure mode).
        let missing_anchors = if verification.is_satisfied {
            Vec::new()
        } else {
            verification
                .endorsements
                .iter()
                .filter_map(|(prefix, status)| match status {
                    EndorsementStatus::NotEndorsed | EndorsementStatus::KelError(_) => {
                        Some(*prefix)
                    }
                    EndorsementStatus::Endorsed
                    | EndorsementStatus::Poisoned
                    | EndorsementStatus::KelPermanentFail(_) => None,
                })
                .collect()
        };
        Ok(AnchorEvaluation {
            satisfied: verification.is_satisfied,
            missing_anchors,
        })
    }

    async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError> {
        let resolved = self
            .resolver
            .resolve_policy(policy)
            .await
            .map_err(map_policy_error)?;
        Ok(resolved.is_immune())
    }
}

/// #156: lift a [`crate::PolicyError`] to a [`KelsError`] preserving the
/// deferrable [`PolicyError::PolicyNotFound`] case as a structured
/// [`KelsError::MissingSadObject`] (so verifier collect-mode can
/// accumulate as `DeferredFailure::MissingSadObject` instead of halting
/// with a stringified `VerificationFailed`).
fn map_policy_error(e: crate::PolicyError) -> KelsError {
    match e {
        crate::PolicyError::PolicyNotFound { said } => KelsError::missing_sad_object(said),
        other => KelsError::VerificationFailed(other.to_string()),
    }
}
