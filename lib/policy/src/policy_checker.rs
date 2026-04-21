//! Canonical `PolicyChecker` implementation backed by KEL anchoring.
//!
//! Evaluates write_policy satisfaction by checking that the endorsers required
//! by the policy have anchored the record's SAID in their KELs.

use kels_core::{KelsError, PagedKelSource, PolicyChecker, SadPointer};

use crate::{evaluate_anchored_policy, resolver::PolicyResolver};

/// `PolicyChecker` backed by `evaluate_anchored_policy`.
///
/// For v0 inception: resolves the record's `write_policy`, checks that
/// endorsers anchored `record.said` per that policy.
///
/// For v1+ advances: resolves `previous_policy`, checks that endorsers
/// anchored `new_record.said` per the previous policy.
pub struct AnchoredPolicyChecker<'a> {
    kel_source: &'a (dyn PagedKelSource + Sync),
    resolver: &'a (dyn PolicyResolver + Sync),
}

impl<'a> AnchoredPolicyChecker<'a> {
    pub fn new(
        kel_source: &'a (dyn PagedKelSource + Sync),
        resolver: &'a (dyn PolicyResolver + Sync),
    ) -> Self {
        Self {
            kel_source,
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl PolicyChecker for AnchoredPolicyChecker<'_> {
    async fn satisfies(
        &self,
        new_record: &SadPointer,
        previous_policy: &cesr::Digest256,
    ) -> Result<bool, KelsError> {
        let policy = self
            .resolver
            .resolve_policy(previous_policy)
            .await
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))?;
        match evaluate_anchored_policy(&policy, &new_record.said, self.kel_source, self.resolver)
            .await
        {
            Ok(v) => Ok(v.is_satisfied),
            Err(e) => Err(KelsError::VerificationFailed(e.to_string())),
        }
    }

    async fn self_satisfies(&self, record: &SadPointer) -> Result<bool, KelsError> {
        let write_policy = record.write_policy.as_ref().ok_or_else(|| {
            KelsError::VerificationFailed(
                "Icp record missing write_policy — validate_structure should have rejected".into(),
            )
        })?;
        let policy = self
            .resolver
            .resolve_policy(write_policy)
            .await
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))?;
        match evaluate_anchored_policy(&policy, &record.said, self.kel_source, self.resolver).await
        {
            Ok(v) => Ok(v.is_satisfied),
            Err(e) => Err(KelsError::VerificationFailed(e.to_string())),
        }
    }
}
