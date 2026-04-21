//! SAD chain verification (structural + policy authorization)

use std::collections::HashMap;

use verifiable_storage::{Chained, SelfAddressed};

use super::pointer::{SadPointer, SadPointerKind};
use crate::KelsError;

// ==================== Policy Checker Trait ====================

/// Trait for checking policy satisfaction during chain verification.
///
/// `SadChainVerifier` calls this at each generation:
/// - v0: `self_satisfies(record)` — the inception must be authorized by its own write_policy
/// - v1+: `satisfies(record, &branch.tracked_write_policy)` — each advance must be authorized
///   by the branch's currently-tracked write_policy (seeded by v0, updated when Evl carries
///   a new write_policy *and* the evolution was authorized). Called unconditionally,
///   whether or not the policy changed.
///
/// Implementations live outside `lib/kels` to avoid circular deps (e.g., `lib/policy`
/// calls `evaluate_anchored_policy` to check KEL anchoring).
#[async_trait::async_trait]
pub trait PolicyChecker: Send + Sync {
    /// Check if the advance to `new_record` is authorized by `previous_policy`.
    ///
    /// Evaluates `previous_policy` via anchoring — the endorsers required by
    /// `previous_policy` must have anchored `new_record.said` in their KELs.
    async fn satisfies(
        &self,
        new_record: &SadPointer,
        previous_policy: &cesr::Digest256,
    ) -> Result<bool, KelsError>;

    /// Check if v0 inception with this record is authorized.
    ///
    /// Evaluates `record.write_policy` via anchoring — endorsers must have
    /// anchored `record.said` in their KELs.
    async fn self_satisfies(&self, record: &SadPointer) -> Result<bool, KelsError>;
}

// ==================== Incremental Chain Verification ====================

/// Per-branch state for divergent SAD chains.
#[derive(Debug, Clone)]
struct SadBranchState {
    tip: SadPointer,
    /// The effective write_policy for this branch.
    /// Seeded from v0 (Icp always has write_policy) and updated when an Evl
    /// record carries a new write_policy *and* the evolution was authorized
    /// by the previous policy. Used to authorize v1+ advances.
    tracked_write_policy: cesr::Digest256,
    /// The checkpoint policy SAID tracked on this branch.
    /// `None` until the first checkpoint_policy is declared.
    checkpoint_policy: Option<cesr::Digest256>,
    /// Number of records since the last checkpoint (or since chain start).
    records_since_checkpoint: usize,
}

/// Streaming structural + policy verifier for SAD pointer chains.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks per-branch state so that both forks of a
/// divergent chain are fully verified (SAID, prefix, topic, chain linkage,
/// and write_policy authorization via `PolicyChecker`).
///
/// The verifier never errors on policy failure — it records the result in
/// `policy_satisfied`. Structural errors (bad SAID, wrong prefix, etc.)
/// still return errors. Callers check `policy_satisfied()` on the verification
/// token to decide what to do (e.g., server returns 403, client logs a warning).
pub struct SadChainVerifier<'a> {
    prefix: cesr::Digest256,
    topic: Option<String>,
    /// Branches keyed by tip SAID. Pre-divergence: one branch.
    branches: HashMap<cesr::Digest256, SadBranchState>,
    /// Records buffered for the current generation (same version).
    generation_buffer: Vec<SadPointer>,
    /// The version of the current buffered generation.
    current_generation_version: Option<u64>,
    saw_any_records: bool,
    policy_satisfied: bool,
    /// The version of the most recent evaluated checkpoint across all branches.
    /// For divergent chains, this is the minimum across branches (weakest seal).
    last_checkpoint_version: Option<u64>,
    /// The version at which checkpoint_policy was first established (v0 or v1).
    /// Chain-wide, set once.
    establishment_version: Option<u64>,
    checker: &'a dyn PolicyChecker,
}

impl<'a> SadChainVerifier<'a> {
    pub fn new(prefix: &cesr::Digest256, checker: &'a dyn PolicyChecker) -> Self {
        Self {
            prefix: *prefix,
            topic: None,
            branches: HashMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_records: false,
            policy_satisfied: true,
            last_checkpoint_version: None,
            establishment_version: None,
            checker,
        }
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a single record's SAID, prefix, and topic.
    fn verify_record(&self, record: &SadPointer) -> Result<(), KelsError> {
        record.verify_said()?;

        if record.prefix != self.prefix {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} prefix {} doesn't match chain prefix {}",
                record.said, record.prefix, self.prefix
            )));
        }

        if let Some(ref expected) = self.topic
            && record.topic != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} topic {} doesn't match chain topic {}",
                record.said, record.topic, expected
            )));
        }

        Ok(())
    }

    /// Process a complete generation (all records at the same version).
    async fn flush_generation(&mut self) -> Result<(), KelsError> {
        let records = std::mem::take(&mut self.generation_buffer);
        let version = match self.current_generation_version.take() {
            Some(v) => v,
            None => return Ok(()),
        };

        if records.is_empty() {
            return Ok(());
        }

        // Structural validation first — before any chain state reasoning
        for record in &records {
            record
                .validate_structure()
                .map_err(KelsError::VerificationFailed)?;
        }

        if self.branches.is_empty() {
            // First generation — inception (version 0)
            if records.len() != 1 {
                return Err(KelsError::VerificationFailed(
                    "Multiple records at version 0".into(),
                ));
            }

            let record = &records[0];
            record.verify_prefix()?;

            // Policy check: v0 must self-satisfy
            if !self.checker.self_satisfies(record).await? {
                self.policy_satisfied = false;
            }

            // Track checkpoint_policy if declared on v0
            let checkpoint_policy = record.checkpoint_policy;
            if checkpoint_policy.is_some() {
                self.establishment_version = Some(0);
            }

            // Seed tracked_write_policy from v0. validate_structure guarantees
            // Icp has Some(write_policy).
            #[allow(clippy::expect_used)]
            let tracked_write_policy = record
                .write_policy
                .expect("Icp record must have write_policy per validate_structure");

            self.branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
                    tracked_write_policy,
                    checkpoint_policy,
                    records_since_checkpoint: 0,
                },
            );
            return Ok(());
        }

        // Max 2 records per generation (owner + adversary fork)
        if records.len() > 2 {
            return Err(KelsError::VerificationFailed(format!(
                "Generation at version {} has {} records, max 2 allowed",
                version,
                records.len()
            )));
        }

        let mut new_branches: HashMap<cesr::Digest256, SadBranchState> = HashMap::new();

        for record in &records {
            let previous = record.previous.as_ref().ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "Non-inception SAD record {} has no previous pointer",
                    record.said,
                ))
            })?;

            let branch = self.branches.get(previous).ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "SAD record {} previous {} does not match any branch tip",
                    record.said, previous,
                ))
            })?;

            let expected_version = branch.tip.version + 1;
            if record.version != expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} has version {} but expected {} (branch tip version + 1)",
                    record.said, record.version, expected_version
                )));
            }

            // Policy check: every v1+ record must satisfy the branch's tracked write_policy.
            // Defense-in-depth: when this check fails, we also refuse to advance
            // `tracked_write_policy` below, so subsequent records on the same branch
            // keep failing against the still-legitimate previous policy. This gives
            // consumers multiple soft signals instead of relying on a single
            // `policy_satisfied` flag being checked.
            let write_policy_satisfied = self
                .checker
                .satisfies(record, &branch.tracked_write_policy)
                .await?;
            if !write_policy_satisfied {
                self.policy_satisfied = false;
            }

            // Guard: all non-Icp/non-Est kinds require checkpoint_policy established
            if !record.kind.is_inception()
                && record.kind != SadPointerKind::Est
                && branch.checkpoint_policy.is_none()
            {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} kind {} requires checkpoint_policy to be established",
                    record.said, record.kind,
                )));
            }

            // Kind-specific chain-state logic
            let (checkpoint_policy, records_since_checkpoint, tracked_write_policy) = match record
                .kind
            {
                SadPointerKind::Icp => {
                    // Icp at v1+ is rejected by validate_structure (version != 0)
                    unreachable!("Icp at v1+ should be rejected by validate_structure")
                }
                SadPointerKind::Est => {
                    // Est: checkpoint_policy declaration — only valid when branch has none from v0
                    if branch.checkpoint_policy.is_some() {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD record {} Est rejected — checkpoint_policy already established from v0",
                            record.said,
                        )));
                    }
                    self.establishment_version = Some(1);
                    // tracked_write_policy unchanged — Est forbids write_policy (validate_structure)
                    (record.checkpoint_policy, 1, branch.tracked_write_policy)
                }
                kind if kind.evaluates_checkpoint() => {
                    // Evl or Rpr: evaluate against tracked checkpoint_policy
                    let tracked = branch.checkpoint_policy.as_ref().ok_or_else(|| {
                        KelsError::VerificationFailed(format!(
                            "SAD record {} {} but no checkpoint_policy established",
                            record.said, record.kind,
                        ))
                    })?;

                    if !self.checker.satisfies(record, tracked).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD record {} checkpoint policy not satisfied",
                            record.said,
                        )));
                    }

                    // Track the checkpoint version as a seal
                    self.last_checkpoint_version = Some(match self.last_checkpoint_version {
                        Some(existing) => existing.min(record.version),
                        None => record.version,
                    });

                    // Evl allows checkpoint_policy evolution; Rpr forbids it (validate_structure)
                    let new_cp = record.checkpoint_policy.or(Some(*tracked));
                    // Evl with Some(write_policy) = policy evolution. None = pure checkpoint.
                    // Rpr forbids write_policy entirely (validate_structure).
                    //
                    // Defense-in-depth: only advance tracked_write_policy when the
                    // soft write_policy check above passed. On soft-fail, keep the
                    // previous policy so subsequent records remain gated against it.
                    let new_wp = if write_policy_satisfied {
                        record.write_policy.unwrap_or(branch.tracked_write_policy)
                    } else {
                        branch.tracked_write_policy
                    };
                    (new_cp, 0, new_wp)
                }
                SadPointerKind::Upd => {
                    // Normal record — increment counter, check bound
                    let count = branch.records_since_checkpoint + 1;
                    if count > crate::MAX_NON_CHECKPOINT_RECORDS {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD record {} exceeds checkpoint bound ({} non-checkpoint records, max {})",
                            record.said,
                            count,
                            crate::MAX_NON_CHECKPOINT_RECORDS,
                        )));
                    }
                    // tracked_write_policy unchanged — Upd forbids write_policy (validate_structure)
                    (branch.checkpoint_policy, count, branch.tracked_write_policy)
                }
                _ => unreachable!("All SadPointerKind variants handled"),
            };

            new_branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
                    tracked_write_policy,
                    checkpoint_policy,
                    records_since_checkpoint,
                },
            );
        }

        // Keep un-extended branches
        for (said, state) in &self.branches {
            if !records.iter().any(|r| r.previous.as_ref() == Some(said)) {
                new_branches.insert(*said, state.clone());
            }
        }

        self.branches = new_branches;
        Ok(())
    }

    /// Verify a page of records incrementally.
    pub async fn verify_page(&mut self, records: &[SadPointer]) -> Result<(), KelsError> {
        for record in records {
            self.saw_any_records = true;

            self.verify_record(record)?;

            if self.topic.is_none() {
                self.topic = Some(record.topic.clone());
            }

            if let Some(current_version) = self.current_generation_version
                && record.version != current_version
            {
                self.flush_generation().await?;
            }

            self.current_generation_version = Some(record.version);
            self.generation_buffer.push(record.clone());
        }

        Ok(())
    }

    pub async fn finish(mut self) -> Result<super::pointer::SadPointerVerification, KelsError> {
        self.flush_generation().await?;

        if !self.saw_any_records {
            return Err(KelsError::VerificationFailed(
                "Empty SAD record chain".into(),
            ));
        }

        if self.branches.is_empty() {
            return Err(KelsError::VerificationFailed(
                "No tip after verification".into(),
            ));
        }

        // Global invariant: at least one branch must have a checkpoint policy established
        if !self
            .branches
            .values()
            .any(|b| b.checkpoint_policy.is_some())
        {
            return Err(KelsError::VerificationFailed(
                "SAD chain has no checkpoint_policy — at least one checkpoint is required".into(),
            ));
        }

        // Deterministic tie-break: higher version wins; equal versions break
        // on lexicographically greater SAID. Matters for divergent chains so
        // `verification.write_policy()` is reproducible across callers.
        let winning_branch = self
            .branches
            .into_values()
            .max_by(|a, b| {
                a.tip
                    .version
                    .cmp(&b.tip.version)
                    .then_with(|| a.tip.said.as_ref().cmp(b.tip.said.as_ref()))
            })
            .ok_or_else(|| KelsError::VerificationFailed("No tip after verification".into()))?;

        Ok(super::pointer::SadPointerVerification::new(
            winning_branch.tip,
            winning_branch.tracked_write_policy,
            self.policy_satisfied,
            self.last_checkpoint_version,
            self.establishment_version,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::super::pointer::{SadPointer, SadPointerKind};
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    /// Create a v0 pointer with checkpoint_policy declared.
    fn create_v0_with_checkpoint(wp: cesr::Digest256) -> SadPointer {
        let cp = test_digest(b"checkpoint-policy");
        SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(wp),
            Some(cp),
        )
        .unwrap()
    }

    /// Create a v0 pointer without checkpoint (prefix stays deterministic).
    fn create_v0_no_checkpoint(wp: cesr::Digest256) -> SadPointer {
        SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(wp),
            None,
        )
        .unwrap()
    }

    /// Declare checkpoint_policy on a pointer (Est kind) and increment.
    fn add_checkpoint_declaration(pointer: &mut SadPointer) {
        let cp = test_digest(b"checkpoint-policy");
        pointer.kind = SadPointerKind::Est;
        pointer.checkpoint_policy = Some(cp);
        pointer.write_policy = None; // Est forbids write_policy
        pointer.increment().unwrap();
    }

    /// Set Evl kind and increment (evaluated checkpoint, no policy evolution).
    fn add_checkpoint(pointer: &mut SadPointer) {
        pointer.kind = SadPointerKind::Evl;
        pointer.write_policy = None; // pure checkpoint
        pointer.increment().unwrap();
    }

    struct AlwaysPassChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn satisfies(&self, _: &SadPointer, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct RejectingChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectingChecker {
        async fn satisfies(&self, _: &SadPointer, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(false)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct RejectInceptionChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectInceptionChecker {
        async fn satisfies(&self, _: &SadPointer, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
            Ok(false)
        }
    }

    /// Test-only `PolicyChecker` that accepts checkpoint_policy evaluations
    /// and rejects write_policy evaluations. Disambiguates the two by comparing
    /// the requested policy SAID against the stored `checkpoint_policy`.
    ///
    /// **Callers must not reuse the same SAID for write_policy and
    /// checkpoint_policy in the same test** — both checks would then accept,
    /// masking write_policy rejection. Tests using distinct `test_digest(b"...")`
    /// labels are already safe.
    struct AcceptCheckpointRejectWriteChecker {
        checkpoint_policy: cesr::Digest256,
    }
    #[async_trait::async_trait]
    impl PolicyChecker for AcceptCheckpointRejectWriteChecker {
        async fn satisfies(
            &self,
            _: &SadPointer,
            policy: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(*policy == self.checkpoint_policy)
        }
        async fn self_satisfies(&self, _: &SadPointer) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    // ==================== Original tests (updated with kinds) ====================

    #[tokio::test]
    async fn test_sad_chain_verifier_valid_chain() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        assert!(verifier.verify_page(&[v0.clone(), v1]).await.is_ok());
        assert!(!verifier.is_divergent());
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
    }

    #[tokio::test]
    async fn test_sad_chain_verifier_empty_fails() {
        let checker = AlwaysPassChecker;
        let verifier = SadChainVerifier::new(&test_digest(b"test"), &checker);
        assert!(verifier.finish().await.is_err());
    }

    #[tokio::test]
    async fn test_sad_chain_verifier_wrong_version_fails() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();
        v1.version = 5;
        v1.derive_said().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("has version 5 but expected 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_sad_chain_verifier_multi_page() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();
        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        assert!(verifier.verify_page(&[v0]).await.is_ok());
        assert!(verifier.verify_page(&[v1, v2]).await.is_ok());

        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 2);
    }

    #[tokio::test]
    async fn test_same_write_policy_authorized() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_evolving_write_policy_authorized() {
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.write_policy = Some(wp2);
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
        // Tracked write_policy updated from Evl
        assert_eq!(verification.write_policy(), &wp2);
    }

    #[tokio::test]
    async fn test_rejected_write_policy_evolution() {
        // An Evl that evolves write_policy must be authorized against the
        // *previous* write_policy. Use AcceptCheckpointRejectWriteChecker so
        // the checkpoint_policy evaluation passes (no hard error) but the
        // write_policy evaluation fails (soft rejection). This cleanly isolates
        // the write_policy rejection path.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let cp = test_digest(b"checkpoint-policy"); // matches create_v0_with_checkpoint
        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.write_policy = Some(wp2);
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = AcceptCheckpointRejectWriteChecker {
            checkpoint_policy: cp,
        };
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Expected policy_satisfied=false — previous write_policy rejected the evolution"
        );
        // Defense-in-depth: tracked_write_policy did NOT advance to wp2 because
        // the soft write_policy check failed. Chain state remains authorized
        // against the legitimate previous policy.
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_evl_without_write_policy_inherits_tracked() {
        let wp1 = test_digest(b"write-policy-1");
        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        // Pure checkpoint — tracked write_policy inherited from v0
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_evl_evolution_rejected_does_not_advance_tracked_policy() {
        // Defense-in-depth: when Evl evolves write_policy but the previous
        // policy rejects the advance, tracked_write_policy must remain at the
        // previous value. Any subsequent record on this branch will then be
        // checked against the legitimate previous policy, not the attacker's
        // proposed replacement.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let cp = test_digest(b"checkpoint-policy"); // matches create_v0_with_checkpoint
        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.write_policy = Some(wp2);
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        // Accepts checkpoint_policy evaluation, rejects write_policy authorization.
        let checker = AcceptCheckpointRejectWriteChecker {
            checkpoint_policy: cp,
        };
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Expected policy_satisfied=false because the previous write_policy rejected the evolution"
        );
        // tracked_write_policy did NOT advance — advance is gated on the soft check.
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_rpr_inherits_tracked_write_policy() {
        // Rpr cannot carry write_policy (validate_structure forbids it).
        // The verifier must leave tracked_write_policy unchanged across Rpr.
        let wp1 = test_digest(b"write-policy-1");
        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Rpr;
        v1.write_policy = None;
        v1.checkpoint_policy = None; // Rpr forbids checkpoint_policy
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        // Rpr inherits wp1 from branch state
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_multi_step_write_policy_evolution() {
        // v0 Icp(wp1) → v1 Est → v2 Evl(wp2) → v3 Evl(wp3).
        // After verification, tracked_write_policy must equal wp3 — each Evl
        // advances from the previously-tracked policy, not from v0's seed.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let wp3 = test_digest(b"write-policy-3");

        let v0 = create_v0_no_checkpoint(wp1);
        let mut v1 = v0.clone();
        add_checkpoint_declaration(&mut v1); // Est @ v1 establishes checkpoint_policy

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadPointerKind::Evl;
        v2.write_policy = Some(wp2);
        v2.checkpoint_policy = None;
        v2.increment().unwrap();

        let mut v3 = v2.clone();
        v3.content = Some(test_digest(b"content3"));
        v3.kind = SadPointerKind::Evl;
        v3.write_policy = Some(wp3);
        v3.checkpoint_policy = None;
        v3.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier
            .verify_page(&[v0.clone(), v1, v2, v3])
            .await
            .unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
        assert_eq!(verification.write_policy(), &wp3);
    }

    #[tokio::test]
    async fn test_multi_step_evolution_rejected_keeps_seed_policy() {
        // Chain: v0 Icp(wp1) → v1 Evl(wp2) → v2 Evl(wp3). The checker rejects
        // every write_policy check. Because advance is gated on the soft check,
        // neither v1 nor v2 advances tracked_write_policy, and the final
        // tracked value remains wp1. Combined with
        // test_multi_step_write_policy_evolution (which proves tracked advances
        // to wp3 under AlwaysPassChecker), the pair covers the advance-and-check
        // loop in both directions.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let wp3 = test_digest(b"write-policy-3");
        let cp = test_digest(b"checkpoint-policy"); // matches create_v0_with_checkpoint

        let v0 = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.write_policy = Some(wp2);
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadPointerKind::Evl;
        v2.write_policy = Some(wp3);
        v2.checkpoint_policy = None;
        v2.increment().unwrap();

        let checker = AcceptCheckpointRejectWriteChecker {
            checkpoint_policy: cp,
        };
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Both v1 and v2 evolutions must soft-fail under this checker"
        );
        // Advance is gated on soft-check — neither v1 nor v2 advanced tracked.
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_divergent_branches_tracked_write_policy_tiebreak_deterministic() {
        // Two divergent Evl branches at v1 carry different new write_policies.
        // finish() must pick one deterministically regardless of input order.
        let wp0 = test_digest(b"write-policy-0");
        let wp_a = test_digest(b"write-policy-a");
        let wp_b = test_digest(b"write-policy-b");
        let v0 = create_v0_with_checkpoint(wp0);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadPointerKind::Evl;
        v1_a.write_policy = Some(wp_a);
        v1_a.checkpoint_policy = None;
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadPointerKind::Evl;
        v1_b.write_policy = Some(wp_b);
        v1_b.checkpoint_policy = None;
        v1_b.increment().unwrap();

        // Expected tie-break: higher version wins; equal versions break on
        // lexicographically greater SAID bytes.
        let expected_wp = if v1_a.said.as_ref() > v1_b.said.as_ref() {
            wp_a
        } else {
            wp_b
        };

        // Order 1: a then b
        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier
            .verify_page(&[v0.clone(), v1_a.clone(), v1_b.clone()])
            .await
            .unwrap();
        let v1 = verifier.finish().await.unwrap();
        assert!(v1.policy_satisfied());
        assert_eq!(v1.write_policy(), &expected_wp);

        // Order 2: b then a — must return the same branch
        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1_b, v1_a]).await.unwrap();
        let v2 = verifier.finish().await.unwrap();
        assert_eq!(v2.write_policy(), &expected_wp);
    }

    #[tokio::test]
    async fn test_rejected_same_write_policy() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        let checker = RejectingChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_self_satisfies_failure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);

        let checker = RejectInceptionChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    // ==================== Checkpoint policy tests ====================

    #[tokio::test]
    async fn test_v0_with_checkpoint_policy_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 0);
        assert_eq!(verification.establishment_version(), Some(0));
    }

    #[tokio::test]
    async fn test_v0_no_checkpoint_v1_est_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_checkpoint_declaration(&mut v1);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
        assert_eq!(verification.establishment_version(), Some(1));
    }

    #[tokio::test]
    async fn test_checkpoint_overdue_at_64() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);

        let mut records = vec![v0.clone()];
        let mut current = v0.clone();
        // v1: Est (checkpoint_policy declaration)
        current.content = Some(test_digest(b"content_1"));
        current.kind = SadPointerKind::Est;
        current.write_policy = None;
        current.checkpoint_policy = Some(test_digest(b"checkpoint-policy"));
        current.increment().unwrap();
        records.push(current.clone());

        // v2..v63: 62 Upd records — within bound (1 Est + 62 Upd = 63 non-checkpoint)
        current.kind = SadPointerKind::Upd;
        current.checkpoint_policy = None;
        for _ in 2..=63 {
            current.content = Some(test_digest(
                format!("content_{}", current.version + 1).as_bytes(),
            ));
            current.increment().unwrap();
            records.push(current.clone());
        }

        // v64 — should be rejected (overdue: 63 non-checkpoint records, max is 63)
        current.content = Some(test_digest(b"content_64"));
        current.increment().unwrap();
        records.push(current.clone());

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&records).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("checkpoint bound"),
            "Expected checkpoint overdue error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_valid_checkpoint_cycle() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);

        let mut records = vec![v0.clone()];
        let mut current = v0.clone();

        // v1: Est (checkpoint_policy declaration, counts as non-checkpoint)
        current.content = Some(test_digest(b"content_1"));
        add_checkpoint_declaration(&mut current);
        records.push(current.clone());

        // v2..v63: 62 more Upd records (total 63 non-checkpoint: v1..v63)
        current.kind = SadPointerKind::Upd;
        current.write_policy = None;
        current.checkpoint_policy = None;
        for i in 2..=63 {
            current.content = Some(test_digest(format!("content_{}", i).as_bytes()));
            current.increment().unwrap();
            records.push(current.clone());
        }

        // v64: first evaluated checkpoint (resets counter)
        current.content = Some(test_digest(b"content_64"));
        add_checkpoint(&mut current);
        records.push(current.clone());

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&records).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 64);
    }

    #[tokio::test]
    async fn test_checkpoint_policy_evolution_on_evl_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        // Change checkpoint_policy on an Evl record — valid (policy evolution)
        v1.checkpoint_policy = Some(test_digest(b"new-checkpoint-policy"));
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
    }

    #[tokio::test]
    async fn test_upd_with_checkpoint_policy_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        // Upd must not set checkpoint_policy — validate_structure rejects
        v1.checkpoint_policy = Some(test_digest(b"new-checkpoint-policy"));
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("must not have checkpointPolicy"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_evl_without_checkpoint_policy_on_branch_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires checkpoint_policy to be established"),
            "Expected missing policy error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_chain_with_no_checkpoint_rejected_at_finish() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Est;
        v1.write_policy = None;
        v1.checkpoint_policy = Some(test_digest(b"checkpoint-policy"));
        v1.increment().unwrap();

        // Chain has checkpoint_policy established but never evaluated — still passes finish
        // (finish only checks that checkpoint_policy exists on at least one branch)
        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
    }

    #[tokio::test]
    async fn test_chain_with_no_checkpoint_policy_at_all_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);

        // v0 without checkpoint_policy and no Est — finish should reject
        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("no checkpoint"),
            "Expected no checkpoint error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_v0_with_checkpoint_policy_changes_prefix() {
        let wp = test_digest(b"write-policy");
        let v0_no_cp = create_v0_no_checkpoint(wp);
        let v0_with_cp = create_v0_with_checkpoint(wp);
        assert_ne!(v0_no_cp.prefix, v0_with_cp.prefix);
    }

    // ==================== Kind-specific chain-state tests ====================

    #[tokio::test]
    async fn test_est_at_v1_when_v0_had_no_checkpoint_accepted() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_checkpoint_declaration(&mut v1);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
        assert_eq!(verification.establishment_version(), Some(1));
    }

    #[tokio::test]
    async fn test_est_at_v1_when_v0_declared_checkpoint_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Est;
        v1.write_policy = None;
        v1.checkpoint_policy = Some(test_digest(b"another-checkpoint-policy"));
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("already established"),
            "Expected Est rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_est_at_v2_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_checkpoint_declaration(&mut v1);

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadPointerKind::Est;
        v2.write_policy = None;
        v2.checkpoint_policy = Some(test_digest(b"another-cp"));
        v2.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("Est pointer must have version 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_upd_at_v1_when_v0_had_no_checkpoint_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Upd;
        v1.write_policy = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires checkpoint_policy to be established"),
            "Expected checkpoint_policy error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_rpr_evaluates_checkpoint_policy() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Rpr;
        v1.write_policy = None;
        v1.checkpoint_policy = None; // Rpr forbids checkpoint_policy
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_checkpoint_version(), Some(1));
    }

    #[tokio::test]
    async fn test_rpr_with_checkpoint_policy_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Rpr;
        v1.write_policy = None;
        v1.checkpoint_policy = Some(test_digest(b"rpr-cp"));
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("must not have checkpointPolicy"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    // ==================== Checkpoint tracking tests ====================

    #[tokio::test]
    async fn test_last_checkpoint_version_tracked() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_checkpoint_declaration(&mut v1);

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        add_checkpoint(&mut v2);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_checkpoint_version(), Some(2));
    }

    #[tokio::test]
    async fn test_last_checkpoint_version_none_without_evaluated_checkpoint() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_checkpoint_declaration(&mut v1);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_checkpoint_version(), None);
    }

    #[tokio::test]
    async fn test_v0_non_icp_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let cp = test_digest(b"checkpoint-policy");
        // Manually construct a v0 with Evl kind — should fail validate_structure
        let mut v0 = SadPointer {
            said: cesr::Digest256::default(),
            prefix: cesr::Digest256::default(),
            previous: None,
            version: 0,
            topic: "kels/sad/v1/keys/mlkem".to_string(),
            kind: SadPointerKind::Evl,
            content: None,
            custody: None,
            write_policy: Some(wp),
            checkpoint_policy: Some(cp),
        };
        v0.derive_said().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Evl pointer must have version >= 1"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_checkpoint_after_est_accepted() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Est;
        v1.write_policy = None;
        v1.checkpoint_policy = Some(test_digest(b"checkpoint-policy"));
        v1.increment().unwrap();

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadPointerKind::Evl;
        v2.checkpoint_policy = None;
        v2.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 2);
    }

    #[tokio::test]
    async fn test_checkpoint_policy_evaluation_failure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadPointerKind::Evl;
        v1.checkpoint_policy = None;
        v1.increment().unwrap();

        // RejectingChecker returns Ok(false) for all satisfies calls —
        // checkpoint_policy evaluation is a hard error (unlike write_policy which is soft).
        let checker = RejectingChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("checkpoint policy not satisfied"),
            "Expected checkpoint policy error, got: {}",
            err
        );
    }
}
