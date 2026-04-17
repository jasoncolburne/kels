//! SAD chain verification (structural + policy authorization)

use std::collections::HashMap;

use verifiable_storage::{Chained, SelfAddressed};

use super::pointer::SadPointer;
use crate::KelsError;

// ==================== Policy Checker Trait ====================

/// Trait for checking policy satisfaction during chain verification.
///
/// `SadChainVerifier` calls this at each generation:
/// - v0: `self_satisfies(record)` — the inception must be authorized by its own write_policy
/// - v1+: `satisfies(record, &branch_tip.write_policy)` — each advance must be authorized
///   by the current write_policy (unconditionally, whether or not the policy changed)
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
    /// The checkpoint hash from the most recent checkpoint record on this branch.
    /// `None` until the first checkpoint is established.
    last_checkpoint_hash: Option<cesr::Digest256>,
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

        if self.branches.is_empty() {
            // First generation — inception (version 0)
            if records.len() != 1 {
                return Err(KelsError::VerificationFailed(
                    "Multiple records at version 0".into(),
                ));
            }

            let record = &records[0];

            if record.previous.is_some() {
                return Err(KelsError::VerificationFailed(format!(
                    "First SAD record {} has unexpected previous",
                    record.said
                )));
            }

            if version != 0 {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} has version {} but expected 0",
                    record.said, version
                )));
            }

            record.verify_prefix()?;

            // Policy check: v0 must self-satisfy
            if !self.checker.self_satisfies(record).await? {
                self.policy_satisfied = false;
            }

            self.branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
                    last_checkpoint_hash: record.checkpoint_hash,
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

            // Policy check: every v1+ record must satisfy the branch tip's write_policy
            if !self
                .checker
                .satisfies(record, &branch.tip.write_policy)
                .await?
            {
                self.policy_satisfied = false;
            }

            // Checkpoint enforcement
            let (last_checkpoint_hash, records_since_checkpoint) = if let Some(ref nonce) =
                record.checkpoint_nonce
            {
                // Reveal: must have a prior commitment to verify against
                let Some(ref expected_hash) = branch.last_checkpoint_hash else {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} reveals checkpoint nonce but no prior commitment exists",
                        record.said,
                    )));
                };

                let computed = super::pointer::compute_checkpoint_hash(nonce);
                if computed != *expected_hash {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} checkpoint nonce does not match commitment",
                        record.said,
                    )));
                }

                // Reveal must also carry a new commitment
                let Some(new_hash) = record.checkpoint_hash else {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} reveals checkpoint but has no new commitment",
                        record.said,
                    )));
                };

                (Some(new_hash), 0)
            } else if record.checkpoint_hash.is_some() && branch.last_checkpoint_hash.is_none() {
                // First checkpoint — commitment without reveal (nothing to reveal yet)
                (record.checkpoint_hash, 0)
            } else {
                // No checkpoint activity — tick the counter
                let count = branch.records_since_checkpoint + 1;
                if count > crate::MAX_NON_CHECKPOINT_RECORDS {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} exceeds checkpoint bound ({} non-checkpoint records, max {})",
                        record.said,
                        count,
                        crate::MAX_NON_CHECKPOINT_RECORDS,
                    )));
                }
                (branch.last_checkpoint_hash, count)
            };

            new_branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
                    last_checkpoint_hash,
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

        // Global invariant: at least one branch must have a checkpoint established
        if !self
            .branches
            .values()
            .any(|b| b.last_checkpoint_hash.is_some())
        {
            return Err(KelsError::VerificationFailed(
                "SAD chain has no checkpoint — at least one checkpoint is required".into(),
            ));
        }

        let tip = self
            .branches
            .into_values()
            .max_by_key(|b| b.tip.version)
            .map(|b| b.tip)
            .ok_or_else(|| KelsError::VerificationFailed("No tip after verification".into()))?;

        Ok(super::pointer::SadPointerVerification::new(
            tip,
            self.policy_satisfied,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::super::pointer::{SadPointer, compute_checkpoint_hash};
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    /// Create a v0 pointer with a checkpoint hash on v0.
    fn create_v0_with_checkpoint(
        wp: cesr::Digest256,
    ) -> (SadPointer, cesr::Nonce256, cesr::Digest256) {
        let nonce = cesr::Nonce256::generate();
        let hash = compute_checkpoint_hash(&nonce);
        let v0 = SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            wp,
            Some(hash),
            None,
        )
        .unwrap();
        (v0, nonce, hash)
    }

    /// Create a v0 pointer without a checkpoint (prefix stays deterministic).
    fn create_v0_no_checkpoint(wp: cesr::Digest256) -> SadPointer {
        SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            wp,
            None,
            None,
        )
        .unwrap()
    }

    /// Increment a pointer, adding a first checkpoint (no reveal).
    fn add_first_checkpoint(pointer: &mut SadPointer) -> (cesr::Nonce256, cesr::Digest256) {
        let nonce = cesr::Nonce256::generate();
        let hash = compute_checkpoint_hash(&nonce);
        pointer.checkpoint_hash = Some(hash);
        pointer.checkpoint_nonce = None;
        pointer.increment().unwrap();
        (nonce, hash)
    }

    /// Increment a pointer, revealing the previous nonce and committing a new one.
    fn add_checkpoint_reveal(
        pointer: &mut SadPointer,
        prev_nonce: &cesr::Nonce256,
    ) -> (cesr::Nonce256, cesr::Digest256) {
        let new_nonce = cesr::Nonce256::generate();
        let new_hash = compute_checkpoint_hash(&new_nonce);
        pointer.checkpoint_nonce = Some(*prev_nonce);
        pointer.checkpoint_hash = Some(new_hash);
        pointer.increment().unwrap();
        (new_nonce, new_hash)
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

    // ==================== Original tests (updated with checkpoints) ====================

    #[tokio::test]
    async fn test_sad_chain_verifier_valid_chain() {
        let wp = test_digest(b"write-policy");
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
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
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
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
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
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
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
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
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.write_policy = wp2;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_rejected_write_policy_evolution() {
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.write_policy = wp2;
        v1.increment().unwrap();

        let checker = RejectingChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_rejected_same_write_policy() {
        let wp = test_digest(b"write-policy");
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
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
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);

        let checker = RejectInceptionChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    // ==================== Checkpoint tests ====================

    #[tokio::test]
    async fn test_v0_with_checkpoint_hash_valid() {
        let wp = test_digest(b"write-policy");
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 0);
    }

    #[tokio::test]
    async fn test_v0_no_checkpoint_v1_first_checkpoint_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_first_checkpoint(&mut v1);

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 1);
    }

    #[tokio::test]
    async fn test_v0_no_checkpoint_overdue_at_64() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);

        let mut records = vec![v0.clone()];
        let mut current = v0.clone();
        // 63 non-checkpoint records (v1..v63) — within bound
        for _ in 1..=63 {
            current.content = Some(test_digest(
                format!("content_{}", current.version + 1).as_bytes(),
            ));
            current.increment().unwrap();
            records.push(current.clone());
        }

        // v64 — should be rejected (overdue)
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
    async fn test_valid_reveal_cycle() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);

        let mut records = vec![v0.clone()];
        let mut current = v0.clone();

        // v1: first checkpoint
        current.content = Some(test_digest(b"content_1"));
        let (nonce1, _hash1) = add_first_checkpoint(&mut current);
        records.push(current.clone());

        // v2..v64: 63 non-checkpoint records
        for i in 2..=64 {
            current.content = Some(test_digest(format!("content_{}", i).as_bytes()));
            current.increment().unwrap();
            records.push(current.clone());
        }

        // v65: reveal + new commitment
        current.content = Some(test_digest(b"content_65"));
        let (_nonce2, _hash2) = add_checkpoint_reveal(&mut current, &nonce1);
        records.push(current.clone());

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&records).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_record().version, 65);
    }

    #[tokio::test]
    async fn test_invalid_nonce_hash_mismatch() {
        let wp = test_digest(b"write-policy");
        let (v0, _nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        // Use a wrong nonce for the reveal
        let wrong_nonce = cesr::Nonce256::generate();
        let new_nonce = cesr::Nonce256::generate();
        let new_hash = compute_checkpoint_hash(&new_nonce);
        v1.checkpoint_nonce = Some(wrong_nonce);
        v1.checkpoint_hash = Some(new_hash);
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("does not match commitment"),
            "Expected nonce mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_reveal_without_prior_commitment() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        // Try to reveal with no prior commitment
        let nonce = cesr::Nonce256::generate();
        let new_nonce = cesr::Nonce256::generate();
        let new_hash = compute_checkpoint_hash(&new_nonce);
        v1.checkpoint_nonce = Some(nonce);
        v1.checkpoint_hash = Some(new_hash);
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("no prior commitment"),
            "Expected no prior commitment error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_reveal_without_new_commitment() {
        let wp = test_digest(b"write-policy");
        let (v0, nonce, _hash) = create_v0_with_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        // Reveal previous nonce but no new commitment
        v1.checkpoint_nonce = Some(nonce);
        v1.checkpoint_hash = None;
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("no new commitment"),
            "Expected missing new commitment error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_chain_with_no_checkpoint_rejected_at_finish() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_checkpoint(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.increment().unwrap();

        let checker = AlwaysPassChecker;
        let mut verifier = SadChainVerifier::new(&v0.prefix, &checker);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("no checkpoint"),
            "Expected no checkpoint error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_v0_with_checkpoint_changes_prefix() {
        let wp = test_digest(b"write-policy");
        let v0_no_cp = create_v0_no_checkpoint(wp);
        let (v0_with_cp, _nonce, _hash) = create_v0_with_checkpoint(wp);
        assert_ne!(v0_no_cp.prefix, v0_with_cp.prefix);
    }
}
