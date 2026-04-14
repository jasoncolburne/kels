//! SAD chain verification (structural only — no signatures with anchoring model)

use std::collections::HashMap;

use verifiable_storage::{Chained, SelfAddressed};

use super::pointer::SadPointer;
use crate::KelsError;

// ==================== Incremental Chain Verification ====================

/// Per-branch state for divergent SAD chains.
#[derive(Debug, Clone)]
struct SadBranchState {
    tip: SadPointer,
}

/// Streaming structural verifier for SAD pointer chains.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks per-branch state so that both forks of a
/// divergent chain are fully verified (SAID, prefix, topic, write_policy, chain linkage).
///
/// No signature verification — the anchoring model defers authorization to consumers.
pub struct SadChainVerifier {
    prefix: cesr::Digest256,
    write_policy: Option<cesr::Digest256>,
    topic: Option<String>,
    /// Branches keyed by tip SAID. Pre-divergence: one branch.
    branches: HashMap<cesr::Digest256, SadBranchState>,
    /// Records buffered for the current generation (same version).
    generation_buffer: Vec<SadPointer>,
    /// The version of the current buffered generation.
    current_generation_version: Option<u64>,
    saw_any_records: bool,
}

impl SadChainVerifier {
    pub fn new(prefix: &cesr::Digest256) -> Self {
        Self {
            prefix: *prefix,
            write_policy: None,
            topic: None,
            branches: HashMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_records: false,
        }
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a single record's SAID, prefix, write_policy, and topic.
    fn verify_record(&self, record: &SadPointer) -> Result<(), KelsError> {
        record.verify_said()?;

        if record.prefix != self.prefix {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} prefix {} doesn't match chain prefix {}",
                record.said, record.prefix, self.prefix
            )));
        }

        if let Some(ref expected) = self.write_policy
            && &record.write_policy != expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} write_policy {} doesn't match chain write_policy {}",
                record.said, record.write_policy, expected
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
    fn flush_generation(&mut self) -> Result<(), KelsError> {
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

            self.branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
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

            new_branches.insert(
                record.said,
                SadBranchState {
                    tip: record.clone(),
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
    pub fn verify_page(&mut self, records: &[SadPointer]) -> Result<(), KelsError> {
        for record in records {
            self.saw_any_records = true;

            self.verify_record(record)?;

            if self.write_policy.is_none() {
                self.write_policy = Some(record.write_policy);
            }
            if self.topic.is_none() {
                self.topic = Some(record.topic.clone());
            }

            if let Some(current_version) = self.current_generation_version
                && record.version != current_version
            {
                self.flush_generation()?;
            }

            self.current_generation_version = Some(record.version);
            self.generation_buffer.push(record.clone());
        }

        Ok(())
    }

    pub fn finish(mut self) -> Result<SadPointer, KelsError> {
        self.flush_generation()?;

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

        let tip = self
            .branches
            .into_values()
            .max_by_key(|b| b.tip.version)
            .map(|b| b.tip)
            .ok_or_else(|| KelsError::VerificationFailed("No tip after verification".into()))?;

        Ok(tip)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::super::pointer::SadPointer;
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_sad_chain_verifier_valid_chain() {
        let wp = test_digest(b"write-policy");
        let v0 =
            SadPointer::create("kels/exchange/v1/keys/mlkem".to_string(), None, None, wp).unwrap();
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        assert!(verifier.verify_page(&[v0.clone(), v1]).is_ok());
        assert!(!verifier.is_divergent());
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn test_sad_chain_verifier_empty_fails() {
        let verifier = SadChainVerifier::new(&test_digest(b"test"));
        assert!(verifier.finish().is_err());
    }

    #[test]
    fn test_sad_chain_verifier_wrong_version_fails() {
        let wp = test_digest(b"write-policy");
        let v0 =
            SadPointer::create("kels/exchange/v1/keys/mlkem".to_string(), None, None, wp).unwrap();
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.increment().unwrap();
        v1.version = 5;
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        verifier.verify_page(&[v0, v1]).unwrap();
        let err = verifier.finish().unwrap_err();
        assert!(
            err.to_string().contains("has version 5 but expected 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_multi_page() {
        let wp = test_digest(b"write-policy");
        let v0 =
            SadPointer::create("kels/exchange/v1/keys/mlkem".to_string(), None, None, wp).unwrap();
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.increment().unwrap();
        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        assert!(verifier.verify_page(&[v0]).is_ok());
        assert!(verifier.verify_page(&[v1, v2]).is_ok());

        let tip = verifier.finish().unwrap();
        assert_eq!(tip.version, 2);
    }
}
