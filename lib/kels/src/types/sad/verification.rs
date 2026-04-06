//! SAD chain verification

use std::collections::{BTreeSet, HashMap};

use cesr::{Matter, VerificationKey};
use verifiable_storage::{Chained, SelfAddressed};

use super::pointer::SignedSadPointer;
use super::sync::PagedSadSource;
use crate::KelsError;

// ==================== Incremental Chain Verification ====================

/// Per-branch state for divergent SAD chains. Keyed by tip SAID in the branches map.
#[derive(Debug, Clone)]
struct SadBranchState {
    tip: SignedSadPointer,
}

/// Streaming structural verifier for SAD record chains.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks per-branch state so that both forks of a
/// divergent chain are fully verified (SAID, prefix, kel_prefix, kind, chain
/// linkage, and signature).
///
/// Records at the same version are processed as a generation (like `KelVerifier`
/// processes events at the same serial). Both fork records can match the same
/// parent branch within a generation.
///
/// Used by both the transfer infrastructure (pass 2) and the repository
/// (DB chain walk). Divergence detection is tracked but not rejected —
/// the caller decides how to handle it.
pub struct SadChainVerifier {
    prefix: cesr::Digest,
    kel_prefix: Option<cesr::Digest>,
    kind: Option<String>,
    /// Branches keyed by tip SAID. Pre-divergence: one branch.
    /// At divergence: two branches (one per fork).
    branches: HashMap<cesr::Digest, SadBranchState>,
    /// Records buffered for the current generation (same version).
    generation_buffer: Vec<SignedSadPointer>,
    /// The version of the current buffered generation.
    current_generation_version: Option<u64>,
    saw_any_records: bool,
    establishment_keys: HashMap<u64, VerificationKey>,
}

impl SadChainVerifier {
    pub fn new(prefix: &cesr::Digest, establishment_keys: HashMap<u64, VerificationKey>) -> Self {
        Self {
            prefix: prefix.clone(),
            kel_prefix: None,
            kind: None,
            branches: HashMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_records: false,
            establishment_keys,
        }
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a single record's SAID, prefix, kel_prefix, kind, and signature.
    fn verify_record(&self, stored: &SignedSadPointer) -> Result<(), KelsError> {
        let record = &stored.pointer;

        record.verify_said()?;

        if record.prefix != self.prefix {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} prefix {} doesn't match chain prefix {}",
                record.said, record.prefix, self.prefix
            )));
        }

        if let Some(ref expected) = self.kel_prefix
            && &record.kel_prefix != expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} kel_prefix {} doesn't match chain kel_prefix {}",
                record.said, record.kel_prefix, expected
            )));
        }

        if let Some(ref expected) = self.kind
            && record.kind != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD record {} kind {} doesn't match chain kind {}",
                record.said, record.kind, expected
            )));
        }

        let public_key = self
            .establishment_keys
            .get(&stored.establishment_serial)
            .ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "No establishment key for serial {} (record {})",
                    stored.establishment_serial, record.said
                ))
            })?;
        public_key
            .verify(record.said.qb64().as_bytes(), &stored.signature)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;

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

            let stored = &records[0];
            let record = &stored.pointer;

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
                record.said.clone(),
                SadBranchState {
                    tip: stored.clone(),
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

        // Match each record to its branch via `previous` pointer
        let mut new_branches: HashMap<cesr::Digest, SadBranchState> = HashMap::new();

        for stored in &records {
            let record = &stored.pointer;

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

            // Version must be branch tip version + 1
            let expected_branch_version = branch.tip.pointer.version + 1;
            if record.version != expected_branch_version {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} has version {} but expected {} (branch tip version + 1)",
                    record.said, record.version, expected_branch_version
                )));
            }

            new_branches.insert(
                record.said.clone(),
                SadBranchState {
                    tip: stored.clone(),
                },
            );
        }

        // Keep un-extended branches (in divergent chains, one branch may be shorter)
        for (said, state) in &self.branches {
            if !records
                .iter()
                .any(|r| r.pointer.previous.as_ref() == Some(said))
            {
                new_branches.insert(said.clone(), state.clone());
            }
        }

        self.branches = new_branches;

        Ok(())
    }

    /// Verify a page of records incrementally. Carries forward state for the next page.
    pub fn verify_page(&mut self, records: &[SignedSadPointer]) -> Result<(), KelsError> {
        for stored in records {
            self.saw_any_records = true;
            let record = &stored.pointer;

            // Verify SAID, prefix, kel_prefix, kind, and signature for ALL records.
            self.verify_record(stored)?;

            // First record establishes chain invariants
            if self.kel_prefix.is_none() {
                self.kel_prefix = Some(record.kel_prefix.clone());
            }
            if self.kind.is_none() {
                self.kind = Some(record.kind.clone());
            }

            // Buffer records by version and flush when the version changes
            if let Some(current_version) = self.current_generation_version
                && record.version != current_version
            {
                // New version — flush the previous generation
                self.flush_generation()?;
            }

            self.current_generation_version = Some(record.version);
            self.generation_buffer.push(stored.clone());
        }

        Ok(())
    }

    pub fn finish(mut self) -> Result<(SignedSadPointer, cesr::Digest), KelsError> {
        // Flush any remaining buffered generation
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

        // Return the tip with the highest version (owner branch in divergent case)
        let tip = self
            .branches
            .into_values()
            .max_by_key(|b| b.tip.pointer.version)
            .map(|b| b.tip)
            .ok_or_else(|| KelsError::VerificationFailed("No tip after verification".into()))?;

        let kel_prefix = self.kel_prefix.ok_or_else(|| {
            KelsError::VerificationFailed("No kel_prefix after verification".into())
        })?;

        Ok((tip, kel_prefix))
    }
}

/// Collect establishment serials from a paged source without verification.
/// Used as pass 1 to determine which KEL keys are needed before full verification.
pub async fn collect_establishment_serials(
    prefix: &cesr::Digest,
    source: &(dyn PagedSadSource + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<(BTreeSet<u64>, cesr::Digest), KelsError> {
    let mut serials = BTreeSet::new();
    let mut kel_prefix: Option<cesr::Digest> = None;
    let mut since: Option<cesr::Digest> = None;

    for _ in 0..max_pages {
        let (records, has_more) = source.fetch_page(prefix, since.as_ref(), page_size).await?;

        if records.is_empty() {
            break;
        }

        for stored in &records {
            serials.insert(stored.establishment_serial);
            if kel_prefix.is_none() {
                kel_prefix = Some(stored.pointer.kel_prefix.clone());
            }
        }

        since = records.last().map(|r| r.pointer.said.clone());

        if !has_more {
            break;
        }
    }

    let kel_prefix =
        kel_prefix.ok_or_else(|| KelsError::VerificationFailed("Empty SAD record chain".into()))?;

    Ok((serials, kel_prefix))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use cesr::generate_secp256r1;
    use verifiable_storage::{Chained, SelfAddressed};

    use super::super::pointer::SadPointer;
    use super::*;

    fn test_keys() -> (VerificationKey, cesr::SigningKey) {
        generate_secp256r1().unwrap()
    }

    fn test_digest(label: &[u8]) -> cesr::Digest {
        cesr::Digest::blake3_256(label)
    }

    fn signed(record: &SadPointer, signing_key: &cesr::SigningKey) -> SignedSadPointer {
        let sig = signing_key.sign(record.said.qb64().as_bytes()).unwrap();
        SignedSadPointer {
            pointer: record.clone(),
            signature: sig,
            establishment_serial: 0,
        }
    }

    fn keys_map(vk: &VerificationKey) -> HashMap<u64, VerificationKey> {
        let mut m = HashMap::new();
        m.insert(0, vk.clone());
        m
    }

    #[test]
    fn test_sad_chain_verifier_valid_chain() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some(test_digest(b"content1"));
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        assert!(
            verifier
                .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
                .is_ok()
        );
        assert!(!verifier.is_divergent());
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn test_sad_chain_verifier_empty_fails() {
        let (vk, _) = test_keys();
        let verifier = SadChainVerifier::new(&test_digest(b"test"), keys_map(&vk));
        assert!(verifier.finish().is_err());
    }

    #[test]
    fn test_sad_chain_verifier_broken_linkage_fails() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        v1.version = 1;
        v1.previous = Some(test_digest(b"wrong_said"));
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        // verify_page buffers records; flush happens at finish()
        verifier
            .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
            .unwrap();
        let err = verifier.finish().unwrap_err();
        assert!(
            err.to_string().contains("does not match any branch tip"),
            "Expected chain linkage error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_inconsistent_kind_fails() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.kind = "kels/v1/other-kind".to_string();
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        let err = verifier
            .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
            .unwrap_err();
        assert!(
            err.to_string().contains("kind"),
            "Expected kind mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_wrong_version_fails() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some(test_digest(b"content1"));
        v1.increment().unwrap();
        v1.version = 5;
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        // verify_page buffers records; flush happens at finish()
        verifier
            .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
            .unwrap();
        let err = verifier.finish().unwrap_err();
        assert!(
            err.to_string().contains("has version 5 but expected 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_multi_page() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some(test_digest(b"content1"));
        v1.increment().unwrap();
        let mut v2 = v1.clone();
        v2.content_said = Some(test_digest(b"content2"));
        v2.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        assert!(verifier.verify_page(&[signed(&v0, &sk)]).is_ok());
        assert!(
            verifier
                .verify_page(&[signed(&v1, &sk), signed(&v2, &sk)])
                .is_ok()
        );

        let (tip, kel_prefix) = verifier.finish().unwrap();
        assert_eq!(tip.pointer.version, 2);
        assert_eq!(kel_prefix, test_digest(b"kel123"));
    }

    #[test]
    fn test_sad_chain_verifier_bad_signature_fails() {
        let (vk, _) = test_keys();
        let (_, other_sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        let err = verifier.verify_page(&[signed(&v0, &other_sk)]).unwrap_err();
        assert!(
            err.to_string().contains("Signature verification failed")
                || err.to_string().contains("signature"),
            "Expected signature error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_missing_key_fails() {
        let (_, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        // Empty keys map — no key for serial 0
        let mut verifier = SadChainVerifier::new(&v0.prefix, HashMap::new());
        let err = verifier.verify_page(&[signed(&v0, &sk)]).unwrap_err();
        assert!(
            err.to_string().contains("No establishment key"),
            "Expected missing key error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_divergent_chain() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        // Two competing v1 records (fork at version 1)
        let mut v1a = v0.clone();
        v1a.content_said = Some(test_digest(b"content_a"));
        v1a.increment().unwrap();

        let mut v1b = v0.clone();
        v1b.content_said = Some(test_digest(b"content_b"));
        v1b.increment().unwrap();

        // Sort by said ASC (as DB would)
        let mut records = vec![signed(&v1a, &sk), signed(&v1b, &sk)];
        records.sort_by(|a, b| a.pointer.said.cmp(&b.pointer.said));

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        verifier.verify_page(&[signed(&v0, &sk)]).unwrap();
        assert!(!verifier.is_divergent());

        verifier.verify_page(&records).unwrap();
        // is_divergent() reflects state after flush (triggered by finish)
        let (tip, _) = verifier.finish().unwrap();
        assert_eq!(tip.pointer.version, 1);
    }

    #[test]
    fn test_sad_chain_verifier_divergent_bad_signature_rejected() {
        let (vk, sk) = test_keys();
        let (_, bad_sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1a = v0.clone();
        v1a.content_said = Some(test_digest(b"content_a"));
        v1a.increment().unwrap();

        let mut v1b = v0.clone();
        v1b.content_said = Some(test_digest(b"content_b"));
        v1b.increment().unwrap();

        let mut records = vec![signed(&v1a, &sk), signed(&v1b, &bad_sk)];
        records.sort_by(|a, b| a.pointer.said.cmp(&b.pointer.said));

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        verifier.verify_page(&[signed(&v0, &sk)]).unwrap();

        // The divergent record with a bad signature must be rejected
        let err = verifier.verify_page(&records).unwrap_err();
        assert!(
            err.to_string().contains("Signature verification failed")
                || err.to_string().contains("signature"),
            "Expected signature error on divergent record, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_divergent_chain_linkage_verified() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        // Create a properly linked v1
        let mut v1a = v0.clone();
        v1a.content_said = Some(test_digest(b"content_a"));
        v1a.increment().unwrap();

        // Create a v1 with wrong previous (not pointing to v0)
        let mut v1b = v0.clone();
        v1b.content_said = Some(test_digest(b"content_b"));
        v1b.version = 1;
        v1b.previous = Some(test_digest(b"wrong_said"));
        v1b.derive_said().unwrap();

        let mut records = vec![signed(&v1a, &sk), signed(&v1b, &sk)];
        records.sort_by(|a, b| a.pointer.said.cmp(&b.pointer.said));

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        verifier.verify_page(&[signed(&v0, &sk)]).unwrap();
        verifier.verify_page(&records).unwrap();

        // The divergent record with bad chain linkage is rejected at flush
        let err = verifier.finish().unwrap_err();
        assert!(
            err.to_string().contains("does not match any branch tip"),
            "Expected chain linkage error on divergent record, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_divergent_across_pages() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            test_digest(b"kel123"),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1a = v0.clone();
        v1a.content_said = Some(test_digest(b"content_a"));
        v1a.increment().unwrap();

        let mut v1b = v0.clone();
        v1b.content_said = Some(test_digest(b"content_b"));
        v1b.increment().unwrap();

        // Sort by said ASC
        let (first, second) = if v1a.said < v1b.said {
            (v1a, v1b)
        } else {
            (v1b, v1a)
        };

        // Page boundary splits the two v1 records
        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        verifier
            .verify_page(&[signed(&v0, &sk), signed(&first, &sk)])
            .unwrap();

        verifier.verify_page(&[signed(&second, &sk)]).unwrap();

        // Divergence is detected when the generation is flushed at finish()
        let (tip, _) = verifier.finish().unwrap();
        assert_eq!(tip.pointer.version, 1);
    }
}
