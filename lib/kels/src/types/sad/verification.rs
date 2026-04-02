//! SAD chain verification

use std::collections::{BTreeSet, HashMap};

use cesr::{Matter, Signature, VerificationKey};
use verifiable_storage::{Chained, SelfAddressed};

use super::pointer::SignedSadPointer;
use super::sync::PagedSadSource;
use crate::KelsError;

// ==================== Incremental Chain Verification ====================

/// Streaming structural verifier for SAD record chains.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks evolving chain state (previous SAID, version,
/// kel_prefix, kind) and collects establishment serials for later signature
/// verification against the KEL.
/// Verifier for SAD record chains. Checks structural integrity AND signatures.
///
/// Verifies incrementally per page: SAID integrity, prefix derivation (v0),
/// chain linkage, version monotonicity, kel_prefix/kind consistency, and
/// signature verification against provided establishment keys.
///
/// Used by both the transfer infrastructure (pass 2) and the repository
/// (DB chain walk). Divergence detection is tracked but not rejected —
/// the caller decides how to handle it.
pub struct SadChainVerifier {
    prefix: String,
    expected_version: u64,
    last_said: Option<String>,
    kel_prefix: Option<String>,
    kind: Option<String>,
    tip: Option<SignedSadPointer>,
    saw_any_records: bool,
    is_divergent: bool,
    establishment_keys: HashMap<u64, VerificationKey>,
}

impl SadChainVerifier {
    pub fn new(prefix: &str, establishment_keys: HashMap<u64, VerificationKey>) -> Self {
        Self {
            prefix: prefix.to_string(),
            expected_version: 0,
            last_said: None,
            kel_prefix: None,
            kind: None,
            tip: None,
            saw_any_records: false,
            is_divergent: false,
            establishment_keys,
        }
    }

    pub fn is_divergent(&self) -> bool {
        self.is_divergent
    }

    /// Verify a page of records incrementally. Carries forward state for the next page.
    pub fn verify_page(&mut self, records: &[SignedSadPointer]) -> Result<(), KelsError> {
        for stored in records {
            self.saw_any_records = true;
            let record = &stored.pointer;

            // Always verify SAID and signature, even for divergent records,
            // so the is_divergent flag is only set by cryptographically valid records.
            record.verify_said()?;

            let public_key = self
                .establishment_keys
                .get(&stored.establishment_serial)
                .ok_or_else(|| {
                    KelsError::VerificationFailed(format!(
                        "No establishment key for serial {} (record {})",
                        stored.establishment_serial, record.said
                    ))
                })?;
            let sig = Signature::from_qb64(&stored.signature)
                .map_err(|e| KelsError::VerificationFailed(format!("Invalid signature: {}", e)))?;
            public_key
                .verify(record.said.as_bytes(), &sig)
                .map_err(|_| KelsError::SignatureVerificationFailed)?;

            // Divergence: duplicate version (same version as previous record)
            if record.version + 1 == self.expected_version {
                self.is_divergent = true;
                continue;
            }

            if self.expected_version == 0 {
                record.verify_prefix()?;
            }

            if record.prefix != self.prefix {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} prefix {} doesn't match chain prefix {}",
                    record.said, record.prefix, self.prefix
                )));
            }

            if let Some(ref expected) = self.kel_prefix {
                if record.kel_prefix != *expected {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} kel_prefix {} doesn't match chain kel_prefix {}",
                        record.said, record.kel_prefix, expected
                    )));
                }
            } else {
                self.kel_prefix = Some(record.kel_prefix.clone());
            }

            if let Some(ref expected) = self.kind {
                if record.kind != *expected {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} kind {} doesn't match chain kind {}",
                        record.said, record.kind, expected
                    )));
                }
            } else {
                self.kind = Some(record.kind.clone());
            }

            if let Some(ref last) = self.last_said {
                if record.previous.as_deref() != Some(last.as_str()) {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} previous doesn't match {}",
                        record.said, last
                    )));
                }
            } else if record.previous.is_some() {
                return Err(KelsError::VerificationFailed(format!(
                    "First SAD record {} has unexpected previous",
                    record.said
                )));
            }

            if record.version != self.expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} has version {} but expected {}",
                    record.said, record.version, self.expected_version
                )));
            }

            self.last_said = Some(record.said.clone());
            self.expected_version += 1;
            self.tip = Some(stored.clone());
        }

        Ok(())
    }

    pub fn finish(self) -> Result<(SignedSadPointer, String), KelsError> {
        if !self.saw_any_records {
            return Err(KelsError::VerificationFailed(
                "Empty SAD record chain".into(),
            ));
        }

        let tip = self
            .tip
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
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<(BTreeSet<u64>, String), KelsError> {
    let mut serials = BTreeSet::new();
    let mut kel_prefix: Option<String> = None;
    let mut since: Option<String> = None;

    for _ in 0..max_pages {
        let (records, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

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

    fn signed(record: &SadPointer, signing_key: &cesr::SigningKey) -> SignedSadPointer {
        let sig = signing_key.sign(record.said.as_bytes()).unwrap();
        SignedSadPointer {
            pointer: record.clone(),
            signature: sig.qb64(),
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
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        assert!(
            verifier
                .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
                .is_ok()
        );
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn test_sad_chain_verifier_empty_fails() {
        let (vk, _) = test_keys();
        let verifier = SadChainVerifier::new("Etest", keys_map(&vk));
        assert!(verifier.finish().is_err());
    }

    #[test]
    fn test_sad_chain_verifier_broken_linkage_fails() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        v1.version = 1;
        v1.previous = Some("Ewrong_said".to_string());
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        let err = verifier
            .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
            .unwrap_err();
        assert!(
            err.to_string().contains("previous doesn't match"),
            "Expected chain linkage error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_inconsistent_kind_fails() {
        let (vk, sk) = test_keys();
        let v0 = SadPointer::create(
            "Ekel123".to_string(),
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
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();
        v1.version = 5;
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix, keys_map(&vk));
        let err = verifier
            .verify_page(&[signed(&v0, &sk), signed(&v1, &sk)])
            .unwrap_err();
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
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();
        let mut v2 = v1.clone();
        v2.content_said = Some("Econtent2".to_string());
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
        assert_eq!(kel_prefix, "Ekel123");
    }

    #[test]
    fn test_sad_chain_verifier_bad_signature_fails() {
        let (vk, _) = test_keys();
        let (_, other_sk) = test_keys();
        let v0 = SadPointer::create(
            "Ekel123".to_string(),
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
            "Ekel123".to_string(),
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
}
