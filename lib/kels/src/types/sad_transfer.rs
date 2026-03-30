//! Paginated transfer infrastructure for SAD record chains.
//!
//! Mirrors the KEL `transfer_key_events` pattern: `PagedSadSource` / `PagedSadSink`
//! traits abstract data movement, and `transfer_sad_records` is the core private
//! function that pages through a source, optionally verifies structure, and sends
//! to a sink.
//!
//! Public functions:
//! - `verify_sad_records` — two-pass verify, returns `SadRecordVerification`
//! - `forward_sad_records` — forward without verification, supports delta via `since`
//!
//! Verification uses a two-pass approach to stay O(page_size) in memory:
//! - Pass 1: `transfer_sad_records` with structural verifier + NoOp sink (collects serials)
//! - Between: verify KEL, collect establishment keys for those serials
//! - Pass 2: `transfer_sad_records` without verifier + NoOp sink (signature checks)

use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use cesr::{Matter, Signature, VerificationKey};
use verifiable_storage::{Chained, SelfAddressed};

use crate::{KelVerifier, KelsError, SadRecordVerification, SignedSadRecord};

// ==================== Source / Sink Traits ====================

/// Source of paginated signed SAD records (e.g., HTTP client).
///
/// Implementations must return records in `version ASC, said ASC` order.
/// The `bool` return value indicates whether more pages are available (`has_more`).
#[async_trait]
pub trait PagedSadSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<SignedSadRecord>, bool), KelsError>;
}

/// Destination for signed SAD records (e.g., local SADStore).
#[async_trait]
pub trait PagedSadSink: Send + Sync {
    async fn store_page(&self, prefix: &str, records: &[SignedSadRecord]) -> Result<(), KelsError>;
}

// ==================== Sink Implementations ====================

/// No-op sink that discards records. Used for verify-only flows.
struct NoOpSadSink;

#[async_trait]
impl PagedSadSink for NoOpSadSink {
    async fn store_page(
        &self,
        _prefix: &str,
        _records: &[SignedSadRecord],
    ) -> Result<(), KelsError> {
        Ok(())
    }
}

// ==================== HTTP Source / Sink ====================

/// HTTP-based source of paginated signed SAD records.
pub struct HttpSadSource {
    base_url: String,
    client: reqwest::Client,
}

impl HttpSadSource {
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait]
impl PagedSadSource for HttpSadSource {
    async fn fetch_page(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<SignedSadRecord>, bool), KelsError> {
        let mut url = format!(
            "{}/api/v1/sad/chain/{}?limit={}",
            self.base_url, prefix, limit
        );
        if let Some(since_said) = since {
            url.push_str(&format!("&since={}", since_said));
        }

        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            let page: crate::SadRecordPage = resp.json().await?;
            Ok((page.records, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok((Vec::new(), false))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(
                text,
                crate::types::ErrorCode::InternalError,
            ))
        }
    }
}

/// HTTP-based sink that submits SAD records to a SADStore service.
pub struct HttpSadSink {
    base_url: String,
    repair: bool,
    client: reqwest::Client,
}

impl HttpSadSink {
    fn build(base_url: &str, repair: bool) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            repair,
            client,
        })
    }

    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        Self::build(base_url, false)
    }

    /// Create a repair sink that submits with `?repair=true`.
    pub fn new_repair(base_url: &str) -> Result<Self, KelsError> {
        Self::build(base_url, true)
    }
}

#[async_trait]
impl PagedSadSink for HttpSadSink {
    async fn store_page(
        &self,
        _prefix: &str,
        records: &[SignedSadRecord],
    ) -> Result<(), KelsError> {
        if records.is_empty() {
            return Ok(());
        }

        let url = if self.repair {
            format!("{}/api/v1/sad/records?repair=true", self.base_url)
        } else {
            format!("{}/api/v1/sad/records", self.base_url)
        };
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(
                text,
                crate::types::ErrorCode::InternalError,
            ))
        }
    }
}

// ==================== Incremental Chain Verification ====================

/// Streaming structural verifier for SAD record chains.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks evolving chain state (previous SAID, version,
/// kel_prefix, kind) and collects establishment serials for later signature
/// verification against the KEL.
struct SadChainVerifier {
    prefix: String,
    expected_version: u64,
    last_said: Option<String>,
    kel_prefix: Option<String>,
    kind: Option<String>,
    establishment_serials: BTreeSet<u64>,
    tip: Option<SignedSadRecord>,
    saw_any_records: bool,
}

impl SadChainVerifier {
    fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            expected_version: 0,
            last_said: None,
            kel_prefix: None,
            kind: None,
            establishment_serials: BTreeSet::new(),
            tip: None,
            saw_any_records: false,
        }
    }

    /// Verify a page of records incrementally. Carries forward state for the next page.
    fn verify_page(&mut self, records: &[SignedSadRecord]) -> Result<(), KelsError> {
        for stored in records {
            self.saw_any_records = true;
            let record = &stored.record;
            record.verify_said()?;

            // Verify prefix derivation on v0 — ensures the prefix was correctly
            // computed from the inception record content, not fabricated.
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
            self.establishment_serials
                .insert(stored.establishment_serial);
            self.tip = Some(stored.clone());
        }

        Ok(())
    }

    fn finish(self) -> Result<(BTreeSet<u64>, SignedSadRecord, String), KelsError> {
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

        Ok((self.establishment_serials, tip, kel_prefix))
    }
}

// ==================== Core Transfer Function ====================

/// Page through a SAD chain from source to sink, optionally verifying structure.
///
/// Mirrors `transfer_key_events`: takes an optional structural verifier that
/// verifies incrementally per page. SAD chains are simpler than KELs — no fork
/// reordering or held-back events. Divergence is detected and stored by the sink
/// (SADStore service), not handled during transfer.
///
/// When `verifier` is Some, structural checks run inline (SAID, chain linkage,
/// version monotonicity, consistency). Signature verification is NOT done here —
/// it requires KEL keys from a separate source and happens in a second pass
/// in `verify_sad_records`.
async fn transfer_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    mut verifier: Option<&mut SadChainVerifier>,
    page_size: usize,
    max_pages: usize,
    since: Option<&str>,
) -> Result<(), KelsError> {
    if verifier.is_some() && since.is_some() {
        return Err(KelsError::InvalidKel(
            "Cannot use since with verification — verifier must see the full chain".to_string(),
        ));
    }

    let mut since: Option<String> = since.map(String::from);

    for _ in 0..max_pages {
        let (records, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

        if records.is_empty() {
            return Ok(());
        }

        since = records.last().map(|r| r.record.said.clone());

        if let Some(ref mut v) = verifier {
            v.verify_page(&records)?;
        }

        sink.store_page(prefix, &records).await?;

        if !has_more {
            return Ok(());
        }
    }

    Err(KelsError::InvalidKel(format!(
        "SAD chain for {} exceeds max_pages limit ({}) — transfer incomplete",
        prefix, max_pages,
    )))
}

/// Verify signatures for a page of SAD records against pre-collected establishment keys.
fn verify_page_signatures(
    records: &[SignedSadRecord],
    establishment_keys: &HashMap<u64, String>,
) -> Result<(), KelsError> {
    for stored in records {
        let public_key_qb64 = establishment_keys
            .get(&stored.establishment_serial)
            .ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "No establishment key for serial {} (record {})",
                    stored.establishment_serial, stored.record.said
                ))
            })?;

        let public_key = VerificationKey::from_qb64(public_key_qb64)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid public key: {}", e)))?;

        let sig = Signature::from_qb64(&stored.signature)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        public_key
            .verify(stored.record.said.as_bytes(), &sig)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;
    }
    Ok(())
}

// ==================== Public API ====================

/// Verify a SAD record chain by paging through a source. Returns a verification token.
///
/// Two-pass verification with O(page_size) memory:
/// 1. Structure: `transfer_sad_records` with verifier + NoOp sink (SAID, chain linkage,
///    version monotonicity, consistency) — collects establishment serials.
/// 2. KEL verification with collected serials to obtain establishment keys.
/// 3. Signatures: page through again, verify each record's signature against the keys.
pub async fn verify_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    kels_source: &(dyn crate::PagedKelSource + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<SadRecordVerification, KelsError> {
    // Pass 1: structural verification via transfer_sad_records with verifier + NoOp sink
    let mut verifier = SadChainVerifier::new(prefix);
    transfer_sad_records(
        prefix,
        source,
        &NoOpSadSink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;

    let (establishment_serials, tip, kel_prefix) = verifier.finish()?;

    // Between: verify KEL and collect establishment keys
    let kel_verifier = KelVerifier::new(&kel_prefix)
        .with_establishment_key_collection(establishment_serials, crate::page_size())?;

    let (kel_verification, establishment_keys) =
        crate::verify_key_events_collecting_establishment_keys(
            &kel_prefix,
            kels_source,
            kel_verifier,
            crate::page_size(),
            crate::max_pages(),
        )
        .await?;

    if kel_verification.is_divergent() {
        return Err(KelsError::Divergent);
    }

    // Pass 2: signature verification — page through again with keys in hand
    let mut since: Option<String> = None;

    for _ in 0..max_pages {
        let (records, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

        if records.is_empty() {
            break;
        }

        since = records.last().map(|r| r.record.said.clone());
        verify_page_signatures(&records, &establishment_keys)?;

        if !has_more {
            break;
        }
    }

    Ok(SadRecordVerification::new(
        tip.record,
        tip.establishment_serial,
    ))
}

/// Forward SAD records from source to sink without verification. Supports delta via `since`.
///
/// Used by gossip sync to replicate chains between nodes.
pub async fn forward_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&str>,
) -> Result<(), KelsError> {
    transfer_sad_records(prefix, source, sink, None, page_size, max_pages, since).await
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::*;
    use crate::SadRecord;

    fn stored(record: SadRecord) -> SignedSadRecord {
        SignedSadRecord {
            record,
            signature: "test_sig".to_string(),
            establishment_serial: 0,
        }
    }

    #[test]
    fn test_sad_chain_verifier_valid_chain() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        assert!(verifier.verify_page(&[stored(v0), stored(v1)]).is_ok());
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn test_sad_chain_verifier_empty_fails() {
        let verifier = SadChainVerifier::new("Etest");
        let err = verifier.finish();
        assert!(err.is_err());
    }

    #[test]
    fn test_sad_chain_verifier_broken_linkage_fails() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        v1.version = 1;
        v1.previous = Some("Ewrong_said".to_string());
        v1.derive_said().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        let err = verifier.verify_page(&[stored(v0), stored(v1)]).unwrap_err();
        assert!(
            err.to_string().contains("previous doesn't match"),
            "Expected chain linkage error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_inconsistent_kind_fails() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.kind = "kels/v1/other-kind".to_string();
        v1.increment().unwrap();

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        let err = verifier.verify_page(&[stored(v0), stored(v1)]).unwrap_err();
        assert!(
            err.to_string().contains("kind"),
            "Expected kind mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_wrong_version_fails() {
        let v0 = SadRecord::create(
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

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        let err = verifier.verify_page(&[stored(v0), stored(v1)]).unwrap_err();
        assert!(
            err.to_string().contains("has version 5 but expected 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_chain_verifier_multi_page() {
        let v0 = SadRecord::create(
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

        let mut verifier = SadChainVerifier::new(&v0.prefix);
        assert!(verifier.verify_page(&[stored(v0)]).is_ok());
        assert!(verifier.verify_page(&[stored(v1), stored(v2)]).is_ok());

        let (serials, tip, kel_prefix) = verifier.finish().unwrap();
        assert!(serials.contains(&0));
        assert_eq!(tip.record.version, 2);
        assert_eq!(kel_prefix, "Ekel123");
    }

    #[test]
    fn test_sad_chain_verifier_collects_establishment_serials() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();

        let records = vec![
            stored(v0),
            SignedSadRecord {
                record: v1,
                signature: "test_sig".to_string(),
                establishment_serial: 3,
            },
        ];

        let mut verifier = SadChainVerifier::new(&records[0].record.prefix);
        assert!(verifier.verify_page(&records).is_ok());

        let (serials, _, _) = verifier.finish().unwrap();
        assert!(serials.contains(&0));
        assert!(serials.contains(&3));
        assert_eq!(serials.len(), 2);
    }
}
