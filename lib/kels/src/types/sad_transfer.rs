//! Paginated transfer infrastructure for SAD record chains.
//!
//! Mirrors the KEL `transfer_key_events` pattern: `PagedSadSource` / `PagedSadSink`
//! traits abstract data movement, and `transfer_sad_records` is the core private
//! function that pages through a source, optionally verifies, and sends to a sink.
//!
//! Public functions:
//! - `verify_sad_records` — verify only (NoOp sink), returns `SadRecordVerification`
//! - `forward_sad_records` — forward without verification, supports delta via `since`

use std::collections::BTreeSet;

use async_trait::async_trait;
use cesr::{Matter, Signature, VerificationKey};

use crate::{
    KelVerifier, KelsError, SadRecordVerification, SignedSadRecord,
    types::sad_record::SadRecordChain,
};

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
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
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
    client: reqwest::Client,
}

impl HttpSadSink {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
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

        let url = format!("{}/api/v1/sad/records", self.base_url);
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

// ==================== Core Transfer Function ====================

/// Page through a SAD chain from source to sink, optionally verifying.
///
/// SAD chains are simpler than KELs — no fork reordering or held-back events.
/// Divergence is detected and stored by the sink (SADStore service), not handled
/// during transfer. The transfer just pages records through faithfully.
///
/// When `verify` is true, performs structural integrity checks (SAID, chain linkage,
/// version monotonicity) and signature verification against the owner's KEL.
/// Verification requires seeing the full chain (since = None).
async fn transfer_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    verify: bool,
    kels_source: Option<&(dyn crate::PagedKelSource + Sync)>,
    page_size: usize,
    max_pages: usize,
    since: Option<&str>,
) -> Result<Option<SadRecordVerification>, KelsError> {
    if verify && since.is_some() {
        return Err(KelsError::InvalidKel(
            "Cannot use since with verification — verifier must see the full chain".to_string(),
        ));
    }

    if verify && kels_source.is_none() {
        return Err(KelsError::InvalidKel(
            "KEL source required for verification".to_string(),
        ));
    }

    let mut since: Option<String> = since.map(String::from);
    let mut all_records: Vec<SignedSadRecord> = Vec::new();
    let mut exhausted = false;

    for _ in 0..max_pages {
        let (records, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

        if records.is_empty() {
            exhausted = true;
            break;
        }

        since = records.last().map(|r| r.record.said.clone());

        if verify {
            all_records.extend(records.iter().cloned());
        }

        sink.store_page(prefix, &records).await?;

        if !has_more {
            exhausted = true;
            break;
        }
    }

    if !exhausted {
        return Err(KelsError::InvalidKel(format!(
            "SAD chain for {} exceeds max_pages limit ({}) — transfer incomplete",
            prefix, max_pages,
        )));
    }

    if !verify {
        return Ok(None);
    }

    if all_records.is_empty() {
        return Err(KelsError::EventNotFound(prefix.to_string()));
    }

    // Structural integrity verification
    let chain = SadRecordChain {
        prefix: prefix.to_string(),
        records: all_records,
    };
    chain.verify_records()?;

    let tip = chain
        .tip()
        .ok_or_else(|| KelsError::VerificationFailed("Empty chain after verify".to_string()))?;

    // Collect unique establishment serials for signature verification
    let establishment_serials: BTreeSet<u64> = chain
        .records
        .iter()
        .map(|r| r.establishment_serial)
        .collect();

    let kel_prefix = &tip.record.kel_prefix;
    let kels_source =
        kels_source.ok_or_else(|| KelsError::InvalidKel("KEL source required".to_string()))?;
    let verifier = KelVerifier::new(kel_prefix)
        .with_establishment_key_collection(establishment_serials, crate::page_size())?;

    let (kel_verification, establishment_keys) = crate::verify_key_events_with_establishment_keys(
        kel_prefix,
        kels_source,
        verifier,
        crate::page_size(),
        crate::max_pages(),
    )
    .await?;

    if kel_verification.is_divergent() {
        return Err(KelsError::Divergent);
    }

    // Verify every record's signature against its establishment key
    for stored in &chain.records {
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

    Ok(Some(SadRecordVerification::new(
        tip.record.clone(),
        tip.establishment_serial,
    )))
}

// ==================== Public API ====================

/// Verify a SAD record chain by paging through a source. Returns a verification token.
///
/// Pages through the full chain, verifies structural integrity (SAID, chain linkage,
/// version monotonicity), then verifies every record's signature against the owner's KEL.
pub async fn verify_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    kels_source: &(dyn crate::PagedKelSource + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<SadRecordVerification, KelsError> {
    transfer_sad_records(
        prefix,
        source,
        &NoOpSadSink,
        true,
        Some(kels_source),
        page_size,
        max_pages,
        None,
    )
    .await?
    .ok_or_else(|| KelsError::VerificationFailed("Verification produced no result".to_string()))
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
    transfer_sad_records(
        prefix, source, sink, false, None, page_size, max_pages, since,
    )
    .await?;
    Ok(())
}
