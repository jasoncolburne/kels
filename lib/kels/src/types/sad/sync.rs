//! Paginated transfer infrastructure for SAD record chains
//!
//! Mirrors the KEL `transfer_key_events` pattern: `PagedSadSource` / `PagedSadSink`
//! traits abstract data movement, and `transfer_sad_records` is the core private
//! function that pages through a source, optionally verifies structure, and sends
//! to a sink.
//!
//! Public functions:
//! - `verify_sad_records` — two-pass verify, returns `SadPointerVerification`
//! - `forward_sad_records` — forward without verification, supports delta via `since`
//!
//! Verification uses a two-pass approach to stay O(page_size) in memory:
//! - Pass 1: `transfer_sad_records` with structural verifier + NoOp sink (collects serials)
//! - Between: verify KEL, collect establishment keys for those serials
//! - Pass 2: `transfer_sad_records` without verifier + NoOp sink (signature checks)

use async_trait::async_trait;

use super::super::error::ErrorCode;
use super::pointer::{SadPointerPage, SignedSadPointer};
use super::verification::{SadChainVerifier, collect_establishment_serials};
use crate::{KelVerifier, KelsError, SadPointerVerification};

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
    ) -> Result<(Vec<SignedSadPointer>, bool), KelsError>;
}

/// Destination for signed SAD records (e.g., local SADStore).
#[async_trait]
pub trait PagedSadSink: Send + Sync {
    async fn store_page(&self, records: &[SignedSadPointer]) -> Result<(), KelsError>;
}

// ==================== Sink Implementations ====================

/// No-op sink that discards records. Used for verify-only flows.
struct NoOpSadSink;

#[async_trait]
impl PagedSadSink for NoOpSadSink {
    async fn store_page(&self, _records: &[SignedSadPointer]) -> Result<(), KelsError> {
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
    ) -> Result<(Vec<SignedSadPointer>, bool), KelsError> {
        let mut url = format!(
            "{}/api/v1/sad/pointers/{}?limit={}",
            self.base_url, prefix, limit
        );
        if let Some(since_said) = since {
            url.push_str(&format!("&since={}", since_said));
        }

        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            let page: SadPointerPage = resp.json().await?;
            Ok((page.pointers, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok((Vec::new(), false))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
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
    async fn store_page(&self, records: &[SignedSadPointer]) -> Result<(), KelsError> {
        if records.is_empty() {
            return Ok(());
        }

        let url = if self.repair {
            format!("{}/api/v1/sad/pointers?repair=true", self.base_url)
        } else {
            format!("{}/api/v1/sad/pointers", self.base_url)
        };
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

// ==================== Core Transfer Function ====================

/// Page through a SAD chain from source to sink, optionally verifying.
///
/// When `verifier` is provided, full structural + signature checks run inline
/// per page. The verifier must see the full chain (no `since` with verification).
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

        since = records.last().map(|r| r.pointer.said.clone());

        if let Some(ref mut v) = verifier {
            v.verify_page(&records)?;
        }

        sink.store_page(&records).await?;

        if !has_more {
            return Ok(());
        }
    }

    Err(KelsError::InvalidKel(format!(
        "SAD chain for {} exceeds max_pages limit ({}) — transfer incomplete",
        prefix, max_pages,
    )))
}

// ==================== Public API ====================

/// Verify a SAD record chain by paging through a source. Returns a verification token.
///
/// Two-pass verification with O(page_size) memory:
/// 1. Collect establishment serials by paging through the chain.
/// 2. Verify KEL with collected serials to obtain establishment keys.
/// 3. Full verification: page through again with `SadChainVerifier` (structure + signatures).
pub async fn verify_sad_records(
    prefix: &str,
    source: &(dyn PagedSadSource + Sync),
    kels_source: &(dyn crate::PagedKelSource + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<SadPointerVerification, KelsError> {
    // Pass 1: collect establishment serials
    let (establishment_serials, kel_prefix) =
        collect_establishment_serials(prefix, source, page_size, max_pages).await?;

    // Between: verify KEL and collect establishment keys
    let kel_verifier = KelVerifier::new(&kel_prefix)
        .with_establishment_key_collection(establishment_serials, crate::max_collected_keys())?;

    let (kel_verification, establishment_keys): (
        crate::KelVerification,
        std::collections::HashMap<u64, cesr::VerificationKey>,
    ) = crate::verify_key_events_collecting_establishment_keys(
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

    // Pass 2: full verification (structure + signatures) with keys
    let mut verifier = SadChainVerifier::new(prefix, establishment_keys);
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

    let (tip, _kel_prefix) = verifier.finish()?;

    Ok(SadPointerVerification::new(
        tip.pointer,
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
