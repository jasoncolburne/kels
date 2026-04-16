//! Paginated transfer infrastructure for SAD pointer chains
//!
//! Mirrors the KEL `transfer_key_events` pattern: `PagedSadSource` / `PagedSadSink`
//! traits abstract data movement, and `transfer_sad_pointer` is the core private
//! function that pages through a source, optionally verifies structure, and sends
//! to a sink.
//!
//! Public functions:
//! - `verify_sad_pointer` — structural verify (no signatures with anchoring model)
//! - `forward_sad_pointer` — forward without verification, supports delta via `since`

use async_trait::async_trait;

use super::super::error::ErrorCode;
use super::pointer::{SadPointer, SadPointerPage, SadPointerVerification};
use super::verification::SadChainVerifier;
use crate::{KelsError, error::read_error_body};

// ==================== Source / Sink Traits ====================

/// Source of paginated SAD pointers (e.g., HTTP client).
///
/// Implementations must return pointers in `version ASC, said ASC` order.
#[async_trait]
pub trait PagedSadSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<SadPointer>, bool), KelsError>;
}

/// Destination for SAD pointers (e.g., local SADStore).
#[async_trait]
pub trait PagedSadSink: Send + Sync {
    async fn store_page(&self, pointers: &[SadPointer]) -> Result<(), KelsError>;
}

// ==================== Sink Implementations ====================

/// No-op sink that discards pointers. Used for verify-only flows.
struct NoOpSadSink;

#[async_trait]
impl PagedSadSink for NoOpSadSink {
    async fn store_page(&self, _pointers: &[SadPointer]) -> Result<(), KelsError> {
        Ok(())
    }
}

// ==================== HTTP Source / Sink ====================

/// HTTP-based source of paginated SAD pointers.
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
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<SadPointer>, bool), KelsError> {
        let url = format!("{}/api/v1/sad/pointers/fetch", self.base_url);
        let body = crate::SadPointerPageRequest {
            prefix: *prefix,
            since: since.copied(),
            limit: Some(limit),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let page: SadPointerPage = resp.json().await?;
            Ok((page.pointers, page.has_more))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok((Vec::new(), false))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

/// HTTP-based sink that submits SAD pointers to a SADStore service.
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
    async fn store_page(&self, pointers: &[SadPointer]) -> Result<(), KelsError> {
        if pointers.is_empty() {
            return Ok(());
        }

        let url = if self.repair {
            format!("{}/api/v1/sad/pointers?repair=true", self.base_url)
        } else {
            format!("{}/api/v1/sad/pointers", self.base_url)
        };
        let resp = self.client.post(&url).json(pointers).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }
}

// ==================== Core Transfer Function ====================

/// Page through a SAD chain from source to sink, optionally verifying.
async fn transfer_sad_pointer<'a>(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    mut verifier: Option<&mut SadChainVerifier<'a>>,
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    if verifier.is_some() && since.is_some() {
        return Err(KelsError::InvalidKel(
            "Cannot use since with verification — verifier must see the full chain".to_string(),
        ));
    }

    let mut since: Option<cesr::Digest256> = since.cloned();

    for _ in 0..max_pages {
        let (pointers, has_more) = source.fetch_page(prefix, since.as_ref(), page_size).await?;

        if pointers.is_empty() {
            return Ok(());
        }

        since = pointers.last().map(|r| r.said);

        if let Some(ref mut v) = verifier {
            v.verify_page(&pointers).await?;
        }

        sink.store_page(&pointers).await?;

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

/// Verify a SAD pointer chain by paging through a source. Returns a verification token.
///
/// Structural + policy verification. Verifies SAID, prefix, topic, chain linkage,
/// and write_policy authorization via the provided `PolicyChecker`.
pub async fn verify_sad_pointer(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    checker: &(dyn super::verification::PolicyChecker + Sync),
    page_size: usize,
    max_pages: usize,
) -> Result<SadPointerVerification, KelsError> {
    let mut verifier = SadChainVerifier::new(prefix, checker);
    transfer_sad_pointer(
        prefix,
        source,
        &NoOpSadSink,
        Some(&mut verifier),
        page_size,
        max_pages,
        None,
    )
    .await?;

    verifier.finish().await
}

/// Forward SAD pointers from source to sink without verification. Supports delta via `since`.
pub async fn forward_sad_pointer(
    prefix: &cesr::Digest256,
    source: &(dyn PagedSadSource + Sync),
    sink: &(dyn PagedSadSink + Sync),
    page_size: usize,
    max_pages: usize,
    since: Option<&cesr::Digest256>,
) -> Result<(), KelsError> {
    transfer_sad_pointer(prefix, source, sink, None, page_size, max_pages, since).await
}
