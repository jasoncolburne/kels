//! SADStore HTTP Client
//!
//! Client for the replicated SAD store service.
//! Provides methods for both Layer 1 (SAD objects) and Layer 2 (chain records).

use std::time::Duration;

use verifiable_storage::SelfAddressed;

use crate::{
    KelsError, SadPointerPage, SadPointerRepairPage, SadPointerVerification,
    error::read_error_body,
    types::{EffectiveSaidResponse, ErrorCode},
};

/// SADStore API Client.
#[derive(Clone)]
pub struct SadStoreClient {
    base_url: String,
    client: reqwest::Client,
}

impl SadStoreClient {
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(SadStoreClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create an `HttpSadSource` for this client's chain endpoint.
    pub fn as_sad_source(&self) -> Result<crate::HttpSadSource, KelsError> {
        crate::HttpSadSource::new(&self.base_url)
    }

    /// Create an `HttpSadSink` for this client's records endpoint.
    pub fn as_sad_sink(&self) -> Result<crate::HttpSadSink, KelsError> {
        crate::HttpSadSink::new(&self.base_url)
    }

    /// Create an `HttpSadSink` that submits with `?repair=true`.
    pub fn as_sad_repair_sink(&self) -> Result<crate::HttpSadSink, KelsError> {
        crate::HttpSadSink::new_repair(&self.base_url)
    }

    pub async fn health(&self) -> Result<String, KelsError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok("OK".to_string())
        } else {
            Err(KelsError::ServerError(
                format!("Health check failed: {}", resp.status()),
                ErrorCode::InternalError,
            ))
        }
    }

    // === Layer 1: SAD Object Store ===

    /// Store a self-addressed JSON object. Returns the SAID.
    ///
    /// The object must have a valid `said` field. The SAID is verified by
    /// both the client (before sending) and the server (on receipt).
    pub async fn post_sad_object(
        &self,
        object: &serde_json::Value,
    ) -> Result<cesr::Digest256, KelsError> {
        object.verify_said().map_err(|e| {
            KelsError::VerificationFailed(format!("Object SAID verification failed: {}", e))
        })?;

        let said = object.get_said();

        let url = format!("{}/api/v1/sad", self.base_url);
        let body = serde_json::to_vec(object)?;

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(said)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Check if a self-addressed object exists by SAID.
    pub async fn sad_object_exists(&self, said: &cesr::Digest256) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/sad/exists", self.base_url);
        let body = crate::SadFetchRequest {
            said: *said,
            disclosure: None,
        };
        let resp = self.client.post(&url).json(&body).send().await?;
        Ok(resp.status().is_success())
    }

    /// Retrieve a self-addressed JSON object by SAID.
    ///
    /// Uses `POST /api/v1/sad/fetch` to keep the SAID out of the URL path,
    /// preventing leakage via access logs, proxies, and intermediaries.
    pub async fn get_sad_object(
        &self,
        said: &cesr::Digest256,
    ) -> Result<serde_json::Value, KelsError> {
        let url = format!("{}/api/v1/sad/fetch", self.base_url);
        let body = crate::SadFetchRequest {
            said: *said,
            disclosure: None,
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(said.to_string()))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Retrieve a self-addressed JSON object with disclosure expansion.
    ///
    /// Like `get_sad_object`, but applies a disclosure DSL expression to
    /// selectively expand compacted nested SADs in the response.
    pub async fn get_sad_object_with_disclosure(
        &self,
        said: &cesr::Digest256,
        disclosure: &str,
    ) -> Result<serde_json::Value, KelsError> {
        let url = format!("{}/api/v1/sad/fetch", self.base_url);
        let body = crate::SadFetchRequest {
            said: *said,
            disclosure: Some(disclosure.to_string()),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(said.to_string()))
        } else if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            let text = read_error_body(resp).await?;
            Err(KelsError::InvalidDisclosure(text))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// List SAD object SAIDs (paginated, authenticated). Used for bootstrap and anti-entropy.
    pub async fn fetch_sad_objects(
        &self,
        signer: &dyn crate::PeerSigner,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<crate::SadObjectListResponse, KelsError> {
        let request = crate::PaginatedSelfAddressedRequest::create(
            crate::generate_nonce(),
            cursor.cloned(),
            Some(limit),
        )?;
        let signed = crate::sign_request(signer, &request).await?;
        let resp = self
            .client
            .post(format!("{}/api/v1/sad/saids", self.base_url))
            .json(&signed)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    // === Layer 2: Chain Records ===

    /// Submit signed SAD records.
    pub async fn submit_sad_pointer(&self, records: &[crate::SadPointer]) -> Result<(), KelsError> {
        let url = format!("{}/api/v1/sad/pointers", self.base_url);
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Submit signed SAD records as a repair operation.
    ///
    /// Truncates all records at version >= the first record's version, then inserts
    /// the batch. Used to resolve divergent chains.
    pub async fn repair_sad_pointer(&self, records: &[crate::SadPointer]) -> Result<(), KelsError> {
        let url = format!("{}/api/v1/sad/pointers?repair=true", self.base_url);
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch a page of chain records by prefix.
    ///
    /// `since` is an effective SAID cursor — returns records after this SAID's
    /// position. If the SAID is not found (e.g. synthetic divergent SAID), the
    /// server returns the full chain.
    pub async fn fetch_sad_pointer(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
    ) -> Result<SadPointerPage, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/fetch", self.base_url);
        let body = crate::SadPointerPageRequest {
            prefix: *prefix,
            since: since.copied(),
            limit: None,
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Get the effective SAID and divergence status for a chain prefix.
    /// Returns `(said, is_divergent)`. Used for sync comparison.
    pub async fn fetch_sad_pointer_effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(String, bool)>, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/effective-said", self.base_url);
        let body = crate::SadPointerEffectiveSaidRequest { prefix: *prefix };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let body: EffectiveSaidResponse = resp.json().await?;
            Ok(Some((body.said.to_string(), body.divergent)))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Check if a pointer with the given SAID exists on this SADStore.
    pub async fn sad_pointer_exists(&self, said: &cesr::Digest256) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/exists", self.base_url);
        let body = crate::SadFetchRequest {
            said: *said,
            disclosure: None,
        };
        let resp = self.client.post(&url).json(&body).send().await?;
        Ok(resp.status().is_success())
    }

    /// List SAD chain prefixes (paginated, authenticated). Used for bootstrap and anti-entropy.
    pub async fn fetch_sad_pointer_prefixes(
        &self,
        signer: &dyn crate::PeerSigner,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<crate::PrefixListResponse, KelsError> {
        let request = crate::PaginatedSelfAddressedRequest::create(
            crate::generate_nonce(),
            cursor.cloned(),
            Some(limit),
        )?;
        let signed = crate::sign_request(signer, &request).await?;
        let resp = self
            .client
            .post(format!("{}/api/v1/sad/pointers/prefixes", self.base_url))
            .json(&signed)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch repairs for a chain prefix, paginated.
    pub async fn fetch_sad_pointer_repairs(
        &self,
        prefix: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<SadPointerRepairPage, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/repairs", self.base_url);
        let body = crate::SadRepairsRequest {
            prefix: *prefix,
            limit: Some(limit),
            offset: Some(offset),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch archived records for a specific repair, paginated.
    pub async fn fetch_sad_pointer_repair_records(
        &self,
        prefix: &cesr::Digest256,
        repair_said: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<SadPointerPage, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/repairs/records", self.base_url);
        let body = crate::SadRepairPageRequest {
            prefix: *prefix,
            said: *repair_said,
            limit: Some(limit),
            offset: Some(offset),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(repair_said.to_string()))
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Verify a SAD pointer chain and return a verification token.
    ///
    /// Single-pass structural verification: SAID, chain linkage, version
    /// monotonicity, consistent write_policy/topic. No signature verification —
    /// authorization is via the anchoring model (consumer-side).
    pub async fn verify_sad_pointer(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<SadPointerVerification, KelsError> {
        crate::verify_sad_pointer(
            prefix,
            &self.as_sad_source()?,
            crate::page_size(),
            crate::max_pages(),
        )
        .await
    }
}
