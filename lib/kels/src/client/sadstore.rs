//! SADStore HTTP Client
//!
//! Client for the replicated SAD store service.
//! Provides methods for both Layer 1 (SAD objects) and Layer 2 (chain records).

use std::time::Duration;

use verifiable_storage::SelfAddressed;

use crate::{
    KelsError, SadPointerPage, SadPointerRepairPage, SadPointerVerification,
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
    pub async fn post_sad_object(&self, object: &serde_json::Value) -> Result<String, KelsError> {
        object.verify_said().map_err(|e| {
            KelsError::VerificationFailed(format!("Object SAID verification failed: {}", e))
        })?;

        let said = object.get_said().to_string();

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
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Check if a self-addressed object exists by SAID (HEAD check, no data transfer).
    pub async fn sad_object_exists(&self, said: &str) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/sad/{}/exists", self.base_url, said);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    /// Retrieve a self-addressed JSON object by SAID.
    pub async fn get_sad_object(&self, said: &str) -> Result<serde_json::Value, KelsError> {
        let url = format!("{}/api/v1/sad/{}", self.base_url, said);
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(said.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// List SAD object SAIDs (paginated, authenticated). Used for bootstrap and anti-entropy.
    pub async fn fetch_sad_objects(
        &self,
        signer: &dyn crate::PeerSigner,
        cursor: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<crate::SadObjectListResponse, KelsError> {
        let request = crate::PaginatedSelfAddressedRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: crate::generate_nonce().to_string(),
            cursor: cursor.cloned(),
            limit: Some(limit),
        };
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
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    // === Layer 2: Chain Records ===

    /// Submit signed SAD records.
    pub async fn submit_sad_pointer(
        &self,
        records: &[crate::SignedSadPointer],
    ) -> Result<(), KelsError> {
        let url = format!("{}/api/v1/sad/pointers", self.base_url);
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Submit signed SAD records as a repair operation.
    ///
    /// Truncates all records at version >= the first record's version, then inserts
    /// the batch. Used to resolve divergent chains.
    pub async fn repair_sad_pointer(
        &self,
        records: &[crate::SignedSadPointer],
    ) -> Result<(), KelsError> {
        let url = format!("{}/api/v1/sad/pointers?repair=true", self.base_url);
        let resp = self.client.post(&url).json(records).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
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
        prefix: &str,
        since: Option<&str>,
    ) -> Result<SadPointerPage, KelsError> {
        let mut url = format!("{}/api/v1/sad/pointers/{}", self.base_url, prefix);
        if let Some(since_said) = since {
            url.push_str(&format!("?since={}", since_said));
        }

        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Get the effective SAID and divergence status for a chain prefix.
    /// Returns `(said, is_divergent)`. Used for sync comparison.
    pub async fn fetch_sad_pointer_effective_said(
        &self,
        prefix: &cesr::Digest,
    ) -> Result<Option<(String, bool)>, KelsError> {
        let url = format!(
            "{}/api/v1/sad/pointers/{}/effective-said",
            self.base_url, prefix
        );
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            let body: EffectiveSaidResponse = resp.json().await?;
            Ok(Some((body.said.to_string(), body.divergent)))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Check if a pointer with the given SAID exists on this SADStore.
    pub async fn sad_pointer_exists(&self, said: &str) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/sad/pointers/exists/{}", self.base_url, said);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    /// List SAD chain prefixes (paginated, authenticated). Used for bootstrap and anti-entropy.
    pub async fn fetch_sad_pointer_prefixes(
        &self,
        signer: &dyn crate::PeerSigner,
        cursor: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<crate::PrefixListResponse, KelsError> {
        let request = crate::PaginatedSelfAddressedRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: crate::generate_nonce().to_string(),
            cursor: cursor.cloned(),
            limit: Some(limit),
        };
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
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch repairs for a chain prefix, paginated.
    pub async fn fetch_sad_pointer_repairs(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<SadPointerRepairPage, KelsError> {
        let url = format!(
            "{}/api/v1/sad/pointers/{}/repairs?limit={}&offset={}",
            self.base_url, prefix, limit, offset
        );
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch archived records for a specific repair, paginated.
    pub async fn fetch_sad_pointer_repair_records(
        &self,
        prefix: &str,
        repair_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<SadPointerPage, KelsError> {
        let url = format!(
            "{}/api/v1/sad/pointers/{}/repairs/{}/records?limit={}&offset={}",
            self.base_url, prefix, repair_said, limit, offset
        );
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(repair_said.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Verify a SAD record chain and return a verification token.
    ///
    /// Pages through the full chain, verifies structural integrity (SAID, chain linkage,
    /// version monotonicity, consistent kel_prefix/kind), then verifies every
    /// record's signature against the owner's KEL at each record's establishment serial.
    ///
    /// The `kels_client` is used to fetch and verify the owner's KEL for
    /// signature verification.
    pub async fn verify_sad_pointer(
        &self,
        prefix: &cesr::Digest,
        kels_client: &crate::KelsClient,
    ) -> Result<SadPointerVerification, KelsError> {
        crate::verify_sad_pointer(
            prefix,
            &self.as_sad_source()?,
            &kels_client.as_kel_source()?,
            crate::page_size(),
            crate::max_pages(),
        )
        .await
    }
}
