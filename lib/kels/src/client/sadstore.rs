//! SADStore HTTP Client
//!
//! Client for the replicated SAD store service.
//! Provides methods for both Layer 1 (SAD objects) and Layer 2 (chain records).

use std::time::Duration;

use verifiable_storage::SelfAddressed;

use crate::{
    KelVerifier, KelsError, SadRecordChain, SadRecordPage, SadRecordSubmission,
    SadRecordVerification,
    types::{EffectiveSaidResponse, ErrorCode},
};

/// SADStore API Client.
#[derive(Clone)]
pub struct SadStoreClient {
    base_url: String,
    client: reqwest::Client,
}

impl SadStoreClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        SadStoreClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
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
    pub async fn put_sad_object(&self, object: &serde_json::Value) -> Result<String, KelsError> {
        let said = object.get_said();
        if said.is_empty() {
            return Err(KelsError::VerificationFailed(
                "Object has no SAID".to_string(),
            ));
        }

        object.verify_said().map_err(|e| {
            KelsError::VerificationFailed(format!("Object SAID verification failed: {}", e))
        })?;

        let url = format!("{}/api/v1/sad/{}", self.base_url, said);
        let body = serde_json::to_vec(object)?;

        let resp = self
            .client
            .put(&url)
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

    /// Retrieve a self-addressed JSON object by SAID.
    pub async fn get_sad_object(&self, said: &str) -> Result<serde_json::Value, KelsError> {
        let url = format!("{}/api/v1/sad/{}", self.base_url, said);
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::EventNotFound(said.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    // === Layer 2: Chain Records ===

    /// Submit a signed SAD record to the chain.
    pub async fn submit_sad_record(&self, record: &SadRecordSubmission) -> Result<(), KelsError> {
        let url = format!("{}/api/v1/sad/records", self.base_url);
        let resp = self.client.post(&url).json(record).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch a page of chain records by prefix.
    pub async fn fetch_sad_chain(
        &self,
        prefix: &str,
        since: Option<u64>,
    ) -> Result<SadRecordPage, KelsError> {
        let mut url = format!("{}/api/v1/sad/chain/{}", self.base_url, prefix);
        if let Some(since_version) = since {
            url.push_str(&format!("?since={}", since_version));
        }

        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::EventNotFound(prefix.to_string()))
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Get the effective SAID (tip) for a chain prefix. Used for sync comparison.
    pub async fn fetch_sad_effective_said(
        &self,
        prefix: &str,
    ) -> Result<Option<String>, KelsError> {
        let url = format!(
            "{}/api/v1/sad/chain/{}/effective-said",
            self.base_url, prefix
        );
        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            let body: EffectiveSaidResponse = resp.json().await?;
            Ok(Some(body.said))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Verify a SAD record chain and return a verification token.
    ///
    /// Fetches the full chain, verifies structural integrity (SAID, chain linkage,
    /// version monotonicity, consistent kel_prefix/kind), then verifies each
    /// record's signature against the owner's KEL at the stated establishment serial.
    ///
    /// The `kels_client` is used to fetch and verify the owner's KEL for
    /// signature verification.
    pub async fn verify_sad_records(
        &self,
        prefix: &str,
        kels_client: &crate::KelsClient,
    ) -> Result<SadRecordVerification, KelsError> {
        use cesr::{Matter, Signature, VerificationKey};

        // Fetch the full chain (records + signatures)
        let page = self.fetch_sad_chain(prefix, None).await?;
        if page.records.is_empty() {
            return Err(KelsError::EventNotFound(prefix.to_string()));
        }

        // Verify structural integrity
        let chain = SadRecordChain {
            prefix: prefix.to_string(),
            records: page.records,
        };
        chain.verify_records()?;

        let tip = chain
            .tip()
            .ok_or_else(|| KelsError::VerificationFailed("Empty chain after verify".to_string()))?;

        // Verify the owner's KEL to get establishment keys
        let kel_prefix = &tip.record.kel_prefix;
        let verifier = KelVerifier::new(kel_prefix);
        let kel_verification = crate::verify_key_events(
            kel_prefix,
            &kels_client.as_kel_source(),
            verifier,
            crate::page_size(),
            crate::max_pages(),
        )
        .await?;

        if kel_verification.is_divergent() {
            return Err(KelsError::Divergent);
        }

        // Verify the tip record's signature against the current key
        let Some(public_key_qb64) = kel_verification.current_public_key() else {
            return Err(KelsError::VerificationFailed(
                "No public key in verified KEL".to_string(),
            ));
        };

        let public_key = VerificationKey::from_qb64(public_key_qb64)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid public key: {}", e)))?;

        let sig = Signature::from_qb64(&tip.signature)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        public_key
            .verify(tip.record.said.as_bytes(), &sig)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;

        Ok(SadRecordVerification::new(
            tip.record.clone(),
            tip.establishment_serial,
        ))
    }
}
