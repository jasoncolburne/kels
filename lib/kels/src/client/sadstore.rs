//! SADStore HTTP Client
//!
//! Client for the replicated SAD store service.
//! Provides methods for both Layer 1 (SAD objects) and Layer 2 (SAD events).

use std::{sync::Arc, time::Duration};

use verifiable_storage::SelfAddressed;

use crate::{
    KelsError, PostSadObjectResponse, SadEventPage, SadEventRepairPage, SelVerification,
    SubmitSadEventsResponse,
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

    /// Create an `HttpSadSource` for this client's events endpoint.
    ///
    /// Constructs a fresh `reqwest::Client` (with its own connection pool)
    /// rather than sharing this `SadStoreClient`'s. Acceptable for one-off
    /// flows like `SadEventBuilder::repair` (called once per repair); if a
    /// caller invokes this in a hot loop, refactor to share the underlying
    /// `reqwest::Client` to reuse pooled connections.
    pub fn as_sad_source(&self) -> Result<crate::HttpSadSource, KelsError> {
        crate::HttpSadSource::new(&self.base_url)
    }

    /// Create an `HttpSadSink` for this client's events endpoint.
    ///
    /// Constructs a fresh `reqwest::Client` per call — see `as_sad_source` for
    /// the same trade-off note. Gossip/sync flows that call this repeatedly
    /// would benefit from sharing the underlying client.
    pub fn as_sad_sink(&self) -> Result<crate::HttpSadSink, KelsError> {
        crate::HttpSadSink::new(&self.base_url)
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
        // Pre-flight: catches tampered or partially-constructed payloads before
        // they hit the wire. The returned SAID is the *server's* canonical one
        // (post-compaction), which differs from the client-computed value when
        // the submission is in expanded form.
        object.verify_said().map_err(|e| {
            KelsError::VerificationFailed(format!("Object SAID verification failed: {}", e))
        })?;

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
            let parsed: PostSadObjectResponse = resp.json().await?;
            Ok(parsed.said)
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

    // === Layer 2: SAD Events ===

    /// Submit SAD events to the SADStore.
    ///
    /// Authorization is via KEL anchoring: each event's SAID must be anchored
    /// via ixn by `write_policy` endorsers in their KELs. There are no per-event
    /// signatures — the server validates anchoring against the endorsers' KELs.
    ///
    /// Returns the server-reported `SubmitSadEventsResponse`. The `diverged_at`
    /// field carries the server's authoritative divergence signal — a fork
    /// created by a concurrent writer at submission time would be invisible to
    /// the local verifier (which only sees the owner's batch). Callers that
    /// build on the local verification token (`SadEventBuilder::flush`) must
    /// propagate this to avoid silent state drift.
    pub async fn submit_sad_events(
        &self,
        events: &[crate::SadEvent],
    ) -> Result<SubmitSadEventsResponse, KelsError> {
        let url = format!("{}/api/v1/sad/events", self.base_url);
        let resp = self.client.post(&url).json(events).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch a page of SAD events by prefix.
    ///
    /// `since` is an effective SAID cursor — returns events after this SAID's
    /// position. If the SAID is not found (e.g. synthetic divergent SAID), the
    /// server returns the full chain.
    pub async fn fetch_sad_events(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
    ) -> Result<SadEventPage, KelsError> {
        let url = format!("{}/api/v1/sad/events/fetch", self.base_url);
        let body = crate::SadEventPageRequest {
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

    /// Fetch the tail of a SAD Event Log — the last `limit` events ordered by
    /// `(version ASC, said ASC)`. Server caps `limit` at `page_size()`.
    ///
    /// Used by `SadEventBuilder::repair`'s adversary-extension walk-back to
    /// pull only the chain segment the walk could possibly need (bounded by
    /// `MAX_NON_EVALUATION_EVENTS = 63` per the governance invariant), in a
    /// single round-trip independent of chain length.
    pub async fn fetch_sad_events_tail(
        &self,
        prefix: &cesr::Digest256,
        limit: usize,
    ) -> Result<SadEventPage, KelsError> {
        let url = format!("{}/api/v1/sad/events/tail", self.base_url);
        let body = crate::SadEventTailRequest {
            prefix: *prefix,
            limit: Some(limit),
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

    /// Get the effective SAID and divergence status for a SEL prefix.
    /// Returns `(said, is_divergent)`. Used for sync comparison.
    pub async fn fetch_sel_effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(String, bool)>, KelsError> {
        let url = format!("{}/api/v1/sad/events/effective-said", self.base_url);
        let body = crate::SadEventEffectiveSaidRequest { prefix: *prefix };
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

    /// Check if an event with the given SAID exists on this SADStore.
    pub async fn sad_event_exists(&self, said: &cesr::Digest256) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/sad/events/exists", self.base_url);
        let body = crate::SadFetchRequest {
            said: *said,
            disclosure: None,
        };
        let resp = self.client.post(&url).json(&body).send().await?;
        Ok(resp.status().is_success())
    }

    /// List SAD Event Log prefixes (paginated, authenticated). Used for bootstrap and anti-entropy.
    pub async fn fetch_sel_prefixes(
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
            .post(format!("{}/api/v1/sad/events/prefixes", self.base_url))
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

    /// Fetch repairs for a SEL prefix, paginated.
    pub async fn fetch_sel_repairs(
        &self,
        prefix: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<SadEventRepairPage, KelsError> {
        let url = format!("{}/api/v1/sad/events/repairs", self.base_url);
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

    /// Fetch archived events for a specific repair, paginated.
    pub async fn fetch_sel_repair_events(
        &self,
        prefix: &cesr::Digest256,
        repair_said: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<SadEventPage, KelsError> {
        let url = format!("{}/api/v1/sad/events/repairs/events", self.base_url);
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

    /// Verify a SAD Event Log and return a verification token.
    ///
    /// Structural + policy verification: SAID, chain linkage, version
    /// monotonicity, topic consistency, and write_policy authorization via
    /// the provided `PolicyChecker`.
    pub async fn verify_sad_events(
        &self,
        prefix: &cesr::Digest256,
        checker: Arc<dyn crate::PolicyChecker + Send + Sync>,
    ) -> Result<SelVerification, KelsError> {
        crate::verify_sad_events(
            prefix,
            &self.as_sad_source()?,
            checker,
            crate::page_size(),
            crate::max_pages(),
        )
        .await
    }

    // ==================== Identity Event Log (IEL) ====================

    /// Construct an `HttpIelSource` for paging through an IEL on this server.
    ///
    /// Constructs a fresh `reqwest::Client` per call (mirrors `as_sad_source`).
    pub fn as_iel_source(&self) -> Result<crate::HttpIelSource, KelsError> {
        crate::HttpIelSource::new(&self.base_url)
    }

    /// Submit an IEL event batch.
    pub async fn submit_identity_events(
        &self,
        events: &[crate::IdentityEvent],
    ) -> Result<crate::SubmitIdentityEventsResponse, KelsError> {
        let url = format!("{}/api/v1/iel/events", self.base_url);
        let resp = self.client.post(&url).json(events).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let text = read_error_body(resp).await?;
            Err(KelsError::ServerError(text, ErrorCode::InternalError))
        }
    }

    /// Fetch a page of IEL events.
    pub async fn fetch_identity_events(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
    ) -> Result<crate::IdentityEventPage, KelsError> {
        let url = format!("{}/api/v1/iel/events/fetch", self.base_url);
        let body = crate::IdentityEventPageRequest {
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

    /// Get the effective SAID and divergence status for an IEL prefix.
    pub async fn fetch_iel_effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(String, bool)>, KelsError> {
        let url = format!("{}/api/v1/iel/events/effective-said", self.base_url);
        let body = crate::IdentityEventEffectiveSaidRequest { prefix: *prefix };
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

    /// Check whether a specific IEL event SAID exists on the server.
    pub async fn identity_event_exists(&self, said: &cesr::Digest256) -> Result<bool, KelsError> {
        let url = format!("{}/api/v1/iel/events/exists", self.base_url);
        let body = crate::IdentityEventExistsRequest { said: *said };
        let resp = self.client.post(&url).json(&body).send().await?;
        Ok(resp.status().is_success())
    }

    /// Verify an IEL by paging through this server. Returns the verification
    /// token. Mirrors `verify_sad_events` for IEL.
    pub async fn verify_identity_events(
        &self,
        prefix: &cesr::Digest256,
        checker: Arc<dyn crate::PolicyChecker + Send + Sync>,
    ) -> Result<crate::IelVerification, KelsError> {
        crate::verify_identity_events(
            prefix,
            &self.as_iel_source()?,
            checker,
            crate::page_size(),
            crate::max_pages(),
        )
        .await
    }
}
