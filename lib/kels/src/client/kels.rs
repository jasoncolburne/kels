//! KELS HTTP Client
//!
//! Pass-through pagination client — no client-side caching.
//! Server-side Redis cache handles caching.

use std::time::{Duration, Instant};

use cesr::Matter;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    error::KelsError,
    types::{
        ErrorCode, ErrorResponse, RecoveryRecordPage, SignedKeyEvent, SignedKeyEventPage,
        SubmitEventsResponse,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Bootstrapping,
    Ready,
    Unhealthy,
}

/// KELS API Client - fetches/submits key events via HTTP.
/// No client-side caching — server-side Redis cache handles that.
#[derive(Clone)]
pub struct KelsClient {
    base_url: String,
    path_prefix: String,
    client: reqwest::Client,
}

impl KelsClient {
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        Self::with_path_prefix(base_url, "/api/v1/kels")
    }

    /// Create a client with a custom path prefix (e.g., "/api/v1/member-kels").
    pub fn with_path_prefix(base_url: &str, path_prefix: &str) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            path_prefix: path_prefix.to_string(),
            client,
        })
    }

    /// Create a client with a custom timeout (useful for latency testing).
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()?;
        Ok(KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            path_prefix: "/api/v1/kels".to_string(),
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create an `HttpKelSource` for this client's KEL endpoint.
    pub fn as_kel_source(&self) -> Result<crate::HttpKelSource, KelsError> {
        crate::HttpKelSource::new(&self.base_url, &format!("{}/kel/fetch", self.path_prefix))
    }

    /// Create an `HttpKelSink` for this client's events endpoint.
    pub fn as_kel_sink(&self) -> Result<crate::HttpKelSink, KelsError> {
        crate::HttpKelSink::new(&self.base_url, &format!("{}/events", self.path_prefix))
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

    /// Test latency to this node by measuring health check round-trip time.
    pub async fn test_latency(&self) -> Result<Duration, KelsError> {
        let start = Instant::now();
        self.health().await?;
        Ok(start.elapsed())
    }

    /// Check if this node is ready by querying its /ready endpoint.
    pub async fn check_ready_status(&self) -> NodeStatus {
        let ready_url = format!("{}/ready", self.base_url.trim_end_matches('/'));

        match self
            .client
            .get(&ready_url)
            .timeout(Duration::from_secs(2))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(body) = response.json::<serde_json::Value>().await
                        && body.get("ready") == Some(&serde_json::Value::Bool(true))
                    {
                        return NodeStatus::Ready;
                    }
                    NodeStatus::Bootstrapping
                } else if response.status().as_u16() == 503 {
                    debug!(url = %self.base_url, "503 from /ready — treating as Bootstrapping");
                    NodeStatus::Bootstrapping
                } else {
                    NodeStatus::Unhealthy
                }
            }
            Err(_) => NodeStatus::Unhealthy,
        }
    }

    /// Submit events in chunks, respecting the server's max event count limit.
    /// For linear KELs, this is a naive chunker that submits sequentially.
    /// For divergent KELs, use partition_for_seeding in the gossip service.
    pub async fn submit_events_chunked(
        &self,
        events: &[SignedKeyEvent],
        max_events: usize,
    ) -> Result<SubmitEventsResponse, KelsError> {
        if events.len() <= max_events {
            return self.submit_events(events).await;
        }
        let mut last_response = SubmitEventsResponse {
            diverged_at: None,
            applied: true,
        };
        for chunk in events.chunks(max_events) {
            last_response = self.submit_events(chunk).await?;
        }
        Ok(last_response)
    }

    pub async fn submit_events(
        &self,
        events: &[SignedKeyEvent],
    ) -> Result<SubmitEventsResponse, KelsError> {
        let url = format!("{}{}/events", self.base_url, self.path_prefix);

        let resp = self.client.post(&url).json(events).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::GONE {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ContestedKel(err.error))
        } else {
            let err: ErrorResponse = resp.json().await?;
            if err.code == ErrorCode::ContestRequired {
                Err(KelsError::ContestRequired)
            } else {
                Err(KelsError::ServerError(err.error, err.code))
            }
        }
    }

    /// Fetch a page of KEL events. Pass-through to server pagination.
    ///
    /// - `since`: Optional SAID for delta fetch (events after this SAID).
    /// - `limit`: Page size.
    ///
    /// Returns `SignedKeyEventPage` with `events` and `has_more`.
    pub async fn fetch_key_events(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<SignedKeyEventPage, KelsError> {
        let url = format!("{}{}/kel/fetch", self.base_url, self.path_prefix);
        let body = crate::KelPageRequest {
            prefix: *prefix,
            since: since.copied(),
            limit: Some(limit),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch all KEL events by paginating through all pages.
    ///
    /// Accumulates events from all pages into a single `Vec`. Uses `max_pages`
    /// to bound resource consumption — returns an error if exceeded.
    ///
    /// - `since`: Optional SAID for delta fetch (events after this SAID).
    /// - `limit`: Page size per request.
    /// - `max_pages`: Maximum number of pages to fetch before failing.
    pub async fn fetch_all_key_events(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
        max_pages: usize,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let mut all_events = Vec::new();
        let mut current_since: Option<cesr::Digest256> = since.copied();
        let mut exhausted = false;

        for _ in 0..max_pages {
            let page = self
                .fetch_key_events(prefix, current_since.as_ref(), limit)
                .await?;

            if page.events.is_empty() {
                exhausted = true;
                break;
            }

            let last_said = page.events.last().map(|e| e.event.said);
            all_events.extend(page.events);

            if !page.has_more {
                exhausted = true;
                break;
            }

            current_since = last_said;
        }

        if !exhausted {
            return Err(KelsError::InvalidKel(format!(
                "KEL fetch for {} exceeds max_pages limit ({})",
                prefix, max_pages,
            )));
        }

        Ok(all_events)
    }

    /// Fetch the effective tail SAID for a prefix.
    ///
    /// **RESOLVING ONLY — NOT VERIFIED.** Use only for sync comparison.
    /// A wrong value triggers an unnecessary sync, not a security hole.
    /// Returns `None` if the prefix doesn't exist.
    pub async fn fetch_effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(cesr::Digest256, bool)>, KelsError> {
        let url = format!("{}{}/kel/effective-said", self.base_url, self.path_prefix);
        let body = crate::KelEffectiveSaidRequest { prefix: *prefix };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await?;
            let said = body
                .get("said")
                .and_then(|s| s.as_str())
                .map(cesr::Digest256::from_qb64)
                .transpose()
                .map_err(|e| KelsError::HttpError(format!("Invalid effective SAID CESR: {}", e)))?;
            let divergent = body
                .get("divergent")
                .and_then(|d| d.as_bool())
                .ok_or_else(|| {
                    KelsError::HttpError(
                        "missing or invalid 'divergent' field in effective SAID response"
                            .to_string(),
                    )
                })?;
            Ok(said.map(|s| (s, divergent)))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch paginated recovery records for a prefix (recovery history and audit trail).
    pub async fn fetch_kel_audit(
        &self,
        prefix: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<RecoveryRecordPage, KelsError> {
        let url = format!("{}{}/kel/recoveries", self.base_url, self.path_prefix);
        let body = crate::KelRecoveriesRequest {
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
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch paginated archived events for a specific recovery.
    pub async fn fetch_recovery_events(
        &self,
        prefix: &cesr::Digest256,
        recovery_said: &cesr::Digest256,
        limit: usize,
        offset: u64,
    ) -> Result<SignedKeyEventPage, KelsError> {
        let url = format!(
            "{}{}/kel/recoveries/events",
            self.base_url, self.path_prefix
        );
        let body = crate::KelRecoveryEventsRequest {
            prefix: *prefix,
            said: *recovery_said,
            limit: Some(limit),
            offset: Some(offset),
        };
        let resp = self.client.post(&url).json(&body).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::NotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch a page of prefix states via signed POST request.
    pub async fn fetch_prefixes(
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
            .post(format!("{}{}/prefixes", self.base_url, self.path_prefix))
            .json(&signed)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Check if an event SAID exists on the server.
    pub async fn event_exists(&self, said: &cesr::Digest256) -> Result<bool, KelsError> {
        let url = format!("{}{}/events/exists", self.base_url, self.path_prefix);
        let body = crate::KelEventExistsRequest { said: *said };
        let resp = self.client.post(&url).json(&body).send().await?;

        Ok(resp.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use cesr::VerificationKeyCode;

    use super::*;
    use crate::SoftwareKeyProvider;
    use crate::builder::KeyEventBuilder;

    #[test]
    fn test_kels_client_creation() {
        let client = KelsClient::new("http://kels:8091").unwrap();
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_kels_client_strips_trailing_slash() {
        let client = KelsClient::new("http://kels:8091/").unwrap();
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_kels_client_strips_multiple_trailing_slashes() {
        let client = KelsClient::new("http://kels:8091///").unwrap();
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_client_with_timeout() {
        let client =
            KelsClient::with_timeout("http://localhost:8080", Duration::from_secs(60)).unwrap();
        assert_eq!(client.base_url(), "http://localhost:8080");
    }

    #[test]
    fn test_client_with_path_prefix() {
        let client =
            KelsClient::with_path_prefix("http://registry:8080", "/api/v1/member-kels").unwrap();
        assert_eq!(client.base_url(), "http://registry:8080");
        assert_eq!(client.path_prefix, "/api/v1/member-kels");
    }

    // ==================== HTTP Client Tests with Mock Server ====================

    mod http_tests {
        use cesr::test_digest;

        use super::*;
        use crate::types::{ErrorCode, ErrorResponse, SubmitEventsResponse};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn test_health_success() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.health().await;

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "OK");
        }

        #[tokio::test]
        async fn test_health_failure() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.health().await;

            assert!(result.is_err());
            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }

        #[tokio::test]
        async fn test_test_latency() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.test_latency().await;

            assert!(result.is_ok());
            assert!(result.unwrap().as_micros() > 0);
        }

        #[tokio::test]
        async fn test_submit_events_chunked_small_batch() {
            let mock_server = MockServer::start().await;

            let response = SubmitEventsResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.submit_events_chunked(&[signed], 500).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.applied);
        }

        #[tokio::test]
        async fn test_submit_events_chunked_multiple_chunks() {
            let mock_server = MockServer::start().await;

            let response = SubmitEventsResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .expect(3)
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let icp = builder.incept().await.unwrap();
            let ixn1 = builder.interact(&test_digest("anchor1")).await.unwrap();
            let ixn2 = builder.interact(&test_digest("anchor2")).await.unwrap();

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.submit_events_chunked(&[icp, ixn1, ixn2], 1).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.applied);
        }

        #[tokio::test]
        async fn test_submit_events_success() {
            let mock_server = MockServer::start().await;

            let response = SubmitEventsResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.submit_events(&[signed]).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.applied);
            assert!(resp.diverged_at.is_none());
        }

        #[tokio::test]
        async fn test_submit_events_contested() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "KEL is contested".to_string(),
                code: ErrorCode::Contested,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/events"))
                .respond_with(ResponseTemplate::new(410).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::ContestedKel(_))));
        }

        #[tokio::test]
        async fn test_submit_events_contest_required() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Contest required".to_string(),
                code: ErrorCode::ContestRequired,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/events"))
                .respond_with(ResponseTemplate::new(400).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::ContestRequired)));
        }

        #[tokio::test]
        async fn test_fetch_key_events_success() {
            let mock_server = MockServer::start().await;

            let mut builder = KeyEventBuilder::new(
                SoftwareKeyProvider::new(
                    VerificationKeyCode::Secp256r1,
                    VerificationKeyCode::Secp256r1,
                ),
                None,
            );
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix;

            let response = SignedKeyEventPage {
                events: vec![icp],
                has_more: false,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/kel/fetch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client.fetch_key_events(&prefix, None, 32).await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert_eq!(page.events.len(), 1);
            assert!(!page.has_more);
        }

        #[tokio::test]
        async fn test_fetch_key_events_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/kel/fetch"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client
                .fetch_key_events(&test_digest("nonexistent"), None, 32)
                .await;

            assert!(matches!(result, Err(KelsError::NotFound(_))));
        }

        #[tokio::test]
        async fn test_fetch_key_events_server_error() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Database error".to_string(),
                code: ErrorCode::InternalError,
            };

            Mock::given(method("POST"))
                .and(path("/api/v1/kels/kel/fetch"))
                .respond_with(ResponseTemplate::new(500).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri()).unwrap();
            let result = client
                .fetch_key_events(&test_digest("prefix"), None, 32)
                .await;

            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }
    }
}
