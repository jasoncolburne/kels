//! KELS HTTP Client
//!
//! Pass-through pagination client — no client-side caching.
//! Server-side Redis cache handles caching.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{
    error::KelsError,
    types::{
        BatchKelsRequest, BatchSubmitResponse, ErrorCode, ErrorResponse, KelsAuditRecord,
        SignedKeyEvent, SignedKeyEventPage,
    },
};

/// KELS API Client - fetches/submits key events via HTTP.
/// No client-side caching — server-side Redis cache handles that.
#[derive(Clone)]
pub struct KelsClient {
    base_url: String,
    client: reqwest::Client,
}

impl KelsClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Create a client with a custom timeout (useful for latency testing).
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        KelsClient {
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

    /// Test latency to this node by measuring health check round-trip time.
    pub async fn test_latency(&self) -> Result<Duration, KelsError> {
        let start = Instant::now();
        self.health().await?;
        Ok(start.elapsed())
    }

    /// Submit events in chunks, respecting the server's max event count limit.
    /// For linear KELs, this is a naive chunker that submits sequentially.
    /// For divergent KELs, use partition_for_seeding in the gossip service.
    pub async fn submit_events_chunked(
        &self,
        events: &[SignedKeyEvent],
        max_events: usize,
    ) -> Result<BatchSubmitResponse, KelsError> {
        if events.len() <= max_events {
            return self.submit_events(events).await;
        }
        let mut last_response = BatchSubmitResponse {
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
    ) -> Result<BatchSubmitResponse, KelsError> {
        let resp = self
            .client
            .post(format!("{}/api/kels/events", self.base_url))
            .json(events)
            .send()
            .await?;

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
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<SignedKeyEventPage, KelsError> {
        let mut url = format!("{}/api/kels/kel/{}?limit={}", self.base_url, prefix, limit);
        if let Some(since_said) = since {
            url.push_str(&format!("&since={}", since_said));
        }

        let resp = self.client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch the effective tail SAID for a prefix.
    ///
    /// **RESOLVING ONLY — NOT VERIFIED.** Use only for sync comparison.
    /// A wrong value triggers an unnecessary sync, not a security hole.
    /// Returns `None` if the prefix doesn't exist.
    pub async fn fetch_effective_said(&self, prefix: &str) -> Result<Option<String>, KelsError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/kels/kel/{}/effective-said",
                self.base_url, prefix
            ))
            .send()
            .await?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await?;
            Ok(body.get("said").and_then(|s| s.as_str()).map(String::from))
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch audit records for a prefix (separate endpoint from KEL events).
    pub async fn fetch_kel_audit(&self, prefix: &str) -> Result<Vec<KelsAuditRecord>, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/kel/{}/audit", self.base_url, prefix))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch a page of prefix states via signed POST request.
    pub async fn fetch_prefixes(
        &self,
        signer: &dyn crate::RegistrySigner,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<crate::PrefixListResponse, KelsError> {
        let request = crate::PrefixesRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: crate::generate_nonce(),
            since: cursor.map(|s| s.to_string()),
            limit: Some(limit),
        };
        let signed = crate::sign_request(signer, &request).await?;
        let resp = self
            .client
            .post(format!("{}/api/kels/prefixes", self.base_url))
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
    pub async fn event_exists(&self, said: &str) -> Result<bool, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/events/{}/exists", self.base_url, said))
            .send()
            .await?;

        Ok(resp.status().is_success())
    }

    /// Batch-fetch KELs from the server. Automatically chunks to respect the server's
    /// `MAX_BATCH_PREFIXES` limit. Returns `SignedKeyEventPage` per prefix — callers
    /// handle their own verification and pagination loops for `has_more`.
    pub async fn fetch_kels(
        &self,
        prefixes: &HashMap<String, Option<String>>,
    ) -> Result<HashMap<String, SignedKeyEventPage>, KelsError> {
        if prefixes.is_empty() {
            return Ok(HashMap::new());
        }

        let entries: Vec<_> = prefixes.iter().collect();
        let mut result = HashMap::with_capacity(prefixes.len());

        for chunk in entries.chunks(crate::MAX_BATCH_PREFIXES) {
            let request = BatchKelsRequest {
                prefixes: chunk
                    .iter()
                    .map(|(k, v)| ((*k).clone(), (*v).clone()))
                    .collect(),
            };

            let resp = self
                .client
                .post(format!("{}/api/kels/kels", self.base_url))
                .json(&request)
                .send()
                .await?;

            if !resp.status().is_success() {
                let err: ErrorResponse = resp.json().await?;
                return Err(KelsError::ServerError(err.error, err.code));
            }

            let batch: HashMap<String, SignedKeyEventPage> = resp.json().await?;
            result.extend(batch);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareKeyProvider;
    use crate::builder::KeyEventBuilder;

    #[test]
    fn test_kels_client_creation() {
        let client = KelsClient::new("http://kels:8091");
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_kels_client_strips_trailing_slash() {
        let client = KelsClient::new("http://kels:8091/");
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_kels_client_strips_multiple_trailing_slashes() {
        let client = KelsClient::new("http://kels:8091///");
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_client_with_timeout() {
        let client = KelsClient::with_timeout("http://localhost:8080", Duration::from_secs(60));
        assert_eq!(client.base_url(), "http://localhost:8080");
    }

    // ==================== HTTP Client Tests with Mock Server ====================

    mod http_tests {
        use super::*;
        use crate::types::{BatchSubmitResponse, ErrorCode, ErrorResponse};
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn test_health_success() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
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

            let client = KelsClient::new(&mock_server.uri());
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

            let client = KelsClient::new(&mock_server.uri());
            let result = client.test_latency().await;

            assert!(result.is_ok());
            assert!(result.unwrap().as_micros() > 0);
        }

        #[tokio::test]
        async fn test_submit_events_chunked_small_batch() {
            let mock_server = MockServer::start().await;

            let response = BatchSubmitResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events_chunked(&[signed], 500).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.applied);
        }

        #[tokio::test]
        async fn test_submit_events_chunked_multiple_chunks() {
            let mock_server = MockServer::start().await;

            let response = BatchSubmitResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .expect(3)
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let ixn1 = builder.interact("anchor1").await.unwrap();
            let ixn2 = builder.interact("anchor2").await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events_chunked(&[icp, ixn1, ixn2], 1).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.applied);
        }

        #[tokio::test]
        async fn test_submit_events_success() {
            let mock_server = MockServer::start().await;

            let response = BatchSubmitResponse {
                applied: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
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
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(410).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
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
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(400).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::ContestRequired)));
        }

        #[tokio::test]
        async fn test_fetch_key_events_success() {
            let mock_server = MockServer::start().await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix.clone();

            let response = SignedKeyEventPage {
                events: vec![icp],
                has_more: false,
            };

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_key_events(&prefix, None, 512).await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert_eq!(page.events.len(), 1);
            assert!(!page.has_more);
        }

        #[tokio::test]
        async fn test_fetch_key_events_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_key_events("nonexistent", None, 512).await;

            assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
        }

        #[tokio::test]
        async fn test_fetch_key_events_server_error() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Database error".to_string(),
                code: ErrorCode::InternalError,
            };

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(500).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_key_events("prefix", None, 512).await;

            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }
    }
}
