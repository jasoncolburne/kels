//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the kels-registry service.

use crate::error::KelsError;
use crate::types::{
    DeregisterRequest, NodeInfo, NodeRegistration, NodeStatus, NodesResponse, PeersResponse,
    RegisterNodeRequest, SignedRequest, StatusUpdateRequest,
};
use std::sync::Arc;
use std::time::Duration;

/// Result of a signing operation, containing all data needed for a SignedRequest.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// CESR qb64 encoded signature
    pub signature: String,
    /// CESR qb64 encoded public key
    pub public_key: String,
    /// libp2p PeerId derived from public key
    pub peer_id: String,
}

/// Trait for signing registry requests.
///
/// Implementors sign data and return the signature along with the public key
/// and peer ID (all derived from the same HSM call).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait RegistrySigner: Send + Sync {
    /// Sign the given data and return signature, public key, and peer ID.
    async fn sign(&self, data: &[u8]) -> Result<SignResult, KelsError>;
}

/// Client for interacting with the kels-registry service.
#[derive(Clone)]
pub struct KelsRegistryClient {
    client: reqwest::Client,
    base_url: String,
    signer: Option<Arc<dyn RegistrySigner>>,
}

impl KelsRegistryClient {
    /// Create a new registry client with default timeout (no signing capability).
    pub fn new(registry_url: &str) -> Self {
        Self::with_timeout(registry_url, Duration::from_secs(10))
    }

    /// Create a new registry client with custom timeout (no signing capability).
    pub fn with_timeout(registry_url: &str, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
            signer: None,
        }
    }

    /// Create a new registry client with signing capability.
    pub fn with_signer(registry_url: &str, signer: Arc<dyn RegistrySigner>) -> Self {
        Self::with_signer_and_timeout(registry_url, signer, Duration::from_secs(10))
    }

    /// Create a new registry client with signing capability and custom timeout.
    pub fn with_signer_and_timeout(
        registry_url: &str,
        signer: Arc<dyn RegistrySigner>,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
            signer: Some(signer),
        }
    }

    /// Create a signed request wrapper for the given payload.
    async fn sign_request<T>(&self, payload: &T) -> Result<SignedRequest<T>, KelsError>
    where
        T: serde::Serialize + Clone,
    {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| KelsError::SigningFailed("No signer configured".to_string()))?;

        // Serialize payload to JSON for signing
        let payload_json = serde_json::to_vec(payload)?;

        // Sign the payload (returns signature, public key, and peer ID)
        let sign_result = signer.sign(&payload_json).await?;

        Ok(SignedRequest {
            payload: payload.clone(),
            peer_id: sign_result.peer_id,
            public_key: sign_result.public_key,
            signature: sign_result.signature,
        })
    }

    /// Register a node with the registry.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn register(
        &self,
        node_id: &str,
        kels_url: &str,
        kels_url_internal: Option<&str>,
        gossip_multiaddr: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = RegisterNodeRequest {
            node_id: node_id.to_string(),
            node_type: crate::NodeType::Kels,
            kels_url: kels_url.to_string(),
            kels_url_internal: kels_url_internal.map(|s| s.to_string()),
            gossip_multiaddr: gossip_multiaddr.to_string(),
            status,
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        tracing::info!("${:?}", signed_request);

        let response = self
            .client
            .post(format!("{}/api/nodes/register", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Deregister a node from the registry.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn deregister(&self, node_id: &str) -> Result<(), KelsError> {
        let request = DeregisterRequest {
            node_id: node_id.to_string(),
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        let response = self
            .client
            .post(format!("{}/api/nodes/deregister", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Fetch a single page of nodes from the registry.
    async fn fetch_nodes_page(
        &self,
        cursor: Option<&str>,
        exclude: Option<&str>,
        bootstrap_only: bool,
    ) -> Result<NodesResponse, KelsError> {
        let mut url = if bootstrap_only {
            format!("{}/api/nodes/bootstrap?limit=100", self.base_url)
        } else {
            format!("{}/api/nodes?limit=100", self.base_url)
        };
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }
        if let Some(ex) = exclude {
            url.push_str(&format!("&exclude={}", ex));
        }

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Get list of bootstrap nodes (excludes the calling node).
    /// Paginates through all available nodes.
    pub async fn list_nodes(
        &self,
        exclude_node_id: Option<&str>,
    ) -> Result<Vec<NodeRegistration>, KelsError> {
        let mut all_nodes = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let page = self
                .fetch_nodes_page(cursor.as_deref(), exclude_node_id, true)
                .await?;
            all_nodes.extend(page.nodes);

            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(all_nodes)
    }

    /// List all registered nodes with pagination.
    pub async fn list_all_nodes(&self) -> Result<Vec<NodeRegistration>, KelsError> {
        self.list_nodes(None).await
    }

    /// List all registered nodes as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&self) -> Result<Vec<NodeInfo>, KelsError> {
        let nodes = self.list_all_nodes().await?;
        Ok(nodes.into_iter().map(NodeInfo::from).collect())
    }

    /// Send heartbeat for a node.
    pub async fn heartbeat(&self, node_id: &str) -> Result<NodeRegistration, KelsError> {
        let response = self
            .client
            .post(format!("{}/api/nodes/{}/heartbeat", self.base_url, node_id))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(node_id.to_string()))
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Update node status.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = StatusUpdateRequest {
            node_id: node_id.to_string(),
            status,
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        let response = self
            .client
            .post(format!("{}/api/nodes/status", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(node_id.to_string()))
        } else {
            let status_code = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status_code, message
            )))
        }
    }

    /// Check if the registry is healthy.
    pub async fn health_check(&self) -> Result<bool, KelsError> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// Fetch all peers from the registry.
    ///
    /// Returns peer histories containing all versions of each peer record.
    /// This is an unauthenticated endpoint - nodes can check the peer list
    /// before they are authorized.
    pub async fn fetch_peers(&self) -> Result<PeersResponse, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/peers", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Check if a peer is authorized in the allowlist.
    ///
    /// Returns true if the peer_id is found in the allowlist with active=true.
    /// This is an unauthenticated check - nodes can verify their authorization
    /// before attempting to register.
    pub async fn is_peer_authorized(&self, peer_id: &str) -> Result<bool, KelsError> {
        let peers_response = self.fetch_peers().await?;

        // Check if any peer history has a latest record with matching peer_id and active=true
        for history in peers_response.peers {
            if let Some(latest) = history.records.first()
                && latest.peer_id == peer_id
                && latest.active
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if there are any Ready peers available for bootstrap sync.
    ///
    /// Returns true if at least one node with Ready status exists (excluding self).
    pub async fn has_ready_peers(&self, exclude_node_id: Option<&str>) -> Result<bool, KelsError> {
        let nodes = self.list_nodes(exclude_node_id).await?;
        Ok(nodes.iter().any(|n| n.status == NodeStatus::Ready))
    }

    /// Fetch the registry's KEL for verification.
    ///
    /// This is an unauthenticated endpoint - nodes use this to verify
    /// that peer records are anchored in the registry's KEL.
    pub async fn fetch_registry_kel(&self) -> Result<crate::Kel, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/registry-kel", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(KelsError::ServerError(format!(
                "Registry error {}: {}",
                status, message
            )))
        }
    }

    /// Fetch and verify the registry's KEL against an expected prefix.
    ///
    /// This performs cryptographic verification:
    /// 1. Fetches the registry's KEL
    /// 2. Verifies KEL integrity (SAIDs, signatures, chaining, rotation hashes)
    /// 3. Checks that the registry prefix matches the expected trust anchor
    ///
    /// Returns the verified KEL on success, which can be used to check peer anchoring.
    pub async fn verify_registry(&self, expected_prefix: &str) -> Result<crate::Kel, KelsError> {
        let registry_kel = self.fetch_registry_kel().await?;

        registry_kel.verify().map_err(|e| {
            KelsError::VerificationFailed(format!("Registry KEL verification failed: {}", e))
        })?;

        let actual_prefix = registry_kel.prefix().map(|s| s.to_string());
        if actual_prefix.as_deref() != Some(expected_prefix) {
            return Err(KelsError::VerificationFailed(format!(
                "Registry prefix mismatch: expected {}, got {:?}",
                expected_prefix, actual_prefix
            )));
        }

        Ok(registry_kel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::KeyEventBuilder;
    use crate::crypto::SoftwareKeyProvider;
    use crate::kel::Kel;
    use crate::types::{NodeRegistration, NodeType, Peer, PeerHistory, SignedKeyEvent};
    use cesr::Matter;
    use std::time::Duration;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Mock signer for testing
    struct MockSigner;

    #[async_trait::async_trait]
    impl RegistrySigner for MockSigner {
        async fn sign(&self, _data: &[u8]) -> Result<SignResult, KelsError> {
            Ok(SignResult {
                signature: "0BAAAA_mock_signature".to_string(),
                public_key: "1AAA_mock_public_key".to_string(),
                peer_id: "12D3KooWMockPeerId".to_string(),
            })
        }
    }

    // ==================== Constructor Tests ====================

    #[test]
    fn test_new_client() {
        let client = KelsRegistryClient::new("http://registry:8080");
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_with_timeout() {
        let client =
            KelsRegistryClient::with_timeout("http://registry:8080", Duration::from_secs(5));
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_with_signer() {
        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer("http://registry:8080", signer);
        assert!(client.signer.is_some());
    }

    #[test]
    fn test_with_signer_and_timeout() {
        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer_and_timeout(
            "http://registry:8080",
            signer,
            Duration::from_secs(30),
        );
        assert!(client.signer.is_some());
    }

    #[test]
    fn test_url_trailing_slash_stripped() {
        let client = KelsRegistryClient::new("http://registry:8080/");
        assert_eq!(client.base_url, "http://registry:8080");
    }

    // ==================== Health Check Tests ====================

    #[tokio::test]
    async fn test_health_check_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_health_check_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ==================== Registration Tests ====================

    #[tokio::test]
    async fn test_register_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
            kels_url_internal: None,
            gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Bootstrapping,
        };

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                None,
                "/ip4/10.0.0.1/tcp/9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(result.is_ok());
        let reg = result.unwrap();
        assert_eq!(reg.node_id, "node-1");
    }

    #[tokio::test]
    async fn test_register_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                None,
                "/ip4/10.0.0.1/tcp/9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_register_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                None,
                "/ip4/10.0.0.1/tcp/9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(matches!(result, Err(KelsError::ServerError(_))));
    }

    // ==================== Deregistration Tests ====================

    #[tokio::test]
    async fn test_deregister_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.deregister("node-1").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deregister_not_found_ok() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.deregister("node-1").await;

        // 404 is OK for deregister (already deregistered)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deregister_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client.deregister("node-1").await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
    }

    // ==================== List Nodes Tests ====================

    #[tokio::test]
    async fn test_list_nodes_success() {
        let mock_server = MockServer::start().await;

        let response = NodesResponse {
            nodes: vec![NodeRegistration {
                node_id: "node-1".to_string(),
                node_type: NodeType::Kels,
                kels_url: "http://node-1:8091".to_string(),
                kels_url_internal: None,
                gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
                registered_at: chrono::Utc::now(),
                last_heartbeat: chrono::Utc::now(),
                status: NodeStatus::Ready,
            }],
            next_cursor: None,
        };

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_nodes(None).await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
    }

    #[tokio::test]
    async fn test_list_all_nodes() {
        let mock_server = MockServer::start().await;

        let response = NodesResponse {
            nodes: vec![],
            next_cursor: None,
        };

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_all_nodes().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_nodes_info() {
        let mock_server = MockServer::start().await;

        let response = NodesResponse {
            nodes: vec![NodeRegistration {
                node_id: "node-1".to_string(),
                node_type: NodeType::Kels,
                kels_url: "http://node-1:8091".to_string(),
                kels_url_internal: None,
                gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
                registered_at: chrono::Utc::now(),
                last_heartbeat: chrono::Utc::now(),
                status: NodeStatus::Ready,
            }],
            next_cursor: None,
        };

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_nodes_info().await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_list_nodes_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_nodes(None).await;

        assert!(matches!(result, Err(KelsError::ServerError(_))));
    }

    // ==================== Heartbeat Tests ====================

    #[tokio::test]
    async fn test_heartbeat_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
            kels_url_internal: None,
            gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Ready,
        };

        Mock::given(method("POST"))
            .and(path_regex(r"/api/nodes/.*/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.heartbeat("node-1").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_heartbeat_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/nodes/.*/heartbeat"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.heartbeat("unknown-node").await;

        assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_heartbeat_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/nodes/.*/heartbeat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.heartbeat("node-1").await;

        assert!(matches!(result, Err(KelsError::ServerError(_))));
    }

    // ==================== Update Status Tests ====================

    #[tokio::test]
    async fn test_update_status_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
            kels_url_internal: None,
            gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Ready,
        };

        Mock::given(method("POST"))
            .and(path("/api/nodes/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.update_status("node-1", NodeStatus::Ready).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_status_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/status"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.update_status("unknown", NodeStatus::Ready).await;

        assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_update_status_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client.update_status("node-1", NodeStatus::Ready).await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
    }

    // ==================== Peers Tests ====================

    fn make_test_peer(peer_id: &str, node_id: &str, active: bool) -> Peer {
        Peer::create(peer_id.to_string(), node_id.to_string(), active).expect("create peer")
    }

    #[tokio::test]
    async fn test_fetch_peers_success() {
        let mock_server = MockServer::start().await;

        let peer = make_test_peer("12D3KooWPeer1", "node-1", true);
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_peers().await;

        assert!(result.is_ok());
        let peers = result.unwrap();
        assert_eq!(peers.peers.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_peers_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_peers().await;

        assert!(matches!(result, Err(KelsError::ServerError(_))));
    }

    #[tokio::test]
    async fn test_is_peer_authorized_true() {
        let mock_server = MockServer::start().await;

        let peer = make_test_peer("12D3KooWPeer1", "node-1", true);
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.is_peer_authorized("12D3KooWPeer1").await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_is_peer_authorized_false_not_found() {
        let mock_server = MockServer::start().await;

        let peer = make_test_peer("12D3KooWPeer1", "node-1", true);
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.is_peer_authorized("12D3KooWDifferent").await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_is_peer_authorized_false_inactive() {
        let mock_server = MockServer::start().await;

        let peer = make_test_peer("12D3KooWPeer1", "node-1", false);
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.is_peer_authorized("12D3KooWPeer1").await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ==================== Has Ready Peers Tests ====================

    #[tokio::test]
    async fn test_has_ready_peers_true() {
        let mock_server = MockServer::start().await;

        let response = NodesResponse {
            nodes: vec![NodeRegistration {
                node_id: "node-1".to_string(),
                node_type: NodeType::Kels,
                kels_url: "http://node-1:8091".to_string(),
                kels_url_internal: None,
                gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
                registered_at: chrono::Utc::now(),
                last_heartbeat: chrono::Utc::now(),
                status: NodeStatus::Ready,
            }],
            next_cursor: None,
        };

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.has_ready_peers(None).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_has_ready_peers_false() {
        let mock_server = MockServer::start().await;

        let response = NodesResponse {
            nodes: vec![NodeRegistration {
                node_id: "node-1".to_string(),
                node_type: NodeType::Kels,
                kels_url: "http://node-1:8091".to_string(),
                kels_url_internal: None,
                gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
                registered_at: chrono::Utc::now(),
                last_heartbeat: chrono::Utc::now(),
                status: NodeStatus::Bootstrapping, // Not Ready
            }],
            next_cursor: None,
        };

        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.has_ready_peers(None).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ==================== Registry KEL Tests ====================

    #[tokio::test]
    async fn test_fetch_registry_kel_success() {
        let mock_server = MockServer::start().await;

        // Create a valid KEL for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let public_key = icp.public_key.clone().unwrap();
        let signed = SignedKeyEvent::new(icp, public_key, icp_sig.qb64());
        let kel = Kel::from_events(vec![signed], true).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_registry_kel().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_registry_kel_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_registry_kel().await;

        assert!(matches!(result, Err(KelsError::ServerError(_))));
    }

    #[tokio::test]
    async fn test_verify_registry_success() {
        let mock_server = MockServer::start().await;

        // Create a valid KEL for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let public_key = icp.public_key.clone().unwrap();
        let prefix = icp.prefix.clone();
        let signed = SignedKeyEvent::new(icp, public_key, icp_sig.qb64());
        let kel = Kel::from_events(vec![signed], true).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.verify_registry(&prefix).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_registry_prefix_mismatch() {
        let mock_server = MockServer::start().await;

        // Create a valid KEL for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let public_key = icp.public_key.clone().unwrap();
        let signed = SignedKeyEvent::new(icp, public_key, icp_sig.qb64());
        let kel = Kel::from_events(vec![signed], true).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.verify_registry("Ewrong_prefix").await;

        assert!(matches!(result, Err(KelsError::VerificationFailed(_))));
    }
}
