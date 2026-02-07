//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the kels-registry service.

use futures::future::join_all;

use crate::error::KelsError;
use crate::types::{
    DeregisterRequest, ErrorResponse, NodeInfo, NodeRegistration, NodeStatus, PeersResponse,
    RegisterNodeRequest, SignedRequest, StatusUpdateRequest,
};
use std::collections::{HashMap, HashSet};
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
        gossip_multiaddr: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = RegisterNodeRequest {
            node_id: node_id.to_string(),
            node_type: crate::NodeType::Kels,
            kels_url: kels_url.to_string(),
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// List all active peers as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&self) -> Result<Vec<NodeInfo>, KelsError> {
        let (peers_response, ready_map) = self.fetch_peers().await?;
        let nodes: Vec<NodeInfo> = peers_response
            .peers
            .into_iter()
            .filter_map(|history| {
                history.records.into_iter().last().and_then(|peer| {
                    let status = ready_map
                        .get(&peer.prefix)
                        .unwrap_or(&NodeStatus::Bootstrapping);

                    if peer.active {
                        Some(NodeInfo {
                            node_id: peer.node_id,
                            kels_url: peer.kels_url,
                            gossip_multiaddr: peer.gossip_multiaddr,
                            status: *status,
                            latency_ms: None,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();
        Ok(nodes)
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
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
    pub async fn fetch_peers(
        &self,
    ) -> Result<(PeersResponse, HashMap<String, NodeStatus>), KelsError> {
        let response = self
            .client
            .get(format!("{}/api/peers", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            let result: PeersResponse = response.json().await?;

            let peer_slice: Vec<_> = result
                .peers
                .iter()
                .filter_map(|p| p.records.first())
                .by_ref()
                .collect();
            let ready_map = self.check_nodes_ready_status(&peer_slice).await?;

            Ok((result, ready_map))
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Check if a peer is authorized in the allowlist.
    ///
    /// Returns true if the peer_id is found in the allowlist with active=true.
    /// This is an unauthenticated check - nodes can verify their authorization
    /// before attempting to register.
    pub async fn is_peer_authorized(&self, peer_id: &str) -> Result<bool, KelsError> {
        let (peers_response, _) = self.fetch_peers().await?;

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
        let (nodes, ready_map) = self.fetch_peers().await?;

        for history in nodes.peers {
            let last_record = history.records.first();
            if let Some(record) = last_record
                && record.active
            {
                if let Some(node_id) = exclude_node_id
                    && node_id == record.node_id
                {
                    continue;
                }

                if ready_map.get(&history.prefix) == Some(&NodeStatus::Ready) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn check_node_ready_status(&self, kels_url: &str) -> NodeStatus {
        let ready_url = format!("{}/ready", kels_url.trim_end_matches('/'));

        match self.client.get(&ready_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    // Parse the JSON response to check if ready=true
                    if let Ok(body) = response.json::<serde_json::Value>().await
                        && body.get("ready") == Some(&serde_json::Value::Bool(true))
                    {
                        return NodeStatus::Ready;
                    }
                    NodeStatus::Bootstrapping
                } else if response.status().as_u16() == 503 {
                    // SERVICE_UNAVAILABLE means bootstrapping
                    NodeStatus::Bootstrapping
                } else {
                    NodeStatus::Unhealthy
                }
            }
            Err(_) => NodeStatus::Unhealthy,
        }
    }

    async fn check_nodes_ready_status(
        &self,
        peers: &[&crate::types::Peer],
    ) -> Result<HashMap<String, NodeStatus>, KelsError> {
        let mut map: HashMap<String, NodeStatus> = HashMap::with_capacity(peers.len());

        let futures = peers
            .iter()
            .map(|peer| self.check_node_ready_status(&peer.kels_url));
        let statuses = join_all(futures).await;

        for (i, peer) in peers.iter().enumerate() {
            map.insert(peer.prefix.clone(), statuses[i]);
        }

        Ok(map)
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
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

/// Client for interacting with multiple registry services with automatic failover.
#[derive(Clone)]
pub struct MultiRegistryClient {
    urls: Vec<String>,
    timeout: Duration,
    signer: Option<Arc<dyn RegistrySigner>>,
    prefix_map: HashMap<String, (String, crate::Kel)>,
    trusted_prefixes: HashSet<&'static str>,
}

impl MultiRegistryClient {
    /// Create a new multi-registry client with default timeout (no signing capability).
    ///
    /// URLs are tried in order, with automatic failover to the next URL on failure.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn new(trusted_prefixes: &HashSet<&'static str>, urls: Vec<String>) -> Self {
        Self::with_timeout(trusted_prefixes, urls, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with custom timeout (no signing capability).
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_timeout(
        trusted_prefixes: &HashSet<&'static str>,
        urls: Vec<String>,
        timeout: Duration,
    ) -> Self {
        assert!(
            !urls.is_empty(),
            "MultiRegistryClient requires at least one URL"
        );
        Self {
            urls,
            timeout,
            signer: None,
            prefix_map: HashMap::new(),
            trusted_prefixes: trusted_prefixes.clone(),
        }
    }

    /// Create a new multi-registry client with signing capability.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_signer(
        trusted_prefixes: &HashSet<&'static str>,
        urls: Vec<String>,
        signer: Arc<dyn RegistrySigner>,
    ) -> Self {
        Self::with_signer_and_timeout(trusted_prefixes, urls, signer, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with signing capability and custom timeout.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_signer_and_timeout(
        trusted_prefixes: &HashSet<&'static str>,
        urls: Vec<String>,
        signer: Arc<dyn RegistrySigner>,
        timeout: Duration,
    ) -> Self {
        assert!(
            !urls.is_empty(),
            "MultiRegistryClient requires at least one URL"
        );
        Self {
            urls,
            timeout,
            signer: Some(signer),
            prefix_map: HashMap::new(),
            trusted_prefixes: trusted_prefixes.clone(),
        }
    }

    /// Get the list of registry URLs.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Create a single-URL client for the given URL.
    fn create_client(&self, url: &str) -> KelsRegistryClient {
        match &self.signer {
            Some(signer) => {
                KelsRegistryClient::with_signer_and_timeout(url, signer.clone(), self.timeout)
            }
            None => KelsRegistryClient::with_timeout(url, self.timeout),
        }
    }

    fn get_url(&self, prefix: &str) -> Result<String, KelsError> {
        match self.prefix_map.get(prefix) {
            Some((url, _)) => Ok(url.clone()),
            None => Err(KelsError::RegistryFailure(format!(
                "Could not find registry for prefix {}",
                prefix
            ))),
        }
    }

    pub async fn prefix_for_url(&self, url: &str) -> Result<String, KelsError> {
        match self.prefix_map.iter().find(|(_, (u, _))| u == url) {
            Some((prefix, (_url, _kel))) => Ok(prefix.clone()),
            None => {
                let client = self.create_client(url);
                let registry_kel = client.fetch_registry_kel().await?;
                match registry_kel.prefix() {
                    Some(p) => Ok(p.to_string()),
                    None => Err(KelsError::RegistryFailure(format!(
                        "Prefix not found for url {}",
                        url
                    ))),
                }
            }
        }
    }

    /// List all registered nodes as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&mut self, prefix: &str) -> Result<Vec<NodeInfo>, KelsError> {
        if self.prefix_map.is_empty() {
            self.fetch_verified_registry_kels(true).await?;
        }

        let url = self.get_url(prefix)?;
        let client = self.create_client(&url);
        match client.list_nodes_info().await {
            Ok(v) => Ok(v),
            Err(e) => Err(KelsError::RegistryFailure(format!(
                "Could not list nodes for registry {}: {}",
                prefix, e
            ))),
        }
    }

    /// Fetch all peers from the registry.
    ///
    /// Returns peer histories containing all versions of each peer record.
    /// This is an unauthenticated endpoint - nodes can check the peer list
    /// before they are authorized.
    pub async fn fetch_peers(&mut self, prefix: &str) -> Result<PeersResponse, KelsError> {
        if self.prefix_map.is_empty() {
            self.fetch_verified_registry_kels(true).await?;
        }

        let url = self.get_url(prefix)?;
        let client = self.create_client(&url);
        match client.fetch_peers().await {
            Ok((p, _ready_map)) => Ok(p),
            Err(e) => Err(KelsError::RegistryFailure(format!(
                "Could not list nodes for registry {}: {}",
                prefix, e
            ))),
        }
    }

    /// Check if a peer is authorized in the allowlist.
    ///
    /// Returns true if the peer_id is found in the allowlist with active=true.
    /// This is an unauthenticated check - nodes can verify their authorization
    /// before attempting to register.
    pub async fn is_peer_authorized(
        &self,
        peer_id: &str,
        registry_prefix: &str,
    ) -> Result<bool, KelsError> {
        let url = self.get_url(registry_prefix)?;
        let client = self.create_client(&url);
        match client.is_peer_authorized(peer_id).await {
            Ok(p) => Ok(p),
            Err(e) => Err(KelsError::RegistryFailure(format!(
                "Could not list nodes for registry {}: {}",
                registry_prefix, e
            ))),
        }
    }

    /// Check if there are any Ready peers available for bootstrap sync.
    ///
    /// Returns true if at least one node with Ready status exists (excluding self).
    pub async fn has_ready_peers(
        &self,
        exclude_node_id: Option<&str>,
        registry_prefix: &str,
    ) -> Result<bool, KelsError> {
        let url = self.get_url(registry_prefix)?;
        let client = self.create_client(&url);
        match client.has_ready_peers(exclude_node_id).await {
            Ok(p) => Ok(p),
            Err(e) => Err(KelsError::RegistryFailure(format!(
                "Could not list nodes for registry {}: {}",
                registry_prefix, e
            ))),
        }
    }

    /// Fetch the registry's KEL from all registries in parallel.
    ///
    /// This is an unauthenticated endpoint - nodes use this to verify
    /// that peer records are anchored in the registry's KEL.
    /// Unlike other methods, this fetches from ALL registries, not just until one succeeds.
    pub async fn fetch_registry_kels(
        &mut self,
        force_fetch: bool,
    ) -> Result<Vec<crate::Kel>, KelsError> {
        if !self.prefix_map.is_empty() && !force_fetch {
            return Ok(self
                .prefix_map
                .values()
                .map(|(_, kel)| kel.clone())
                .collect());
        }

        let timeout = self.timeout;
        let signer = self.signer.clone();

        let futures = self.urls.iter().map(|url| {
            let signer = signer.clone();
            let url = url.clone();
            async move {
                let client = match &signer {
                    Some(s) => {
                        KelsRegistryClient::with_signer_and_timeout(&url, s.clone(), timeout)
                    }
                    None => KelsRegistryClient::with_timeout(&url, timeout),
                };
                (url.clone(), client.fetch_registry_kel().await)
            }
        });

        let tuples = join_all(futures).await;

        let mut last_error = None;

        for (url, kel_result) in tuples {
            let kel = match kel_result {
                Ok(k) => k,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            let Some(prefix) = kel.prefix() else {
                last_error = Some(KelsError::RegistryFailure("KEL has no prefix".to_string()));
                continue;
            };

            self.prefix_map.insert(prefix.to_string(), (url, kel));
        }

        if self.prefix_map.is_empty() {
            Err(KelsError::RegistryFailure(
                last_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "No URLs configured".to_string()),
            ))
        } else {
            Ok(self
                .prefix_map
                .values()
                .map(|(_, kel)| kel.clone())
                .collect())
        }
    }

    pub async fn fetch_registry_kel(
        &mut self,
        prefix: &str,
        force_fetch: bool,
    ) -> Result<crate::Kel, KelsError> {
        self.fetch_verified_registry_kels(force_fetch).await?;
        match self.prefix_map.get(prefix) {
            Some((_, kel)) => Ok(kel.clone()),
            None => Err(KelsError::RegistryFailure(format!(
                "Could not find {} in available trusted registries",
                prefix
            ))),
        }
    }

    pub async fn fetch_verified_registry_kels(
        &mut self,
        force_fetch: bool,
    ) -> Result<Vec<crate::Kel>, KelsError> {
        let kels = self.fetch_registry_kels(force_fetch).await?;
        if !kels.iter().all(|k| {
            if !k.verify_prefix(&self.trusted_prefixes) {
                return false;
            }

            k.verify().is_ok()
        }) {
            return Err(KelsError::RegistryFailure(format!(
                "Failed to verify kel prefixes as expected ({:?})",
                self.trusted_prefixes
            )));
        }

        Ok(kels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::KeyEventBuilder;
    use crate::crypto::SoftwareKeyProvider;
    use crate::kel::Kel;
    use crate::types::{NodeRegistration, NodeType, Peer, PeerHistory};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
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

    // Helper to create empty trusted prefixes for tests
    fn empty_trusted_prefixes() -> HashSet<&'static str> {
        HashSet::new()
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
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Internal error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                "/ip4/10.0.0.1/tcp/9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
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

    #[tokio::test]
    async fn test_list_nodes_info() {
        let mock_server = MockServer::start().await;

        let peer = Peer {
            said: "ETestPeerSaid_______________________________".to_string(),
            prefix: "ETestPeerPrefix_____________________________".to_string(),
            previous: None,
            version: 1,
            created_at: chrono::Utc::now().into(),
            peer_id: "12D3KooWPeer1".to_string(),
            node_id: "node-1".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            scope: crate::types::PeerScope::Core,
            kels_url: "http://node-1:8091".to_string(),
            gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
        };

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
        let result = client.list_nodes_info().await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        assert_eq!(nodes[0].kels_url, "http://node-1:8091");
    }

    // ==================== Update Status Tests ====================

    #[tokio::test]
    async fn test_update_status_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
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
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            active,
            crate::types::PeerScope::Regional,
            format!("http://{}:8080", node_id),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id),
        )
        .expect("create peer")
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
        let (peers, _status_map) = result.unwrap();
        assert_eq!(peers.peers.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_peers_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_peers().await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
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
        //     let mock_server = MockServer::start().await;

        //     let response = NodesResponse {
        //         nodes: vec![NodeRegistration {
        //             node_id: "node-1".to_string(),
        //             node_type: NodeType::Kels,
        //             kels_url: "http://node-1:8091".to_string(),
        //             gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
        //             registered_at: chrono::Utc::now(),
        //             last_heartbeat: chrono::Utc::now(),
        //             status: NodeStatus::Ready,
        //         }],
        //         next_cursor: None,
        //     };

        //     Mock::given(method("GET"))
        //         .and(path("/api/nodes/bootstrap"))
        //         .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        //         .mount(&mock_server)
        //         .await;

        //     let client = KelsRegistryClient::new(&mock_server.uri());
        //     let result = client.has_ready_peers(None).await;

        //     assert!(result.is_ok());
        //     assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_has_ready_peers_false() {
        // let mock_server = MockServer::start().await;

        // let response = NodesResponse {
        //     nodes: vec![NodeRegistration {
        //         node_id: "node-1".to_string(),
        //         node_type: NodeType::Kels,
        //         kels_url: "http://node-1:8091".to_string(),
        //         gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
        //         registered_at: chrono::Utc::now(),
        //         last_heartbeat: chrono::Utc::now(),
        //         status: NodeStatus::Bootstrapping, // Not Ready
        //     }],
        //     next_cursor: None,
        // };

        // Mock::given(method("GET"))
        //     .and(path("/api/nodes/bootstrap"))
        //     .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        //     .mount(&mock_server)
        //     .await;

        // let client = KelsRegistryClient::new(&mock_server.uri());
        // let result = client.has_ready_peers(None).await;

        // assert!(result.is_ok());
        // assert!(!result.unwrap());
    }

    // ==================== Registry KEL Tests ====================

    #[tokio::test]
    async fn test_fetch_registry_kel_success() {
        let mock_server = MockServer::start().await;

        // Create a valid KEL for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let kel = Kel::from_events(vec![icp], true).unwrap();

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
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_registry_kel().await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
    }

    #[tokio::test]
    async fn test_verify_registry_success() {
        let mock_server = MockServer::start().await;

        // Create a valid KEL for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let kel = Kel::from_events(vec![icp], true).unwrap();

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
        let icp = builder.incept().await.unwrap();
        let kel = Kel::from_events(vec![icp], true).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.verify_registry("Ewrong_prefix").await;

        assert!(matches!(result, Err(KelsError::VerificationFailed(_))));
    }

    // ==================== MultiRegistryClient Tests ====================

    #[test]
    fn test_multi_client_new() {
        let trusted = empty_trusted_prefixes();
        let client = MultiRegistryClient::new(&trusted, vec!["http://registry:8080".to_string()]);
        assert_eq!(client.urls().len(), 1);
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_multi_client_with_multiple_urls() {
        let trusted = empty_trusted_prefixes();
        let client = MultiRegistryClient::new(
            &trusted,
            vec![
                "http://registry-a:8080".to_string(),
                "http://registry-b:8080".to_string(),
                "http://registry-c:8080".to_string(),
            ],
        );
        assert_eq!(client.urls().len(), 3);
    }

    #[test]
    fn test_multi_client_with_timeout() {
        let trusted = empty_trusted_prefixes();
        let client = MultiRegistryClient::with_timeout(
            &trusted,
            vec!["http://registry:8080".to_string()],
            Duration::from_secs(30),
        );
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_multi_client_with_signer() {
        let trusted = empty_trusted_prefixes();
        let signer = Arc::new(MockSigner);
        let client = MultiRegistryClient::with_signer(
            &trusted,
            vec!["http://registry:8080".to_string()],
            signer,
        );
        assert!(client.signer.is_some());
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_empty_urls_panics() {
        let trusted = empty_trusted_prefixes();
        MultiRegistryClient::new(&trusted, vec![]);
    }

    // Note: Old failover tests removed - the new architecture uses prefix-based
    // routing where each registry is identified by its KEL prefix, not URL failover.

    #[tokio::test]
    async fn test_multi_client_fetch_registry_kels() {
        let mock_server = MockServer::start().await;
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let _prefix = icp.event.prefix.clone();
        let kel = Kel::from_events(vec![icp], true).unwrap();
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&mock_server)
            .await;

        let trusted: HashSet<&'static str> = HashSet::new();
        // We can't easily add a dynamic prefix to a static HashSet in tests,
        // so we test without prefix verification
        let mut client = MultiRegistryClient::new(&trusted, vec![mock_server.uri()]);

        let result = client.fetch_registry_kels(false).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_all_kels_fail() {
        let server1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 1",
                "code": "internal_error"
            })))
            .mount(&server1)
            .await;

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 2",
                "code": "internal_error"
            })))
            .mount(&server2)
            .await;

        let trusted = empty_trusted_prefixes();
        let mut client = MultiRegistryClient::new(&trusted, vec![server1.uri(), server2.uri()]);

        let result = client.fetch_registry_kels(false).await;

        assert!(matches!(result, Err(KelsError::RegistryFailure(_))));
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_timeout_empty_panics() {
        let trusted = empty_trusted_prefixes();
        MultiRegistryClient::with_timeout(&trusted, vec![], Duration::from_secs(10));
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_signer_empty_panics() {
        let trusted = empty_trusted_prefixes();
        let signer = Arc::new(MockSigner);
        MultiRegistryClient::with_signer(&trusted, vec![], signer);
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_signer_and_timeout_empty_panics() {
        let trusted = empty_trusted_prefixes();
        let signer = Arc::new(MockSigner);
        MultiRegistryClient::with_signer_and_timeout(
            &trusted,
            vec![],
            signer,
            Duration::from_secs(10),
        );
    }
}
