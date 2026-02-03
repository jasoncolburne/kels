//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the kels-registry service.

use crate::error::KelsError;
use crate::types::{
    DeregisterRequest, ErrorResponse, NodeInfo, NodeRegistration, NodeStatus, NodesResponse,
    PeersResponse, RegisterNodeRequest, SignedRequest, StatusUpdateRequest,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
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
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
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
    pub async fn fetch_peers(&self) -> Result<PeersResponse, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/peers", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
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
///
/// This client maintains an ordered list of registry URLs and automatically fails over
/// to the next URL if the current one fails. It tracks the last successful URL to
/// optimize subsequent requests.
#[derive(Clone)]
pub struct MultiRegistryClient {
    urls: Vec<String>,
    timeout: Duration,
    /// Index of the last successful URL (for optimization)
    current: Arc<AtomicUsize>,
    signer: Option<Arc<dyn RegistrySigner>>,
}

impl MultiRegistryClient {
    /// Create a new multi-registry client with default timeout (no signing capability).
    ///
    /// URLs are tried in order, with automatic failover to the next URL on failure.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn new(urls: Vec<String>) -> Self {
        Self::with_timeout(urls, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with custom timeout (no signing capability).
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_timeout(urls: Vec<String>, timeout: Duration) -> Self {
        assert!(
            !urls.is_empty(),
            "MultiRegistryClient requires at least one URL"
        );
        Self {
            urls,
            timeout,
            current: Arc::new(AtomicUsize::new(0)),
            signer: None,
        }
    }

    /// Create a new multi-registry client with signing capability.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_signer(urls: Vec<String>, signer: Arc<dyn RegistrySigner>) -> Self {
        Self::with_signer_and_timeout(urls, signer, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with signing capability and custom timeout.
    ///
    /// # Panics
    /// Panics if the URL list is empty.
    pub fn with_signer_and_timeout(
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
            current: Arc::new(AtomicUsize::new(0)),
            signer: Some(signer),
        }
    }

    /// Get the list of registry URLs.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Get the current (last successful) URL index.
    pub fn current_index(&self) -> usize {
        self.current.load(Ordering::Relaxed)
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

    /// Get the ordered list of URLs to try, starting from the last successful one.
    fn get_ordered_urls(&self) -> Vec<(usize, &str)> {
        let start_idx = self.current.load(Ordering::Relaxed);
        (0..self.urls.len())
            .map(|i| {
                let idx = (start_idx + i) % self.urls.len();
                (idx, self.urls[idx].as_str())
            })
            .collect()
    }

    /// Record a successful URL index.
    fn record_success(&self, idx: usize) {
        self.current.store(idx, Ordering::Relaxed);
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
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client
                .register(
                    node_id,
                    kels_url,
                    kels_url_internal,
                    gossip_multiaddr,
                    status,
                )
                .await
            {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Deregister a node from the registry.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn deregister(&self, node_id: &str) -> Result<(), KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.deregister(node_id).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Get list of bootstrap nodes (excludes the calling node).
    /// Paginates through all available nodes.
    pub async fn list_nodes(
        &self,
        exclude_node_id: Option<&str>,
    ) -> Result<Vec<NodeRegistration>, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.list_nodes(exclude_node_id).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// List all registered nodes with pagination.
    pub async fn list_all_nodes(&self) -> Result<Vec<NodeRegistration>, KelsError> {
        self.list_nodes(None).await
    }

    /// List all registered nodes as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&self) -> Result<Vec<NodeInfo>, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.list_nodes_info().await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Send heartbeat for a node.
    pub async fn heartbeat(&self, node_id: &str) -> Result<NodeRegistration, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.heartbeat(node_id).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Update node status.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.update_status(node_id, status).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Check if the registry is healthy.
    pub async fn health_check(&self) -> Result<bool, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.health_check().await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Fetch all peers from the registry.
    ///
    /// Returns peer histories containing all versions of each peer record.
    /// This is an unauthenticated endpoint - nodes can check the peer list
    /// before they are authorized.
    pub async fn fetch_peers(&self) -> Result<PeersResponse, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.fetch_peers().await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Check if a peer is authorized in the allowlist.
    ///
    /// Returns true if the peer_id is found in the allowlist with active=true.
    /// This is an unauthenticated check - nodes can verify their authorization
    /// before attempting to register.
    pub async fn is_peer_authorized(&self, peer_id: &str) -> Result<bool, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.is_peer_authorized(peer_id).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Check if there are any Ready peers available for bootstrap sync.
    ///
    /// Returns true if at least one node with Ready status exists (excluding self).
    pub async fn has_ready_peers(&self, exclude_node_id: Option<&str>) -> Result<bool, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.has_ready_peers(exclude_node_id).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
    }

    /// Fetch the registry's KEL for verification.
    ///
    /// This is an unauthenticated endpoint - nodes use this to verify
    /// that peer records are anchored in the registry's KEL.
    pub async fn fetch_registry_kel(&self) -> Result<crate::Kel, KelsError> {
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.fetch_registry_kel().await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
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
        let mut last_error = None;

        for (idx, url) in self.get_ordered_urls() {
            let client = self.create_client(url);
            match client.verify_registry(expected_prefix).await {
                Ok(result) => {
                    self.record_success(idx);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!(url = url, error = %e, "Registry request failed, trying next URL");
                    last_error = Some(e);
                }
            }
        }

        Err(KelsError::AllRegistriesFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No URLs configured".to_string()),
        ))
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
                None,
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
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_nodes(None).await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
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
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.heartbeat("node-1").await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
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
        Peer::create(
            peer_id.to_string(),
            node_id.to_string(),
            active,
            crate::types::PeerScope::Regional,
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
        let peers = result.unwrap();
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
        let client = MultiRegistryClient::new(vec!["http://registry:8080".to_string()]);
        assert_eq!(client.urls().len(), 1);
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_multi_client_with_multiple_urls() {
        let client = MultiRegistryClient::new(vec![
            "http://registry-a:8080".to_string(),
            "http://registry-b:8080".to_string(),
            "http://registry-c:8080".to_string(),
        ]);
        assert_eq!(client.urls().len(), 3);
        assert_eq!(client.current_index(), 0);
    }

    #[test]
    fn test_multi_client_with_timeout() {
        let client = MultiRegistryClient::with_timeout(
            vec!["http://registry:8080".to_string()],
            Duration::from_secs(30),
        );
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_multi_client_with_signer() {
        let signer = Arc::new(MockSigner);
        let client =
            MultiRegistryClient::with_signer(vec!["http://registry:8080".to_string()], signer);
        assert!(client.signer.is_some());
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_empty_urls_panics() {
        MultiRegistryClient::new(vec![]);
    }

    #[tokio::test]
    async fn test_multi_client_health_check_first_url_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = MultiRegistryClient::new(vec![
            mock_server.uri(),
            "http://nonexistent:8080".to_string(),
        ]);
        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(client.current_index(), 0);
    }

    #[tokio::test]
    async fn test_multi_client_failover_to_second_url() {
        // First server returns error (use fetch_peers which returns ServerError on 500)
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Internal error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        // Second server succeeds
        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.fetch_peers().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().peers.len(), 1);
        // Current should now point to the second URL
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_subsequent_request_uses_last_successful() {
        // First server fails
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Internal error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        // Second server succeeds
        let good_server = MockServer::start().await;
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
            .expect(2) // Should be called twice
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        // First request fails over to second
        let result1 = client.fetch_peers().await;
        assert!(result1.is_ok());
        assert_eq!(client.current_index(), 1);

        // Second request should start with second URL (which works)
        let result2 = client.fetch_peers().await;
        assert!(result2.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_all_fail() {
        let server1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 1",
                "code": "internal_error"
            })))
            .mount(&server1)
            .await;

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 2",
                "code": "internal_error"
            })))
            .mount(&server2)
            .await;

        let client = MultiRegistryClient::new(vec![server1.uri(), server2.uri()]);

        let result = client.fetch_peers().await;

        assert!(matches!(result, Err(KelsError::AllRegistriesFailed(_))));
    }

    #[tokio::test]
    async fn test_multi_client_list_nodes_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.list_nodes(None).await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
    }

    #[tokio::test]
    async fn test_multi_client_fetch_peers_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.fetch_peers().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().peers.len(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_register_with_signer() {
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
        let client = MultiRegistryClient::with_signer(vec![mock_server.uri()], signer);

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
    async fn test_multi_client_deregister_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&good_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client =
            MultiRegistryClient::with_signer(vec![bad_server.uri(), good_server.uri()], signer);

        let result = client.deregister("node-1").await;
        assert!(result.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_heartbeat_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/nodes/.*/heartbeat"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.heartbeat("node-1").await;
        assert!(result.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_update_status_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/status"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client =
            MultiRegistryClient::with_signer(vec![bad_server.uri(), good_server.uri()], signer);

        let result = client.update_status("node-1", NodeStatus::Ready).await;
        assert!(result.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_is_peer_authorized_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
        let peer = make_test_peer("12D3KooWAuthorizedPeer", "node-1", true);
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };
        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.is_peer_authorized("12D3KooWAuthorizedPeer").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_multi_client_fetch_registry_kel_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let kel = Kel::from_events(vec![icp], true).unwrap();
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.fetch_registry_kel().await;
        assert!(result.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_verify_registry_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let kel = Kel::from_events(vec![icp], true).unwrap();
        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&kel))
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.verify_registry(&prefix).await;
        assert!(result.is_ok());
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_list_nodes_info_with_failover() {
        let bad_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
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
            .mount(&good_server)
            .await;

        let client = MultiRegistryClient::new(vec![bad_server.uri(), good_server.uri()]);

        let result = client.list_nodes_info().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(client.current_index(), 1);
    }

    #[tokio::test]
    async fn test_multi_client_list_all_nodes() {
        let mock_server = MockServer::start().await;
        let response = NodesResponse {
            nodes: vec![
                NodeRegistration {
                    node_id: "node-1".to_string(),
                    node_type: NodeType::Kels,
                    kels_url: "http://node-1:8091".to_string(),
                    kels_url_internal: None,
                    gossip_multiaddr: "/ip4/10.0.0.1/tcp/9000".to_string(),
                    registered_at: chrono::Utc::now(),
                    last_heartbeat: chrono::Utc::now(),
                    status: NodeStatus::Ready,
                },
                NodeRegistration {
                    node_id: "node-2".to_string(),
                    node_type: NodeType::Kels,
                    kels_url: "http://node-2:8091".to_string(),
                    kels_url_internal: None,
                    gossip_multiaddr: "/ip4/10.0.0.2/tcp/9000".to_string(),
                    registered_at: chrono::Utc::now(),
                    last_heartbeat: chrono::Utc::now(),
                    status: NodeStatus::Bootstrapping,
                },
            ],
            next_cursor: None,
        };
        Mock::given(method("GET"))
            .and(path("/api/nodes/bootstrap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = MultiRegistryClient::new(vec![mock_server.uri()]);

        let result = client.list_all_nodes().await;
        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_timeout_empty_panics() {
        MultiRegistryClient::with_timeout(vec![], Duration::from_secs(10));
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_signer_empty_panics() {
        let signer = Arc::new(MockSigner);
        MultiRegistryClient::with_signer(vec![], signer);
    }

    #[test]
    #[should_panic(expected = "MultiRegistryClient requires at least one URL")]
    fn test_multi_client_with_signer_and_timeout_empty_panics() {
        let signer = Arc::new(MockSigner);
        MultiRegistryClient::with_signer_and_timeout(vec![], signer, Duration::from_secs(10));
    }
}
