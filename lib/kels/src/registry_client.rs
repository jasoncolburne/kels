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
    async fn sign_request<T: serde::Serialize>(
        &self,
        payload: &T,
    ) -> Result<SignedRequest<T>, KelsError>
    where
        T: Clone,
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
            if let Some(latest) = history.records.first() {
                if latest.peer_id == peer_id && latest.active {
                    return Ok(true);
                }
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
}
