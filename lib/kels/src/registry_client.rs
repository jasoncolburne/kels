//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the kels-registry service.

use crate::error::KelsError;
use crate::types::{
    NodeInfo, NodeRegistration, NodeStatus, NodesResponse, RegisterNodeRequest, StatusUpdateRequest,
};
use std::time::Duration;

/// Client for interacting with the kels-registry service.
#[derive(Clone)]
pub struct KelsRegistryClient {
    client: reqwest::Client,
    base_url: String,
}

impl KelsRegistryClient {
    /// Create a new registry client with default timeout.
    pub fn new(registry_url: &str) -> Self {
        Self::with_timeout(registry_url, Duration::from_secs(10))
    }

    /// Create a new registry client with custom timeout.
    pub fn with_timeout(registry_url: &str, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
        }
    }

    /// Register a node with the registry.
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
            kels_url: kels_url.to_string(),
            kels_url_internal: kels_url_internal.map(|s| s.to_string()),
            gossip_multiaddr: gossip_multiaddr.to_string(),
            status,
        };

        let response = self
            .client
            .post(format!("{}/api/nodes/register", self.base_url))
            .json(&request)
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
    pub async fn deregister(&self, node_id: &str) -> Result<(), KelsError> {
        let response = self
            .client
            .delete(format!("{}/api/nodes/{}", self.base_url, node_id))
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
    pub async fn get_bootstrap_nodes(
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
    pub async fn list_nodes(&self) -> Result<Vec<NodeRegistration>, KelsError> {
        let mut all_nodes = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let page = self
                .fetch_nodes_page(cursor.as_deref(), None, false)
                .await?;
            all_nodes.extend(page.nodes);

            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(all_nodes)
    }

    /// List all registered nodes as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&self) -> Result<Vec<NodeInfo>, KelsError> {
        let nodes = self.list_nodes().await?;
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
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = StatusUpdateRequest { status };

        let response = self
            .client
            .put(format!("{}/api/nodes/{}/status", self.base_url, node_id))
            .json(&request)
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
}
