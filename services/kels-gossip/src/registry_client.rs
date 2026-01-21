//! Registry API client for node registration and discovery.

use reqwest::Client;
use std::time::Duration;
use thiserror::Error;

// Re-export shared types from kels library
pub use kels::{NodeRegistration, NodeStatus, RegisterNodeRequest, StatusUpdateRequest};

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Registry returned error: {status} - {message}")]
    RegistryError { status: u16, message: String },
    #[error("Node not found: {0}")]
    NotFound(String),
}

/// Client for interacting with the kels-registry service.
#[derive(Clone)]
pub struct RegistryClient {
    client: Client,
    base_url: String,
}

impl RegistryClient {
    /// Create a new registry client.
    pub fn new(registry_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
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
    ) -> Result<NodeRegistration, RegistryError> {
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
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError { status, message })
        }
    }

    /// Deregister a node from the registry.
    pub async fn deregister(&self, node_id: &str) -> Result<(), RegistryError> {
        let response = self
            .client
            .delete(format!("{}/api/nodes/{}", self.base_url, node_id))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Already gone, that's fine
            Ok(())
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError { status, message })
        }
    }

    /// Get list of bootstrap nodes (excludes the calling node).
    pub async fn get_bootstrap_nodes(
        &self,
        exclude_node_id: Option<&str>,
    ) -> Result<Vec<NodeRegistration>, RegistryError> {
        let mut url = format!("{}/api/nodes/bootstrap", self.base_url);
        if let Some(node_id) = exclude_node_id {
            url.push_str(&format!("?exclude={}", node_id));
        }

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError { status, message })
        }
    }

    /// List all registered nodes.
    pub async fn list_nodes(&self) -> Result<Vec<NodeRegistration>, RegistryError> {
        let response = self
            .client
            .get(format!("{}/api/nodes", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError { status, message })
        }
    }

    /// Send heartbeat for a node.
    pub async fn heartbeat(&self, node_id: &str) -> Result<NodeRegistration, RegistryError> {
        let response = self
            .client
            .post(format!("{}/api/nodes/{}/heartbeat", self.base_url, node_id))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(RegistryError::NotFound(node_id.to_string()))
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError { status, message })
        }
    }

    /// Update node status.
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, RegistryError> {
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
            Err(RegistryError::NotFound(node_id.to_string()))
        } else {
            let status_code = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(RegistryError::RegistryError {
                status: status_code,
                message,
            })
        }
    }

    /// Check if the registry is healthy.
    pub async fn health_check(&self) -> Result<bool, RegistryError> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}
