//! Node registration & discovery

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    #[default]
    Kels,
    Registry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Bootstrapping,
    Ready,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeRegistration {
    pub node_id: String,
    #[serde(default)]
    pub node_type: NodeType,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterNodeRequest {
    pub node_id: String,
    #[serde(default)]
    pub node_type: NodeType,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusUpdateRequest {
    pub node_id: String,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeregisterRequest {
    pub node_id: String,
}

/// Information about a registered KELS node (with client-computed fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub node_id: String,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub status: NodeStatus,
    /// Measured latency in milliseconds (populated by discovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

impl From<NodeRegistration> for NodeInfo {
    fn from(reg: NodeRegistration) -> Self {
        Self {
            node_id: reg.node_id,
            kels_url: reg.kels_url,
            gossip_multiaddr: reg.gossip_multiaddr,
            status: reg.status,
            latency_ms: None,
        }
    }
}
