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

/// Information about a registered KELS node (with client-computed fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub node_id: String,
    pub kels_url: String,
    pub gossip_addr: String,
    pub status: NodeStatus,
    /// Measured latency in milliseconds (populated by discovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}
