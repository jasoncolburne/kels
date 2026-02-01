//! Redis-backed storage for node registrations

use chrono::Utc;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use thiserror::Error;

// Re-export shared types from kels library
pub use kels::{
    DeregisterRequest, HeartbeatRequest, NodeRegistration, NodeStatus, NodeType,
    RegisterNodeRequest, StatusUpdateRequest,
};

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Node not found: {0}")]
    NotFound(String),
}

/// Redis-backed registry store
#[derive(Clone)]
pub struct RegistryStore {
    conn: ConnectionManager,
    key_prefix: String,
    heartbeat_timeout_secs: i64,
}

impl RegistryStore {
    const NODES_SET_KEY: &'static str = "nodes";

    pub fn new(conn: ConnectionManager, key_prefix: &str, heartbeat_timeout_secs: i64) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
            heartbeat_timeout_secs,
        }
    }

    fn node_key(&self, node_id: &str) -> String {
        format!("{}:node:{}", self.key_prefix, node_id)
    }

    fn nodes_set_key(&self) -> String {
        format!("{}:{}", self.key_prefix, Self::NODES_SET_KEY)
    }

    /// Register or update a node
    pub async fn register(
        &self,
        request: RegisterNodeRequest,
    ) -> Result<NodeRegistration, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.node_key(&request.node_id);

        let now = Utc::now();
        let registration = NodeRegistration {
            node_id: request.node_id.clone(),
            node_type: request.node_type,
            kels_url: request.kels_url,
            kels_url_internal: request.kels_url_internal,
            gossip_multiaddr: request.gossip_multiaddr,
            registered_at: now,
            last_heartbeat: now,
            status: request.status,
        };

        let json = serde_json::to_string(&registration)?;

        // Store node data and add to set atomically
        let _: () = redis::pipe()
            .atomic()
            .set(&key, &json)
            .sadd(self.nodes_set_key(), &request.node_id)
            .query_async(&mut conn)
            .await?;

        tracing::info!(
            "Registered node {} with status {:?}",
            request.node_id,
            registration.status
        );

        Ok(registration)
    }

    /// Deregister a node
    pub async fn deregister(&self, node_id: &str) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        let key = self.node_key(node_id);

        // Remove from set and delete data atomically
        let _: () = redis::pipe()
            .atomic()
            .del(&key)
            .srem(self.nodes_set_key(), node_id)
            .query_async(&mut conn)
            .await?;

        tracing::info!("Deregistered node {}", node_id);

        Ok(())
    }

    /// Get a specific node
    pub async fn get(&self, node_id: &str) -> Result<Option<NodeRegistration>, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.node_key(node_id);

        let json: Option<String> = conn.get(&key).await?;

        match json {
            Some(j) => {
                let mut registration: NodeRegistration = serde_json::from_str(&j)?;
                // Check if node should be marked unhealthy
                self.check_health(&mut registration);
                Ok(Some(registration))
            }
            None => Ok(None),
        }
    }

    /// List registered nodes with pagination
    /// Returns (nodes, next_cursor) where next_cursor is the last node_id if there are more results
    pub async fn list_paginated(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<NodeRegistration>, Option<String>), StoreError> {
        let mut conn = self.conn.clone();

        // Get all node IDs sorted
        let mut node_ids: Vec<String> = conn.smembers(self.nodes_set_key()).await?;
        node_ids.sort();

        if node_ids.is_empty() {
            return Ok((Vec::new(), None));
        }

        // Apply cursor - skip nodes up to and including cursor
        let start_idx = if let Some(cursor_id) = cursor {
            node_ids
                .iter()
                .position(|id| id.as_str() > cursor_id)
                .unwrap_or(node_ids.len())
        } else {
            0
        };

        // Take limit + 1 to check if there are more
        let page_ids: Vec<&String> = node_ids.iter().skip(start_idx).take(limit + 1).collect();

        if page_ids.is_empty() {
            return Ok((Vec::new(), None));
        }

        // Fetch node data
        let keys: Vec<String> = page_ids.iter().map(|id| self.node_key(id)).collect();
        let values: Vec<Option<String>> = conn.mget(&keys).await?;

        let mut registrations = Vec::new();
        for json_opt in values.into_iter().flatten() {
            if let Ok(mut registration) = serde_json::from_str::<NodeRegistration>(&json_opt) {
                self.check_health(&mut registration);
                registrations.push(registration);
            }
        }

        // Determine next cursor
        let has_more = registrations.len() > limit;
        if has_more {
            registrations.truncate(limit);
        }

        let next_cursor = if has_more {
            registrations.last().map(|n| n.node_id.clone())
        } else {
            None
        };

        Ok((registrations, next_cursor))
    }

    /// Get bootstrap nodes with pagination (excludes caller, only Ready nodes)
    pub async fn get_bootstrap_nodes_paginated(
        &self,
        exclude_node_id: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<NodeRegistration>, Option<String>), StoreError> {
        let mut conn = self.conn.clone();

        // Get all node IDs sorted
        let mut node_ids: Vec<String> = conn.smembers(self.nodes_set_key()).await?;
        node_ids.sort();

        if node_ids.is_empty() {
            return Ok((Vec::new(), None));
        }

        // Apply cursor
        let start_idx = if let Some(cursor_id) = cursor {
            node_ids
                .iter()
                .position(|id| id.as_str() > cursor_id)
                .unwrap_or(node_ids.len())
        } else {
            0
        };

        // Filter out excluded node
        let candidate_ids: Vec<&String> = node_ids
            .iter()
            .skip(start_idx)
            .filter(|id| exclude_node_id.is_none_or(|ex| *id != ex))
            .collect();

        if candidate_ids.is_empty() {
            return Ok((Vec::new(), None));
        }

        // Fetch more than limit to filter by Ready status
        let fetch_limit = (limit + 1) * 2; // Fetch extra to account for non-Ready nodes
        let fetch_ids: Vec<&String> = candidate_ids.iter().take(fetch_limit).copied().collect();

        let keys: Vec<String> = fetch_ids.iter().map(|id| self.node_key(id)).collect();
        let values: Vec<Option<String>> = conn.mget(&keys).await?;

        let mut registrations = Vec::new();
        for json_opt in values.into_iter().flatten() {
            if let Ok(mut registration) = serde_json::from_str::<NodeRegistration>(&json_opt) {
                self.check_health(&mut registration);
                // Only include KELS nodes that are ready (exclude Registry nodes)
                if registration.node_type == NodeType::Kels
                    && registration.status == NodeStatus::Ready
                {
                    registrations.push(registration);
                    if registrations.len() > limit {
                        break;
                    }
                }
            }
        }

        // Determine next cursor
        let has_more = registrations.len() > limit;
        if has_more {
            registrations.truncate(limit);
        }

        let next_cursor = if has_more {
            registrations.last().map(|n| n.node_id.clone())
        } else {
            None
        };

        Ok((registrations, next_cursor))
    }

    /// Update heartbeat for a node
    pub async fn heartbeat(&self, node_id: &str) -> Result<NodeRegistration, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.node_key(node_id);

        // Get existing registration
        let json: Option<String> = conn.get(&key).await?;
        let json = json.ok_or_else(|| StoreError::NotFound(node_id.to_string()))?;

        let mut registration: NodeRegistration = serde_json::from_str(&json)?;
        registration.last_heartbeat = Utc::now();

        // If node was unhealthy, mark as ready on successful heartbeat
        if registration.status == NodeStatus::Unhealthy {
            registration.status = NodeStatus::Ready;
        }

        let updated_json = serde_json::to_string(&registration)?;
        let _: () = conn.set(&key, &updated_json).await?;

        tracing::info!("Heartbeat from node {}", node_id);

        Ok(registration)
    }

    /// Update node status
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.node_key(node_id);

        // Get existing registration
        let json: Option<String> = conn.get(&key).await?;
        let json = json.ok_or_else(|| StoreError::NotFound(node_id.to_string()))?;

        let mut registration: NodeRegistration = serde_json::from_str(&json)?;
        registration.status = status;
        registration.last_heartbeat = Utc::now();

        let updated_json = serde_json::to_string(&registration)?;
        let _: () = conn.set(&key, &updated_json).await?;

        tracing::info!("Node {} status updated to {:?}", node_id, status);

        Ok(registration)
    }

    /// Check and update node health based on heartbeat timeout
    fn check_health(&self, registration: &mut NodeRegistration) {
        let now = Utc::now();
        let elapsed = now
            .signed_duration_since(registration.last_heartbeat)
            .num_seconds();

        if elapsed > self.heartbeat_timeout_secs && registration.status == NodeStatus::Ready {
            registration.status = NodeStatus::Unhealthy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== StoreError Display Tests ====================

    #[test]
    fn test_store_error_not_found_display() {
        let err = StoreError::NotFound("node-123".to_string());
        assert_eq!(err.to_string(), "Node not found: node-123");
    }

    #[test]
    fn test_store_error_serialization_display() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = StoreError::Serialization(json_err);
        assert!(err.to_string().starts_with("Serialization error:"));
    }

    #[test]
    fn test_store_error_redis_display() {
        let redis_err = redis::RedisError::from((redis::ErrorKind::IoError, "connection refused"));
        let err = StoreError::Redis(redis_err);
        assert!(err.to_string().starts_with("Redis error:"));
    }

    // ==================== StoreError From impls ====================

    #[test]
    fn test_store_error_from_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let store_err: StoreError = json_err.into();
        assert!(matches!(store_err, StoreError::Serialization(_)));
    }

    #[test]
    fn test_store_error_from_redis_error() {
        let redis_err = redis::RedisError::from((redis::ErrorKind::TypeError, "type error"));
        let store_err: StoreError = redis_err.into();
        assert!(matches!(store_err, StoreError::Redis(_)));
    }

    // ==================== NodeType and NodeStatus Re-exports ====================

    #[test]
    fn test_node_type_values() {
        // Verify re-exported types work
        let _kels = NodeType::Kels;
        let _registry = NodeType::Registry;
    }

    #[test]
    fn test_node_status_values() {
        let _bootstrapping = NodeStatus::Bootstrapping;
        let _ready = NodeStatus::Ready;
        let _unhealthy = NodeStatus::Unhealthy;
    }

    // ==================== RegisterNodeRequest Fields ====================

    #[test]
    fn test_register_node_request_serialization() {
        let request = RegisterNodeRequest {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://kels.local".to_string(),
            kels_url_internal: Some("http://kels-internal.local".to_string()),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/4001".to_string(),
            status: NodeStatus::Bootstrapping,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("node-1"));
        assert!(json.contains("http://kels.local"));
    }

    #[test]
    fn test_deregister_request_serialization() {
        let request = DeregisterRequest {
            node_id: "node-to-remove".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("node-to-remove"));
    }

    #[test]
    fn test_status_update_request_serialization() {
        let request = StatusUpdateRequest {
            node_id: "node-1".to_string(),
            status: NodeStatus::Ready,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("node-1"));
    }

    #[test]
    fn test_heartbeat_request_serialization() {
        let request = HeartbeatRequest {
            node_id: "node-heartbeat".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("node-heartbeat"));
    }

    // ==================== NodeRegistration Serialization ====================

    #[test]
    fn test_node_registration_serialization_roundtrip() {
        let now = Utc::now();
        let registration = NodeRegistration {
            node_id: "test-node".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://localhost:8080".to_string(),
            kels_url_internal: None,
            gossip_multiaddr: "/ip4/0.0.0.0/tcp/4001".to_string(),
            registered_at: now,
            last_heartbeat: now,
            status: NodeStatus::Ready,
        };

        let json = serde_json::to_string(&registration).unwrap();
        let parsed: NodeRegistration = serde_json::from_str(&json).unwrap();

        assert_eq!(registration.node_id, parsed.node_id);
        assert_eq!(registration.kels_url, parsed.kels_url);
        assert_eq!(registration.status, parsed.status);
    }
}
