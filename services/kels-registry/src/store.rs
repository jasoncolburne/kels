//! Redis-backed storage for node registrations

use chrono::Utc;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use thiserror::Error;

// Re-export shared types from kels library
pub use kels::{
    DeregisterRequest, NodeRegistration, NodeStatus, NodeType, RegisterNodeRequest,
    StatusUpdateRequest,
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
}

impl RegistryStore {
    const NODES_SET_KEY: &'static str = "nodes";

    pub fn new(conn: ConnectionManager, key_prefix: &str) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
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
            kels_url: "http://kels.kels".to_string(),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/4001".to_string(),
            status: NodeStatus::Bootstrapping,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("node-1"));
        assert!(json.contains("http://kels.kels"));
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

    // ==================== NodeRegistration Serialization ====================

    #[test]
    fn test_node_registration_serialization_roundtrip() {
        let now = Utc::now();
        let registration = NodeRegistration {
            node_id: "test-node".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://localhost:8080".to_string(),
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
