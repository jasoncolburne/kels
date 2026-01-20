//! Redis-backed storage for node registrations

use chrono::Utc;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use thiserror::Error;

// Re-export shared types from kels library
pub use kels::{NodeRegistration, NodeStatus, RegisterNodeRequest, StatusUpdateRequest};

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

    /// List all registered nodes
    pub async fn list(&self) -> Result<Vec<NodeRegistration>, StoreError> {
        let mut conn = self.conn.clone();

        // Get all node IDs
        let node_ids: Vec<String> = conn.smembers(self.nodes_set_key()).await?;

        if node_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Get all node data
        let keys: Vec<String> = node_ids.iter().map(|id| self.node_key(id)).collect();
        let values: Vec<Option<String>> = conn.mget(&keys).await?;

        let mut registrations = Vec::new();
        for json_opt in values.into_iter().flatten() {
            if let Ok(mut registration) = serde_json::from_str::<NodeRegistration>(&json_opt) {
                self.check_health(&mut registration);
                registrations.push(registration);
            }
        }

        Ok(registrations)
    }

    /// Get bootstrap nodes (excludes caller, only Ready nodes)
    pub async fn get_bootstrap_nodes(
        &self,
        exclude_node_id: Option<&str>,
    ) -> Result<Vec<NodeRegistration>, StoreError> {
        let nodes = self.list().await?;

        let bootstrap_nodes: Vec<NodeRegistration> = nodes
            .into_iter()
            .filter(|n| {
                n.status == NodeStatus::Ready && exclude_node_id.is_none_or(|id| n.node_id != id)
            })
            .collect();

        Ok(bootstrap_nodes)
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
