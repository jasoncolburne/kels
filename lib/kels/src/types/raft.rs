//! Raft consensus state

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Raft vote state - tracks which node this node voted for in each term.
/// Chained for full audit trail of vote history.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_vote")]
#[serde(rename_all = "camelCase")]
pub struct RaftVote {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    /// Raft node ID (unique constraint with version)
    pub node_id: u64,
    /// The Raft term number
    pub term: u64,
    /// Node ID that was voted for (None if no vote cast)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voted_for: Option<u64>,
    /// Whether this vote has been committed
    pub committed: bool,
}

/// Raft log entry - individual entries in the Raft log.
/// Chained for full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_log")]
#[serde(rename_all = "camelCase")]
pub struct RaftLogEntry {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    /// Raft node ID for this storage instance
    pub node_id: u64,
    /// Log index
    pub log_index: u64,
    /// Term when entry was received by leader
    pub term: u64,
    /// Node ID of the leader that proposed this entry
    pub leader_node_id: u64,
    /// Entry payload type: "blank", "normal", or "membership"
    pub payload_type: String,
    /// Serialized payload data (JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_data: Option<String>,
}

/// Audit record for Raft log operations (truncate/purge).
/// Preserves full history of removed log entries.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_log_audit")]
#[serde(rename_all = "camelCase")]
pub struct RaftLogAuditRecord {
    #[said]
    pub said: String,
    /// Node ID that performed the operation
    pub node_id: u64,
    /// Operation type: "truncate" or "purge"
    pub operation: String,
    /// JSON-serialized log entries that were removed
    pub entries_json: String,
    #[created_at]
    pub recorded_at: StorageDatetime,
}

impl RaftLogAuditRecord {
    /// Create an audit record for a truncate operation.
    pub fn for_truncate(
        node_id: u64,
        entries: &[RaftLogEntry],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            node_id,
            "truncate".to_string(),
            serde_json::to_string(entries)?,
        )
    }

    /// Create an audit record for a purge operation.
    pub fn for_purge(
        node_id: u64,
        entries: &[RaftLogEntry],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            node_id,
            "purge".to_string(),
            serde_json::to_string(entries)?,
        )
    }

    /// Deserialize the archived entries.
    pub fn entries(&self) -> Result<Vec<RaftLogEntry>, serde_json::Error> {
        serde_json::from_str(&self.entries_json)
    }
}

/// Raft state metadata - tracks purged and committed log positions.
/// Chained for full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_state")]
#[serde(rename_all = "camelCase")]
pub struct RaftState {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    /// Raft node ID (unique constraint with version)
    pub node_id: u64,
    /// Last purged log index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_index: Option<u64>,
    /// Term of last purged entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_term: Option<u64>,
    /// Node ID of leader for last purged entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_node_id: Option<u64>,
    /// Committed log index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_index: Option<u64>,
    /// Term of committed entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_term: Option<u64>,
    /// Node ID of leader for committed entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_node_id: Option<u64>,
}
