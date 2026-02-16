//! PostgreSQL-backed storage for Raft consensus state
//!
//! Uses verifiable-storage patterns with SelfAddressed entities.

use verifiable_storage_postgres::{PgPool, Stored};

use kels::{RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote};

/// PostgreSQL-backed Raft vote repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftVote, table = "raft_vote")]
pub struct RaftVoteRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft log entry repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftLogEntry, table = "raft_log")]
pub struct RaftLogRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft state repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftState, table = "raft_state")]
pub struct RaftStateRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft log audit repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftLogAuditRecord, table = "raft_log_audit", chained = false)]
pub struct RaftLogAuditRepository {
    pub pool: PgPool,
}
