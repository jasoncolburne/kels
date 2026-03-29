//! PostgreSQL-backed storage for Raft consensus state and member KELs
//!
//! Uses verifiable-storage patterns with SelfAddressed entities.

use verifiable_storage_postgres::{PgPool, Stored};

use kels::{KeyEvent, RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote};
use libkels_derive::SignedEvents;

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

/// PostgreSQL-backed member KEL repository (federation member key events)
#[derive(Clone, Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "member_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "member_key_event_signatures",
    recovery_table = "member_recovery",
    archived_events_table = "member_archived_events",
    archived_signatures_table = "member_archived_event_signatures",
    recovery_events_table = "member_recovery_events"
)]
pub struct MemberKelRepository {
    pub pool: PgPool,
}
