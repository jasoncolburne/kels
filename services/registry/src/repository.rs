//! Combined PostgreSQL repository for registry
//!
//! Manages migrations for all registry tables.

use verifiable_storage_postgres::Stored;

use crate::raft_store::{
    MemberKelRepository, RaftLogAuditRepository, RaftLogRepository, RaftStateRepository,
    RaftVoteRepository,
};

/// Combined repository that manages all registry database tables.
///
/// The `migrations` attribute tells Stored to look for SQL files in the
/// "migrations" directory and run them via `initialize()`.
///
/// Use `RegistryRepository::connect(&database_url)` to create an instance.
#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct RegistryRepository {
    pub raft_votes: RaftVoteRepository,
    pub raft_logs: RaftLogRepository,
    pub raft_state: RaftStateRepository,
    pub raft_log_audit: RaftLogAuditRepository,
    pub member_kels: MemberKelRepository,
}
