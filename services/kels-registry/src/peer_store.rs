//! PostgreSQL-backed storage for peer allowlist
//!
//! Uses verifiable-storage patterns with SelfAddressed entities.

use verifiable_storage_postgres::{PgPool, Stored};

use kels::Peer;

/// PostgreSQL-backed peer repository using Stored derive
#[derive(Clone, Stored)]
#[stored(item_type = Peer, table = "peer")]
pub struct PeerRepository {
    pub pool: PgPool,
}
