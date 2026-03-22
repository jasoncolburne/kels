//! PostgreSQL repository for kels-gossip
//!
//! Stores local copies of registry KELs for anchoring verification.

use kels::KeyEvent;
use libkels_derive::SignedEvents;
use verifiable_storage_postgres::{PgPool, Stored};

/// PostgreSQL-backed registry KEL repository (local copy for anchoring verification)
#[derive(Clone, Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "registry_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "registry_key_event_signatures",
    recovery_table = "registry_recovery"
)]
pub struct RegistryKelRepository {
    pub pool: PgPool,
}

/// Combined repository that manages all kels-gossip database tables.
#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct GossipRepository {
    pub registry_kels: RegistryKelRepository,
}
