//! PostgreSQL repository for gossip
//!
//! Stores local copies of registry KELs for anchoring verification.

use kels_core::KeyEvent;
use kels_derive::SignedEvents;
use verifiable_storage_postgres::{PgPool, Stored};

/// PostgreSQL-backed registry KEL repository (local copy for anchoring verification)
#[derive(Clone, Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "registry_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "registry_key_event_signatures",
    recovery_table = "registry_recovery",
    archived_events_table = "registry_archived_events",
    archived_signatures_table = "registry_archived_event_signatures",
    recovery_events_table = "registry_recovery_events"
)]
pub struct RegistryKelRepository {
    pub pool: PgPool,
}

/// Combined repository that manages all gossip database tables.
#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct GossipRepository {
    pub registry_kels: RegistryKelRepository,
}
