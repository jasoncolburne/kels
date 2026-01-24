//! Combined PostgreSQL repository for kels-registry
//!
//! Manages migrations for all registry tables.

use verifiable_storage_postgres::Stored;

use crate::peer_store::PeerRepository;

/// Combined repository that manages all kels-registry database tables.
///
/// The `migrations` attribute tells Stored to look for SQL files in the
/// "migrations" directory and run them via `initialize()`.
///
/// Use `RegistryRepository::connect(&database_url)` to create an instance.
#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct RegistryRepository {
    pub peers: PeerRepository,
}
