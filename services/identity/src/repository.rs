//! PostgreSQL Repository for Identity Service
//!
//! Stores:
//! - HsmKeyBinding (versioned, only updated on establishment events)
//! - AuthorityMapping (versioned name -> KEL prefix + last_said)
//! - KeyEvent + signatures (the authoritative local copy of the KEL)

use kels::KeyEvent;
use libkels_derive::SignedEvents;
use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime, StorageError};
use verifiable_storage_postgres::{Order, PgPool, Query, QueryExecutor, Stored};

// ==================== HSM Key Binding ====================

/// HSM key binding - maps KEL state to HSM key handles.
///
/// Only updated on establishment events (icp, rot).
/// Uses SAID pattern for versioning.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_hsm_key_bindings")]
pub struct HsmKeyBinding {
    /// Self-Addressing IDentifier
    #[said]
    pub said: String,

    /// Content-derived prefix for this binding lineage
    #[prefix]
    pub prefix: String,

    /// Previous version's SAID
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,

    /// Version counter (only increments on establishment events)
    #[version]
    pub version: u64,

    /// The KEL prefix this binding is associated with
    pub kel_prefix: String,

    /// HSM handle for current signing key
    pub current_key_handle: String,

    /// HSM handle for pre-committed next key
    pub next_key_handle: String,

    /// When this binding was created
    #[created_at]
    pub created_at: StorageDatetime,
}

// ==================== HSM Binding Repository ====================

#[derive(Stored)]
#[stored(item_type = HsmKeyBinding, table = "identity_hsm_key_bindings")]
pub struct HsmBindingRepository {
    pub pool: PgPool,
}

impl HsmBindingRepository {
    /// Get the latest HSM binding for a KEL prefix
    pub async fn get_latest_by_kel_prefix(
        &self,
        kel_prefix: &str,
    ) -> Result<Option<HsmKeyBinding>, StorageError> {
        let query = Query::<HsmKeyBinding>::for_table(Self::TABLE_NAME)
            .eq("kel_prefix", kel_prefix)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

// ==================== Authority Constants ====================

/// The name used for the main authority identity mapping
pub const AUTHORITY_IDENTITY_NAME: &str = "identity";

// ==================== Authority Mapping ====================

/// Authority mapping - maps a name to a KEL prefix and tracks last event SAID.
///
/// Used for bootstrap/configuration to store known authority identities.
/// Versioned with the Versioned pattern to track changes over time.
/// The `last_said` field tracks the most recent KEL event for continuity verification.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_authority")]
pub struct AuthorityMapping {
    /// Self-Addressing IDentifier
    #[said]
    pub said: String,

    /// Content-derived prefix for this mapping lineage
    #[prefix]
    pub prefix: String,

    /// Previous version's SAID
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,

    /// Version counter
    #[version]
    pub version: u64,

    /// Unique name for this authority (e.g., "identity")
    pub name: String,

    /// KEL prefix of the authority identity
    pub kel_prefix: String,

    /// SAID of the last KEL event (for verifying continuity with KELS)
    pub last_said: String,

    /// When this mapping was created/updated
    #[created_at]
    pub created_at: StorageDatetime,
}

// ==================== Authority Repository ====================

#[derive(Stored)]
#[stored(item_type = AuthorityMapping, table = "identity_authority")]
pub struct AuthorityRepository {
    pub pool: PgPool,
}

impl AuthorityRepository {
    /// Get latest authority mapping by name
    pub async fn get_by_name(&self, name: &str) -> Result<Option<AuthorityMapping>, StorageError> {
        let query = Query::<AuthorityMapping>::for_table(Self::TABLE_NAME)
            .eq("name", name)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

// ==================== Key Event Repository ====================

/// Repository for storing the identity's KEL locally.
#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "identity_key_events")]
#[signed_events(signatures_table = "identity_key_event_signatures")]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

// ==================== Combined Repository ====================

/// Combined repository that provides access to all sub-repositories.
#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct IdentityRepository {
    pub hsm_bindings: HsmBindingRepository,
    pub authority: AuthorityRepository,
    pub kel: KeyEventRepository,
}
