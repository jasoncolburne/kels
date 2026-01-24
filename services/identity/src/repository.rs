//! PostgreSQL Repository for Identity Service

use kels::KeyEvent;
use libkels_derive::SignedEvents;
use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime, StorageError};
use verifiable_storage_postgres::{Order, PgPool, Query, QueryExecutor, Stored};

/// Maps KEL state to HSM key handles. Updated only on establishment events (icp, rot).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_hsm_key_bindings")]
pub struct HsmKeyBinding {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    pub kel_prefix: String,
    pub current_key_handle: String,
    pub next_key_handle: String,
    #[created_at]
    pub created_at: StorageDatetime,
}

#[derive(Stored)]
#[stored(item_type = HsmKeyBinding, table = "identity_hsm_key_bindings")]
pub struct HsmBindingRepository {
    pub pool: PgPool,
}

impl HsmBindingRepository {
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

pub const AUTHORITY_IDENTITY_NAME: &str = "identity";

/// Maps a name to a KEL prefix and tracks last event SAID for continuity verification.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_authority")]
pub struct AuthorityMapping {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    pub name: String,
    pub kel_prefix: String,
    pub last_said: String,
    #[created_at]
    pub created_at: StorageDatetime,
}

#[derive(Stored)]
#[stored(item_type = AuthorityMapping, table = "identity_authority")]
pub struct AuthorityRepository {
    pub pool: PgPool,
}

impl AuthorityRepository {
    pub async fn get_by_name(&self, name: &str) -> Result<Option<AuthorityMapping>, StorageError> {
        let query = Query::<AuthorityMapping>::for_table(Self::TABLE_NAME)
            .eq("name", name)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "identity_key_events")]
#[signed_events(signatures_table = "identity_key_event_signatures")]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct IdentityRepository {
    pub hsm_bindings: HsmBindingRepository,
    pub authority: AuthorityRepository,
    pub kel: KeyEventRepository,
}
