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
    pub recovery_key_handle: String,
    /// Signing key label generation counter for HSM key creation.
    /// Persisted to survive restarts and prevent key label collisions.
    pub signing_generation: u64,
    /// Recovery key label generation counter for HSM key creation.
    /// Persisted to survive restarts and prevent key label collisions.
    pub recovery_generation: u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{ContainerAsync, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;
    use verifiable_storage::ChainedRepository;
    use verifiable_storage_postgres::RepositoryConnection;

    /// Test harness with container and repository.
    /// Container is cleaned up when harness is dropped.
    struct TestHarness {
        repo: IdentityRepository,
        _postgres: ContainerAsync<Postgres>,
    }

    impl TestHarness {
        async fn new() -> Self {
            let postgres = Postgres::default()
                .start()
                .await
                .expect("Failed to start Postgres container");

            let pg_host = postgres
                .get_host()
                .await
                .expect("Failed to get Postgres host");
            let pg_port = postgres
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to get Postgres port");

            let database_url = format!(
                "postgres://postgres:postgres@{}:{}/postgres",
                pg_host, pg_port
            );

            let repo = IdentityRepository::connect(&database_url)
                .await
                .expect("Failed to connect to database");
            repo.initialize().await.expect("Failed to run migrations");

            Self {
                repo,
                _postgres: postgres,
            }
        }
    }

    #[test]
    fn test_authority_identity_name_constant() {
        assert_eq!(AUTHORITY_IDENTITY_NAME, "identity");
    }

    #[test]
    fn test_hsm_key_binding_struct() {
        let binding = HsmKeyBinding {
            said: "test_said".to_string(),
            prefix: "test_prefix".to_string(),
            previous: None,
            version: 0,
            kel_prefix: "kel_test_prefix".to_string(),
            current_key_handle: "current_handle".to_string(),
            next_key_handle: "next_handle".to_string(),
            recovery_key_handle: "recovery_handle".to_string(),
            signing_generation: 1,
            recovery_generation: 0,
            created_at: StorageDatetime::now(),
        };

        assert_eq!(binding.kel_prefix, "kel_test_prefix");
        assert_eq!(binding.version, 0);
        assert_eq!(binding.signing_generation, 1);
        assert_eq!(binding.recovery_generation, 0);
    }

    #[test]
    fn test_hsm_key_binding_clone() {
        let binding = HsmKeyBinding {
            said: "clone_said".to_string(),
            prefix: "clone_prefix".to_string(),
            previous: Some("prev_said".to_string()),
            version: 5,
            kel_prefix: "clone_kel".to_string(),
            current_key_handle: "cur".to_string(),
            next_key_handle: "nxt".to_string(),
            recovery_key_handle: "rec".to_string(),
            signing_generation: 10,
            recovery_generation: 2,
            created_at: StorageDatetime::now(),
        };

        let cloned = binding.clone();
        assert_eq!(binding.said, cloned.said);
        assert_eq!(binding.version, cloned.version);
        assert_eq!(binding.previous, cloned.previous);
    }

    #[test]
    fn test_hsm_key_binding_debug() {
        let binding = HsmKeyBinding {
            said: "debug_said".to_string(),
            prefix: "debug_prefix".to_string(),
            previous: None,
            version: 0,
            kel_prefix: "debug_kel".to_string(),
            current_key_handle: "debug_cur".to_string(),
            next_key_handle: "debug_nxt".to_string(),
            recovery_key_handle: "debug_rec".to_string(),
            signing_generation: 0,
            recovery_generation: 0,
            created_at: StorageDatetime::now(),
        };

        let debug_str = format!("{:?}", binding);
        assert!(debug_str.contains("debug_said"));
        assert!(debug_str.contains("debug_kel"));
    }

    #[test]
    fn test_authority_mapping_struct() {
        let mapping = AuthorityMapping {
            said: "auth_said".to_string(),
            prefix: "auth_prefix".to_string(),
            previous: None,
            version: 0,
            name: "test_authority".to_string(),
            kel_prefix: "auth_kel".to_string(),
            last_said: "last_event_said".to_string(),
            created_at: StorageDatetime::now(),
        };

        assert_eq!(mapping.name, "test_authority");
        assert_eq!(mapping.kel_prefix, "auth_kel");
    }

    #[test]
    fn test_authority_mapping_clone() {
        let mapping = AuthorityMapping {
            said: "clone_auth".to_string(),
            prefix: "clone_auth_prefix".to_string(),
            previous: Some("prev_auth".to_string()),
            version: 3,
            name: "clone_authority".to_string(),
            kel_prefix: "clone_auth_kel".to_string(),
            last_said: "clone_last".to_string(),
            created_at: StorageDatetime::now(),
        };

        let cloned = mapping.clone();
        assert_eq!(mapping.said, cloned.said);
        assert_eq!(mapping.name, cloned.name);
        assert_eq!(mapping.previous, cloned.previous);
    }

    #[test]
    fn test_authority_mapping_debug() {
        let mapping = AuthorityMapping {
            said: "debug_auth".to_string(),
            prefix: "debug_auth_prefix".to_string(),
            previous: None,
            version: 0,
            name: "debug_authority".to_string(),
            kel_prefix: "debug_auth_kel".to_string(),
            last_said: "debug_last".to_string(),
            created_at: StorageDatetime::now(),
        };

        let debug_str = format!("{:?}", mapping);
        assert!(debug_str.contains("debug_auth"));
        assert!(debug_str.contains("debug_authority"));
    }

    #[test]
    fn test_hsm_key_binding_serialization_camel_case() {
        let binding = HsmKeyBinding {
            said: "ser_said".to_string(),
            prefix: "ser_prefix".to_string(),
            previous: None,
            version: 0,
            kel_prefix: "ser_kel".to_string(),
            current_key_handle: "ser_cur".to_string(),
            next_key_handle: "ser_nxt".to_string(),
            recovery_key_handle: "ser_rec".to_string(),
            signing_generation: 0,
            recovery_generation: 0,
            created_at: StorageDatetime::now(),
        };

        let json = serde_json::to_string(&binding).expect("Serialization failed");
        assert!(json.contains("kelPrefix"));
        assert!(json.contains("currentKeyHandle"));
        assert!(json.contains("nextKeyHandle"));
        assert!(json.contains("recoveryKeyHandle"));
        assert!(json.contains("signingGeneration"));
        assert!(json.contains("recoveryGeneration"));
        assert!(json.contains("createdAt"));
    }

    #[test]
    fn test_authority_mapping_serialization_camel_case() {
        let mapping = AuthorityMapping {
            said: "ser_auth".to_string(),
            prefix: "ser_auth_prefix".to_string(),
            previous: None,
            version: 0,
            name: "ser_authority".to_string(),
            kel_prefix: "ser_auth_kel".to_string(),
            last_said: "ser_last".to_string(),
            created_at: StorageDatetime::now(),
        };

        let json = serde_json::to_string(&mapping).expect("Serialization failed");
        assert!(json.contains("kelPrefix"));
        assert!(json.contains("lastSaid"));
        assert!(json.contains("createdAt"));
    }

    #[tokio::test]
    async fn test_hsm_binding_get_latest_by_kel_prefix_empty() {
        let harness = TestHarness::new().await;

        let result = harness
            .repo
            .hsm_bindings
            .get_latest_by_kel_prefix("nonexistent_prefix")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_hsm_binding_store_and_retrieve() {
        let harness = TestHarness::new().await;

        // Use the constructor provided by the derive macro
        let binding = HsmKeyBinding::new(
            "store_kel_prefix".to_string(),
            "store_cur".to_string(),
            "store_nxt".to_string(),
            "store_rec".to_string(),
            0,
            0,
        );

        harness
            .repo
            .hsm_bindings
            .create(binding.clone())
            .await
            .expect("Failed to store binding");

        let retrieved = harness
            .repo
            .hsm_bindings
            .get_latest_by_kel_prefix("store_kel_prefix")
            .await
            .expect("Query failed")
            .expect("Binding not found");

        // CHAR(44) columns pad with spaces, so use trim() for comparison
        assert_eq!(retrieved.kel_prefix.trim(), "store_kel_prefix");
        assert_eq!(retrieved.current_key_handle, "store_cur");
        assert_eq!(retrieved.version, 0);
    }

    #[tokio::test]
    async fn test_hsm_binding_returns_latest_version() {
        let harness = TestHarness::new().await;

        // Store version 0
        let binding_v0 = HsmKeyBinding::new(
            "versioned_kel".to_string(),
            "cur_v0".to_string(),
            "nxt_v0".to_string(),
            "rec_v0".to_string(),
            0,
            0,
        );

        harness
            .repo
            .hsm_bindings
            .create(binding_v0.clone())
            .await
            .expect("Failed to store v0");

        // Update to create next version (update calls increment internally)
        let mut binding_v1 = binding_v0.clone();
        binding_v1.current_key_handle = "cur_v1".to_string();
        binding_v1.next_key_handle = "nxt_v1".to_string();
        binding_v1.signing_generation = 1;

        harness
            .repo
            .hsm_bindings
            .update(binding_v1)
            .await
            .expect("Failed to store v1");

        // get_latest_by_kel_prefix should return updated version
        let retrieved = harness
            .repo
            .hsm_bindings
            .get_latest_by_kel_prefix("versioned_kel")
            .await
            .expect("Query failed")
            .expect("Binding not found");

        // Update increments version from 0 to 1
        assert!(retrieved.version >= 1);
        assert_eq!(retrieved.current_key_handle, "cur_v1");
        assert_eq!(retrieved.signing_generation, 1);
    }

    #[tokio::test]
    async fn test_authority_get_by_name_empty() {
        let harness = TestHarness::new().await;

        let result = harness
            .repo
            .authority
            .get_by_name("nonexistent_authority")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_authority_store_and_retrieve() {
        let harness = TestHarness::new().await;

        let mapping = AuthorityMapping::new(
            "test_auth_name".to_string(),
            "test_auth_kel".to_string(),
            "test_last_said".to_string(),
        );

        harness
            .repo
            .authority
            .create(mapping.clone())
            .await
            .expect("Failed to store mapping");

        let retrieved = harness
            .repo
            .authority
            .get_by_name("test_auth_name")
            .await
            .expect("Query failed")
            .expect("Mapping not found");

        assert_eq!(retrieved.name, "test_auth_name");
        // CHAR(44) columns pad with spaces, so use trim() for comparison
        assert_eq!(retrieved.kel_prefix.trim(), "test_auth_kel");
        assert_eq!(retrieved.last_said.trim(), "test_last_said");
    }

    #[tokio::test]
    async fn test_authority_returns_latest_version() {
        let harness = TestHarness::new().await;

        // Store version 0
        let mapping_v0 = AuthorityMapping::new(
            "versioned_auth".to_string(),
            "auth_kel_v0".to_string(),
            "last_v0".to_string(),
        );

        harness
            .repo
            .authority
            .create(mapping_v0.clone())
            .await
            .expect("Failed to store v0");

        // Update to create next version (update calls increment internally)
        let mut mapping_v1 = mapping_v0.clone();
        mapping_v1.kel_prefix = "auth_kel_v1".to_string();
        mapping_v1.last_said = "last_v1".to_string();

        harness
            .repo
            .authority
            .update(mapping_v1)
            .await
            .expect("Failed to store v1");

        // get_by_name should return updated version
        let retrieved = harness
            .repo
            .authority
            .get_by_name("versioned_auth")
            .await
            .expect("Query failed")
            .expect("Mapping not found");

        // Update increments version from 0 to 1
        assert!(retrieved.version >= 1);
        assert_eq!(retrieved.kel_prefix.trim(), "auth_kel_v1");
        assert_eq!(retrieved.last_said.trim(), "last_v1");
    }
}
